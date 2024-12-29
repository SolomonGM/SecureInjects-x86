import os
import re
import asyncio
import asyncpg
import qrcode
import logging
import requests
from decimal import Decimal
from datetime import datetime, timedelta
from asyncio import Lock

from Utils.check_wallet_balance import check_wallet_balance
from Utils.fee_charges import calculate_fee

import discord
from discord.ext import commands
from discord.ui import View, Button
from dotenv import load_dotenv
from web3 import Web3
from web3.exceptions import TransactionNotFound

from Database.postgres import (
    initialize_db,
    add_ticket,
    update_ticket_status,
    get_ticket,
    update_ticket_fields,
    update_user_data,
    update_ticket_transaction_hash,
    delete_ticket,
    get_user_passes,
    update_user_passes,
    update_return_transaction_hash,
    get_user_wallet_address,
    validate_ethereum_address,
    ensure_pool
)

DEFAULT_MONITOR_TIMEOUT = int(os.getenv("TRANSACTION_MONITOR_TIMEOUT", 5))

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Web3 instance
w3 = Web3(Web3.HTTPProvider("https://eth-mainnet.g.alchemy.com/v2/-b20tZNUu-AR9n85JXWHBcNebsSRsD2o"))

if not w3.is_connected():
    raise ConnectionError("Unable to connect to Ethereum network.")

# Database Setup
async def setup_postgres():
    """Sets up the PostgreSQL connection pool."""
    try:
        pool = await asyncpg.create_pool(dsn=DATABASE_URL)
        await initialize_db(pool)  # Ensures the database schema exists.
        logger.info("Database connection pool initialized.")
        return pool
    except Exception as e:
        logger.error(f"Failed to set up PostgreSQL database: {e}")
        raise

# Ethereum Channel Configuration
ETH_CHANNEL_CONFIG = {
    "ETH": {
        "embed": discord.Embed(
            title="Ethereum Support",
            description="You have chosen Ethereum. Please wait while we connect you with a support representative.",
            color=discord.Color.blue()
        )
        .set_thumbnail(url="https://seeklogo.com/images/E/ethereum-logo-EC6CDBA45B-seeklogo.com.png")
    }
}

def get_etherscan_transactions():
    """Fetches transaction list for the bot's wallet address using Etherscan Mainnet."""

    address = ""
    apikey = ""
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={apikey}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if data["status"] == "1" and data["result"]:
            return data["result"]
        else:
            logger.warning(f"Etherscan API returned no transactions: {data.get('message', 'Unknown error')}")
            return []
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch transactions from Etherscan: {e}")
        return []

# Persistent Views Registration
class TicketBot(commands.Bot):
    def __init__(self, command_prefix, **options):
        super().__init__(command_prefix, **options)
        self.database_pool = None

    async def on_ready(self):
        self.database_pool = await setup_postgres()
        self.add_persistent_views()
        logger.info(f"Logged in as {self.user}")

    def add_persistent_views(self):
        """Register persistent views."""
        self.add_view(TicketView())

class TicketView(discord.ui.View):
    def __init__(self, user: discord.User, db_pool, channel: discord.TextChannel):
        super().__init__(timeout=None)
        self.user = user
        self.channel = channel
        self.amount_confirmation_started = False
        self.confirmation_completed = False
        self.confirmation_message = None
        self.cancel_button_disabled = False
        self.db_pool = db_pool
        self.message = None
        self.confirmation_active = False
        self.roles_confirmed = False  # Flag to prevent delete if roles are confirmed

    async def set_initial_message(self, message: discord.Message):
        """Sets the initial message associated with this view."""
        self.message = message

    async def disable_cancel_button(self, interaction: discord.Interaction = None):
        """Disables the cancel button in the view."""
        self.cancel_button_disabled = True
        for item in self.children:
            if isinstance(item, discord.ui.Button) and item.label == "Cancel":
                item.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except discord.NotFound:
                logger.warning("Attempted to update a non-existent message while disabling cancel button.")
                if interaction:
                    await interaction.channel.send(
                        "Unable to update the view; the message may no longer exist.",
                        delete_after=10
                    )

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.danger)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Cancel the ticket and trigger a confirmation dialog."""
        if self.cancel_button_disabled:
            await interaction.response.send_message(
                "You already clicked me.",
                ephemeral=True
            )
            return

        # Check if roles are already confirmed
        if self.roles_confirmed:
            await interaction.response.send_message(
                "You cannot cancel the ticket after roles have been confirmed.",
                ephemeral=True
            )
            return

        # Check if the user is the ticket creator
        if interaction.user != self.user:
            await interaction.response.send_message("Only the ticket creator can cancel the ticket.", ephemeral=True)
            return

        # Prevent others from sending messages in the channel
        await interaction.channel.set_permissions(interaction.guild.default_role, send_messages=False, view_channel=False)

        # Create confirmation embed and view
        confirm_embed = discord.Embed(
            title="Confirm Ticket Deletion",
            description=(
                "Are you sure you want to delete this ticket? "
                "All processes will stop, and no one can interact or send messages until you make a decision."
            ),
            color=discord.Color.red()
        )
        self.cancel_button_disabled = True  # Disable the cancel button
        try:
            await interaction.response.send_message(
                embed=confirm_embed,
                view=DeleteConfirmationView(
                    user=self.user,
                    channel=interaction.channel,
                    db_pool=self.db_pool,
                    ticket_view=self
                )
            )
        except discord.NotFound:
            logger.warning("Failed to send confirmation view. Message may not exist.")

class DeleteConfirmationView(discord.ui.View):
    def __init__(self, user: discord.User, channel: discord.TextChannel, db_pool, ticket_view):
        super().__init__(timeout=None)
        self.user = user
        self.channel = channel
        self.db_pool = db_pool
        self.ticket_view = ticket_view  # Pass the TicketView instance

    @discord.ui.button(label="Delete", style=discord.ButtonStyle.danger)
    async def delete_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handles deletion of the ticket."""
        if self.ticket_view.roles_confirmed:
            await interaction.response.send_message(
                "You cannot delete the ticket after roles have been confirmed.",
                ephemeral=True
            )
            return

        if interaction.user == self.user:
            try:
                await interaction.response.send_message("Deleting the ticket...", ephemeral=True)

                # Update database and delete the ticket
                await update_ticket_status(self.db_pool, self.channel.id, "Cancelled")
                await delete_ticket(self.db_pool, self.channel.id)  # Corrected function call
                await self.channel.delete()
            except discord.NotFound:
                logger.warning("Attempted to delete a non-existent channel or send a non-existent message.")
        else:
            await interaction.response.send_message("Only the ticket creator can delete the ticket.", ephemeral=True)

    @discord.ui.button(label="Continue", style=discord.ButtonStyle.success)
    async def continue_ticket(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handles continuation of the ticket."""
        if interaction.user == self.user:
            await interaction.response.send_message("Continuing the process...", ephemeral=True)

            # Restore channel permissions
            await self.channel.set_permissions(interaction.guild.default_role, send_messages=False, view_channel=False)
            await self.channel.set_permissions(self.ticket_view.user, send_messages=True, view_channel=True)

            # Re-enable the cancel button in the TicketView
            self.ticket_view.cancel_button_disabled = False
            self.ticket_view.confirmation_active = False  # Mark confirmation as inactive
            if self.ticket_view.message:
                self.ticket_view.children[0].disabled = False
                await self.ticket_view.message.edit(view=self.ticket_view)

            # Remove the confirmation embed
            await interaction.message.delete()
        else:
            await interaction.response.send_message("Only the ticket creator can continue the ticket.", ephemeral=True)

class RoleSelectionView(discord.ui.View):
    def __init__(self, bot: commands.Bot, user: discord.User, mentioned_user: discord.User, ticket_view, ticket_id: int, channel: discord.TextChannel):
        super().__init__(timeout=None)
        self.bot = bot
        self.user = user
        self.mentioned_user = mentioned_user
        self.ticket_view = ticket_view
        self.selection_made = False
        self.ticket_id = int(ticket_id)
        self.channel = channel

    @discord.ui.button(label="Sender", style=discord.ButtonStyle.green)
    async def sender_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._select_role(interaction, is_sender=True)

    @discord.ui.button(label="Receiver", style=discord.ButtonStyle.danger)
    async def receiver_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self._select_role(interaction, is_sender=False)

    async def _select_role(self, interaction: discord.Interaction, is_sender: bool):
        if self.selection_made:
            await interaction.response.send_message("Role selection is already in progress.", ephemeral=True)
            return

        if interaction.user != self.user:
            await interaction.response.send_message("Only the ticket owner can select this option.", ephemeral=True)
            return

        self.selection_made = True
        await self._disable_buttons(interaction)
        await self._confirm_role_selection(interaction, is_sender)

    async def _disable_buttons(self, interaction: discord.Interaction):
        for item in self.children:
            item.disabled = True
        await interaction.message.edit(view=self)

    async def _confirm_role_selection(self, interaction: discord.Interaction, is_sender: bool):
        sender = self.user if is_sender else self.mentioned_user
        receiver = self.mentioned_user if is_sender else self.user
        confirmation_embed = discord.Embed(
            title="Confirm",
            description=f"**Sender:** {sender.mention}\n**Receiver:** {receiver.mention}\n\n{self.mentioned_user.mention}, please confirm if these roles are correct.",
            color=discord.Color.green()
        )
        role_confirm_view = RoleConfirmView(
            bot=self.bot,
            sender=sender,
            receiver=receiver,
            confirm_user=self.mentioned_user,
            ticket_id=self.channel.id,  
            ticket_view=self.ticket_view
        )
        await interaction.channel.send(embed=confirmation_embed, view=role_confirm_view)


class RoleConfirmView(discord.ui.View):
    def __init__(self, bot, sender, receiver, confirm_user, ticket_id, ticket_view):
        super().__init__(timeout=None)
        self.bot = bot
        self.sender = sender
        self.receiver = receiver
        self.confirm_user = confirm_user  # Only this user can confirm or deny roles
        self.ticket_id = ticket_id
        self.ticket_view = ticket_view

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.success)
    async def confirm_roles(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handles role confirmation by the correct user."""
        if interaction.user != self.confirm_user:
            await interaction.response.send_message("Only the mentioned user can confirm roles.", ephemeral=True)
            return

        await self._disable_buttons(interaction)

        # Notify that roles are confirmed and proceed with the role finalization
        await self._send_confirmation_message(interaction.channel)
        self.ticket_view.roles_confirmed = True  # Mark roles as confirmed
        await self.ticket_view.disable_cancel_button(interaction)  # Disable cancel button
        await self.finalize_role_selection(interaction)

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.danger)
    async def deny_roles(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handles role denial by the correct user."""
        if interaction.user != self.confirm_user:
            await interaction.response.send_message("Only the mentioned user can deny roles.", ephemeral=True)
            return

        # Disable buttons and update the view
        await self._disable_buttons(interaction)
        
        # Notify about the denial and re-initiate the role selection
        await self._send_denial_message(interaction.channel)
        await self._reinitiate_role_selection(interaction.channel)

    async def _disable_buttons(self, interaction: discord.Interaction):
        """Disables all buttons in the view to prevent further interaction."""
        for item in self.children:
            if isinstance(item, discord.ui.Button):
                item.disabled = True
        try:
            await interaction.message.edit(view=self)
        except discord.NotFound:
            logger.warning("Message not found when trying to disable buttons in RoleConfirmView.")

    async def _send_confirmation_message(self, channel: discord.TextChannel):
        """Sends a message confirming the roles and notifying users to proceed."""
        confirmation_embed = discord.Embed(
            title="Roles Confirmed",
            description=(
                f"The roles have been confirmed:\n\n"
                f"**Sender:** {self.sender.mention}\n"
                f"**Receiver:** {self.receiver.mention}\n\n"
                "The transaction process will now continue."
            ),
            color=discord.Color.green()
        )
        await channel.send(embed=confirmation_embed)

    async def _send_denial_message(self, channel: discord.TextChannel):
        """Sends a message notifying users that the roles have been denied."""
        denial_embed = discord.Embed(
            title="Roles Denied",
            description="The roles have been denied. Please ping support or make a new ticket.",
            color=discord.Color.red()
        )
        await channel.send(embed=denial_embed)

    async def _reinitiate_role_selection(self, channel: discord.TextChannel):
        """Reinitiates the role selection process if the roles were denied."""
        role_selection_embed = discord.Embed(
            title="Role Selection",
            description="Please select your role in this transaction.",
            color=discord.Color.green()
        )
        role_selection_view = RoleSelectionView(
            bot=self.bot,
            user=self.sender,  # Start the selection with the original sender
            mentioned_user=self.receiver,  # Keep the original receiver as the mentioned user
            ticket_view=self.ticket_view,
            ticket_id=channel.id,
            channel=channel
        )
        await channel.send(embed=role_selection_embed, view=role_selection_view)

    async def finalize_role_selection(self, interaction: discord.Interaction):
        """Finalizes role selection and prompts the sender to enter the transaction amount."""
        self.ticket_view.confirmation_completed = True
        await self.ticket_view.disable_cancel_button(interaction)

        # Prompt the sender to enter the amount
        await self.prompt_for_amount(interaction.channel, self.sender, self.receiver)

    async def prompt_for_amount(self, channel: discord.TextChannel, sender: discord.User, receiver: discord.User):
        """Prompts the sender to enter the transaction amount they will be sending to the receiver."""
        amount_prompt_embed = discord.Embed(
            title="Enter Amount",
            description=f"{sender.mention}, please enter the amount (in USD) you will be sending to {receiver.mention}.",
            color=discord.Color.green()
        )
        await channel.send(embed=amount_prompt_embed)

        # Wait for the sender's amount entry
        await self._await_amount_input(channel, sender, receiver)

    async def _await_amount_input(self, channel: discord.TextChannel, sender: discord.User, receiver: discord.User):
        """Waits for the sender to input a valid amount and then confirms it with the receiver."""
        amount_regex = r'^\$?(\d{1,3}(,\d{3})*|\d+)(\.\d{1,2})?$'  # Matches standard USD format (e.g., 1000, $1,000.00)

        def check(message: discord.Message):
            return (
                message.author == sender and
                message.channel == channel and
                re.match(amount_regex, message.content.strip())
            )

        try:
            # Wait for a valid price input from the sender within 60 seconds
            amount_message = await self.bot.wait_for("message", timeout=60.0, check=check)
            
            # Sanitize and convert the amount to a float
            amount = self._sanitize_amount(amount_message.content)

            # Prompt the receiver to confirm the amount
            await self.confirm_amount_with_receiver(channel, sender, receiver, amount)

        except asyncio.TimeoutError:
            timeout_embed = discord.Embed(
                title="Timeout",
                description="You took too long to input an amount. Please try again later.",
                color=discord.Color.red()
            )
            await channel.send(embed=timeout_embed)
        except ValueError:
            error_embed = discord.Embed(
                title="Invalid Format",
                description="The amount entered is not valid. Please use a format like `$1000.00` or `1000`.",
                color=discord.Color.red()
            )
            await channel.send(embed=error_embed)

    async def confirm_amount_with_receiver(self, channel: discord.TextChannel, sender: discord.User, receiver: discord.User, amount: float):
        """Prompts the receiver to confirm the entered amount by the sender."""
        confirm_embed = discord.Embed(
            title="Confirm Amount",
            description=(
                f"{sender.mention} will be sending **${amount:,.2f}** to {receiver.mention}.\n\n"
                "Please confirm if this is correct."
            ),
            color=discord.Color.green()
        )

        self.ticket_view.expected_amount = amount

        confirmation_view = AmountConfirmationView(
            confirm_user=receiver,
            amount=amount,
            channel=channel,
            bot=self.bot,
            ticket_owner=sender,
            mentioned_user=receiver,
            ticket_id=channel.id, 
            ticket_view=self.ticket_view,
            db_pool=self.bot.database_pool
        )
        await channel.send(embed=confirm_embed, view=confirmation_view)
    
    @staticmethod
    def _sanitize_amount(amount_text: str) -> float:
        """Sanitizes the amount input by removing currency symbols and commas, then converts it to a float."""
        sanitized_amount = amount_text.strip().replace("$", "").replace(",", "")
        return float(sanitized_amount)

class AmountConfirmationView(discord.ui.View):
    def __init__(self, confirm_user, amount, channel, bot, ticket_owner, mentioned_user, ticket_id, ticket_view, db_pool):
        super().__init__(timeout=None)
        self.confirm_user = confirm_user
        self.amount = float(amount)
        self.channel = channel
        self.bot = bot
        self.ticket_owner = ticket_owner
        self.mentioned_user = mentioned_user
        self.ticket_id = ticket_id
        self.ticket_view = ticket_view
        self.expected_amount = amount
        self.db_pool = db_pool

        # Crypto address configuration
        self.crypto_address = ""
        self.monitor_timeout = DEFAULT_MONITOR_TIMEOUT
        self.alchemy_url = ""

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.success)
    async def confirm_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handles confirmation of the amount by the receiver."""
        if interaction.user != self.confirm_user:
            await interaction.response.send_message("Only the receiver can confirm this transaction.", ephemeral=True)
            return

        # Disable all buttons in the view
        await self.disable_all_buttons(interaction)

        # Show "Use Pass" options
        await self.display_use_pass_options()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.danger)
    async def cancel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Cancels the transaction and disables all buttons."""
        if interaction.user != self.confirm_user:
            await interaction.response.send_message("Only the receiver can cancel this transaction.", ephemeral=True)
            return

        # Update the ticket status to "Cancelled"
        await update_ticket_status(self.db_pool, self.ticket_id, "cancelled")

        # Send the Transaction Cancelled Embed
        cancel_embed = discord.Embed(
            title="Transaction Cancelled",
            description="The transaction has been cancelled. No further actions can be taken. If you need assistance, please contact support.",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=cancel_embed)

        # Disable all buttons in the view
        await self.disable_all_buttons(interaction)

    async def disable_all_buttons(self, interaction: discord.Interaction):
        """Disables all buttons in this view."""
        for item in self.children:
            if isinstance(item, discord.ui.Button):
                item.disabled = True

        try:
            # Update the view to reflect disabled buttons
            await interaction.message.edit(view=self)
        except discord.NotFound:
            logger.warning("The message with the Amount Confirmation view was not found.")

    async def display_use_pass_options(self):
        """Displays options to use a pass or proceed with fees."""
        fee = calculate_fee(self.amount)
        total_amount = self.amount + fee

        embed = discord.Embed(
            title="Use Pass?",
            description=(f"Your total amount (including fees) is **${total_amount:,.2f}**.\n"
                         "Do you want to use a pass? This will waive the fees.\n\n"
                         "**Either of you can use your passes!**\n\n"
                         "Click the button below to confirm using your pass or proceed with fees."),
            color=discord.Color.green()
        )

        view = discord.ui.View(timeout=None)
        view.add_item(self.create_use_pass_button())
        view.add_item(self.create_proceed_button(fee))

        self.use_pass_message = await self.channel.send(embed=embed, view=view)

    def create_use_pass_button(self):
        """Creates the 'Use Pass' button with its callback logic."""
        button = discord.ui.Button(label="🎫 Use Pass", style=discord.ButtonStyle.success)

        async def use_pass_callback(interaction: discord.Interaction):
            """Handles the logic when 'Use Pass' is clicked."""
            if interaction.user.id not in [self.ticket_owner.id, self.mentioned_user.id]:
                await interaction.response.send_message("Only the ticket participants can use a pass.", ephemeral=True)
                return

            try:
                passes = await get_user_passes(self.db_pool, str(interaction.user.id))
                if passes > 0:
                    await update_user_passes(self.db_pool, interaction.user.id, passes - 1)
                    self.expected_amount = self.amount  # No fee if pass is used

                    # Remove "Use Pass" embed and buttons
                    await self.remove_use_pass_embed()

                    # Start transaction monitoring with QR code embed
                    await self.start_transaction_monitor(self.channel)

                    await interaction.response.send_message(
                        "Pass used successfully. Proceeding without fees.", ephemeral=True
                    )
                else:
                    await interaction.response.send_message("You don't have any passes left.", ephemeral=True)
            except Exception as e:
                logger.error(f"Error while using pass: {e}")
                if not interaction.response.is_done():
                    await interaction.response.send_message("An error occurred. Please try again.", ephemeral=True)

        button.callback = use_pass_callback
        return button

    def create_proceed_button(self, fee):
        """Creates the 'Proceed with Fees' button with its callback logic."""
        button = discord.ui.Button(label="Proceed with Fees", style=discord.ButtonStyle.danger)

        async def proceed_callback(interaction: discord.Interaction):
            """Handles the logic when 'Proceed with Fees' is clicked."""
            if interaction.user != self.ticket_owner:
                await interaction.response.send_message("Only the ticket owner can proceed with fees.", ephemeral=True)
                return

            # Update the expected amount with the fee
            self.expected_amount += fee

            # Remove "Use Pass" embed and buttons
            await self.remove_use_pass_embed()

            # Start transaction monitoring with QR code embed
            await self.start_transaction_monitor(self.channel)

            await interaction.response.send_message(
                "Proceeding with the transaction including fees.", ephemeral=True
            )

        button.callback = proceed_callback
        return button

    async def remove_use_pass_embed(self):
        """Removes the 'Use Pass' embed and buttons from the channel."""
        if hasattr(self, "use_pass_message"):
            try:
                await self.use_pass_message.delete()
            except discord.NotFound:
                logger.warning("The 'Use Pass' message was already deleted or not found.")

    async def start_transaction_monitor(self, channel: discord.TextChannel):
        """Starts the transaction monitor for the specified amount and address."""
        try:
            monitor = TransactionMonitor(
                bot=self.bot,
                channel=channel,
                crypto_address=self.crypto_address,
                expected_amount=self.expected_amount,
                alchemy_url=self.alchemy_url,
                monitor_timeout=self.monitor_timeout,
                db_pool=self.db_pool,
                ticket_id=self.ticket_id,
                sender=self.ticket_owner,
                receiver=self.mentioned_user
            )
            asyncio.create_task(monitor.monitor_transactions())
        except Exception as e:
            logger.error(f"Error initializing transaction monitor: {e}")
            await channel.send("Failed to start the transaction monitor. Please contact support.", ephemeral=True)

# Reconnection Logic for Database Pool
async def reconnect_db(pool):
    """Ensures the database pool is active or reconnects if necessary."""
    try:
        if not pool or pool._closed:
            logger.warning("Database pool closed. Reconnecting...")
            pool = await asyncpg.create_pool(dsn=DATABASE_URL)
            logger.info("Database pool reconnected successfully.")
        return pool
    except Exception as e:
        logger.error(f"Failed to reconnect to the database: {e}")
        raise

class TransactionMonitor:
    def __init__(self, bot, channel, crypto_address, expected_amount, alchemy_url, monitor_timeout, db_pool, ticket_id, sender, receiver):
        self.bot = bot
        self.channel = channel
        self.crypto_address = Web3.to_checksum_address(crypto_address)
        self.expected_amount = Decimal(expected_amount)
        self.w3 = Web3(Web3.HTTPProvider("https://eth-mainnet.g.alchemy.com/v2/-b20tZNUu-AR9n85JXWHBcNebsSRsD2o"))  # Initialize Web3 with Alchemy URL
        self.monitor_timeout = monitor_timeout
        self.db_pool = db_pool
        self.ticket_id = ticket_id
        self.sender = sender
        self.receiver = receiver
        self.eth_to_usd_rate = None
        self.detection_message = None
        self.crypto_prompt_sent = False
        self.transaction_confirmed = False
        self._lock = Lock()
        self.processed_transactions = set()

        if not self.w3.is_connected():
            raise ConnectionError("Unable to connect to the Ethereum network. Check your connection.")

    def generate_qr_code(self):
        """Generates a QR code for the bot's Ethereum wallet address and saves it."""
        output_dir = "assets/qrcodes"
        os.makedirs(output_dir, exist_ok=True)  # Ensure the output directory exists

        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(self.crypto_address)
        qr.make(fit=True)

        qr_code_path = os.path.join(output_dir, "bot_wallet_qr.png")
        img = qr.make_image(fill="black", back_color="white")
        img.save(qr_code_path)
        return qr_code_path

    async def _send_crypto_address_prompt(self, channel: discord.TextChannel):
        """Sends the crypto address for the transaction and shows monitoring embed."""
        if self.crypto_prompt_sent:  # Ensure prompt is sent only once
            logger.info("Crypto address prompt already sent; skipping.")
            return

        # Record the current block number accurately
        self.start_block = self.w3.eth.block_number
        logger.info(f"Recorded starting block number: {self.start_block}.")

        qr_code_path = self.generate_qr_code()
        address_prompt_embed = discord.Embed(
            title="Send the Cryptocurrency",
            description=(
                f"Please send **${self.expected_amount:,.2f}** to the following address:\n\n`{self.crypto_address}`\n\n"
                "**Important:** Spillage is **1%**, so ensure you send the exact amount; otherwise, the bot won't detect it. "
                "Once sent, the bot will verify the amount.\n\n"
                "If you have any issues, please contact support."
            ),
            color=discord.Color.blue()
        ).set_footer(text="Monitoring transactions...").set_thumbnail(url="attachment://qr_code.png")

        file = discord.File(qr_code_path, filename="qr_code.png")
        self.paste_view = discord.ui.View(timeout=None)
        paste_button = discord.ui.Button(label="Paste Address", style=discord.ButtonStyle.primary)

        async def paste_callback(interaction: discord.Interaction):
            await interaction.response.send_message(self.crypto_address, ephemeral=True)

        paste_button.callback = paste_callback
        self.paste_view.add_item(paste_button)

        self.crypto_prompt_sent = True
        self.detection_message = await channel.send(embed=address_prompt_embed, file=file, view=self.paste_view)

    def get_eth_to_usd_rate(self):
        """Fetches the ETH-to-USD rate sfrom a public API."""
        try:
            response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd")
            response.raise_for_status()
            eth_to_usd = response.json()["ethereum"]["usd"]
            logger.info(f"ETH-to-USD rate fetched: {eth_to_usd}")
            return eth_to_usd
        except Exception as e:
            logger.error(f"Error fetching ETH-to-USD rate: {e}")
            return None

    async def send_awaiting_embed(self, channel: discord.TextChannel):
        """Sends an embed to notify the channel of the transaction monitoring."""
        embed = discord.Embed(
            title="Awaiting Transaction",
            description=(
                f"Monitoring the blockchain for a transaction of **${self.expected_amount:.2f} USD**.\n"
                "Ensure you send the correct amount to the specified address.\n\n"
                f"**Address:** `{self.crypto_address}`"),
            color=discord.Color.orange()
        )
        self.detection_message = await channel.send(embed=embed)

    async def monitor_transactions(self):
        """Monitor transactions using Etherscan API."""
        logger.info(f"Starting transaction monitoring for ticket ID {self.ticket_id}.")

        try:
            if not hasattr(self, 'processed_transactions'):
                self.processed_transactions = set()

            if not hasattr(self, 'start_block') or self.start_block is None:
                self.start_block = self.w3.eth.block_number
                logger.info(f"Automatically set starting block number: {self.start_block}")

            # Send the crypto address embed once and record the embed sent time
            await self._send_crypto_address_prompt(self.channel)
            embed_sent_time = datetime.now()

            # Define monitoring end time
            end_time = datetime.now() + timedelta(minutes=self.monitor_timeout)

            # Fetch ETH-to-USD rate as a Decimal
            eth_to_usd_rate = Decimal(self.get_eth_to_usd_rate())
            if eth_to_usd_rate is None:
                logger.error("Failed to fetch ETH-to-USD rate. Aborting transaction monitoring.")
                await self.channel.send("Unable to retrieve ETH-to-USD conversion rate. Please contact support.")
                return

            logger.info(f"ETH-to-USD conversion rate: {eth_to_usd_rate:.2f} USD/ETH")

            # Calculate expected bounds in USD as Decimal
            lower_bound_usd = Decimal(self.expected_amount) * Decimal("0.99")
            upper_bound_usd = Decimal(self.expected_amount) * Decimal("1.01")
            logger.info(f"Expected USD range: ${lower_bound_usd:.2f} - ${upper_bound_usd:.2f}.")

            await self.send_awaiting_embed(self.channel)

            while datetime.now() < end_time:
                # Check if the transaction has already been confirmed
                if self.transaction_confirmed:
                    logger.info("Transaction already confirmed. Stopping monitoring.")
                    return

                transactions = get_etherscan_transactions()
                if not transactions:
                    logger.info("No transactions retrieved from Etherscan. Retrying...")
                    await asyncio.sleep(5)
                    continue

                for txn in transactions:
                    # Skip transactions that are already processed
                    if txn["hash"] in self.processed_transactions:
                        continue

                    # Skip transactions in earlier blocks
                    if int(txn["blockNumber"]) <= self.start_block:
                        continue

                    # Check if the transaction timestamp is after the embed was sent
                    txn_time = datetime.fromtimestamp(int(txn["timeStamp"]))
                    if txn_time < embed_sent_time:
                        logger.info(f"Skipping transaction {txn['hash']} before embed was sent at {embed_sent_time}.")
                        continue

                    if "to" not in txn or txn["to"] is None:
                        logger.warning(f"Transaction {txn['hash']} has no 'to' field. Skipping.")
                        continue

                    if txn["to"].lower() != self.crypto_address.lower():
                        logger.info(f"Transaction {txn['hash']} is not to the monitored address. Skipping.")
                        continue

                    # Convert transaction value to ETH
                    try:
                        value_eth = Decimal(self.w3.from_wei(int(txn["value"]), "ether"))
                    except Exception as e:
                        logger.error(f"Error converting transaction value: {e}")
                        continue

                    transaction_hash = txn["hash"]  # Define transaction_hash here
                    logger.info(f"Transaction detected: {transaction_hash} - Amount: {value_eth:.6f} ETH.")

                    # Convert ETH to USD for range check
                    value_usd = value_eth * eth_to_usd_rate
                    logger.debug(f"Converted transaction value: {value_usd:.2f} USD.")

                    # Check if the transaction value is within bounds (in USD)
                    if lower_bound_usd <= value_usd <= upper_bound_usd:
                        logger.info(f"Transaction {transaction_hash} is within the acceptable USD range.")

                        # Prevent duplicate confirmations
                        async with self._lock:
                            if not self.transaction_confirmed:
                                self.transaction_confirmed = True

                                # Add transaction hash to processed transactions
                                self.processed_transactions.add(transaction_hash)
                                logger.info(f"Added transaction {transaction_hash} to processed list.")

                                await self.log_and_confirm_transaction(txn, value_eth, value_usd)
                                return
                    else:
                        logger.warning(
                            f"Transaction value {value_usd:.2f} USD is outside the expected range "
                            f"(${lower_bound_usd:.2f} - ${upper_bound_usd:.2f})."
                        )

                # Wait for a brief period before checking again
                await asyncio.sleep(5)

            # Handle timeout if no transactions are detected
            await self.handle_timeout()
        except Exception as e:
            logger.error(f"Error monitoring transactions: {e}")
            await self.channel.send("Transaction monitoring encountered an error.")

    async def log_and_confirm_transaction(self, txn, value_eth, value_usd):
        """Logs the relevant transaction and sends confirmation."""
        try:
            txn_hash = txn["hash"]

            # Log the transaction
            await add_ticket(
                pool=self.db_pool,
                channel_id=self.ticket_id,
                user_id=str(self.sender.id),
                amount=float(value_usd),  # Log the amount in USD
                wallet_address=self.crypto_address,
                status="Confirmed",
                transaction_hash=txn_hash,
                sender_wallet_address=txn.get("from"),
                receiver_wallet_address=txn.get("to"),
            )
            logger.info(f"Transaction logged: {txn_hash} - {value_usd:.2f} USD for ticket ID {self.ticket_id}.")
            
            # Delete the "Awaiting Transaction" message if it exists
            if hasattr(self, 'detection_message') and self.detection_message:
                try:
                    await self.detection_message.delete()
                    logger.info("Awaiting Transaction message deleted.")
                except discord.NotFound:
                    logger.warning("Awaiting Transaction message not found or already deleted.")

            # Send confirmation embed
            embed = discord.Embed(
                title="Transaction Confirmed",
                description=(
                    f"Bot detected transaction!\n\n"
                    f"**Amount:** `${value_usd:.2f} USD` (~{value_eth:.6f} ETH)\n\n"
                    "Your transaction has been successfully confirmed."
                ),
                color=discord.Color.green(),
            )
            embed.set_thumbnail(url="https://www.pngkit.com/png/full/776-7762350_download-transparent-check-mark-gif.png")
            await self.channel.send(embed=embed)
    
            # Update ticket with transaction hash
            await update_ticket_transaction_hash(self.db_pool, self.ticket_id, txn_hash)
            logger.info(f"Transaction confirmation updated for ticket ID {self.ticket_id}.")

            # Instantiate TradeConfirmationView and call initiate_trade_confirmation
            trade_view = TradeConfirmationView(
                bot=self.bot,
                sender=self.sender,
                receiver=self.receiver,
                ticket_id=self.ticket_id,
                initial_usd_amount=float(value_usd),
                w3=self.w3,
                db_pool=self.db_pool,
                channel=self.channel,
            )
            await trade_view.initiate_trade_confirmation(self.channel)

        except Exception as e:
            logger.error(f"Error confirming transaction: {e}")
            await self.channel.send("An error occurred while confirming the transaction. Please contact support.")

    # Enhanced Notifications and Cleanup
    async def notify_transaction_status(channel, status, description):
        """Send notification for transaction status."""
        color = discord.Color.green() if status == "success" else discord.Color.red()
        embed = discord.Embed(
            title=f"Transaction {status.capitalize()}",
            description=description,
            color=color
        )
        await channel.send(embed=embed)

    async def handle_timeout(self):
        """Handles a timeout if no transaction is detected."""
        if self.detection_message:
            await self.detection_message.delete()

        embed = discord.Embed(
            title="Transaction Timeout",
            description=("No transaction matching the specified amount was detected within the monitoring period. "
                         "If you have sent the funds, please ping support with proof."),
            color=discord.Color.red()
        )
        await self.channel.send(embed=embed)

async def remove_use_pass_embed(self):
    """Removes the 'Use Pass' embed and buttons from the channel."""
    if hasattr(self, "use_pass_message"):
        try:
            await self.use_pass_message.delete()
        except discord.NotFound:
            logger.warning("The 'Use Pass' message was already deleted or not found.")

class TradeConfirmationView(discord.ui.View):
    def __init__(self, bot: commands.Bot, sender: discord.User, receiver: discord.User, ticket_id: int, initial_usd_amount: float, w3: Web3, db_pool, channel: discord.TextChannel):
        super().__init__(timeout=None)
        self.bot = bot
        self.sender = sender
        self.receiver = receiver
        self.ticket_id = ticket_id
        self.initial_usd_amount = initial_usd_amount  # The initially agreed USD amount
        self.eth_amount = None  # This will store the equivalent ETH amount after conversion
        self.release_message = None  # To store the "Release" message reference
        self.confirmation_message = None  # To store the transaction confirmation message reference
        self.w3 = w3
        self.db_pool = db_pool
        self.channel = channel
        self.confirmed_address = None
        self.private_key = ""

    def get_eth_to_usd_rate(self):
        """Fetches the ETH-to-USD rates from a public API."""
        try:
            response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=ethereum&vs_currencies=usd")
            response.raise_for_status()
            eth_to_usd = response.json()["ethereum"]["usd"]
            logger.info(f"ETH-to-USD rate fetched: {eth_to_usd}")
            return eth_to_usd
        except Exception as e:
            logger.error(f"Error fetching ETH-to-USD rate: {e}")
            return None

    async def initiate_trade_confirmation(self, channel: discord.TextChannel):
        """Prompts the receiver to proceed with the trade and notifies them of the process."""
        
        # Check for receiver's wallet address
        receiver_wallet_address = await get_user_wallet_address(pool=self.db_pool, user_id=self.receiver.id)

        if not receiver_wallet_address:
            logger.warning(f"No wallet address found for user ID {self.receiver.id}.")
            receiver_wallet_address = None  # Set to None if missing instead of stopping
        
        # Update the ticket with the receiver wallet address if available
        await update_ticket_fields(
            pool=self.db_pool,
            channel_id=self.channel.id,  # Replace ticket_id with channel.id
            receiver_wallet_address=receiver_wallet_address
        )
        
        # Send trade confirmation embed
        trade_confirmation_embed = discord.Embed(
            title="Proceed with Trade",
            description=(
                f"{self.receiver.mention}, you may now proceed with the trade.\n\n"
                f"Once {self.sender.mention} receives the agreed-upon goods, they will confirm completion, "
                "and only they can press the 'Release' button below to finalize the transaction.\n\n"
                "**Note**: Only the sender can press the 'Release' button once the trade is fully complete."
            ),
            color=discord.Color.green()
        )
        self.release_message = await channel.send(embed=trade_confirmation_embed, view=self)

    @discord.ui.button(label="Release", style=discord.ButtonStyle.success)
    async def complete_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """Handles the trade completion confirmation by the sender."""
        if interaction.user != self.sender:
            await interaction.response.send_message("Only the sender can confirm trade completion.", ephemeral=True)
            return

        # Remove any existing "Transaction Confirmed" message before continuing
        if self.confirmation_message:
            try:
                await self.confirmation_message.delete()
            except discord.NotFound:
                pass  # Message already deleted or not found

        # Prompt the sender to enter an address for the ETH transfer of the full received amount
        await self.prompt_for_eth_address(interaction.channel)

    async def prompt_for_eth_address(self, channel: discord.TextChannel):
        """Prompts the receiver to enter the Ethereum address to receive the full amount in ETH equivalent of the USD value."""
        # Convert the initial USD amount to ETH
        eth_to_usd_rate = self.get_eth_to_usd_rate()
        if eth_to_usd_rate is None:
            await channel.send("Failed to retrieve the ETH to USD conversion rate. Please try again later or contact support.")
            return

        self.eth_amount = self.initial_usd_amount / eth_to_usd_rate

        address_prompt_embed = discord.Embed(
            title="Enter ETH Address",
            description=(
                f"{self.receiver.mention}, please provide your Ethereum wallet address where you would like to receive "
                f"the equivalent of **${self.initial_usd_amount:.2f} USD** (~{self.eth_amount:.6f} ETH)."
            ),
            color=discord.Color.blue()
        )

        # Delete the "Release" message after sending the new prompt
        if self.release_message:
            try:
                await self.release_message.delete()
            except discord.NotFound:
                pass

        # Keep reprompting until the user confirms a valid address
        while True:
            address_message = await channel.send(embed=address_prompt_embed)

            # Wait for the user to provide an address
            def address_check(message):
                return message.author == self.receiver and message.channel == channel

            address_message_content = await self.bot.wait_for("message", check=address_check)
            address = address_message_content.content.strip()

            if Web3.is_address(address):
                # Send confirmation embed with buttons
                confirmation_embed = discord.Embed(
                    title="Confirm Ethereum Address",
                    description=(
                        f"{self.receiver.mention}, are you sure you want to receive the funds at this address?\n\n"
                        f"**Address:** `{address}`"
                    ),
                    color=discord.Color.orange()
                )

                confirm_view = discord.ui.View(timeout=60)  # Timeout after 60 seconds
                confirm_button = discord.ui.Button(label="Confirm", style=discord.ButtonStyle.success)
                deny_button = discord.ui.Button(label="Deny", style=discord.ButtonStyle.danger)

                confirmation_message = await channel.send(embed=confirmation_embed, view=confirm_view)

                async def confirm_callback(interaction: discord.Interaction):
                    if interaction.user != self.receiver:
                        await interaction.response.send_message(
                            "Only the receiver can confirm this address.", ephemeral=True
                        )
                        return

                    self.confirmed_address = address

                    # Update wallet addresses in the database
                    await update_ticket_fields(
                        pool=self.db_pool,
                        channel_id=self.ticket_id,
                        receiver_wallet_address=self.confirmed_address
                    )

                    # Delete the confirmation embed
                    await confirmation_message.delete()
                    await interaction.response.send_message("Address confirmed!", ephemeral=True)
                    await self.awaiting_confirmation_embed(channel)
                    await self.process_eth_transfer(channel)
                    confirm_view.stop()

                async def deny_callback(interaction: discord.Interaction):
                    if interaction.user != self.receiver:
                        await interaction.response.send_message(
                            "Only the receiver can deny this address.", ephemeral=True
                        )
                        return

                    # Delete the confirmation embed and reprompt
                    await confirmation_message.delete()
                    await address_message.delete()
                    await interaction.response.send_message(
                        "Address denied. Please provide a new Ethereum address.", ephemeral=True
                    )
                    confirm_view.stop()

                confirm_button.callback = confirm_callback
                deny_button.callback = deny_callback
                confirm_view.add_item(confirm_button)
                confirm_view.add_item(deny_button)

                await confirmation_message.edit(embed=confirmation_embed, view=confirm_view)

                # Wait for user confirmation
                await confirm_view.wait()

                # If the user confirms the address, exit the loop
                if self.confirmed_address:
                    break
            else:
                await channel.send(f"{self.receiver.mention}, the address you provided is invalid. Please try again.")

    async def awaiting_confirmation_embed(self, channel: discord.TextChannel):
        """Displays an embed indicating that the transaction is awaiting confirmation."""
        awaiting_embed = discord.Embed(
            title="Awaiting Confirmation",
            description="The transaction is being processed. Please wait for confirmation.",
            color=discord.Color.orange()
        ).set_footer(text="This may take a few moments.")
        self.awaiting_message = await channel.send(embed=awaiting_embed)

    async def process_eth_transfer(self, channel: discord.TextChannel):
        """Transfers the full USD equivalent in ETH to the confirmed address and sends confirmation once complete."""
        
        # Send ETH to the confirmed address
        transaction_hash = await self.send_eth(self.confirmed_address, self.eth_amount)

        # Confirm transaction success
        if transaction_hash:
            # Store the outgoing transaction hash (bot to user) in the database
            logger.info(f"Updating return transaction hash: {transaction_hash} for ticket ID {self.ticket_id}")
            await update_return_transaction_hash(self.db_pool, int(self.ticket_id), transaction_hash)  
            await self.transaction_confirmed_embed(channel, transaction_hash)
        else:
            await channel.send("Transaction failed to confirm. Please check your wallet and ping support.")

    async def send_eth(self, to_address: str, amount: float):
        """Sends ETH to the specified address with robust error handling and logging."""
        try:
            account = self.w3.eth.account.from_key(self.private_key)
            sender_address = account.address

            # Convert transaction amount to Wei
            wei_amount = self.w3.to_wei(amount, 'ether')

            while True:  # Retry loop for handling insufficient balance
                # Fetch gas price dynamically
                gas_price = await self.get_current_gas_price()

                # Estimate gas limit for the transaction
                try:
                    gas_limit = self.w3.eth.estimate_gas({'to': to_address, 'value': wei_amount})
                except Exception as e:
                    logger.error("Failed to estimate gas limit. Transaction may fail.")
                    await self.channel.send("Error: Failed to estimate gas fees. Please contact support.")
                    return None

                # Calculate total ETH required
                total_required_eth = self.w3.from_wei(wei_amount + (gas_price * gas_limit), 'ether')

                # Check wallet balance
                wallet_balance = self.w3.eth.get_balance(sender_address)

                # Build transaction
                transaction = {
                    'to': to_address,
                    'value': wei_amount,
                    'gas': gas_limit,
                    'gasPrice': gas_price,
                    'nonce': self.w3.eth.get_transaction_count(sender_address),
                }

                # Sign and send transaction
                signed_txn = self.w3.eth.account.sign_transaction(transaction, private_key=self.private_key)
                txn_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
                logger.info(f"Transaction sent! Hash: {txn_hash.hex()}")

                # Asynchronously poll for transaction receipt
                for _ in range(240):  # Poll every 5 seconds for up to 5 minutes
                    try:
                        receipt = self.w3.eth.get_transaction_receipt(txn_hash)
                        if receipt:
                            if receipt.status == 1:
                                logger.info(f"Transaction successful: {txn_hash.hex()}")
                                return txn_hash.hex()
                            else:
                                logger.error(f"Transaction reverted on-chain: {txn_hash.hex()}")
                                await self.channel.send("Error: Transaction reverted. Please contact support.")
                                return None
                    except TransactionNotFound:
                        logger.warning(f"Transaction {txn_hash.hex()} not found. Retrying...")
                        await asyncio.sleep(15)  # Wait before polling again
                        continue

                # If receipt is still not available after timeout
                logger.error(f"Transaction {txn_hash.hex()} timed out without confirmation.")
                await self.channel.send(
                    "Transaction is taking longer than expected. Please check back later or contact support."
                )
                return None

        except requests.exceptions.ConnectionError:
            logger.critical("Failed to connect to Ethereum node. Check your ETH_NODE_URL configuration.")
            await self.channel.send("Error: Unable to connect to Ethereum network. Please contact support.")
            return None
        except Exception as e:
            logger.exception(f"Unexpected error while sending ETH: {e}")
            await self.channel.send("An unexpected error occurred. Please contact support.")
            return None

    async def get_current_gas_price(self):
        """ Fetches the current gas price from Etherscan. Fallback to w3's gas price estimate if failed. """
        try:
            response = requests.get(
                "https://api.etherscan.io/api?module=gastracker&action=gasoracle&apikey=1TVPGM59W7JVY2DF18ZNTI4Z2A92M41FWY"
            )
            if response.status_code == 200:
                gas_price_gwei = float(response.json()['result']['ProposeGasPrice'])
                return self.w3.to_wei(gas_price_gwei, 'gwei')  # Convert Gwei to Wei
            logger.warning("Failed to fetch gas price from Etherscan. Using Web3 fallback.")
        except Exception as e:
            logger.error(f"Error fetching gas price: {e}")

        return self.w3.eth.gas_price  # Fallback to Web3 gas estimate

    async def transaction_confirmed_embed(self, channel: discord.TextChannel, transaction_hash):
        """Sends an embed confirming that the transaction has been completed successfully."""
        # Remove the "Awaiting Confirmation" message if it exists
        if hasattr(self, 'awaiting_message') and self.awaiting_message:
            try:
                await self.awaiting_message.delete()
            except discord.NotFound:
                logger.warning("The 'Awaiting Confirmation' message was already deleted or not found.")

        confirmation_embed = discord.Embed(
            title="Transaction Confirmed",
            description=(
                f"The transaction of **${self.initial_usd_amount:.2f} USD** (~{self.eth_amount:.6f} ETH) "
                "has been successfully sent to the confirmed address.\n\nYour transaction is complete."
            ),
            color=discord.Color.green()
        ).set_thumbnail(url="https://www.lappymaker.com/images/greentick-unscreen.gif")
        
        # Store the confirmation message reference for potential deletion later
        self.confirmation_message = await channel.send(embed=confirmation_embed)

        # Update ticket fields with the return transaction hash
        try:
            await update_ticket_fields(
                pool=self.db_pool,
                channel_id=self.ticket_id,
                return_transaction_hash=transaction_hash,  # Pass the correct hash
                status="complete"
            )
            logger.info(f"Return transaction hash updated successfully for ticket ID {self.ticket_id}.")
        except Exception as e:
            logger.error(f"Failed to update return transaction hash: {e}")

        # **Update statistics for both users**
        await self.update_user_statistics()

        # Send vouch prompt and finish button
        await self.send_vouch_prompt(channel)

    async def update_user_statistics(self):
        try:
            # Ensure the sender and receiver exist
            if not self.sender or not self.receiver:
                logger.error("Sender or receiver information is missing.")
                return

            # Ensure the pool is active before using it
            self.db_pool = await ensure_pool(self.db_pool)

            async with self.db_pool.acquire() as conn:
                # Update sender statistics
                await update_user_data(
                    pool=self.db_pool,
                    user_id=self.sender.id,
                    usd_value=self.initial_usd_amount,  # Increment USD value
                    deals_completed_increment=1        # Increment deals completed
                )
                logger.info(f"Updated stats for sender {self.sender.id}.")

                # Update receiver statistics
                await update_user_data(
                    pool=self.db_pool,
                    user_id=self.receiver.id,
                    usd_value=self.initial_usd_amount,  # Increment USD value
                    deals_completed_increment=1        # Increment deals completed
                )
                logger.info(f"Updated stats for receiver {self.receiver.id}.")
        except Exception as e:
            logger.error(f"Failed to update user stats: {e}")

    async def send_vouch_prompt(self, channel: discord.TextChannel):
        """Sends a prompt asking the user to vouch and provides a 'Finish' button to close the ticket."""
        
        vouch_channel = self.bot.get_channel(1317779835094962196)

        vouch_embed = discord.Embed(
            title="Vouches!",
            description=(
                f"If you had a successful experience using our bot, please consider leaving a vouch in our {vouch_channel.mention}.\n\n"
                "Click the 'Finish' button below to close this ticket."
            ),
            color=discord.Color.blurple()
        )
        
        # Create a "Finish" button to close the ticket
        finish_view = discord.ui.View()
        finish_button = discord.ui.Button(label="Finish", style=discord.ButtonStyle.blurple)

        async def finish_callback(interaction: discord.Interaction):
            await interaction.response.send_message("This ticket will be closed in 10 seconds.", ephemeral=True)
            await asyncio.sleep(10)
            await channel.delete()

        finish_button.callback = finish_callback
        finish_view.add_item(finish_button)

        await channel.send(embed=vouch_embed, view=finish_view)

async def setup_eth_ticket_channel(bot: commands.Bot, channel: discord.TextChannel, user: discord.Member):
    """Initializes an Ethereum support ticket channel."""
    pool = bot.database_pool
    ticket_id = channel.id
    STAFF_ROLE_IDS = {1297929632598851677, 1297929631961448559, 1313190690070593536, 1297929633869860895, 1311122265471189052, 1297929624516558931, 1297929623266398209, 1297929622222147665, 1297929618619236422}

    # Initialize TicketView
    ticket_view = TicketView(user=user, db_pool=bot.database_pool, channel=channel)

    # Welcome message with initial TicketView
    welcome_embed = discord.Embed(
        title=f"Welcome to {channel.name}",
        description="Our bot will assist you shortly. To close this ticket, press the button below.",
        color=discord.Color.green()
    )
    message = await channel.send(content=user.mention, embed=welcome_embed, view=ticket_view)
    bot.persistent_views.append(ticket_view)
    await ticket_view.set_initial_message(message)
    await asyncio.sleep(10)  # Delay for clarity

    # Prompt the user to mention another participant
    prompt_embed = discord.Embed(
        title="Add user to transaction ticket",
        description=(
            "Please mention the user you will transact with (e.g., **@john123**).\n"
            "Note: Do not mention staff members or bots."
        ),
        color=discord.Color.green()
    )
    await channel.send(embed=prompt_embed)

    def is_valid_participant(mentioned_user: discord.Member) -> bool:
        """Checks if the mentioned user is valid (not staff, bot, or the same user)."""
        # Check if the user has any of the staff roles
        is_staff = any(role.id in STAFF_ROLE_IDS for role in mentioned_user.roles)
        return (
            mentioned_user != user
            and not mentioned_user.bot
            and not is_staff  # Ensure the user is not a staff member
            and mentioned_user not in channel.members
        )

    try:
        while True:  # Loop until a valid mention is received
            def check(message: discord.Message):
                return (
                    message.author == user
                    and message.channel == channel
                    and len(message.mentions) == 1
                )

            mention_message = await bot.wait_for('message', timeout=120.0, check=check)
            mentioned_user = mention_message.mentions[0]

            if not is_valid_participant(mentioned_user):
                # Send a message indicating the mention is invalid
                invalid_user_embed = discord.Embed(
                    title="Invalid Mention",
                    description="You cannot mention a staff member or bot. Please mention a valid user.",
                    color=discord.Color.red()
                )
                error_message = await channel.send(embed=invalid_user_embed)

                # Wait for 3 seconds and then delete the error message
                await asyncio.sleep(3)
                await error_message.delete()
                continue  # Restart the loop to wait for a valid mention

            # Grant permissions to the mentioned user
            await channel.set_permissions(mentioned_user, read_messages=True, send_messages=True)

            added_embed = discord.Embed(
                title="User Added",
                description=f"{mentioned_user.mention} has been added to the ticket channel {channel.mention}.",
                color=discord.Color.green()
            )
            await channel.send(embed=added_embed)
            await asyncio.sleep(3)

            # Role selection prompt
            role_selection_embed = discord.Embed(
                title="Role Selection",
                description="Please select your role in this transaction.",
                color=discord.Color.green()
            )
            role_selection_view = RoleSelectionView(
                bot=bot,
                user=user,
                mentioned_user=mentioned_user,
                ticket_view=ticket_view,
                ticket_id=channel.id,
                channel=channel
            )
            await channel.send(embed=role_selection_embed, view=role_selection_view)
            break  # Exit after valid mention

    except asyncio.TimeoutError:
        timeout_embed = discord.Embed(
            title="Timeout",
            description="You took too long to mention another user. Please try again later.",
            color=discord.Color.red()
        )
        await channel.send(embed=timeout_embed)