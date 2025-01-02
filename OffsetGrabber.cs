
import os
import asyncio
import asyncpg
import re
import qrcode
import logging
import aiohttp
import requests
from decimal import Decimal
from datetime import datetime, timedelta
from datetime import timezone
from asyncio import Lock

from blockcypher import simple_spend, from_base_unit

from Utils.check_wallet_balance import check_wallet_balance
from Utils.fee_charges import calculate_fee

from ecdsa import SigningKey, SECP256k1
from hashlib import sha256

from bit.exceptions import InsufficientFunds

from pycoin.symbols.ltc import network as ltc_network

import discord
from discord.ext import commands
from discord.ui import View, Button
from dotenv import load_dotenv
from scripts.commands.privacy import anonymous_users, anonymous_receivers

from Database.postgres import (
    initialize_db,
    add_ticket,
    update_ticket_status,
    get_ticket,
    update_ticket_amount,
    update_ticket_fields,
    update_user_data,
    update_ticket_transaction_hash,
    delete_ticket,
    get_user_passes,
    update_user_passes,
    update_return_transaction_hash,
    get_user_wallet_address,
    validate_ethereum_address,
    add_processed_transaction,
    get_processed_transactions,
    ensure_pool
)

# Default timeout for transaction monitoring
DEFAULT_MONITOR_TIMEOUT = int(os.getenv("TRANSACTION_MONITOR_TIMEOUT", 5))

# Load environment v
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# BlockCypher API Configuration
BLOCKCYPHER_BASE_URL = "https://api.blockcypher.com/v1/ltc/main"
BLOCKCYPHER_API_TOKEN = "4494713e9fee4fc28c4e2f37088e1f1d"

FROM_ADDRESS = "LMWPbWSahWAZuHsbJQecHgkv4WboQbX6vZ" 
PRIVATE_KEY = "T3YXxnfCrpBevCUU7RACq1Gb1RJdBubuSs6ZQFJTJA3kS35eyc9w"

TATUM_API_BASE_URL = "https://litecoin-mainnet.gateway.tatum.io"

# Test connection to BlockCypher API
def test_blockcypher_connection():
    try:
        response = requests.get(f"{BLOCKCYPHER_BASE_URL}?token={BLOCKCYPHER_API_TOKEN}")
        if response.status_code == 200:
            logger.info("Connected to Litecoin network via BlockCypher.")
        else:
            logger.error(f"Failed to connect to Litecoin network: {response.text}")
            raise ConnectionError("Unable to connect to Litecoin network.")
    except Exception as e:
        logger.error(f"Error connecting to Litecoin network: {e}")
        raise

test_blockcypher_connection()

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

# Configuration specifically for Litecoin (LTC)
LTC_CHANNEL_CONFIG = {
    "LTC": {
        "embed": discord.Embed(
            title="Litecoin Support",
            description="You have chosen Litecoin. Please wait while we connect you with a support representative.",
            color=discord.Color.light_grey()
        ) .set_thumbnail(url="https://seeklogo.com/images/L/litecoin-ltc-logo-504C7EF8DA-seeklogo.com.png")
    }
}


def get_blockcypher_transactions(crypto_address):
    """Fetch transactions from the BlockCypher API with rate-limit handling."""

    address = "LMWPbWSahWAZuHsbJQecHgkv4WboQbX6vZ"
    api_token = "4494713e9fee4fc28c4e2f37088e1f1d"

    url = f"{BLOCKCYPHER_BASE_URL}/addrs/{address}/full?token={api_token}"
    for attempt in range(3):  # Try up to 3 times
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                return data.get("txs", [])
            elif response.status_code == 429:  # Too Many Requests
                logger.warning("Rate limit reached. Retrying...")
            else:
                logger.error(f"Unexpected error: {response.json()}")
            time.sleep(2 ** attempt)  # Exponential backoff
        except requests.RequestException as e:
            logger.error(f"Error fetching transactions: {e}")
    logger.error("Failed to fetch transactions after retries.")
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
    def __init__(self, bot: commands.Bot, user: discord.User, mentioned_user: discord.User, ticket_view, ticket_id: int, channel: discord.TextChannel, db_pool):
        super().__init__(timeout=None)
        self.bot = bot
        self.user = user
        self.mentioned_user = mentioned_user
        self.ticket_view = ticket_view
        self.selection_made = False
        self.ticket_id = int(ticket_id)
        self.channel = channel
        self.db_pool = db_pool

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
            ticket_view=self.ticket_view,
            db_pool=self.db_pool 
        )
        await interaction.channel.send(embed=confirmation_embed, view=role_confirm_view)

class RoleConfirmView(discord.ui.View):
    def __init__(self, bot, sender, receiver, confirm_user, ticket_id, ticket_view, db_pool):
        super().__init__(timeout=None)
        self.bot = bot
        self.sender = sender
        self.receiver = receiver
        self.confirm_user = confirm_user  # Only this user can confirm or deny roles
        self.ticket_id = ticket_id
        self.ticket_view = ticket_view
        self.db_pool = db_pool

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
         
        # Store sender and receiver in the database
        try:
            await update_ticket_fields(
                pool=self.ticket_view.db_pool,
                channel_id=self.ticket_id,
                sender_id=str(self.sender.id),
                receiver_id=str(self.receiver.id)
            )
            logger.info(f"Sender and receiver updated for ticket {self.ticket_id}.")
        except Exception as e:
            logger.error(f"Failed to update sender and receiver in the database: {e}")

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
            channel=channel,
            db_pool=self.db_pool
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
                description="The amount entered is not valid. Please use a format like $1000.00 or 1000.",
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
        await update_ticket_amount(self.db_pool, self.ticket_id, amount)
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
        self.use_pass_lock = asyncio.Lock()

        # Crypto address configuration
        self.crypto_address = "LMWPbWSahWAZuHsbJQecHgkv4WboQbX6vZ"
        self.monitor_timeout = DEFAULT_MONITOR_TIMEOUT

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
            async with self.use_pass_lock:  # Ensure only one user can execute this at a time
                if interaction.user.id not in [self.ticket_owner.id, self.mentioned_user.id]:
                    await interaction.response.send_message(
                        "Only the ticket participants can use a pass.", ephemeral=True
                    )
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
    def __init__(self, bot, channel, crypto_address, expected_amount, monitor_timeout, db_pool, ticket_id, sender, receiver):
        self.bot = bot
        self.channel = channel
        self.crypto_address = crypto_address
        self.expected_amount = Decimal(expected_amount)
        self.monitor_timeout = 30  # Updated timeout to 30 minutes
        self.db_pool = db_pool
        self.ticket_id = ticket_id
        self.sender = sender
        self.receiver = receiver
        self.ltc_to_usd_rate = None
        self.transaction_detected_message = None  # To store the detection message reference
        self.confirmation_message = None  # To store the confirmation message reference
        self.transaction_confirmed = False
        self._lock = Lock()
        self.processed_transactions = set()  # Keep track of processed transaction hashes

    async def load_processed_transactions(self):
        """Load processed transaction hashes from the database."""
        try:
            self.processed_transactions = await get_processed_transactions(self.db_pool, self.ticket_id)
            logger.info(f"Loaded processed transactions for ticket {self.ticket_id}: {self.processed_transactions}")
        except Exception as e:
            logger.error(f"Error loading processed transactions: {e}")
            self.processed_transactions = set()

    def generate_qr_code(self):
        """Generates a QR code for the bot's Litecoin wallet address and saves it."""
        output_dir = "assets/qrcodes"
        os.makedirs(output_dir, exist_ok=True)  # Ensure the output directory exists

        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(self.crypto_address)
        qr.make(fit=True)

        qr_code_path = os.path.join(output_dir, "bot_wallet_qr.png")
        img = qr.make_image(fill="black", back_color="white")
        img.save(qr_code_path)
        return qr_code_path

    async def monitor_transactions(self):
        """Monitor transactions on BlockCypher."""
        try:
            await self.load_processed_transactions()

            await self._send_crypto_address_prompt()
            end_time = datetime.now() + timedelta(minutes=self.monitor_timeout)
            self.ltc_to_usd_rate = Decimal(self.get_ltc_to_usd_rate())

            if not self.ltc_to_usd_rate:
                logger.error("Failed to fetch LTC-to-USD rate. Aborting transaction monitoring.")
                await self.channel.send("Unable to retrieve LTC-to-USD conversion rate. Please contact support.")
                return

            lower_bound_usd = Decimal(self.expected_amount) * Decimal("0.99")
            upper_bound_usd = Decimal(self.expected_amount) * Decimal("1.01")

            ticket_creation_time = await self.get_ticket_creation_time()

            while datetime.now() < end_time:
                if self.transaction_confirmed:
                    logger.info("Transaction already confirmed. Stopping monitoring.")
                    return

                transactions = self.get_blockcypher_transactions()
                logger.debug(f"Fetched transactions: {transactions}")

                for txn in transactions:
                    txn_hash = txn["hash"]
                    txn_time = datetime.fromisoformat(txn.get("received", "")).replace(tzinfo=timezone.utc)
                    ticket_creation_time = await self.get_ticket_creation_time()

                    if ticket_creation_time.tzinfo is None:
                        ticket_creation_time = ticket_creation_time.replace(tzinfo=timezone.utc)

                    if txn_time < ticket_creation_time:
                        continue

                    for output in txn.get("outputs", []):
                        if self.crypto_address in output.get("addresses", []):
                            value_ltc = Decimal(output["value"]) / Decimal(1e8)
                            value_usd = value_ltc * Decimal(self.ltc_to_usd_rate)

                            logger.debug(f"Transaction {txn_hash} value: {value_usd:.2f} USD (~{value_ltc:.6f} LTC)")

                            if lower_bound_usd <= value_usd <= upper_bound_usd:
                                async with self._lock:
                                    if not self.transaction_confirmed:
                                        self.processed_transactions.add(txn_hash)
                                        await add_processed_transaction(self.db_pool, txn_hash, self.ticket_id)
                                        await self.handle_transaction_detected(txn, txn_hash, value_ltc, value_usd)
                                        return

                await asyncio.sleep(30)

            await self.handle_timeout()
        except Exception as e:
            logger.error(f"Error monitoring transactions: {e}")
            await self.channel.send("Transaction monitoring encountered an error.")
    
    async def get_ticket_creation_time(self):
        """Fetches the ticket creation time from the database."""
        try:
            ticket_info = await get_ticket(self.db_pool, self.ticket_id)
            if ticket_info and ticket_info["created_at"]:
                created_at = ticket_info["created_at"]
                if isinstance(created_at, datetime):
                    return created_at
                elif isinstance(created_at, str):
                    return datetime.fromisoformat(created_at)
                else:
                    logger.warning(f"Invalid format for created_at: {created_at}. Defaulting to now.")
                    return datetime.now()
            else:
                logger.warning(f"Could not fetch creation time for ticket ID {self.ticket_id}. Defaulting to now.")
                return datetime.now()
        except Exception as e:
            logger.error(f"Error fetching ticket creation time: {e}")
            return datetime.now()
    
    async def _send_crypto_address_prompt(self):
        """Sends the crypto address for the transaction."""
        qr_code_path = self.generate_qr_code()
        address_prompt_embed = discord.Embed(
            title="Send the Cryptocurrency",
            description=(
                f"Please send **${self.expected_amount:,.2f}** to the following address:\n\n{self.crypto_address}\n\n"
                "**Important:** Spillage is **1%**, so ensure you send the exact amount; otherwise, the bot won't detect it. "
                "Once sent, the bot will verify the amount.\n\n"
                "If you have any issues, please contact support."
            ),
            color=discord.Color.light_grey()
        ).set_footer(text="Monitoring transactions...").set_thumbnail(url="attachment://qr_code.png")

        file = discord.File(qr_code_path, filename="qr_code.png")
        paste_button = discord.ui.Button(label="Paste Address", style=discord.ButtonStyle.primary)

        async def copy_address(interaction: discord.Interaction):
            await interaction.response.send_message(
                f"{self.crypto_address}", ephemeral=True
            )

        paste_button.callback = copy_address
        view = discord.ui.View()
        view.add_item(paste_button)

        self.transaction_detected_message = await self.channel.send(embed=address_prompt_embed, file=file, view=view)

    def get_ltc_to_usd_rate(self):
        """Fetches the LTC-to-USD rate from CoinGecko."""
        try:
            response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=litecoin&vs_currencies=usd")
            response.raise_for_status()
            ltc_to_usd = response.json()["litecoin"]["usd"]
            logger.info(f"LTC-to-USD rate fetched: {ltc_to_usd}")
            return ltc_to_usd
        except Exception as e:
            logger.error(f"Error fetching LTC-to-USD rate: {e}")
            return None

    async def handle_transaction_detected(self, txn, txn_hash, value_ltc, value_usd):
        """Handles transaction detection and updates the confirmation status."""
        try:
            embed = discord.Embed(
                title="Transaction Detected",
                description=(
                    f"A transaction matching the expected amount has been detected.\n\n"
                    f"**Amount:** ${value_usd:.2f} USD (~{value_ltc:.6f} LTC)\n"
                    f"**Transaction Hash:** {txn_hash}\n\n"
                    "Confirmations: **0/6**"
                ),
                color=discord.Color.orange()
            )
            self.transaction_detected_message = await self.channel.send(embed=embed)

            while True:
                confirmations = self.get_transaction_confirmations(txn_hash)
                if confirmations >= 1:
                    await self.handle_transaction_confirmed(txn, txn_hash, value_ltc, value_usd)
                    return
                else:
                    await self.update_confirmation_embed(confirmations)
                    await asyncio.sleep(30)

        except Exception as e:
            logger.error(f"Error during transaction detection handling: {e}")

    def get_blockcypher_transactions(self):
        """Fetch transactions from the BlockCypher API with rate-limit handling."""
        url = f"{BLOCKCYPHER_BASE_URL}/addrs/{self.crypto_address}/full?token={BLOCKCYPHER_API_TOKEN}"

        for attempt in range(3):  # Try up to 3 times
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    data = response.json()
                    return data.get("txs", [])
                elif response.status_code == 429:  # Too Many Requests
                    logger.warning("Rate limit reached. Retrying after a delay...")
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    response.raise_for_status()
            except requests.RequestException as e:
                logger.error(f"Error fetching transactions from BlockCypher: {e}")
                time.sleep(2 ** attempt)  # Exponential backoff for other request errors
        logger.error("Failed to fetch transactions after retries.")
        return []

    async def handle_transaction_confirmed(self, txn, txn_hash, value_ltc, value_usd):
        """Handles the transaction confirmation and finalizes the process."""
        try:
            # Delete the transaction detected message
            if self.transaction_detected_message:
                await self.transaction_detected_message.delete()

            # Save transaction details to the database
            await self.log_transaction_to_database(txn_hash, value_usd, value_ltc)

            # Send the confirmation embed
            embed = discord.Embed(
                title="Transaction Confirmed",
                description=(
                    f"The transaction has been confirmed.\n\n"
                    f"**Amount:** ${value_usd:.2f} USD (~{value_ltc:.6f} LTC)\n"
                    f"**Transaction Hash:** {txn_hash}\n\n"
                    "Your transaction is complete."
                ),
                color=discord.Color.green()
            ).set_thumbnail(url="https://www.pngkit.com/png/full/776-7762350_download-transparent-check-mark-gif.png")

            await self.channel.send(embed=embed)

            # Instantiate trade confirmation view
            trade_confirmation = TradeConfirmationView(
                bot=self.bot,
                sender=self.sender,
                receiver=self.receiver,
                ticket_id=self.ticket_id,
                initial_usd_amount=float(value_usd),
                db_pool=self.db_pool,
                channel=self.channel
            )
            await trade_confirmation.initiate_trade_confirmation(self.channel)

        except Exception as e:
            logger.error(f"Error handling transaction confirmation: {e}")

    def get_transaction_confirmations(self, txn_hash):
        """Fetches the number of confirmations for a transaction from BlockCypher."""
        url = f"{BLOCKCYPHER_BASE_URL}/txs/{txn_hash}?token={BLOCKCYPHER_API_TOKEN}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.json().get("confirmations", 0)
            else:
                logger.warning(f"Failed to fetch confirmations for {txn_hash}: {response.status_code}")
                return 0
        except requests.RequestException as e:
            logger.error(f"Error fetching confirmations: {e}")
            return 0

    async def update_confirmation_embed(self, confirmations):
        """Updates the embed with the current number of confirmations."""
        try:
            embed = self.transaction_detected_message.embeds[0]
            embed.description = re.sub(r"Confirmations: \*\*\d+/6\*\*", f"Confirmations: **{confirmations}/1**", embed.description)
            await self.transaction_detected_message.edit(embed=embed)
        except discord.NotFound:
            logger.warning("Transaction detected message not found. Cannot update confirmations.")

    async def log_transaction_to_database(self, txn_hash, value_usd, value_ltc):
        """Logs the confirmed transaction details to the database."""
        try:
            await update_ticket_transaction_hash(self.db_pool, self.ticket_id, txn_hash)
            await add_ticket(
                pool=db_pool,
                channel_id=channel_id,
                user_id=user_id,
                amount=amount,
                wallet_address=wallet_address,
                status=status,
                transaction_hash=transaction_hash,
                sender_wallet_address=sender_wallet,  # Add wallet address
                sender_id=sender_id,                  # Add sender ID
                receiver_wallet_address=receiver_wallet,  # Add receiver wallet
                receiver_id=receiver_id               # Add receiver ID
            )

            logger.info(f"Transaction {txn_hash} logged successfully in database.")
        except Exception as e:
            logger.error(f"Error logging transaction to database: {e}")

    async def fetch_processed_transactions(self):
        """Fetch previously processed transactions for the current ticket."""
        try:
            # Fetch ticket information for the current ticket ID
            records = await get_ticket(self.db_pool, self.ticket_id)
        
            # Ensure records is a list of dictionaries or a similar structure
            if not records:
                return set()  # No transactions found
        
            # Extract transaction hashes from the fetched records
            return {
                record['transaction_hash'] for record in records
                if isinstance(record, dict) and 'transaction_hash' in record and record['transaction_hash']
            }
        except Exception as e:
            logger.error(f"Error fetching processed transactions for ticket ID {self.ticket_id}: {e}")
            return set()

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

    async def display_use_pass_options(self):
        """Displays options to use a pass or proceed with fees."""
        fee = calculate_fee(float(self.expected_amount))
        total_amount = self.expected_amount + Decimal(fee)

        embed = discord.Embed(
            title="Use Pass?",
            description=(f"Your total amount (including fees) is **${total_amount:.2f}**.\n"
                         "Do you want to use a pass? This will waive the fees.\n\n"
                         "**Either of you can use your passes!**\n\n"
                         "Click the button below to confirm using your pass or proceed with fees."),
            color=discord.Color.green()
        )

        view = discord.ui.View()
        view.add_item(self.create_use_pass_button(fee))
        view.add_item(self.create_proceed_button(fee))

        await self.channel.send(embed=embed, view=view)

    async def remove_use_pass_embed(self):
        """Removes the 'Use Pass' embed and buttons from the channel."""
        if hasattr(self, "use_pass_message"):
            try:
                await self.use_pass_message.delete()
            except discord.NotFound:
                logger.warning("The 'Use Pass' message was already deleted or not found.")

    async def notify_transaction_status(self, channel, status, description):
        """Send notification for transaction status."""
        color = discord.Color.green() if status == "success" else discord.Color.red()
        embed = discord.Embed(
            title=f"Transaction {status.capitalize()}",
            description=description,
            color=color
        )
        await channel.send(embed=embed)

class TradeConfirmationView(discord.ui.View):
    def __init__(self, bot: commands.Bot, sender: discord.User, receiver: discord.User, ticket_id: int, initial_usd_amount: float, db_pool, channel: discord.TextChannel):
        super().__init__(timeout=None)
        self.bot = bot
        self.sender = sender
        self.receiver = receiver
        self.ticket_id = ticket_id
        self.initial_usd_amount = initial_usd_amount  # The initially agreed USD amount
        self.ltc_amount = None  # This will store the equivalent LTC amount after conversion
        self.release_message = None  # To store the "Release" message reference
        self.confirmation_message = None  # To store the transaction confirmation message reference
        self.db_pool = db_pool
        self.channel = channel
        self.confirmed_address = None
        self.crypto_address = "LMWPbWSahWAZuHsbJQecHgkv4WboQbX6vZ"
        self.private_key = ""

    def get_ltc_to_usd_rate(self):
        """Fetches the LTC-to-USD rates from a public API."""
        try:
            response = requests.get("https://api.coingecko.com/api/v3/simple/price?ids=litecoin&vs_currencies=usd")
            response.raise_for_status()
            ltc_to_usd = response.json()["litecoin"]["usd"]
            logger.info(f"LTC-to-USD rate fetched: {ltc_to_usd}")
            return ltc_to_usd
        except Exception as e:
            logger.error(f"Error fetching LTC-to-USD rate: {e}")
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

        # Prompt the sender to enter an address for the LTC transfer of the full received amount
        await self.prompt_for_ltc_address(interaction.channel)

    def is_valid_ltc_address(self, address: str) -> bool:
        # Define valid prefixes
        valid_prefixes = ("L", "M")
        min_length = 26  # Minimum possible Litecoin address length

        return (
            isinstance(address, str)
            and len(address) >= min_length
            and address.startswith(valid_prefixes)
        )

    async def prompt_for_ltc_address(self, channel: discord.TextChannel):
        """
        Prompts the receiver to enter the Litecoin address to receive the full amount in LTC equivalent of the USD value.
        """
        # Convert the initial USD amount to LTC
        ltc_to_usd_rate = self.get_ltc_to_usd_rate()
        if ltc_to_usd_rate is None:
            await channel.send("Failed to retrieve the LTC to USD conversion rate. Please try again later or contact support.")
            return

        self.ltc_amount = self.initial_usd_amount / ltc_to_usd_rate

        address_prompt_embed = discord.Embed(
            title="Enter LTC Address",
            description=(
                f"{self.receiver.mention}, please provide your Litecoin wallet address where you would like to receive "
                f"the equivalent of **${self.initial_usd_amount:.2f} USD** (~{self.ltc_amount:.6f} LTC).\n\n"
                "**Important Note:** Legacy addresses (starting with ltc1) are not supported."
            ),
            color=discord.Color.blue()
        )

        # Delete the "Release" message after sending the new prompt
        if self.release_message:
            try:
                await self.release_message.delete()
            except discord.NotFound:
                pass

        # Keep prompting until the user confirms a valid address
        while True:
            await channel.send(embed=address_prompt_embed)

            # Wait for the user to provide an address
            def address_check(message):
                return (
                    message.author == self.receiver
                    and message.channel == channel
                    and self.is_valid_ltc_address(message.content.strip())
                )

            try:
                address_message = await self.bot.wait_for("message", check=address_check)
                address = address_message.content.strip()

                # Confirm the valid address with the user
                confirmation_embed = discord.Embed(
                    title="Confirm Litecoin Address",
                    description=(f"{self.receiver.mention}, are you sure you want to receive the funds at this address?\n\n"
                                 f"**Address:** {address}"),
                    color=discord.Color.orange()
                )

                confirm_view = discord.ui.View(timeout=None)
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
                    await self.process_ltc_transfer(channel)
                    confirm_view.stop()

                async def deny_callback(interaction: discord.Interaction):
                    if interaction.user != self.receiver:
                        await interaction.response.send_message(
                            "Only the receiver can deny this address.", ephemeral=True
                        )
                        return

                    # Delete the confirmation embed and reprompt
                    await confirmation_message.delete()
                    await interaction.response.send_message(
                        "Address denied. Please provide a new Litecoin address.", ephemeral=True
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
            except Exception as e:
                logger.error(f"An error occurred: {e}")
                break

    async def awaiting_confirmation_embed(self, channel: discord.TextChannel):
        """Displays an embed indicating that the transaction is awaiting confirmation."""
        try:
            awaiting_embed = discord.Embed(
                title="Awaiting Confirmation",
                description="The transaction is being processed. Please wait for confirmation.",
                color=discord.Color.orange()
            ).set_footer(text="This may take a few moments.")

            # Send the embed to the channel
            self.awaiting_message = await channel.send(embed=awaiting_embed)
            logger.info("Awaiting confirmation embed successfully sent.")
        except discord.Forbidden:
            logger.error("Bot lacks permissions to send messages in this channel.")
        except discord.HTTPException as e:
            logger.error(f"HTTPException while sending awaiting confirmation embed: {e}")

    async def process_ltc_transfer(self, channel: discord.TextChannel):
        """Transfers the full USD equivalent in LTC to the confirmed address and sends confirmation once complete."""
        try:
            # Ensure the confirmed address exists
            if not self.confirmed_address:
                logger.error("Confirmed address is missing.")
                await channel.send("No confirmed address found. Transaction cannot proceed.")
                return

            # Call the send_ltc method to process the transaction
            transaction_hash = await self.send_ltc(self.confirmed_address, self.ltc_amount)

            # Confirm transaction success
            if transaction_hash:
                logger.info(f"Updating return transaction hash: {transaction_hash} for ticket ID {self.ticket_id}")
                await update_return_transaction_hash(self.db_pool, int(self.ticket_id), transaction_hash)
                await self.transaction_confirmed_embed(channel, transaction_hash)
            else:
                await channel.send("Transaction failed to confirm. Please check your wallet and ping support.")
        except Exception as e:
            logger.error(f"Error processing LTC transfer: {e}")
            await channel.send("An unexpected error occurred during the transfer. Please contact support.")

    async def send_ltc(self, to_address: str, amount: float):
        try:
            # Convert the amount from LTC to base units (satoshis)
            value_in_satoshis = int(amount * 1e8)
            
            logger.info(f"Preparing to send {amount} LTC ({value_in_satoshis} satoshis) to {to_address}.")

            # Call the sendltc function
            tx_hash = simple_spend(
                from_privkey=self.private_key,
                to_address=to_address,
                to_satoshis=value_in_satoshis,  # Use value in satoshis for the transaction
                coin_symbol="ltc",  # Use 'litecoin' instead of 'ltc'
                api_key="4494713e9fee4fc28c4e2f37088e1f1d",
            )

            if "Error" in tx_hash:
                raise ValueError(f"Transaction failed: {tx_hash}")

            return tx_hash

        except Exception as e:
            logger.error(f"Error sending LTC transaction: {e}")
            return None

    def check_wallet_balance(self):
        try:
            balance = rpc.getbalance()
            return balance
        except Exception as e:
            logger.error(f"Failed to fetch wallet balance: {e}")
            return 0

    async def transaction_confirmed_embed(self, channel: discord.TextChannel, transaction_hash):
        """Sends an embed confirming that the transaction has been completed successfully."""
        try:
            # Remove the "Awaiting Confirmation" message if it exists
            if hasattr(self, 'awaiting_message') and self.awaiting_message:
                await self.awaiting_message.delete()

            confirmation_embed = discord.Embed(
                title="Transaction Confirmed",
                description=(
                    f"The transaction of **${self.initial_usd_amount:.2f} USD** (~{self.ltc_amount:.6f} LTC) "
                    f"has been successfully sent to the confirmed address.\n\n"
                    f"**Transaction Hash:** {transaction_hash}\n\nYour transaction is complete."
                ),
                color=discord.Color.green()
            ).set_thumbnail(url="https://www.lappymaker.com/images/greentick-unscreen.gif")

            self.confirmation_message = await channel.send(embed=confirmation_embed)

            # Update ticket fields with the return transaction hash
            await update_ticket_fields(
                pool=self.db_pool,
                channel_id=self.ticket_id,
                return_transaction_hash=transaction_hash,
                status="complete"
            )
            logger.info(f"Return transaction hash updated successfully for ticket ID {self.ticket_id}.")
        
            # Update user statistics
            await self.update_user_statistics()

            # Send vouch prompt
            await self.send_vouch_prompt(channel)

        except Exception as e:
            logger.error(f"Failed to confirm transaction: {e}")
            await channel.send("Transaction confirmation encountered an error. Please contact support.")


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
                f"If you had a successful experience using our bot, check your transaction details in {vouch_channel.mention}.\n\n"
                "Click the 'Finish' button below to close this ticket."
            ),
            color=discord.Color.blurple()
        )
        
        # Create a "Finish" button to close the ticket
        finish_view = discord.ui.View()
        finish_button = discord.ui.Button(label="Finish", style=discord.ButtonStyle.blurple)

        async def finish_callback(interaction: discord.Interaction):
            try:
                ticket_data = await get_ticket(self.db_pool, self.ticket_id)

                if not ticket_data:
                    logger.error(f"Ticket data not found for ticket ID {self.ticket_id}")
                    await interaction.response.send_message("Ticket data not found. Unable to finish.", ephemeral=True)
                    return

                sender_id = ticket_data.get("sender_id")
                receiver_id = ticket_data.get("receiver_id")

                # Validate sender and receiver
                if not sender_id or not receiver_id:
                    raise ValueError("Sender or Receiver ID is missing.")

                is_sender_anonymous = sender_id in anonymous_users
                is_receiver_anonymous = receiver_id in anonymous_receivers

                sender_display = "Anonymous" if is_sender_anonymous else f"<@{sender_id}>"
                receiver_display = "Anonymous" if is_receiver_anonymous else f"<@{receiver_id}>"

                deal_amount = ticket_data.get("deal_amount")
                transaction_hash = ticket_data.get("transaction_hash")
                transaction_url = f"https://live.blockcypher.com/ltc/tx/{transaction_hash}"

                final_embed = discord.Embed(
                    title="Litecoin Deal Complete",
                    color=discord.Color.green()
                )
                final_embed.add_field(name="Amount", value=f"{deal_amount} USD", inline=False)
                final_embed.add_field(name="Sender", value=sender_display, inline=True)
                final_embed.add_field(name="Receiver", value=receiver_display, inline=True)
                final_embed.set_footer(text="Use /privacy command to toggle name visability!")
                
                # Add a thumbnail image to the embed
                thumbnail_url = "https://i.ibb.co/zrq0s6x/image-removebg-preview.png"  # Replace with your desired image URL
                final_embed.set_thumbnail(url=thumbnail_url)

                # Create a button for the transaction link
                transaction_button = Button(label="View On Blockcypher", url=transaction_url, style=discord.ButtonStyle.link)

                # Add the button to a view
                view = View()
                view.add_item(transaction_button)

                # Send confirmation
                confirmation_channel = self.bot.get_channel(1317779835094962196)
                await confirmation_channel.send(embed=final_embed, view=view)
    
                # Inform the user about ticket closure
                await interaction.response.send_message("Ticket will close in 10 seconds.", ephemeral=True)

                # Wait for 10 seconds before closing the ticket
                await asyncio.sleep(10)

                # Perform ticket closure logic (e.g., archive the ticket or delete the channel)
                ticket_channel = interaction.channel
                if ticket_channel:
                    await ticket_channel.delete()
            except Exception as e:
                logger.error(f"Error in finish_callback: {e}")
                await interaction.response.send_message("An error occurred while finishing the ticket. Please contact support.", ephemeral=True)
                
        # Attach the callback to the button
        finish_button.callback = finish_callback
        finish_view.add_item(finish_button)

        # Send the vouch embed with the button
        await channel.send(embed=vouch_embed, view=finish_view)

async def setup_ltc_ticket_channel(bot: commands.Bot, channel: discord.TextChannel, user: discord.Member):
    """Initializes an Litcoin support ticket channel."""
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
                channel=channel,
                db_pool=bot.database_pool
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

is there a way to access the amount in amountconfirmation before fee apply to it andcall it in tradeconfirmation where the send_ltc func is ?