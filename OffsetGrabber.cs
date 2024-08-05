using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class OffsetGrabber
{
    // Declare the necessary Windows API functions
    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int cbsize, out int lpNumberOfBytesRead);

    public static void GrabOffsets(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length == 0)
        {
            Console.WriteLine($"No process was found with the name: '{processName}'.");
            return;
        }

        Process targetProcess = processes[0];

        //Open the target process
        IntPtr processHandle = OpenProcess(0x0010, false, (uint)targetProcess.Id);

        if (processHandle == IntPtr.Zero)
        {
            Console.WriteLine($"Failed to open the process '{processName}'.");
            return;
        }

        // Read the memory at the known offsets
        byte[] buffer = new byte[4]; //assume it is a 4 byte offset
        int bytesRead;
        ReadProcessMemory(processHandle, (IntPtr)0x12345678, buffer, buffer.Length, out bytesRead);

        uint offset = BitConverter.ToUInt32(buffer, 0);
        Console.WriteLine($"Offset value: {offset}");

        //Clean up
        CloseHandle(processHandle);
    }

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

}
