using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace OracleProxy.Tailscale;

/// <summary>Starts the engine in its own Windows console process group.</summary>
internal static class DaemonConsole
{
    private const uint NewProcessGroup = 0x00000200;
    private const uint UnicodeEnvironment = 0x00000400;
    private const uint CtrlBreak = 1;

    internal static Process Start(ProcessStartInfo info)
    {
        // A GUI/service process may be started without a console. Windows
        // delivers Ctrl+Break only when sender and target share one.
        if (GetConsoleCP() == 0)
        {
            if (!AllocConsole())
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TAILSCALE_CONSOLE_UNAVAILABLE");
            ShowWindow(GetConsoleWindow(), 0);
        }

        var command = new StringBuilder(Quote(info.FileName));
        foreach (string argument in info.ArgumentList)
            command.Append(' ').Append(Quote(argument));

        string environment = string.Join('\0', info.Environment
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
            .Select(pair => pair.Key + "=" + pair.Value)) + "\0\0";
        IntPtr block = Marshal.StringToHGlobalUni(environment);
        try
        {
            var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>() };
            if (!CreateProcess(info.FileName, command, IntPtr.Zero, IntPtr.Zero, false,
                    NewProcessGroup | UnicodeEnvironment, block, info.WorkingDirectory, ref startup, out var result))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TAILSCALE_PROCESS_START_FAILED");
            try
            {
                var process = Process.GetProcessById((int)result.ProcessId);
                try
                {
                    _ = process.SafeHandle;
                    return process;
                }
                catch { process.Dispose(); throw; }
            }
            finally
            {
                CloseHandle(result.Thread);
                CloseHandle(result.Process);
            }
        }
        finally { Marshal.FreeHGlobal(block); }
    }

    internal static bool SignalExit(Process process) =>
        !process.HasExited && GenerateConsoleCtrlEvent(CtrlBreak, (uint)process.Id);

    private static string Quote(string value)
    {
        if (value.Contains('"'))
            throw new ArgumentException("TAILSCALE_PROCESS_ARGUMENT_QUOTE", nameof(value));
        return "\"" + value + new string('\\', value.Length - value.TrimEnd('\\').Length) + "\"";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        internal int Size;
        internal IntPtr Reserved, Desktop, Title;
        internal int X, Y, XSize, YSize, XChars, YChars, Fill, Flags;
        internal short ShowWindow, Reserved2Length;
        internal IntPtr Reserved2, StandardInput, StandardOutput, StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        internal IntPtr Process, Thread;
        internal uint ProcessId, ThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processSecurity,
        IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string workingDirectory,
        ref StartupInfo startup, out ProcessInformation result);

    [DllImport("kernel32.dll")] private static extern uint GetConsoleCP();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AllocConsole();
    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(uint signal, uint processGroup);
}
