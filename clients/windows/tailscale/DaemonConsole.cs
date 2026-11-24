using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace OracleProxy.Tailscale;

/// <summary>Starts the engine in its own Windows console process group.</summary>
internal static class DaemonConsole
{
    private const uint NewProcessGroup = 0x00000200;
    private const uint UnicodeEnvironment = 0x00000400;
    private const uint Suspended = 0x00000004;
    private const uint CtrlBreak = 1;
    private const int ExtendedLimitInformation = 9;
    private const uint KillOnJobClose = 0x00002000;

    internal static (Process Process, SafeFileHandle Job) Start(ProcessStartInfo info)
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
        var job = CreateJobObject(IntPtr.Zero, null);
        bool returned = false;
        try
        {
            if (job.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TAILSCALE_JOB_CREATE_FAILED");
            var limits = new ExtendedLimit
            {
                Basic = new BasicLimit { LimitFlags = KillOnJobClose },
            };
            if (!SetInformationJobObject(job, ExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf<ExtendedLimit>()))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TAILSCALE_JOB_LIMIT_FAILED");
            var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>() };
            if (!CreateProcess(info.FileName, command, IntPtr.Zero, IntPtr.Zero, false,
                    NewProcessGroup | UnicodeEnvironment | Suspended, block, info.WorkingDirectory, ref startup, out var result))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "TAILSCALE_PROCESS_START_FAILED");
            try
            {
                if (!AssignProcessToJobObject(job, result.Process))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "TAILSCALE_JOB_ASSIGN_FAILED");
                var process = Process.GetProcessById((int)result.ProcessId);
                try
                {
                    _ = process.SafeHandle;
                    if (ResumeThread(result.Thread) == uint.MaxValue)
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "TAILSCALE_PROCESS_RESUME_FAILED");
                    returned = true;
                    return (process, job);
                }
                catch { process.Dispose(); throw; }
            }
            finally
            {
                if (!returned) TerminateProcess(result.Process, 1);
                CloseHandle(result.Thread);
                CloseHandle(result.Process);
            }
        }
        finally
        {
            if (!returned) job.Dispose();
            Marshal.FreeHGlobal(block);
        }
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

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimit
    {
        internal long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimit
    {
        internal BasicLimit Basic;
        internal ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        internal ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        internal UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, EntryPoint = "CreateProcessW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processSecurity,
        IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string workingDirectory,
        ref StartupInfo startup, out ProcessInformation result);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref ExtendedLimit info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] private static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll")] private static extern uint GetConsoleCP();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AllocConsole();
    [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] private static extern bool ShowWindow(IntPtr window, int command);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GenerateConsoleCtrlEvent(uint signal, uint processGroup);
}
