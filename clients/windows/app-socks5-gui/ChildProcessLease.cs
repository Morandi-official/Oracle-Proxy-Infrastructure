using System.Diagnostics;
using System.Runtime.InteropServices;

namespace OracleProxy.AppSocks5.GUI.Experimental;

// Owns only an explicitly started child process and its Windows kill-on-close
// job. A GUI crash closes the noninheritable job handle and kills the helper;
// R55 itself separately owns/kills the OpenSSH child in its own job.
internal sealed class ChildProcessLease : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        public BasicLimits BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr handle, int infoClass, ref ExtendedLimits limits, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private IntPtr _job;
    private bool _disposed;

    internal Process Process { get; }

    private ChildProcessLease(Process process, IntPtr job)
    {
        Process = process;
        _job = job;
    }

    internal static ChildProcessLease Start(ProcessStartInfo start)
    {
        if (!OperatingSystem.IsWindows())
            throw new InvalidOperationException("仅支持 Windows。");
        // Safety boundary: CreateJobObject is done before the subprocess.
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
            throw new InvalidOperationException("无法建立后台进程恢复保障。");
        Process? process = null;
        try
        {
            var limit = new ExtendedLimits();
            limit.BasicLimitInformation.LimitFlags = 0x2000; // KILL_ON_JOB_CLOSE
            if (!SetInformationJobObject(job, 9, ref limit,
                (uint)Marshal.SizeOf<ExtendedLimits>()))
                throw new InvalidOperationException("无法设置 SSH 进程关闭保障。");
            process = Process.Start(start)
                ?? throw new InvalidOperationException("无法启动本地实验代理。");
            if (!AssignProcessToJobObject(job, process.Handle))
                throw new InvalidOperationException("无法管理 SSH 进程，已拒绝连接。");
            return new ChildProcessLease(process, job);
        }
        catch
        {
            if (process is not null)
            {
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
                catch { }
                process.Dispose();
            }
            CloseHandle(job);
            throw;
        }
    }

    internal bool Running
    {
        get { try { return !_disposed && !Process.HasExited; } catch { return false; } }
    }

    internal void Stop()
    {
        if (_disposed) return;
        // R55 reads Enter and exits cleanly, but never depend solely on it.
        try
        {
            if (Process.StartInfo.RedirectStandardInput && !Process.HasExited)
                Process.StandardInput.WriteLine();
        }
        catch { }
        // Closing JOB is OS-controlled cancellation even on helper crash.
        if (_job != IntPtr.Zero)
        {
            CloseHandle(_job);
            _job = IntPtr.Zero;
        }
        try { if (!Process.HasExited) Process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
        catch (System.ComponentModel.Win32Exception) { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _disposed = true;
        Process.Dispose();
    }

    internal static bool JobSelfTest()
    {
        if (!OperatingSystem.IsWindows()) return false;
        string ping = Path.Combine(Environment.GetFolderPath(
            Environment.SpecialFolder.Windows), "System32", "ping.exe");
        if (!File.Exists(ping)) return false;
        var start = new ProcessStartInfo(ping)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true
        };
        start.ArgumentList.Add("-n");
        start.ArgumentList.Add("30");
        start.ArgumentList.Add("127.0.0.1");
        using var child = Start(start);
        if (!child.Running) return false;
        child.Stop();
        bool exited = child.Process.WaitForExit(5000) && !child.Running;
        if (exited) Console.WriteLine("R56_GUI_JOB_KILL_ON_CLOSE_PASS");
        return exited;
    }
}
