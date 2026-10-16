using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace OracleProxy.AppSocks5.Experimental;

// Opt-in Oracle-over-SSH application SOCKS5 helper; NOT WireGuard.
// Windows network settings, system proxy, WFP and UU are never modified.
internal static class Program
{
    private const int LocalSocksPort = 10880;
    private sealed record Options(string Host, string User, int Port,
        string PrivateKey, string KnownHosts);

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimit
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
    private struct ExtendedLimit
    {
        public BasicLimit BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(IntPtr job, int infoClass,
        ref ExtendedLimit info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    private static bool ValidHost(string host) =>
        host.Length is >= 1 and <= 253 &&
        Regex.IsMatch(host, @"\A[a-zA-Z0-9][a-zA-Z0-9.-]*\z",
            RegexOptions.CultureInvariant) &&
        !host.Contains("..", StringComparison.Ordinal) &&
        !host.EndsWith(".", StringComparison.Ordinal) &&
        host != "localhost";

    private static bool ValidUser(string name) =>
        name.Length is >= 1 and <= 32 &&
        Regex.IsMatch(name, @"\A[a-zA-Z_][a-zA-Z0-9_.-]*\z",
            RegexOptions.CultureInvariant);

    private static bool TryOptions(string[] args, out Options? parsed)
    {
        parsed = null;
        if (args.Length is < 6 or > 8 || args.Length % 2 != 0) return false;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = 0; i < args.Length; i += 2)
        {
            if (args[i] is not ("--host" or "--user" or "--identity" or "--ssh-port") ||
                values.ContainsKey(args[i]) || string.IsNullOrWhiteSpace(args[i + 1]))
                return false;
            values.Add(args[i], args[i + 1]);
        }
        if (values.Count != args.Length / 2 ||
            !values.TryGetValue("--host", out string? host) ||
            !values.TryGetValue("--user", out string? user) ||
            !values.TryGetValue("--identity", out string? key) ||
            !ValidHost(host) || !ValidUser(user)) return false;
        int port = 22;
        if (values.TryGetValue("--ssh-port", out string? requested) &&
            (!int.TryParse(requested, out port) || port is < 1 or > 65535))
            return false;
        if (!Path.IsPathFullyQualified(key)) return false;
        string identity;
        try
        {
            identity = Path.GetFullPath(key);
            var file = new FileInfo(identity);
            if (!file.Exists || file.Length is <= 0 or > 1048576 ||
                (file.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
        }
        catch { return false; }
        string profile = Environment.GetFolderPath(
            Environment.SpecialFolder.UserProfile);
        string knownHosts = Path.Combine(profile, ".ssh", "known_hosts");
        try
        {
            var file = new FileInfo(knownHosts);
            if (!file.Exists || file.Length is <= 0 or > 1048576 ||
                (file.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
        }
        catch { return false; }
        parsed = new(host, user, port, identity, knownHosts);
        return true;
    }

    private static bool SelfTest()
    {
        if (ValidHost("-oProxyCommand=evil") ||
            ValidHost("x@y") || ValidHost("a;whoami") ||
            ValidHost("a..b") || ValidHost("a b") ||
            ValidUser("-o") || ValidUser("opc;whoami") ||
            ValidUser("opc@evil") ||
            TryOptions(new[] { "--host", "example.com", "--user", "opc",
                "--identity", "relative-key" }, out _) ||
            TryOptions(new[] { "--host", "example.com", "--user", "opc",
                "--identity", "relative-key", "--unknown", "x" }, out _))
            return false;
        Console.WriteLine("R55_SSH_SOCKS5_INPUT_VALIDATION_PASS");
        return true;
    }

    // The disposable Windows runner exercises job-backed child lifetime,
    // not just a theoretical kill-on-close flag. Only local 127.0.0.1 ping.
    private static bool JobLifecycleSelfTest()
    {
        if (!OperatingSystem.IsWindows()) return false;
        IntPtr job = IntPtr.Zero;
        Process? child = null;
        try
        {
            job = CreateKillOnCloseJob();
            var start = new ProcessStartInfo(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "ping.exe"))
            {
                UseShellExecute = false,
                CreateNoWindow = true
            };
            start.ArgumentList.Add("-n");
            start.ArgumentList.Add("30");
            start.ArgumentList.Add("127.0.0.1");
            child = Process.Start(start);
            if (child is null || child.HasExited ||
                !AssignProcessToJobObject(job, child.Handle))
                return false;
            // The only test action: close own job handle and verify OS
            // terminates a formerly running dummy child.
            CloseHandle(job);
            job = IntPtr.Zero;
            bool cleaned = child.WaitForExit(4000) && child.HasExited;
            if (cleaned)
                Console.WriteLine("R55_WINDOWS_JOB_KILL_ON_CLOSE_PASS");
            return cleaned;
        }
        catch { return false; }
        finally
        {
            if (child is not null)
            {
                try
                {
                    if (!child.HasExited) child.Kill(entireProcessTree: true);
                    child.WaitForExit(1500);
                }
                catch { }
                child.Dispose();
            }
            if (job != IntPtr.Zero) CloseHandle(job);
        }
    }

    private static void Help()
    {
        Console.WriteLine(
            "Oracle Proxy R55 · SSH SOCKS5 实验代理（非 WireGuard）\n" +
            "用途：仅为手动设置了 SOCKS5 的浏览器通过你已有的 Oracle SSH 服务器代理 TCP。\n" +
            "绝不更改系统代理、UU、WireSock、DNS、路由或防火墙。\n" +
            "前置：Windows OpenSSH 客户端；用户已核对并加入 known_hosts 的服务端公钥；已有 SSH 私钥。\n" +
            "用法：OracleProxy.AppSocks5.Experimental.exe --host <Oracle域名或IPv4> --user <SSH账户> --identity <SSH私钥绝对路径> [--ssh-port 22]\n" +
            "连接成功后，在支持独立代理设置的浏览器中手动使用 SOCKS5 127.0.0.1:10880，打开 SOCKS5 远端DNS。\n" +
            "必须按 Enter 关闭代理；如凭据或服务器不可用，立即失败且不修改网络。\n" +
            "禁止当作系统级 VPN、防泄漏开关或 WireSock 替代品。请勿关闭任何 Windows 安全保护。");
    }

    private static bool LocalPortFree()
    {
        TcpListener? probe = null;
        try
        {
            probe = new TcpListener(IPAddress.Loopback, LocalSocksPort);
            probe.Start();
            return true;
        }
        catch (SocketException) { return false; }
        finally { probe?.Stop(); }
    }

    private static async Task<bool> LocalListenerReadyAsync(Process child,
        CancellationToken token)
    {
        for (int i = 0; i < 36; i++)
        {
            if (child.HasExited) return false;
            using var client = new TcpClient(AddressFamily.InterNetwork);
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(TimeSpan.FromMilliseconds(300));
                await client.ConnectAsync(IPAddress.Loopback, LocalSocksPort,
                    timeout.Token);
                return !child.HasExited;
            }
            catch (SocketException) { }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { }
            await Task.Delay(200, token);
        }
        return false;
    }

    private static IntPtr CreateKillOnCloseJob()
    {
        IntPtr handle = CreateJobObject(IntPtr.Zero, null);
        if (handle == IntPtr.Zero) throw new InvalidOperationException(
            "无法建立子进程退出保障，拒绝启动 SSH。");
        var limits = new ExtendedLimit();
        limits.BasicLimitInformation.LimitFlags = 0x00002000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(handle, 9, ref limits,
            checked((uint)Marshal.SizeOf<ExtendedLimit>())))
        {
            CloseHandle(handle);
            throw new InvalidOperationException(
                "无法确认 SSH 子进程退出保障，拒绝连接。");
        }
        return handle;
    }

    private static async Task<int> RunAsync(Options options)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("仅支持 Windows。");
            return 3;
        }
        string ssh = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "OpenSSH", "ssh.exe");
        if (!File.Exists(ssh))
        {
            Console.Error.WriteLine("未安装 Windows 系统 OpenSSH 客户端。没有进行任何连接。");
            return 3;
        }
        if (!LocalPortFree())
        {
            Console.Error.WriteLine("127.0.0.1:10880 已被占用；不会接管其他代理。");
            return 3;
        }

        IntPtr job = IntPtr.Zero;
        Process? process = null;
        using var cancelled = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => {
            e.Cancel = true;
            cancelled.Cancel();
        };
        Console.CancelKeyPress += handler;
        try
        {
            job = CreateKillOnCloseJob();
            var start = new ProcessStartInfo(ssh)
            {
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = false,
                CreateNoWindow = true
            };
            foreach (string arg in new[] {
                "-F", "none", "-N", "-T", "-D", "127.0.0.1:10880",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "ExitOnForwardFailure=yes",
                "-o", "GatewayPorts=no",
                "-o", "PermitLocalCommand=no",
                "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=2",
                "-o", "ControlMaster=no",
                "-o", "IdentitiesOnly=yes",
                "-i", options.PrivateKey,
                "-p", options.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "-l", options.User, "--", options.Host
            })
                start.ArgumentList.Add(arg);
            process = Process.Start(start);
            if (process is null) throw new InvalidOperationException("SSH 启动失败。");
            if (!AssignProcessToJobObject(job, process.Handle))
                throw new InvalidOperationException("SSH 退出隔离未建立，已经拒绝连接。");

            // Discard stderr without writing credentials, server IDs or key paths.
            Task errorDrain = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
            if (!await LocalListenerReadyAsync(process, cancelled.Token))
                throw new InvalidOperationException(
                    "SSH 未建立本地 SOCKS5 监听：请核对 SSH 主机密钥/私钥/端口/转发权限。");
            Console.WriteLine("R55_LOCAL_SOCKS5_LISTENING: 127.0.0.1:10880");
            Console.WriteLine("重要：本地端口就绪不代表已经验证 Oracle 出口。");
            Console.WriteLine("请仅在单独的浏览器配置 SOCKS5 与代理DNS，并访问测试网页核实出口。");
            Console.WriteLine("按 Enter 关闭本实验代理。切勿更改 Windows 系统代理。");
            Task<string?> input = Task.Run(Console.ReadLine);
            Task exited = process.WaitForExitAsync(cancelled.Token);
            await Task.WhenAny(input, exited);
            return 0;
        }
        catch (OperationCanceledException)
        {
            return 0;
        }
        catch (Exception)
        {
            Console.Error.WriteLine(
                "R55_SSH_SOCKS5_REFUSED: 安全前置条件不满足或连接失败。未修改系统网络。");
            return 3;
        }
        finally
        {
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    process.WaitForExit(3000);
                }
                catch { /* job close is authoritative process cleanup */ }
                process.Dispose();
            }
            if (job != IntPtr.Zero) CloseHandle(job);
            Console.CancelKeyPress -= handler;
        }
    }

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test")
            return SelfTest() ? 0 : 1;
        if (args.Length == 1 && args[0] == "--job-self-test")
            return JobLifecycleSelfTest() ? 0 : 1;
        if (args.Length == 0 || args is ["--help"])
        {
            Help();
            return 0;
        }
        if (!TryOptions(args, out Options? options) || options is null)
        {
            Console.Error.WriteLine(
                "R55_REFUSED: 无效参数、私钥不存在、主机密钥尚未预登记或缺少必要设置。运行 --help 查看要求。");
            return 2;
        }
        return await RunAsync(options);
    }
}
