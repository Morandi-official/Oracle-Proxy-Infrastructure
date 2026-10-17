using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;

namespace OracleProxy.R86.NoNetworkMock;

// NO sockets, native WireGuard, WFP, adapter, routing, DNS or firewall APIs.
// The only privileged mutation is STOP of this exact owned mock SCM service.
internal sealed class NoNetworkMock : ServiceBase
{
    internal const string Name = "OracleProxyR86NoNetworkMock";
    internal NoNetworkMock()
    {
        ServiceName = Name;
        CanStop = true;
        CanShutdown = true;
        CanPauseAndContinue = false;
        AutoLog = false;
    }
    protected override void OnStart(string[] args) { }
    protected override void OnStop() { }
}
internal static class Program
{
    private const string MarkerText = "R86-ATTENDED-OWNED-NO-NETWORK-ONLY";
    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "OracleProxyR86Attended");
    private static readonly string ExePath = Path.Combine(Root, "R86NoNetworkMock.exe");
    private static readonly string StatePath = Path.Combine(Root, "state.txt");
    private static readonly string ReceiptPath = Path.Combine(Root, "expired.ok");

    private static bool IsSystemSession()
    {
        using WindowsIdentity id = WindowsIdentity.GetCurrent();
        return id.IsSystem && Process.GetCurrentProcess().SessionId == 0;
    }

    private static bool StrictOwned()
    {
        string marker = Path.Combine(Root, "owner.txt");
        return Directory.Exists(Root) && File.Exists(marker) &&
            (File.GetAttributes(Root) & FileAttributes.ReparsePoint) == 0 &&
            (File.GetAttributes(marker) & FileAttributes.ReparsePoint) == 0 &&
            (File.GetAttributes(ExePath) & FileAttributes.ReparsePoint) == 0 &&
            (File.GetAttributes(StatePath) & FileAttributes.ReparsePoint) == 0 &&
            File.ReadAllText(marker, Encoding.ASCII).Trim() == MarkerText &&
            !File.Exists(ReceiptPath);
    }

    private static bool ExactIdentityAndDeadline(string deadlineUtc, string token)
    {
        if (token.Length != 32 || !Guid.TryParseExact(token, "N", out _) ||
            !DateTimeOffset.TryParseExact(deadlineUtc, "yyyy-MM-ddTHH:mm:ssZ",
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal,
                out DateTimeOffset expiry)) return false;
        var now = DateTimeOffset.UtcNow;
        if (now < expiry || now - expiry > TimeSpan.FromMinutes(3)) return false;
        string[] fields = File.ReadAllLines(StatePath, Encoding.ASCII);
        if (fields.Length != 3 || fields[0] != deadlineUtc ||
            fields[1] != token || fields[2].Length != 64) return false;
        string digest = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(ExePath)));
        if (!string.Equals(digest, fields[2], StringComparison.OrdinalIgnoreCase))
            return false;

        // Only accept the fixed executable running as a LocalSystem MANUAL
        // service; never stop a service of the same name with another path.
        using RegistryKey? service = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\" + NoNetworkMock.Name, false);
        if (service == null ||
            !string.Equals(service.GetValue("ObjectName") as string,
                "LocalSystem", StringComparison.OrdinalIgnoreCase) ||
            Convert.ToInt32(service.GetValue("Start")) != 3) return false;
        string expected = "\"" + ExePath + "\" --r86-no-network-mock";
        if (!string.Equals(service.GetValue("ImagePath") as string,
            expected, StringComparison.OrdinalIgnoreCase)) return false;
        return true;
    }

    private static int Expire(string deadline, string token)
    {
        if (!IsSystemSession() || !StrictOwned() ||
            !ExactIdentityAndDeadline(deadline, token)) return 3;
        try
        {
            using var svc = new ServiceController(NoNetworkMock.Name);
            if (svc.Status != ServiceControllerStatus.Running) return 3;
            svc.Stop();
            svc.WaitForStatus(ServiceControllerStatus.Stopped,
                TimeSpan.FromSeconds(25));
            svc.Refresh();
            if (svc.Status != ServiceControllerStatus.Stopped) return 3;
            File.WriteAllText(ReceiptPath,
                "R86_SYSTEM_STOPPED_EXACT_NONNETWORK_MOCK" + Environment.NewLine,
                Encoding.ASCII);
            return 0;
        }
        catch { return 3; }
    }

    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows()) return 3;
        try
        {
            if (args.Length == 1 && args[0] == "--r86-no-network-mock")
            {
                if (!IsSystemSession() || !StrictOwned()) return 3;
                ServiceBase.Run(new NoNetworkMock());
                return 0;
            }
            if (args.Length == 3 && args[0] == "--r86-expire")
                return Expire(args[1], args[2]);
            return 2;
        }
        catch { return 3; }
    }
}
