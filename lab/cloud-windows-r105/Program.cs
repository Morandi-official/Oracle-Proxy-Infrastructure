using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace OracleProxy.IsolatedGuestReadOnly;

internal static class Program
{
    private const string ChallengePrefix = "OPX-R105-CHAL/1/";
    private const string ProofPrefix = "OPX-R105-READONLY/1/";
    private static readonly Regex ChallengePattern =
        new(@"^OPX-R105-CHAL/1/([A-F0-9]{64})$", RegexOptions.CultureInvariant);
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;
    private const uint InvalidHandle = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    private struct CommTimeouts
    {
        public uint ReadIntervalTimeout, ReadTotalTimeoutMultiplier,
            ReadTotalTimeoutConstant, WriteTotalTimeoutMultiplier,
            WriteTotalTimeoutConstant;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW",
        SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string name, uint access, uint share, IntPtr security, uint mode,
        uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCommTimeouts(SafeFileHandle port,
        ref CommTimeouts timeouts);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadFile(
        SafeFileHandle file, byte[] buffer, uint count, out uint read,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(
        SafeFileHandle file, byte[] buffer, uint count, out uint written,
        IntPtr overlapped);

    // No generic stdin/JSON/PowerShell commands. Read-only one-shot challenge,
    // strict nonce echo, OS build and SYSTEM SID bit. Not cryptographic OS
    // attestation: the independent offline System.evtx gate is still required.
    internal static string? Respond(string challenge, bool runningAsSystem, int build)
    {
        Match m = ChallengePattern.Match(challenge);
        if (!m.Success || build < 19041 || build > 99999)
            return null;
        return ProofPrefix + m.Groups[1].Value + "/" +
            build.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            "/" + (runningAsSystem ? "SYSTEM" : "NOT_SYSTEM");
    }

    private static bool SelfTest()
    {
        string nonce = new('A', 64);
        string good = ChallengePrefix + nonce;
        string? response = Respond(good, true, 26100);
        return response == ProofPrefix + nonce + "/26100/SYSTEM" &&
            Respond(good.ToLowerInvariant(), true, 26100) is null &&
            Respond(good + "/EXEC", true, 26100) is null &&
            Respond(good + "\r", true, 26100) is null &&
            Respond(ChallengePrefix + new string('B', 63), true, 26100) is null &&
            Respond(good, true, 18999) is null &&
            Respond(good, false, 26100)!.EndsWith("/NOT_SYSTEM",
                StringComparison.Ordinal);
    }

    private static int RunSerialOnce()
    {
        if (!OperatingSystem.IsWindows() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("R105_ISOLATED_CLOUD_WITNESS") !=
                "EPHEMERAL_NO_NIC_ONLY")
            return 4;
        string sid = WindowsIdentity.GetCurrent().User?.Value ?? "";
        if (sid != "S-1-5-18")
            return 4;
        using SafeFileHandle h = CreateFile(@"\\.\COM1",
            GenericRead | GenericWrite, 0, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (h.IsInvalid)
            return 5;
        var timeouts = new CommTimeouts
        {
            ReadIntervalTimeout = 100,
            ReadTotalTimeoutConstant = 350,
            ReadTotalTimeoutMultiplier = 0,
            WriteTotalTimeoutConstant = 1200,
            WriteTotalTimeoutMultiplier = 0
        };
        if (!SetCommTimeouts(h, ref timeouts))
            return 5;
        // Challenge deadline is bounded. Never read/write an arbitrary file,
        // start any Windows service, change WFP/route/DNS, or log host metadata.
        using var buf = new MemoryStream();
        var one = new byte[1];
        long start = Stopwatch.GetTimestamp();
        while (Stopwatch.GetElapsedTime(start) < TimeSpan.FromSeconds(20) &&
               buf.Length < 100)
        {
            if (!ReadFile(h, one, 1, out uint got, IntPtr.Zero))
                return 5;
            if (got == 0) continue;
            if (one[0] == (byte)'\n') break;
            if (one[0] < 0x20 || one[0] > 0x7E)
                return 5;
            buf.WriteByte(one[0]);
        }
        if (buf.Length != ChallengePrefix.Length + 64)
            return 5;
        string request = Encoding.ASCII.GetString(buf.ToArray());
        string? response = Respond(request, true, Environment.OSVersion.Version.Build);
        if (response is null)
            return 5;
        byte[] result = Encoding.ASCII.GetBytes(response + "\n");
        if (!WriteFile(h, result, (uint)result.Length, out uint written,
                       IntPtr.Zero) || written != result.Length)
            return 5;
        // The response is only a guest-origin witness, NOT signed installation,
        // real VPN/WFP, reboot durability, packet leak-proof, or field approval.
        return 0;
    }

    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test")
        {
            if (!SelfTest()) return 6;
            Console.WriteLine("R105_FIXED_READONLY_CHALLENGE_DENIAL_TESTS_PASS");
            Console.WriteLine("R105_GUEST_DRIVER_WFP_NETWORK_AND_OS_BOOT_TESTED=false");
            return 0;
        }
        if (args.Length == 1 && args[0] == "--serial-once")
            return RunSerialOnce();
        return 4;
    }
}
