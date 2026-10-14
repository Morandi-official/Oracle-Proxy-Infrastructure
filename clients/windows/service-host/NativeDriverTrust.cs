using System;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace OracleProxy.WireGuardHost;

/// <summary>
/// Local Windows Authenticode chain/timestamp verification for the pinned
/// upstream WireGuardNT DLL before any privileged native load. No network
/// settings are changed. Integrity pins + protected ACLs are still required;
/// valid Authenticode alone does not prove this is our intended vendor.
/// </summary>
internal static class NativeDriverTrust
{
    private static readonly Guid GenericVerifyV2 =
        new("00aac56b-cd44-11d0-8cc2-00c04fc295ee");

    // WINTRUST_FILE_INFO from wintrust.h.
    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    // WINTRUST_DATA from wintrust.h.
    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int WinVerifyTrust(
        IntPtr hwnd, ref Guid pgActionID, IntPtr pWVTData);

    // WTD_UI_NONE=2, WTD_REVOKE_NONE=0, WTD_CHOICE_FILE=1,
    // WTD_STATEACTION_IGNORE=0, WTD_CACHE_ONLY_URL_RETRIEVAL=0x1000.
    // We cannot do an online revocation proof while booting without network.
    // A separately audited signing policy + pinned file hash remain mandatory.
    internal static bool IsTrustedLocalSignature(string path)
    {
        if (!OperatingSystem.IsWindows() ||
            string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            return false;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length is < 1024 or > 20_000_000 ||
                (fi.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;

            IntPtr pathMem = IntPtr.Zero;
            IntPtr fileMem = IntPtr.Zero;
            IntPtr dataMem = IntPtr.Zero;
            try
            {
                pathMem = Marshal.StringToCoTaskMemUni(Path.GetFullPath(path));
                var file = new WinTrustFileInfo
                {
                    cbStruct = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
                    pcwszFilePath = pathMem,
                    hFile = IntPtr.Zero,
                    pgKnownSubject = IntPtr.Zero
                };
                fileMem = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
                Marshal.StructureToPtr(file, fileMem, false);
                var data = new WinTrustData
                {
                    cbStruct = (uint)Marshal.SizeOf<WinTrustData>(),
                    dwUIChoice = 2,
                    fdwRevocationChecks = 0,
                    dwUnionChoice = 1,
                    pFile = fileMem,
                    dwStateAction = 0,
                    dwProvFlags = 0x00001000,
                    dwUIContext = 0
                };
                dataMem = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
                Marshal.StructureToPtr(data, dataMem, false);
                Guid policy = GenericVerifyV2;
                return WinVerifyTrust(IntPtr.Zero, ref policy, dataMem) == 0;
            }
            finally
            {
                if (dataMem != IntPtr.Zero) Marshal.FreeHGlobal(dataMem);
                if (fileMem != IntPtr.Zero) Marshal.FreeHGlobal(fileMem);
                if (pathMem != IntPtr.Zero) Marshal.FreeCoTaskMem(pathMem);
            }
        }
        catch
        {
            // A missing, corrupt, revocation-unverifiable, or untrusted DLL
            // must not get a native-load opportunity.
            return false;
        }
    }

    // Compile-time fixed vendor SDK v1.1 AMD64 driver SHA-256. Unlike a
    // mutable companion engine-pins.json, this is part of the compiled host.
    internal const string OfficialWireGuardNtV11Sha256 =
        "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3";

    internal static bool IsPinnedOfficialDriver(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path))
            return false;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists || fi.Length is < 1024 or > 20_000_000 ||
                (fi.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read,
                FileShare.Read);
            byte[] digest = SHA256.HashData(stream);
            byte[] known = Convert.FromHexString(OfficialWireGuardNtV11Sha256);
            try { return CryptographicOperations.FixedTimeEquals(digest, known); }
            finally {
                CryptographicOperations.ZeroMemory(digest);
                CryptographicOperations.ZeroMemory(known);
            }
        }
        catch { return false; }
    }

    internal static void RequireTrustedPinnedOfficialDriver(string path)
    {
        // Both checks are mandatory, even if an attacker can replace a local
        // manifest with hashes for a different signed Windows system DLL.
        if (!IsPinnedOfficialDriver(path) || !IsTrustedLocalSignature(path))
            throw new InvalidOperationException(
                "Native WireGuard driver does not match pinned signed upstream v1.1");
    }

    internal static void RequireTrustedSignature(string path)
    {
        if (!IsTrustedLocalSignature(path))
            throw new InvalidOperationException("Unsigned or untrusted native WireGuard driver");
    }
}
