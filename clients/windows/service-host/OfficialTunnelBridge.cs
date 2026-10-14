using System;
using System.Runtime.InteropServices;

namespace OracleProxy.WireGuardHost;

// ACTUAL native export interop contract from the official WireGuard Windows
// embeddable-dll-service README. This code will never run in CI because the
// official DLLs are deliberately NOT packaged and no SCM service is installed.
internal static class OfficialTunnelBridge
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool WireGuardTunnelService(
        [MarshalAs(UnmanagedType.LPWStr)] string configFile);

    private const uint LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100;
    private const uint LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000;

    [DllImport("kernel32.dll", EntryPoint = "LoadLibraryExW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(
        string fileName, IntPtr file, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FreeLibrary(IntPtr module);

    internal static int InvokeFromService(string profile = "lab-only")
    {
        // No CLI-supplied file path, tunnel name or arbitrary DLL locations.
        EngineBundle.VerifiedFiles files =
            EngineBundle.Verify(AppContext.BaseDirectory, EngineBundle.FixedConfigPath(profile));
        // Mandatory lab config/binary ownership and DACL preflight; refuses
        // installation from a user-writable folder. Does not change ACLs.
        ConfigAclGate.RequireProtectedLabInstallation(
            AppContext.BaseDirectory, files.Config, profile);
        // Runtime attestation: reject unsigned/altered driver even if a
        // local manifest was regenerated. The service never fixes signatures.
        NativeDriverTrust.RequireTrustedPinnedOfficialDriver(files.WireGuardDll);

        // Explicit secure DLL search flags avoid current-working-directory
        // dependency loading. It is STILL necessary to validate signature,
        // provenance, x64 architecture and protected installation ACLs.
        IntPtr dll = LoadLibraryEx(files.TunnelDll, IntPtr.Zero,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (dll == IntPtr.Zero)
            return 3;
        try
        {
            IntPtr export = NativeLibrary.GetExport(dll, "WireGuardTunnelService");
            var entry = Marshal.GetDelegateForFunctionPointer<WireGuardTunnelService>(export);
            // Blocks as the actual Windows service entrypoint when registered
            // with SCM according to the official WireGuard embedding guidance.
            return entry(files.Config) ? 0 : 3;
        }
        finally
        {
            _ = FreeLibrary(dll);
        }
    }
}
