#if ENABLE_DISPOSABLE_LAB_CONTROLS
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace OracleProxy.LabManager;

// R45: real DPAPI(LocalMachine) + plaintext key lease exercised exclusively
// in disposable LocalSystem SCM CI. NEVER a production key store or tunnel.
internal static class CiSystemDpapiKeyLease
{
    private static readonly byte[] Entropy =
        Encoding.ASCII.GetBytes("OracleProxy.R45.CI.SYSTEM.EphemeralKeyLease.NOT-PRODUCTION");

    internal static bool IsSystemServiceIdentity()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.IsSystem && Process.GetCurrentProcess().SessionId == 0;
        }
        catch { return false; }
    }

    internal static bool RunSystemOnly()
    {
        // Must reject non-SYSTEM BEFORE allocating/decrypting any key material.
        if (!IsSystemServiceIdentity()) return false;

        byte[]? generated = null;
        byte[]? ciphertext = null;
        byte[]? plaintext = null;
        byte[]? digest = null;
        byte[]? wrong = null;
        try
        {
            generated = RandomNumberGenerator.GetBytes(32);
            digest = SHA256.HashData(generated);
            ciphertext = ProtectedData.Protect(
                generated, Entropy, DataProtectionScope.LocalMachine);
            if (ciphertext.Length <= 32 || ciphertext.Length > 8192)
                return false;

            CryptographicOperations.ZeroMemory(generated);
            generated = null;
            plaintext = ProtectedData.Unprotect(
                ciphertext, Entropy, DataProtectionScope.LocalMachine);
            if (plaintext.Length != 32) return false;

            // Lease owns the native WireGuard-size secret, and MUST zero it.
            // In-memory test does not call any native adapter or save a file.
            using (var lease = new ProtectedKeyLease(plaintext))
            {
                byte[] actualHash = SHA256.HashData(lease.Bytes);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(actualHash, digest))
                        return false;
                }
                finally { CryptographicOperations.ZeroMemory(actualHash); }
            }
            if (plaintext.Any(value => value != 0))
                return false;
            plaintext = null;

            wrong = (byte[])ciphertext.Clone();
            wrong[wrong.Length / 2] ^= 0x80;
            try
            {
                byte[] unexpected = ProtectedData.Unprotect(
                    wrong, Entropy, DataProtectionScope.LocalMachine);
                CryptographicOperations.ZeroMemory(unexpected);
                // Tampered DPAPI ciphertext must never be accepted.
                return false;
            }
            catch (CryptographicException)
            {
                return true;
            }
        }
        catch
        {
            return false;
        }
        finally
        {
            if (generated is not null) CryptographicOperations.ZeroMemory(generated);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (ciphertext is not null) CryptographicOperations.ZeroMemory(ciphertext);
            if (digest is not null) CryptographicOperations.ZeroMemory(digest);
            if (wrong is not null) CryptographicOperations.ZeroMemory(wrong);
        }
    }
}
#endif
