using System;
using System.IO;
using System.Security.Cryptography;

namespace OracleProxy.WireGuardHost;

// Negative native trust tests on actual pinned official DLL bytes. Does not
// load a driver, install a service or expose keys. CI only via guarded CLI.
internal static class NativeDriverTrustSelfTests
{
    internal static bool Run(string signedSource)
    {
        string scratch = Path.Combine(Path.GetTempPath(),
            "oracle-r16-trust-" + Guid.NewGuid().ToString("N"));
        int assertions = 0;
        try
        {
            void Require(bool condition)
            {
                if (!condition) throw new InvalidOperationException(
                    "R16 native trust assertion " + assertions);
                assertions++;
            }

            // Upstream SDK v1.1 exact fixed wireguard.dll pin; do not allow
            // test input to replace the genuine upstream binary at will.
            if (!File.Exists(signedSource)) return false;
            byte[] expected = Convert.FromHexString(
                NativeDriverTrust.OfficialWireGuardNtV11Sha256);
            using (var stream = File.OpenRead(signedSource))
                Require(CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(stream), expected));

            Directory.CreateDirectory(scratch);
            string copied = Path.Combine(scratch, "wireguard.dll");
            File.Copy(signedSource, copied);
            Require(NativeDriverTrust.IsTrustedLocalSignature(signedSource));
            Require(NativeDriverTrust.IsTrustedLocalSignature(copied));
            NativeDriverTrust.RequireTrustedPinnedOfficialDriver(copied);
            assertions++;
            Require(NativeDriverTrust.IsPinnedOfficialDriver(signedSource));
            Require(NativeDriverTrust.IsPinnedOfficialDriver(copied));

            string unsigned = Path.Combine(scratch, "unsigned.dll");
            File.WriteAllBytes(unsigned, new byte[4096]);
            Require(!NativeDriverTrust.IsTrustedLocalSignature(unsigned));
            Require(!NativeDriverTrust.IsPinnedOfficialDriver(unsigned));
            Require(!NativeDriverTrust.IsTrustedLocalSignature(scratch));
            Require(!NativeDriverTrust.IsTrustedLocalSignature("relative.dll"));
            Require(!NativeDriverTrust.IsTrustedLocalSignature(""));

            byte[] copy = File.ReadAllBytes(copied);
            Require(copy.Length > 8192);
            copy[4096] ^= 0x5a; // modify signed PE section, not certificate table
            File.WriteAllBytes(copied, copy);
            Require(!NativeDriverTrust.IsTrustedLocalSignature(copied));
            Require(!NativeDriverTrust.IsPinnedOfficialDriver(copied));
            bool threw = false;
            try { NativeDriverTrust.RequireTrustedPinnedOfficialDriver(copied); }
            catch (InvalidOperationException) { threw = true; }
            Require(threw);
            // A different Windows-signed binary is still prohibited even
            // if its Authenticode chain is trusted by Windows.
            string otherSigned = Path.Combine(Environment.SystemDirectory,
                "kernel32.dll");
            Require(File.Exists(otherSigned));
            Require(!NativeDriverTrust.IsPinnedOfficialDriver(otherSigned));
            bool otherThrew = false;
            try { NativeDriverTrust.RequireTrustedPinnedOfficialDriver(otherSigned); }
            catch (InvalidOperationException) { otherThrew = true; }
            Require(otherThrew);
            Console.WriteLine("R23_HARD_PIN_PASS: signed alternative rejected by compiled hash");
            Console.WriteLine("R16_DRIVER_TRUST_PASS: " + assertions +
                " real Windows trust/hash/tamper/refusal assertions");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("R16_DRIVER_TRUST_FAIL: " +
                ex.GetType().Name + " checks=" + assertions);
            return false;
        }
        finally
        {
            try { if (Directory.Exists(scratch)) Directory.Delete(scratch, true); }
            catch { /* disposal of ephemeral CI runner is final fallback */ }
        }
    }
}
