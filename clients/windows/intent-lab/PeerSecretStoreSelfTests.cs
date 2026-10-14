using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace OracleProxy.IntentLab;

internal static class PeerSecretStoreSelfTests
{
    internal static bool Run()
    {
        if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows")
            return false;

        string root = Path.Combine(Environment.GetEnvironmentVariable("RUNNER_TEMP")!,
            "oracle-r17-peersecret-" + Guid.NewGuid().ToString("N"));
        int checks = 0;
        byte[] secret = RandomNumberGenerator.GetBytes(32);
        byte[] expected = (byte[])secret.Clone();
        try
        {
            void Check(bool result)
            {
                if (!result)
                    throw new InvalidOperationException("R17 check " + checks);
                checks++;
            }
            void Reject(Action action)
            {
                try { action(); }
                catch (InvalidOperationException) { checks++; return; }
                catch (CryptographicException) { checks++; return; }
                throw new InvalidOperationException("R17 unsafe key operation accepted");
            }
            Directory.CreateDirectory(root);
            Reject(() => new PeerSecretStore(root));
            Reject(() => new PeerSecretStore(Path.GetTempPath()));
            PeerSecretStore.ProtectNewTestFolder(root);
            var store = new PeerSecretStore(root);
            Reject(() => store.Seal(new byte[31]));
            Reject(() => store.Seal(new byte[33]));
            store.Seal(secret);
            Check(File.Exists(store.TestFile));
            byte[] ciphertext = File.ReadAllBytes(store.TestFile);
            Check(ciphertext.Length > secret.Length);
            Check(!ciphertext.AsSpan().SequenceEqual(secret));
            // Ensure entire 32-byte key is not embedded anywhere in the file.
            bool rawPresent = false;
            for (int i = 0; i <= ciphertext.Length - secret.Length; i++)
                if (ciphertext.AsSpan(i, secret.Length).SequenceEqual(secret))
                    rawPresent = true;
            Check(!rawPresent);
            Reject(() => store.Seal(secret));

            var restarted = new PeerSecretStore(root);
            byte[] recovered = restarted.Open();
            Check(CryptographicOperations.FixedTimeEquals(recovered, expected));
            CryptographicOperations.ZeroMemory(recovered);
            Check(recovered.AsSpan().IndexOfAnyExcept((byte)0) == -1);

            // Disturb ciphertext; DPAPI must refuse the untrusted bytes.
            byte[] modified = (byte[])ciphertext.Clone();
            modified[modified.Length / 2] ^= 0x5a;
            File.WriteAllBytes(store.TestFile, modified);
            Reject(() => restarted.Open());
            File.WriteAllBytes(store.TestFile, ciphertext);
            byte[] recoveredAgain = restarted.Open();
            Check(CryptographicOperations.FixedTimeEquals(recoveredAgain, expected));
            CryptographicOperations.ZeroMemory(recoveredAgain);

            // A world-readable secret must be rejected even if DPAPI could
            // unprotect it under LocalMachine.
            var fi = new FileInfo(store.TestFile);
            var acl = fi.GetAccessControl();
            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.Read, AccessControlType.Allow));
            fi.SetAccessControl(acl);
            Reject(() => restarted.Open());
            // Recreate a safe file ACL without ever placing plaintext on disk.
            acl.SetAccessRuleProtection(true, false);
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true,
                         typeof(SecurityIdentifier)))
            {
                if (rule.IdentityReference.Value ==
                    new SecurityIdentifier(WellKnownSidType.WorldSid, null).Value)
                    acl.RemoveAccessRuleSpecific(rule);
            }
            fi.SetAccessControl(acl);
            recoveredAgain = restarted.Open();
            Check(CryptographicOperations.FixedTimeEquals(recoveredAgain, expected));
            CryptographicOperations.ZeroMemory(recoveredAgain);

            restarted.Delete();
            Check(!File.Exists(store.TestFile));
            Reject(() => restarted.Open());
            WriteSuccess();
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("R17_PEER_SECRET_FAIL: " +
                ex.GetType().Name + " checks=" + checks);
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
            CryptographicOperations.ZeroMemory(expected);
            try { if (Directory.Exists(root)) Directory.Delete(root, true); }
            catch { /* disposable runner is destroyed */ }
        }

        void WriteSuccess() => Console.WriteLine(
            "R17_PEER_SECRET_PASS: " + checks +
            " DPAPI and protected NTFS lifecycle checks; no native tunnel");
    }
}
