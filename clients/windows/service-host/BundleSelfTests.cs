using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OracleProxy.WireGuardHost;

// Exercises file integrity and native-service launch boundaries WITHOUT
// loading a DLL, installing a service, or sending a network packet.
internal static class BundleSelfTests
{
    internal static bool Run()
    {
        string temp = Path.Combine(Path.GetTempPath(),
            "oracle-wg-host-selftest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        string configFolder = Path.Combine(temp, "config");
        Directory.CreateDirectory(configFolder);
        string conf = Path.Combine(configFolder, EngineBundle.FixedLabConfigFile);
        string driver = Path.Combine(temp, EngineBundle.DriverFile);
        string tunnel = Path.Combine(temp, EngineBundle.TunnelFile);
        string manifest = Path.Combine(temp, EngineBundle.ManifestFile);
        int passed = 0;
        try
        {
            void Check(bool condition)
            {
                if (!condition) throw new InvalidOperationException("Self-test assertion " + passed);
                passed++;
            }
            void ExpectReject(Action action)
            {
                try { action(); }
                catch (InvalidOperationException) { passed++; return; }
                catch (JsonException) { passed++; return; }
                throw new InvalidOperationException("Unsafe input unexpectedly accepted");
            }
            string Pin(string path)
            {
                using FileStream s = File.OpenRead(path);
                return Convert.ToHexString(SHA256.HashData(s));
            }
            void WriteManifest(string? overridePin = null, int version = 1)
            {
                File.WriteAllText(manifest, JsonSerializer.Serialize(new
                {
                    schema_version = version,
                    tunnel_sha256 = overridePin ?? Pin(tunnel),
                    wireguard_sha256 = Pin(driver),
                    config_sha256 = Pin(conf)
                }));
            }

            // Fake files are only bytes for hashing; never loadable modules.
            File.WriteAllBytes(tunnel, Encoding.UTF8.GetBytes("not a native DLL"));
            File.WriteAllBytes(driver, Encoding.UTF8.GetBytes("not a native driver DLL"));
            File.WriteAllText(conf, "[Interface]\nAddress = 192.0.2.17/32\n");
            WriteManifest();
            var accepted = EngineBundle.Verify(temp, conf);
            Check(accepted.TunnelDll == tunnel && accepted.WireGuardDll == driver);
            Check(accepted.Config == conf);
            Check(EngineBundle.FixedConfigPath().EndsWith(
                Path.Combine("config", "lab-only.conf"), StringComparison.OrdinalIgnoreCase));

            // All real inputs are pinned and a mutation is rejected.
            File.AppendAllText(tunnel, "tamper");
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest();
            Check(EngineBundle.Verify(temp, conf).TunnelDll == tunnel);
            File.AppendAllText(driver, "tamper");
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest();
            File.AppendAllText(conf, "garbage");
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest();

            foreach (string hook in new[] { "PreUp", "PostUp", "PreDown", "PostDown" })
            {
                File.WriteAllText(conf, "[Interface]\n" + hook + " = calc.exe\n");
                WriteManifest();
                ExpectReject(() => EngineBundle.Verify(temp, conf));
            }
            File.WriteAllText(conf, "[Interface]\nAddress = 192.0.2.17/32\n");
            WriteManifest();

            WriteManifest(overridePin: new string('0', 64));
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest(overridePin: "invalid-sha256");
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest(version: 2);
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest();

            File.WriteAllText(manifest, "{broken");
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest();
            string json = File.ReadAllText(manifest);
            File.WriteAllText(manifest, json.Replace(
                "\"schema_version\":1", "\"schema_version\":1,\"config_path\":\"not-allowed\""));
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest();

            // Duplicate manifest keys must be rejected rather than "last wins".
            string duplicateVersion = File.ReadAllText(manifest).Replace(
                "\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1");
            File.WriteAllText(manifest, duplicateVersion);
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            WriteManifest();

            // Missing native dependency must never be considered a valid bundle.
            File.Delete(driver);
            ExpectReject(() => EngineBundle.Verify(temp, conf));
            File.WriteAllBytes(driver, Encoding.UTF8.GetBytes("not a native driver DLL"));
            WriteManifest();

            ExpectReject(() => EngineBundle.Verify(temp, Path.Combine(configFolder, "other.conf")));
            ExpectReject(() => EngineBundle.Verify("relative", conf));

            // Verify the new real Windows NTFS DACL gate using fake config
            // bytes only. No production file or private key is touched.
            using (var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                string callerSid = currentUser.User?.Value ??
                    throw new InvalidOperationException("Missing Windows SID");
                ExpectReject(() => ConfigAclGate.AssertProtectedFixture(conf, callerSid));
                var fileInfo = new FileInfo(conf);
                var fileSecurity = fileInfo.GetAccessControl();
                fileSecurity.SetAccessRuleProtection(true, false);
                fileSecurity.SetAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    currentUser.User!,
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));
                fileSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.AccessControlType.Allow));
                fileInfo.SetAccessControl(fileSecurity);
                ConfigAclGate.AssertProtectedFixture(conf, callerSid);
                passed++;

                fileSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.WorldSid, null),
                    System.Security.AccessControl.FileSystemRights.Read,
                    System.Security.AccessControl.AccessControlType.Allow));
                fileInfo.SetAccessControl(fileSecurity);
                ExpectReject(() => ConfigAclGate.AssertProtectedFixture(conf, callerSid));
            }

            // A normal CI user is NOT an elevated SYSTEM service. Actual
            // exported WireGuardTunnelService must never be invoked here.
            Check(accepted.TunnelDll.EndsWith("tunnel.dll", StringComparison.Ordinal));
            Check(passed >= 20);
            Console.WriteLine("PASS: pinned official DLL host preflight; no DLLs loaded or services installed");
            return true;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("FAIL: offline service-host selftest " +
                error.GetType().Name + " (completed assertions=" + passed + ")");
            return false;
        }
        finally
        {
            try { Directory.Delete(temp, recursive: true); }
            catch { /* cleanup failure does not touch any production location */ }
        }
    }
}
