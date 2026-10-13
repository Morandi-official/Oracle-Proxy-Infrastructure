using System.Security.Cryptography;

namespace OracleProxy.IntentLab;

// Genuine Windows DPAPI + actual local file writes, restricted to disposable
// GitHub-hosted runner temp. Does NOT enforce packets or install anything.
internal static class IntentSelfTests
{
    internal static bool Run()
    {
        int checkedCases = 0;
        string root = Path.Combine(Path.GetTempPath(),
            "oracle-intent-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string file = Path.Combine(root, "intent.protected");
        try
        {
            void Check(bool assertion)
            {
                if (!assertion) throw new InvalidOperationException(
                    "Intent prototype assertion " + checkedCases);
                checkedCases++;
            }
            void MustReject(Action operation)
            {
                try { operation(); }
                catch (InvalidOperationException) { checkedCases++; return; }
                catch (ArgumentException) { checkedCases++; return; }
                throw new InvalidOperationException("Unexpectedly accepted unsafe intent write");
            }
            var store = new IntentStore(root, "intent.protected");

            // No valid record is UNKNOWN: cannot be silently treated as OFF.
            var absent = store.Read();
            Check(absent.Intent == UserIntent.UnknownFailClosed);
            Check(absent.RequiresFailClosed);
            Check(absent.Reason == "MISSING_FILE");
            MustReject(() => store.RecordExplicitChoice(UserIntent.Disabled));
            MustReject(() => store.RecordExplicitChoice(UserIntent.UnknownFailClosed));

            var on = store.RecordExplicitChoice(UserIntent.Enabled);
            Check(on.Intent == UserIntent.Enabled);
            Check(on.Revision == 1);
            Check(on.RequiresFailClosed);
            byte[] cipher = File.ReadAllBytes(file);
            Check(cipher.Length > 0 && cipher.Length < 4096);
            Check(!System.Text.Encoding.ASCII.GetString(cipher).Contains("Enabled"));

            // A tunnel disconnect is an OBSERVATION, not an explicit OFF.
            // This prototype deliberately has no "disconnect" mutation API.
            Check(store.Read().Intent == UserIntent.Enabled);
            Check(store.Read().RequiresFailClosed);

            var off = store.RecordExplicitChoice(UserIntent.Disabled);
            Check(off.Intent == UserIntent.Disabled);
            Check(off.Revision == 2);
            Check(!off.RequiresFailClosed);
            Check(store.Read().Reason == "EXPLICIT_DISABLED");

            var onAgain = store.RecordExplicitChoice(UserIntent.Enabled);
            Check(onAgain.Revision == 3);
            Check(onAgain.RequiresFailClosed);

            // Tampering DPAPI ciphertext cannot silently disable protection.
            cipher = File.ReadAllBytes(file);
            cipher[cipher.Length / 2] ^= 0x40;
            File.WriteAllBytes(file, cipher);
            Check(store.Read().Intent == UserIntent.UnknownFailClosed);
            Check(store.Read().RequiresFailClosed);
            MustReject(() => store.RecordExplicitChoice(UserIntent.Disabled));
            MustReject(() => store.RecordExplicitChoice(UserIntent.Enabled));

            File.WriteAllBytes(file, Array.Empty<byte>());
            Check(store.Read().Intent == UserIntent.UnknownFailClosed);
            Check(store.Read().RequiresFailClosed);

            File.WriteAllBytes(file, RandomNumberGenerator.GetBytes(4097));
            Check(store.Read().Intent == UserIntent.UnknownFailClosed);
            Check(store.Read().RequiresFailClosed);

            File.Delete(file);
            Check(store.Read().Intent == UserIntent.UnknownFailClosed);
            Check(store.Read().RequiresFailClosed);
            MustReject(() => store.RecordExplicitChoice(UserIntent.Disabled));

            // Reprovision requires a separately authorized Enabled choice;
            // never auto restore direct access just because state was lost.
            var provisioned = store.RecordExplicitChoice(UserIntent.Enabled);
            Check(provisioned.Intent == UserIntent.Enabled);
            Check(provisioned.Revision == 1);
            Check(provisioned.RequiresFailClosed);

            MustReject(() => new IntentStore("relative-path", "intent.protected"));
            MustReject(() => new IntentStore(root, "oracle-production.conf"));

            Check(checkedCases >= 30);
            Console.WriteLine("PASS: " + checkedCases +
                " real Windows DPAPI + offline intent corruption/recovery checks; " +
                "NO service/WFP/driver/network changes");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FAIL: offline intent prototype " +
                ex.GetType().Name + " at assertion " + checkedCases);
            return false;
        }
        finally
        {
            try { Directory.Delete(root, true); }
            catch { /* disposable CI runner will be discarded */ }
        }
    }
}
