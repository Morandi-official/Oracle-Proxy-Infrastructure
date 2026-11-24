using OracleProxy.Tailscale;

if (args.Length != 1) return 2;
using var control = new LocalControl(args[0]);
var state = await control.ReadState();
if (state.State is not ("NeedsLogin" or "Stopped") || state.HasNodeKey)
    return 1;
Console.WriteLine("TAILSCALE_WINDOWS_DIRECT_PROTECTED_PIPE=PASS");
return 0;
