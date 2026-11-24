using OracleProxy.Tailscale;

if (args.Length != 1) return 2;
using var control = new LocalControl(args[0]);
var state = await control.ReadState();
if (state.State is not ("NeedsLogin" or "Stopped") || state.HasNodeKey)
    return 1;
Console.WriteLine("TAILSCALE_WINDOWS_DIRECT_PROTECTED_PIPE=PASS");
try
{
    await control.Enroll(new Uri("http://coordinator.invalid/"), "");
    return 1;
}
catch (ArgumentException exception) when (exception.ParamName == "coordinator")
{
    Console.WriteLine("TAILSCALE_WINDOWS_REJECTS_HTTP_COORDINATOR=PASS");
}
await control.Stop();
if ((await control.ReadState()).HasNodeKey)
    return 1;
Console.WriteLine("TAILSCALE_WINDOWS_LOCAL_DAEMON_STOP=PASS");
return 0;
