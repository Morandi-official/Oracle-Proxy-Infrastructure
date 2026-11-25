using System.Net.NetworkInformation;
using OracleProxy.Tailscale;

if (args.Length == 3 && args[2] == "--dns-recovery")
    return await DnsRecoveryAcceptance.Run(args[0], args[1]);
if (args.Length != 2) return 2;
string adapter;
await using (var daemon = await DaemonProcess.Start(args[0], args[1], CancellationToken.None))
{
    adapter = daemon.AdapterName;
    var control = daemon.Control;
    var state = await control.ReadState();
    if (state.State is not ("NeedsLogin" or "Stopped") || state.HasNodeKey)
        return 1;
    Console.WriteLine("TAILSCALE_WINDOWS_DIRECT_PROTECTED_PIPE=PASS");
    if (!NetworkInterface.GetAllNetworkInterfaces().Any(value => value.Name == adapter))
        throw new IOException("TAILSCALE_OWNED_ADAPTER_NOT_FOUND");
    Console.WriteLine("TAILSCALE_WINDOWS_NATIVE_ADAPTER_READY=PASS");
    try
    {
        await control.Enroll(new Uri("http://coordinator.invalid/"), "");
        return 1;
    }
    catch (ArgumentException exception) when (exception.ParamName == "coordinator")
    {
        Console.WriteLine("TAILSCALE_WINDOWS_REJECTS_HTTP_COORDINATOR=PASS");
    }
}
for (int attempt = 0; attempt < 16; attempt++)
{
    if (!NetworkInterface.GetAllNetworkInterfaces().Any(value => value.Name == adapter))
    {
        Console.WriteLine("TAILSCALE_WINDOWS_OWNED_DAEMON_AND_ADAPTER_STOPPED=PASS");
        return 0;
    }
    await Task.Delay(250);
}
return 1;
