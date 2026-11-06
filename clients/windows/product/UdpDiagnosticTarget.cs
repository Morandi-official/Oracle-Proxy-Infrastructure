using System.Text.Json.Nodes;
namespace OracleProxy.Product;

internal sealed record UdpDiagnosticTarget
{
    internal string Address { get; }
    internal int Port { get; }
    internal UdpDiagnosticTarget(string address,int port)
    {
        if(address is not ("152.67.156.100" or "141.147.78.44") || port is not (443 or 8443 or 51820))throw new IOException("INVALID_UDP_DIAGNOSTIC_TARGET");
        Address=address;Port=port;
    }
    internal static UdpDiagnosticTarget[] All=>[new("152.67.156.100",443),new("152.67.156.100",8443),new("152.67.156.100",51820),new("141.147.78.44",443),new("141.147.78.44",8443),new("141.147.78.44",51820)];
    internal void Apply(JsonObject config,TunnelTransport transport)
    {
        if(transport!=TunnelTransport.WireGuardUdp)throw new IOException("DIAGNOSTIC_REQUIRES_NATIVE_UDP");
        var outbound=config["outbounds"]!.AsArray().OfType<JsonObject>().Single(o=>o["type"]?.GetValue<string>()=="oracle-native-udp");
        outbound["address"]=Address;outbound["ports"]=new JsonArray(Port);
    }
}
