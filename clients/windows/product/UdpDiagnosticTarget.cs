using System.Text.Json.Nodes;
namespace OracleProxy.Product;

internal sealed record UdpDiagnosticTarget
{
    internal string Address { get; }
    internal int Port { get; }
    internal UdpDiagnosticTarget(string address,int port)
    {
        if(port is not (443 or 8443 or 51820))throw new IOException("INVALID_UDP_DIAGNOSTIC_TARGET");
        Address=EndpointCatalog.Public(address);Port=port;
    }
    internal static UdpDiagnosticTarget[] All=>[new("152.67.154.225",443),new("152.67.154.225",8443),new("152.67.154.225",51820),new("150.230.113.158",443),new("150.230.113.158",8443),new("150.230.113.158",51820)];
    internal static UdpDiagnosticTarget[] ForState(JsonObject state)
    {
        var addresses=EndpointCatalog.Addresses(state);
        return addresses.Length==0?All:addresses.SelectMany(a=>new[]{443,8443,51820}.Select(p=>new UdpDiagnosticTarget(a,p))).ToArray();
    }
    internal void Apply(JsonObject config,TunnelTransport transport)
    {
        if(transport!=TunnelTransport.WireGuardUdp)throw new IOException("DIAGNOSTIC_REQUIRES_NATIVE_UDP");
        var outbound=config["outbounds"]!.AsArray().OfType<JsonObject>().Single(o=>o["type"]?.GetValue<string>()=="oracle-native-udp");
        outbound["address"]=Address;outbound["ports"]=new JsonArray(Port);
    }
}
