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
    internal static UdpDiagnosticTarget[] All=>[new(AccountApi.BootstrapAddress,443),new(AccountApi.BootstrapAddress,8443),new(AccountApi.BootstrapAddress,51820)];
    internal static UdpDiagnosticTarget[] ForState(JsonObject state)
    {
        var addresses=state["tunnel"]?["server_public_keys"] is JsonObject keys?keys.Select(p=>EndpointCatalog.Public(p.Key)).ToArray():EndpointCatalog.Addresses(state);
        return addresses.Length==0?All:addresses.SelectMany(a=>new[]{443,8443,51820}.Select(p=>new UdpDiagnosticTarget(a,p))).ToArray();
    }
    internal void Apply(JsonObject config)
    {
        var outbound=config["outbounds"]!.AsArray().OfType<JsonObject>().Single(o=>o["type"]?.GetValue<string>()=="oracle-native-udp");
        outbound["address"]=Address;outbound["ports"]=new JsonArray(Port);
    }
}
