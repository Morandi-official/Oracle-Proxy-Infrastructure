using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal static class TransportPolicy
{
    internal static string IngressAddress(JsonObject? state)
    {
        var node=state?["tunnel"]?["transport_address"];
        if(node is null)return "152.67.156.100";
        if(node is JsonValue value && value.TryGetValue<string>(out var address))return EndpointCatalog.Public(address);
        throw new IOException("INVALID_TRANSPORT_ADDRESS");
    }
    internal static bool Native8443Available(JsonObject? state)=>state?["tunnel"]?["native_udp_ports"] is JsonArray ports && ports.Any(n=>n?.GetValue<int>()==8443);
}
