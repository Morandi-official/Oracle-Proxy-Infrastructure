using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
namespace OracleProxy.Product;

internal static class EndpointCatalog
{
    internal static string Public(string value)
    {
        if(!IPAddress.TryParse(value,out var ip) || ip.AddressFamily!=AddressFamily.InterNetwork || ip.ToString()!=value)throw new IOException("INVALID_PUBLIC_ENDPOINT");
        var b=ip.GetAddressBytes();
        if(b[0] is 0 or 10 or 127 || b[0]>=224 || (b[0]==100 && b[1] is >=64 and <=127) || (b[0]==169 && b[1]==254) || (b[0]==172 && b[1] is >=16 and <=31) || (b[0]==192 && (b[1]==168 || b[1]==0)) || (b[0]==198 && (b[1] is 18 or 19 || (b[1]==51 && b[2]==100))) || (b[0]==203 && b[1]==0 && b[2]==113))throw new IOException("INVALID_PUBLIC_ENDPOINT");
        return value;
    }
    internal static string[] Addresses(JsonObject state)
    {
        if(state["network_endpoints"] is not JsonObject network)return [];
        if(network["schema"]?.GetValue<int>()!=1 || network["revision"]?.GetValue<int>() is not >=1)throw new IOException("INVALID_ENDPOINT_CATALOG");
        string primary=Public(network["primary"]!.GetValue<string>()),backup=Public(network["backup"]!.GetValue<string>());
        if(primary==backup)throw new IOException("DUPLICATE_ENDPOINT");
        return [primary,backup];
    }
    internal static JsonObject Normalize(JsonObject state)
    {
        var addresses=Addresses(state);
        if(addresses.Length==0)return state;
        if(state["network_endpoints"]!["egress_ipv4"] is not JsonArray exits || exits.Count is <1 or >2)throw new IOException("INVALID_EGRESS_CATALOG");
        foreach(var address in exits)Public(address!.GetValue<string>());
        if(state["tunnel"] is JsonObject tunnel){
            tunnel["transport_address"]=addresses[0];tunnel["backup_address"]=addresses[1];
            tunnel["egress_ipv4_candidates"]=exits.DeepClone();
        }
        return state;
    }
    internal static string PrivateAddress(JsonObject? state,string address)
    {
        string? value=(state?["network_endpoints"]?["private_ipv4"]?[address] ?? state?["tunnel"]?["private_ipv4"]?[address])?.GetValue<string>();
        return IPAddress.TryParse(value,out var ip) && ip.AddressFamily==AddressFamily.InterNetwork?ip.ToString():"";
    }
    internal static string[] Egress(JsonObject state)=>state["tunnel"]?["egress_ipv4_candidates"] is JsonArray values && values.Count is >0 and <=2?values.Select(v=>Public(v!.GetValue<string>())).Distinct().ToArray():["152.67.156.100"];
    internal static JsonObject ForIngress(JsonObject state,bool backup)
    {
        var value=(JsonObject)state.DeepClone();
        if(backup && value["tunnel"]?["backup_address"] is JsonValue address)value["tunnel"]!["transport_address"]=Public(address.GetValue<string>());
        if(value["tunnel"] is JsonObject tunnel && tunnel["server_public_keys"] is JsonObject keys){
            string selected=TransportPolicy.IngressAddress(value);
            if(keys[selected] is not JsonValue key || !key.TryGetValue<string>(out var encoded) || Convert.FromBase64String(encoded).Length!=32)throw new IOException("UNAUTHORIZED_INGRESS_IDENTITY");
            tunnel["server_public_key"]=encoded;
        }
        return value;
    }
}
