using System.Net;
using System.Text.Json.Nodes;

namespace OracleProxy.Product;
internal static class CoreConfig
{
    internal static JsonObject Build(JsonObject state,DurableState secret,string socksPassword)
    {
        var tunnel=state["tunnel"]!.AsObject();string endpoint=tunnel["endpoint"]!.GetValue<string>();
        if(!endpoint.StartsWith("152.67.156.100:",StringComparison.Ordinal) || !int.TryParse(endpoint[15..],out int port) || port is <1 or >65535)
            throw new IOException("INVALID_SERVER_ENDPOINT");
        var addresses=tunnel["addresses"]!.AsArray();if(addresses.Count is <1 or >2)throw new IOException("INVALID_TUNNEL_ADDRESS");
        foreach(var node in addresses){var parts=node!.GetValue<string>().Split('/');
            if(parts.Length!=2 || !IPAddress.TryParse(parts[0],out var ip) || (ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork?parts[1]!="32":parts[1]!="128"))throw new IOException("INVALID_TUNNEL_ADDRESS");}
        string serverKey=tunnel["server_public_key"]!.GetValue<string>();if(Convert.FromBase64String(serverKey).Length!=32)throw new IOException("INVALID_SERVER_KEY");
        var rules=new JsonArray();
        if(secret.UuPaths.Length>0)rules.Add(new JsonObject{["process_path"]=new JsonArray(secret.UuPaths.Select(p=>(JsonNode?)JsonValue.Create(p)).ToArray()),["action"]="route",["outbound"]="uu-direct"});
        rules.Add(new JsonObject{["port"]=53,["action"]="hijack-dns"});
        // Explicit secure policy until Oracle IPv6 is provisioned and proven.
        if(tunnel["ipv6_policy"]?.GetValue<string>()!="tunnel")rules.Add(new JsonObject{["ip_version"]=6,["action"]="reject"});
        return new JsonObject{
            ["log"]=new JsonObject{["disabled"]=true},
            ["dns"]=new JsonObject{["servers"]=new JsonArray(new JsonObject{["type"]="udp",["tag"]="vpn-dns",["server"]="1.1.1.1",["detour"]="oracle-wireguard"}),["final"]="vpn-dns"},
            ["inbounds"]=new JsonArray(new JsonObject{["type"]="tun",["tag"]="device",["interface_name"]="OracleProxy",["address"]=new JsonArray("172.29.255.1/30","fd42:6f70:78::1/126"),["mtu"]=1380,["auto_route"]=true,["strict_route"]=true,["stack"]="mixed"},new JsonObject{["type"]="socks",["tag"]="service-probe",["listen"]="127.0.0.1",["listen_port"]=28083,["users"]=new JsonArray(new JsonObject{["username"]="service",["password"]=socksPassword})}),
            ["endpoints"]=new JsonArray(new JsonObject{["type"]="wireguard",["tag"]="oracle-wireguard",["system"]=false,["mtu"]=1380,["address"]=addresses.DeepClone(),["private_key"]=secret.PrivateKey,["peers"]=new JsonArray(new JsonObject{["address"]="152.67.156.100",["port"]=port,["public_key"]=serverKey,["allowed_ips"]=new JsonArray("0.0.0.0/0","::/0"),["persistent_keepalive_interval"]=25})}),
            ["outbounds"]=new JsonArray(new JsonObject{["type"]="direct",["tag"]="uu-direct"}),
            ["route"]=new JsonObject{["auto_detect_interface"]=true,["find_process"]=true,["rules"]=rules,["final"]="oracle-wireguard"}
        };
    }
}
