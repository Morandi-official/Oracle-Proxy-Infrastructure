using System.Net;
using System.Text.Json.Nodes;

namespace OracleProxy.Product;
internal static class CoreConfig
{
    private static string ProcessPattern(string path)=>"(?i)^"+string.Concat(path.Select(c=>"\\.+*?()|[]{}^$".Contains(c)?"\\"+c:c.ToString()))+"$";
    internal static JsonObject Build(JsonObject state,DurableState secret,string socksPassword,UdpDiagnosticTarget? diagnosticTarget=null)
        =>Build(state,secret,socksPassword,out _,diagnosticTarget);
    internal static JsonObject Build(JsonObject state,DurableState secret,string socksPassword,out int[] nativePorts,UdpDiagnosticTarget? diagnosticTarget=null,
        string[]? directApplicationPaths=null)
    {
        string ingress=TransportPolicy.IngressAddress(state);
        var tunnel=state["tunnel"]!.AsObject();string endpoint=tunnel["endpoint"]!.GetValue<string>();
        if(!endpoint.StartsWith("152.67.156.100:",StringComparison.Ordinal) || !int.TryParse(endpoint[15..],out int port) || port is <1 or >65535)
            throw new IOException("INVALID_SERVER_ENDPOINT");
        bool dual=tunnel["ipv6_policy"]?.GetValue<string>()=="tunnel";
        if(dual && tunnel["ipv6_egress"]?.GetValue<string>()!="2603:c020:c015:8100::10")throw new IOException("INVALID_IPV6_EGRESS");
        var addresses=tunnel["addresses"]!.AsArray();if(addresses.Count is <1 or >2)throw new IOException("INVALID_TUNNEL_ADDRESS");
        foreach(var node in addresses){var parts=node!.GetValue<string>().Split('/');
            if(parts.Length!=2 || !IPAddress.TryParse(parts[0],out var ip) || (ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork?parts[1]!="32":parts[1]!="128"))throw new IOException("INVALID_TUNNEL_ADDRESS");}
        string serverKey=(diagnosticTarget is not null && tunnel["server_public_keys"] is JsonObject keys ? keys[diagnosticTarget.Address] : tunnel["server_public_key"])?.GetValue<string>() ?? throw new IOException("UNAUTHORIZED_INGRESS_IDENTITY");if(Convert.FromBase64String(serverKey).Length!=32)throw new IOException("INVALID_SERVER_KEY");
        var rules=new JsonArray();
        string[] directPaths=secret.UuPaths.Concat(directApplicationPaths??[]).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        bool routeDirectProcesses=directPaths.Length>0;
        if(routeDirectProcesses)rules.Add(new JsonObject{["inbound"]="device",["process_path_regex"]=new JsonArray(directPaths.Select(p=>(JsonNode?)JsonValue.Create(ProcessPattern(p))).ToArray()),["action"]="route",["outbound"]="uu-direct"});
        rules.Add(new JsonObject{["port"]=53,["action"]="hijack-dns"});
        // Explicit secure policy until Oracle IPv6 is provisioned and proven.
        if(tunnel["ipv6_policy"]?.GetValue<string>()!="tunnel")rules.Add(new JsonObject{["ip_version"]=6,["action"]="reject"});
        var config=new JsonObject{
            ["log"]=new JsonObject{["disabled"]=true},
            ["dns"]=new JsonObject{["servers"]=new JsonArray(new JsonObject{["type"]="udp",["tag"]="vpn-dns",["server"]="1.1.1.1",["detour"]="oracle-wireguard"}),["final"]="vpn-dns",["strategy"]=tunnel["ipv6_policy"]?.GetValue<string>()=="tunnel"?"prefer_ipv4":"ipv4_only"},
            ["inbounds"]=new JsonArray(new JsonObject{["type"]="tun",["tag"]="device",["interface_name"]="OracleProxy",["address"]=new JsonArray("172.29.255.1/30","fd42:6f70:78::1/126"),["mtu"]=1280,["auto_route"]=true,["route_address"]=new JsonArray("0.0.0.0/1","128.0.0.0/1","::/1","8000::/1"),["strict_route"]=true,["stack"]="mixed"},new JsonObject{["type"]="socks",["tag"]="service-probe",["listen"]="127.0.0.1",["listen_port"]=28083,["users"]=new JsonArray(new JsonObject{["username"]="service",["password"]=socksPassword})}),
            ["endpoints"]=new JsonArray(new JsonObject{["type"]="wireguard",["tag"]="oracle-wireguard",["system"]=false,["mtu"]=tunnel["ipv6_policy"]?.GetValue<string>()=="tunnel"?1280:1200,["address"]=addresses.DeepClone(),["private_key"]=secret.PrivateKey,["peers"]=new JsonArray(new JsonObject{["address"]="152.67.156.100",["port"]=port,["public_key"]=serverKey,["allowed_ips"]=new JsonArray("0.0.0.0/0","::/0"),["persistent_keepalive_interval"]=25})}),
            ["outbounds"]=new JsonArray(new JsonObject{["type"]="direct",["tag"]="uu-direct"}),
            ["route"]=new JsonObject{["auto_detect_interface"]=true,["find_process"]=routeDirectProcesses,["rules"]=rules,["final"]="oracle-wireguard"}
        };
        // WireGuard uses connected UDP sockets on the physical interface.
        config["endpoints"]![0]!["detour"]="oracle-native-udp";
        nativePorts=NativeUdpPortPolicy.Select(state,secret,port);
        config["outbounds"]!.AsArray().Add(new JsonObject{["type"]="oracle-native-udp",["ipv6_payload"]=dual,["address"]=ingress,["tag"]="oracle-native-udp",["ports"]=new JsonArray(nativePorts.Select(p=>(JsonNode?)JsonValue.Create(p)).ToArray())});
        if(diagnosticTarget is not null){diagnosticTarget.Apply(config);nativePorts=[diagnosticTarget.Port];}
        return config;
    }
}
