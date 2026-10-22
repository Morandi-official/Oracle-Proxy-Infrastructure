using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Math.EC.Rfc7748;
namespace OracleProxy.Product;
internal static class ProductSelfTests
{
    internal static bool Run()
    {
        byte[] key=Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),pub=new byte[32];
        X25519.GeneratePublicKey(key,0,pub,0);
        if(Convert.ToHexString(pub).ToLowerInvariant()!="8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")return false;
        var state=new JsonObject{["tunnel"]=new JsonObject{["endpoint"]="152.67.156.100:51820",["server_public_key"]=Convert.ToBase64String(pub),["addresses"]=new JsonArray("10.200.0.2/32"),["ipv6_policy"]="block"}};
        var secret=new DurableState{PrivateKey=Convert.ToBase64String(key),UuPaths=[@"E:\Different\GameViewer\GameViewer.exe"]};
        var config=CoreConfig.Build(state,secret,"synthetic-only");
        if(config["route"]?["final"]?.GetValue<string>()!="oracle-wireguard" || !System.Text.RegularExpressions.Regex.IsMatch(secret.UuPaths[0].ToLowerInvariant(),config["route"]!["rules"]![0]!["process_path_regex"]![0]!.GetValue<string>()))return false;
        if(config["endpoints"]?[0]?["peers"]?[0]?["port"]?.GetValue<int>()!=51820)return false;
        try{CoreConfig.Build(state,secret,"synthetic-only",true);return false;}catch(IOException){}
        state["tunnel"]!["https_relay"]=true;secret.Token=new string('A',43);
        var relay=CoreConfig.Build(state,secret,"synthetic-only",true);
        if(relay["endpoints"]?[0]?["detour"]?.GetValue<string>()!="oracle-https-relay" ||
           relay["outbounds"]?[1]?["type"]?.GetValue<string>()!="oracle-https" ||
           relay["inbounds"]?[0]?["route_exclude_address"] is not null)return false;
        if(TransportPolicy.Next(TunnelTransport.WireGuardUdp,state)!=TunnelTransport.WireGuardHttps)return false;
        state["tunnel"]!["quic"]=new JsonObject{["enabled"]=true,["port"]=8443,["certificate"]="-----BEGIN CERTIFICATE-----synthetic"};
        if(TransportPolicy.Next(TunnelTransport.WireGuardUdp,state)!=TunnelTransport.WireGuardQuic || TransportPolicy.Next(TunnelTransport.WireGuardQuic,state)!=TunnelTransport.WireGuardHttps || TransportPolicy.Next(TunnelTransport.WireGuardHttps,state) is not null)return false;
        var quic=CoreConfig.Build(state,secret,"synthetic-only",TunnelTransport.WireGuardQuic);
        if(quic["endpoints"]?[0]?["detour"]?.GetValue<string>()!="oracle-quic-relay" || quic["outbounds"]?[1]?["type"]?.GetValue<string>()!="oracle-quic")return false;
        state["tunnel"]!["quic"]!["enabled"]=false;
        try{CoreConfig.Build(state,secret,"synthetic-only",TunnelTransport.WireGuardQuic);return false;}catch(IOException){}
        state["tunnel"]!["endpoint"]="evil.invalid:443";
        try{CoreConfig.Build(state,secret,"synthetic-only");return false;}catch(IOException){}
        CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(pub);return true;
    }
}
