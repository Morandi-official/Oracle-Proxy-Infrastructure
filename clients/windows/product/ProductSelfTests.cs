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
        if(config["route"]?["final"]?.GetValue<string>()!="oracle-wireguard" || config["route"]?["rules"]?[0]?["process_path"]?[0]?.GetValue<string>()!=secret.UuPaths[0])return false;
        if(config["endpoints"]?[0]?["peers"]?[0]?["port"]?.GetValue<int>()!=51820)return false;
        state["tunnel"]!["endpoint"]="evil.invalid:443";
        try{CoreConfig.Build(state,secret,"synthetic-only");return false;}catch(IOException){}
        CryptographicOperations.ZeroMemory(key);CryptographicOperations.ZeroMemory(pub);return true;
    }
}
