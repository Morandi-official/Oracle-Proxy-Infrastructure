using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal enum TunnelTransport { WireGuardUdp, WireGuardQuic, WireGuardHttps }
internal static class TransportPolicy
{
    internal static string IngressAddress(JsonObject? state)
    {
        var node=state?["tunnel"]?["transport_address"];
        if(node is null)return "152.67.156.100";
        if(node is JsonValue value && value.TryGetValue<string>(out var address) && address is "152.67.156.100" or "141.147.78.44")return address;
        throw new IOException("INVALID_TRANSPORT_ADDRESS");
    }
    internal static string Name(TunnelTransport value)=>value switch{
        TunnelTransport.WireGuardUdp=>"wireguard-udp",TunnelTransport.WireGuardQuic=>"wireguard-quic",_=>"wireguard-https"};
    internal static bool Native8443Available(JsonObject? state)=>state?["tunnel"]?["native_udp_ports"] is JsonArray ports && ports.Any(n=>n?.GetValue<int>()==8443);
    internal static string ClientSelection(int index,bool native8443)=>index switch{
        0=>native8443?"PreferAuto8443":"PreferAuto",1=>native8443?"PreferUdp8443":"PreferUdp",2=>"PreferQuic",_=>throw new IOException("INVALID_TRANSPORT_SELECTION")};
    internal static TunnelTransport First(string preference,JsonObject? state)=>preference=="quic"?TunnelTransport.WireGuardQuic:TunnelTransport.WireGuardUdp;
    internal static bool QuicAvailable(JsonObject state)=>state["tunnel"]?["quic"] is JsonObject quic &&
        quic["enabled"]?.GetValue<bool>()==true && quic["port"]?.GetValue<int>()==8443 &&
        quic["certificate"]?.GetValue<string>() is string certificate && certificate.Length is >0 and <=4096 &&
        certificate.StartsWith("-----BEGIN CERTIFICATE-----",StringComparison.Ordinal) && !certificate.Contains("PRIVATE KEY",StringComparison.Ordinal);
    internal static TunnelTransport? Next(TunnelTransport current,JsonObject state)=>current switch{
        TunnelTransport.WireGuardUdp when QuicAvailable(state)=>TunnelTransport.WireGuardQuic,
        TunnelTransport.WireGuardUdp or TunnelTransport.WireGuardQuic when state["tunnel"]?["https_relay"]?.GetValue<bool>()==true=>TunnelTransport.WireGuardHttps,
        _=>null};
}
