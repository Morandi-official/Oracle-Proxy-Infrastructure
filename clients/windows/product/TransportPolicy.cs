using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal enum TunnelTransport { WireGuardUdp, WireGuardQuic, WireGuardHttps }
internal static class TransportPolicy
{
    internal static string Name(TunnelTransport value)=>value switch{
        TunnelTransport.WireGuardUdp=>"wireguard-udp",TunnelTransport.WireGuardQuic=>"wireguard-quic",_=>"wireguard-https"};
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
