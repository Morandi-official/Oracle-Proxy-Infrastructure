using System.Net.NetworkInformation;
using System.Net.Sockets;
namespace OracleProxy.Product;
// Performance hint only, never an authorization decision. No address or
// network identifier is sent to the GUI, persisted, or exported in diagnostics.
internal sealed class CarrierMemory
{
    private string _network="";
    private readonly Dictionary<TunnelTransport,long> _failed=new();
    internal bool Observe(string network)
    {
        if(network==_network)return false;
        _network=network;_failed.Clear();return true;
    }
    internal static string Scope(System.Text.Json.Nodes.JsonObject? state)=>Network()+"|"+TransportPolicy.IngressAddress(state);
    internal static string NetworkHash(System.Text.Json.Nodes.JsonObject? state=null)=>Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Scope(state))));
    internal void Clear()=>_failed.Clear();
    internal void Failed(TunnelTransport transport)=>_failed[transport]=System.Diagnostics.Stopwatch.GetTimestamp();
    internal TunnelTransport Preferred(System.Text.Json.Nodes.JsonObject state)
    {
        var value=TunnelTransport.WireGuardUdp;
        while(_failed.TryGetValue(value,out long at) && System.Diagnostics.Stopwatch.GetElapsedTime(at)<TimeSpan.FromMinutes(5) && TransportPolicy.Next(value,state) is TunnelTransport next)value=next;
        return value;
    }
    internal static string Network()=>string.Join(";",NetworkInterface.GetAllNetworkInterfaces()
        .Where(n=>n.Name!="OracleProxy" && n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType!=NetworkInterfaceType.Loopback)
        .Select(n=>{
            var ip=n.GetIPProperties();
            return n.Id+":"+string.Join(",",ip.GatewayAddresses.Select(a=>a.Address.ToString()).Order())+":"+
                string.Join(",",ip.UnicastAddresses.Where(a=>a.Address.AddressFamily==AddressFamily.InterNetwork).Select(a=>a.Address.ToString()).Order());
        }).Order());
}
