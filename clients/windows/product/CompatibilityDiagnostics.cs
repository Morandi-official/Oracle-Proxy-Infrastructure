using Microsoft.Win32;
using System.Net;
using System.Net.NetworkInformation;
using System.ServiceProcess;
namespace OracleProxy.Product;

// Read only in the desktop owner's context. Never export proxy credentials,
// PAC URLs, remote host names, adapter names or third-party rules.
internal static class CompatibilityDiagnostics
{
    internal static int[] LoopbackPorts(string? proxy)
    {
        if(proxy is null || proxy.Length>4096)return [];
        var ports=new HashSet<int>();
        foreach(string item in proxy.Split(';',StringSplitOptions.RemoveEmptyEntries)){
            string value=item.Trim();int equal=value.IndexOf('=');if(equal>=0)value=value[(equal+1)..].Trim();
            if(!value.Contains("://",StringComparison.Ordinal))value="http://"+value;
            if(Uri.TryCreate(value,UriKind.Absolute,out var uri) && uri.IsLoopback && uri.Port is >0 and <=65535)ports.Add(uri.Port);
        }
        return ports.Order().ToArray();
    }
    internal static string Read()
    {
        var lines=new List<string>{"其他代理兼容性检查（只读；检测到设置不代表已确认冲突）"};
        try{using var service=new ServiceController(Platform.Service);lines.Add("control_service_status: "+service.Status);}
        catch{lines.Add("control_service_status: unavailable");}
        try{
            using var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            bool enabled=key?.GetValue("ProxyEnable") is int value && value!=0;
            bool pac=key?.GetValue("AutoConfigURL") is string url && !string.IsNullOrWhiteSpace(url);
            int[] ports=LoopbackPorts(key?.GetValue("ProxyServer") as string);
            lines.Add("current_user_system_proxy_enabled: "+enabled);lines.Add("current_user_pac_configured: "+pac);
            lines.Add("configured_loopback_proxy_ports: "+string.Join(',',ports));
            if(enabled || pac)lines.Add("浏览器可能仍经由其他代理。请核对该软件和系统代理设置；本客户端不会自动修改它们。");
            try{
                var listening=IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners();
                lines.Add("listening_loopback_proxy_ports: "+string.Join(',',ports.Where(p=>listening.Any(e=>e.Port==p && (IPAddress.IsLoopback(e.Address) || e.Address.Equals(IPAddress.Any) || e.Address.Equals(IPAddress.IPv6Any))))));
            }catch{lines.Add("listening_loopback_proxy_ports: unavailable");}
        }catch{lines.Add("current_user_system_proxy: unavailable");}
        try{
            int count=NetworkInterface.GetAllNetworkInterfaces().Count(n=>n.Name!="OracleProxy" && n.OperationalStatus==OperationalStatus.Up &&
                (n.NetworkInterfaceType is NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp || new[]{"Wintun","WireGuard","TAP-Windows","Clash"}.Any(term=>n.Description.Contains(term,StringComparison.OrdinalIgnoreCase))));
            lines.Add("other_active_vpn_adapter_candidates: "+count);
            if(count>0)lines.Add("其他虚拟网卡可能影响路由；此项仅记录候选数量，不会停用网卡或删除其他软件的规则。");
        }catch{lines.Add("other_active_vpn_adapter_candidates: unavailable");}
        return string.Join("\r\n",lines)+"\r\n";
    }
}
