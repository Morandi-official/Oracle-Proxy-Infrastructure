using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
namespace OracleProxy.Product;
internal static class GitHubDiagnostics
{
    private static readonly (string Host,string Path)[] Targets=[("github.com","/"),("github.githubassets.com","/favicons/favicon.svg"),("avatars.githubusercontent.com","/u/204281968?v=4&size=64"),("raw.githubusercontent.com","/Morandi-official/Oracle-Proxy-Infrastructure/main/README.md")];
    internal static bool LocalOverride(IEnumerable<IPAddress> addresses)=>addresses.Any(IPAddress.IsLoopback);
    internal static async Task<string> Run()
    {
        var report=new StringBuilder("GitHub 只读连通性检查（无账号、令牌或密钥）\r\n");
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(25));
        using var client=new HttpClient(new SocketsHttpHandler{UseProxy=false,UseCookies=false,AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(7)};
        foreach(var target in Targets){
            report.Append(target.Host).Append(": ");
            try{
                var addresses=await Dns.GetHostAddressesAsync(target.Host,deadline.Token);
                if(LocalOverride(addresses)){
                    report.AppendLine("本机地址重写："+string.Join(", ",addresses.Select(x=>x.ToString())));
                    report.AppendLine("可能由 Steam++ / Watt Toolkit、FastGitHub 或 hosts 规则接管。请在对应软件关闭 GitHub 加速并恢复其规则；本产品不会修改 hosts 或关闭其他软件。");
                    continue;
                }
                var timer=System.Diagnostics.Stopwatch.StartNew();
                using var response=await client.GetAsync("https://"+target.Host+target.Path,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
                report.Append("HTTP ").Append((int)response.StatusCode).Append(" · ").Append(timer.ElapsedMilliseconds).AppendLine(" ms");
            }catch(Exception error)when(error is HttpRequestException or SocketException or OperationCanceledException){report.AppendLine(error.GetType().Name);}
        }
        report.AppendLine("检查使用当前系统路由与默认 TLS 证书验证；HTTP 状态和耗时不等于带宽测速。hosts 规则未被修改。");
        return report.ToString();
    }
}
