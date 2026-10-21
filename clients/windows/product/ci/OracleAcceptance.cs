// Non-shipped integration fixture. Uses only the dedicated low-quota client
// account from the windows-client-acceptance Environment, never SSH/OAuth keys.
using System.Diagnostics;
using System.Net;
using System.Text.Json.Nodes;
using OracleProxy.Product;

internal static class OracleAcceptance
{
    // Disposable hosted fault only; this is never compiled into the product.
    private sealed class InitialUdpLoss : IDisposable
    {
        private readonly dynamic _policy;
        private const string Name="OracleProxyCandidateInitialUdp";
        private const string Marker="Oracle Proxy disposable initial handshake loss";
        internal InitialUdpLoss(int port)
        {
            _policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
            // Hosted images can have inactive firewall profiles. Enable their
            // filtering before using a block rule; never disable a profile.
            // This fixture is restricted to disposable GitHub-hosted runners.
            foreach(int profile in new[]{1,2,4}){
                _policy.FirewallEnabled[profile]=true;
                Check((bool)_policy.FirewallEnabled[profile],"REAL_HOSTED_FIREWALL_PROFILE_"+profile+"_ENABLED");
            }
            foreach(dynamic existing in _policy.Rules)if(existing.Name==Name)throw new IOException("PREEXISTING_FIREWALL_RULE_REFUSED");
            dynamic rule=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
            rule.Name=Name;rule.Description=Marker;rule.ApplicationName=Platform.Core;rule.Protocol=17;rule.RemoteAddresses="152.67.156.100";rule.RemotePorts=port.ToString();rule.Direction=2;rule.Action=0;rule.Profiles=int.MaxValue;rule.Enabled=true;
            _policy.Rules.Add(rule);
        }
        public void Dispose()
        {
            dynamic rule=_policy.Rules.Item(Name);
            if(rule.Description!=Marker || !string.Equals((string)rule.ApplicationName,Platform.Core,StringComparison.OrdinalIgnoreCase))throw new IOException("FOREIGN_FIREWALL_RULE_REFUSED");
            _policy.Rules.Remove(Name);
        }
    }
    private static void Check(bool condition,string code){if(!condition)throw new IOException(code);Console.WriteLine(code+"=PASS");}
    private static async Task<JsonObject> Send(string command)
    {
        var value=await ControlPipe.Send(command);
        if(value["ok"]?.GetValue<bool>()!=true)throw new IOException("ORACLE_SERVICE_COMMAND_FAILED");
        return value;
    }
    private static async Task<string> ExitIp()
    {
        using var client=new HttpClient(new SocketsHttpHandler{UseProxy=false,UseCookies=false,AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(10)};
        string value=await client.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace");
        string? ip=value.Split('\n').FirstOrDefault(v=>v.StartsWith("ip="))?[3..];
        if(value.Length>8192 || !IPAddress.TryParse(ip,out _))throw new IOException("EXIT_PROBE_FAILED");
        return ip;
    }
    private static async Task<JsonObject> Connected()
    {
        for(int i=0;i<50;i++){
            try{var state=await Send("Status");if(state["mode"]?.GetValue<string>()=="connected" && state["guard"]?.GetValue<bool>()==true)return state;}catch{}
            await Task.Delay(1000);
        }
        throw new IOException("ORACLE_RECONNECT_TIMED_OUT");
    }
    internal static async Task<int> Run()
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
        string? username=Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_USERNAME"),password=Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD");
        if(string.IsNullOrWhiteSpace(username)||string.IsNullOrEmpty(password)){Console.WriteLine("ORACLE_ACCEPTANCE_CREDENTIALS_MISSING");return 2;}
        string stage="BASELINE";
        try{
            Check(await ExitIp()!="152.67.156.100","REAL_RUNNER_DIRECT_BASELINE");
            stage="LOGIN";var login=await ControlPipe.Send("Login",username,password);password=null;
            Check(login["ok"]?.GetValue<bool>()==true && login["account"]?["username"]?.GetValue<string>()==username,"REAL_ORACLE_CLIENT_LOGIN_AND_AUTOMATIC_ENROLLMENT");
            var account=login["account"]!;long used=account["used_bytes"]!.GetValue<long>();int devices=account["device_count"]!.GetValue<int>();
            Check(account["status"]?.GetValue<string>()=="active" && account["limit_bytes"]?.GetValue<long>() is long limit && limit<=128*1024*1024 && limit-used>=4*1024*1024,"REAL_ACCOUNT_HAS_BOUNDED_TEST_BUDGET");
            stage="UU_MAINTENANCE_CONCURRENCY";
            using(UuAclRepair.AcquireMaintenance()){
                var blocked=await ControlPipe.Send("Connect");
                Check(blocked["ok"]?.GetValue<bool>()==false && blocked["error"]?.GetValue<string>()=="UU_MAINTENANCE_BUSY" && blocked["mode"]?.GetValue<string>()=="disconnected" && blocked["intent"]?.GetValue<bool>()==false,"REAL_CONNECT_REFUSED_DURING_ELEVATED_UU_MAINTENANCE");
            }
            stage="INITIAL_TRANSIENT_UDP_LOSS";uint initialPid;
            // The acceptance target has a fixed deployed WireGuard port. The
            // ordinary GUI IPC deliberately never exposes the tunnel profile.
            using(var loss=new InitialUdpLoss(51820)){
                var waiting=await ControlPipe.Send("Connect");
                // Same fixed, credential-free fields as the public diagnostic
                // report; never print the response object or exception message.
                foreach(string field in new[]{"mode","error","guard","tun_permitted","core_stage","core_pid","connection_stage"})Console.WriteLine("INITIAL_LOSS_"+field.ToUpperInvariant()+"="+waiting[field]);
                if(waiting["failure"] is JsonObject failure)foreach(string field in new[]{"category","hresult","native_error","socket_error","http_error","http_status"})Console.WriteLine("INITIAL_LOSS_FAILURE_"+field.ToUpperInvariant()+"="+failure[field]);
                string code=waiting["error"]?.GetValue<string>() ?? "";
                Check(waiting["mode"]?.GetValue<string>()=="protected" && waiting["guard"]?.GetValue<bool>()==true && waiting["tun_permitted"]?.GetValue<bool>()==true && waiting["core_stage"]?.GetValue<string>()=="READY" && code is "ORACLE_PROBE_TIMEOUT" or "ORACLE_PROBE_HTTP_FAILED","REAL_INITIAL_PROBE_FAILURE_RETAINS_LIVE_GUARDED_TUNNEL");
                initialPid=waiting["core_pid"]!.GetValue<uint>();Check(initialPid>0,"REAL_INITIAL_HANDSHAKE_CORE_STAYS_ALIVE");
            }
            stage="CONNECT_AFTER_TRANSIENT_LOSS";var stable=await Connected();
            Check(stable["core_pid"]?.GetValue<uint>()==initialPid,"REAL_ORACLE_HANDSHAKE_RECOVERS_WITHOUT_CORE_RESTART");
            Check((await Send("Status"))["uu_verified_programs"]?.GetValue<int>()==19,"REAL_ORACLE_CONNECTION_WITH_NINETEEN_VERIFIED_NETEASE_PATHS");
            Check(await ExitIp()=="152.67.156.100","REAL_ORDINARY_WINDOWS_HTTP_THROUGH_ORACLE_WIREGUARD_EXIT");
            // The real public GUI is an ordinary process; closing/crashing it must
            // not control the SYSTEM tunnel lifetime.
            stage="GUI_PROCESS_LOSS";using(var gui=Process.Start(new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"..","product","OracleProxy.exe")){UseShellExecute=false})!){await Task.Delay(1500);if(!gui.HasExited)gui.Kill(true);}
            Check((await Send("Status"))["mode"]?.GetValue<string>()=="connected" && await ExitIp()=="152.67.156.100","REAL_GUI_PROCESS_LOSS_KEEPS_SYSTEM_TUNNEL");
            stage="SERVICE_CRASH_RECOVERY";var service=Process.GetProcessesByName("OracleProxy.Service").Single(p=>p.SessionId==0 && p.MainModule?.FileName==Platform.Exe);
            using(service){service.Kill(true);await service.WaitForExitAsync();}
            // Recovery may finish during this probe. Any successful probe must
            // still use Oracle; a direct runner exit is always a failure.
            try{Check(await ExitIp()=="152.67.156.100","REAL_SERVICE_CRASH_PROBE_HAS_NO_DIRECT_EXIT");}
            catch(IOException){throw;}catch{Console.WriteLine("REAL_SERVICE_CRASH_PROBE_BLOCKED=PASS");}
            var recovered=await Connected();
            Check(recovered["account"]?["device_count"]?.GetValue<int>()==devices,"REAL_SCM_RECOVERY_REUSES_EXISTING_DEVICE_IDENTITY");
            Check(await ExitIp()=="152.67.156.100","REAL_SCM_RECOVERY_ORACLE_EXIT");
            stage="USAGE_LINKAGE";await Task.Delay(6000);var after=await Send("Status");
            Check(after["account"]?["used_bytes"]?.GetValue<long>()>used,"REAL_SERVER_ACCOUNT_USAGE_LINKAGE");
            stage="DISCONNECT";Check((await Send("Disconnect"))["mode"]?.GetValue<string>()=="disconnected" && await ExitIp()!="152.67.156.100","REAL_EXPLICIT_DISCONNECT_RESTORES_DIRECT_EXIT");
            await Send("Logout");Console.WriteLine("REAL_ORACLE_CLIENT_END_TO_END=PASS");return 0;
        }catch{Console.WriteLine("REAL_ORACLE_STAGE="+stage);Console.WriteLine("REAL_ORACLE_CLIENT_END_TO_END=FAIL");return 1;}
    }
}
