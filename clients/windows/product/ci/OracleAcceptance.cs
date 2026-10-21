// Non-shipped integration fixture. Uses only the dedicated low-quota client
// account from the windows-client-acceptance Environment, never SSH/OAuth keys.
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using OracleProxy.Product;

internal static class OracleAcceptance
{
    // Disposable hosted fault only; this is never compiled into the product.
    private sealed class InitialUdpLoss : IDisposable
    {
        private IntPtr _engine;
        [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_loss_begin(out IntPtr engine);
        [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_loss_end(IntPtr engine);
        internal InitialUdpLoss()
        {
            uint code=fixture_udp_loss_begin(out _engine);
            if(code!=0){Console.WriteLine("INITIAL_UDP_NATIVE_ERROR="+code);throw new Win32Exception((int)code);}
        }
        public void Dispose()
        {
            if(_engine==IntPtr.Zero)return;
            uint code=fixture_udp_loss_end(_engine);_engine=IntPtr.Zero;
            if(code!=0)throw new Win32Exception((int)code);
        }
    }
    internal static int VerifyUdpFaultSession()
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted" || !Platform.IsAdmin)return 3;
        using(var loss=new InitialUdpLoss())Check(true,"REAL_DISPOSABLE_PACKET_LAYER_UDP_FAULT_SESSION");
        return 0;
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
    private static async Task<bool> CarrierDirectBlocked()
    {
        using var socket=new TcpClient();using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try{await socket.ConnectAsync(IPAddress.Parse("152.67.156.100"),443,timeout.Token);return false;}catch{return true;}
    }
    private static async Task<bool> FreshDns()
    {
        byte[] id=System.Security.Cryptography.RandomNumberGenerator.GetBytes(2);
        var query=new List<byte>{id[0],id[1],1,0,0,1,0,0,0,0,0,0};
        foreach(string part in ("opx-"+Guid.NewGuid().ToString("N")+".example.com").Split('.')){query.Add((byte)part.Length);query.AddRange(System.Text.Encoding.ASCII.GetBytes(part));}
        query.AddRange(new byte[]{0,0,1,0,1});
        using var udp=new UdpClient();udp.Connect("1.1.1.1",53);
        await udp.SendAsync(query.ToArray());using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var reply=(await udp.ReceiveAsync(timeout.Token)).Buffer;
        return reply.Length>=12 && reply[0]==id[0] && reply[1]==id[1] && (reply[2]&128)!=0 && (reply[3]&15) is 0 or 3;
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
            using(var loss=new InitialUdpLoss()){
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
            stage="AUTOMATIC_HTTPS_FALLBACK";await Send("Disconnect");
            using(var loss=new InitialUdpLoss()){
                var pending=await ControlPipe.Send("Connect");
                Check(pending["mode"]?.GetValue<string>()=="protected" && pending["guard"]?.GetValue<bool>()==true,"REAL_UDP_LOSS_STARTS_WITH_PROTECTED_NATIVE_ATTEMPT");
                var carrier=await Connected();
                Check(carrier["transport"]?.GetValue<string>()=="wireguard-https" && await ExitIp()=="152.67.156.100","REAL_AUTOMATIC_HTTPS_WIREGUARD_ORACLE_EXIT_WITH_NATIVE_UDP_BLOCKED");
                Check(await FreshDns(),"REAL_HTTPS_WIREGUARD_FRESH_UDP_DNS");
                Check(await CarrierDirectBlocked(),"REAL_ORDINARY_APP_CANNOT_USE_CARRIER_ROUTE_AS_DIRECT_ESCAPE");
                stage="HTTPS_SERVICE_CRASH_RECOVERY";
                using(var carrierService=Process.GetProcessesByName("OracleProxy.Service").Single(p=>p.SessionId==0 && p.MainModule?.FileName==Platform.Exe)){
                    carrierService.Kill(true);await carrierService.WaitForExitAsync();
                }
                try{Check(await ExitIp()=="152.67.156.100","REAL_HTTPS_SERVICE_CRASH_NO_DIRECT_EXIT");}catch(IOException){throw;}catch{Console.WriteLine("REAL_HTTPS_SERVICE_CRASH_PROBE_BLOCKED=PASS");}
                var restored=await Connected();
                Check(restored["transport"]?.GetValue<string>()=="wireguard-https" && restored["account"]?["device_count"]?.GetValue<int>()==devices && await ExitIp()=="152.67.156.100","REAL_SCM_HTTPS_FALLBACK_RECOVERY_SAME_DEVICE_WHILE_NATIVE_UDP_REMAINS_BLOCKED");
            }
            stage="USAGE_LINKAGE";await Task.Delay(6000);var after=await Send("Status");
            Check(after["account"]?["used_bytes"]?.GetValue<long>()>used,"REAL_SERVER_ACCOUNT_USAGE_LINKAGE");
            stage="DISCONNECT";Check((await Send("Disconnect"))["mode"]?.GetValue<string>()=="disconnected" && await ExitIp()!="152.67.156.100","REAL_EXPLICIT_DISCONNECT_RESTORES_DIRECT_EXIT");
            await Send("Logout");Console.WriteLine("REAL_ORACLE_CLIENT_END_TO_END=PASS");return 0;
        }catch{Console.WriteLine("REAL_ORACLE_STAGE="+stage);Console.WriteLine("REAL_ORACLE_CLIENT_END_TO_END=FAIL");return 1;}
    }
}
