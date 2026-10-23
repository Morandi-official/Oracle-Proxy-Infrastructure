using System.Net.NetworkInformation;
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
        [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_all_loss_begin(out IntPtr engine);
        [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_primary_loss_begin(out IntPtr engine);
        [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_primary_reply_loss_begin(out IntPtr engine);
        internal InitialUdpLoss(bool blockQuic=false,bool primaryOnly=false,bool primaryRepliesOnly=false)
        {
            uint code=primaryRepliesOnly?fixture_udp_primary_reply_loss_begin(out _engine):primaryOnly?fixture_udp_primary_loss_begin(out _engine):blockQuic?fixture_udp_all_loss_begin(out _engine):fixture_udp_loss_begin(out _engine);
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
    private const long RunBudgetBytes=16L*1024*1024;
    private static long? _runUsageStart;
    private static string _lastAssertion="";
    private static void Check(bool condition,string code){if(!condition){_lastAssertion=code;throw new IOException("ORACLE_ASSERTION_FAILED");}Console.WriteLine(code+"=PASS");}
    private static JsonObject RequireSuccess(string command,JsonObject value)
    {
        if(value["ok"]?.GetValue<bool>()!=true){
            foreach(string field in new[]{"mode","error","intent","guard","transport","connection_stage","core_stage","core_pid","tun_permitted","quick_ready","preparing"})Console.WriteLine("FAILED_"+command.ToUpperInvariant()+"_"+field.ToUpperInvariant()+"="+value[field]);
            if(value["failure"] is JsonObject failure)foreach(string field in new[]{"stage","category","hresult","native_error","socket_error","core_stage"})Console.WriteLine("FAILED_COMMAND_"+field.ToUpperInvariant()+"="+failure[field]);
            throw new IOException("ORACLE_SERVICE_COMMAND_FAILED");
        }
        if(_runUsageStart is long start && value["account"]?["used_bytes"]?.GetValue<long>() is long used){
            if(used<start || used-start>RunBudgetBytes){_lastAssertion="REAL_ORACLE_RUN_USAGE_WITHIN_16_MIB";throw new IOException("ORACLE_ASSERTION_FAILED");}
        }
        return value;
    }
    private static async Task<JsonObject> Send(string command)=>RequireSuccess(command,await ControlPipe.Send(command));
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
        for(int i=0;i<500;i++){
            try{var state=await Send("Status");if(state["mode"]?.GetValue<string>()=="connected" && state["guard"]?.GetValue<bool>()==true && state["core_pid"]?.GetValue<uint>()>0 && state["tun_permitted"]?.GetValue<bool>()==true)return state;}catch{}
            await Task.Delay(100);
        }
        throw new IOException("ORACLE_RECONNECT_TIMED_OUT");
    }
    private static async Task<uint> ColdCore()
    {
        var state=await Send("Status");uint pid=state["core_pid"]!.GetValue<uint>();
        if(pid==0)return 0;
        using var process=Process.GetProcessById((int)pid);
        if(process.SessionId!=0 || process.MainModule?.FileName!=Platform.Core)throw new IOException("FIXTURE_CORE_IDENTITY_MISMATCH");
        process.Kill(true);await process.WaitForExitAsync();return pid;
    }
    private static int PhysicalIndex()=>NetworkInterface.GetAllNetworkInterfaces()
        .Where(n=>n.Name!="OracleProxy" && n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType!=NetworkInterfaceType.Loopback)
        .Where(n=>n.GetIPProperties().GatewayAddresses.Any(a=>a.Address.AddressFamily==AddressFamily.InterNetwork && !a.Address.Equals(IPAddress.Any)))
        .Select(n=>n.GetIPProperties().GetIPv4Properties().Index).First();
    private static async Task<bool> CarrierDirectBlocked()
    {
        using var socket=new TcpClient(AddressFamily.InterNetwork);using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(2));
        int index=PhysicalIndex();socket.Client.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(index));
        try{await socket.ConnectAsync(IPAddress.Parse("152.67.156.100"),443,timeout.Token);return false;}
        catch(SocketException error)when(error.SocketErrorCode is SocketError.AccessDenied or SocketError.TimedOut){return true;}
        catch(OperationCanceledException)when(timeout.IsCancellationRequested){return true;}
    }
    private static async Task<bool> AdminThroughVPN(){
        using var client=new HttpClient(new SocketsHttpHandler{UseProxy=false,UseCookies=false,AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(8)};
        using var response=await client.GetAsync("https://vpn-admin.morandi.dpdns.org/login/");
        return response.StatusCode==HttpStatusCode.OK && (await response.Content.ReadAsStringAsync()).Contains("csrfmiddlewaretoken",StringComparison.Ordinal);
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
            stage="LOGIN";var login=RequireSuccess("Login",await ControlPipe.Send("Login",username,password));password=null;
            Check(login["ok"]?.GetValue<bool>()==true && login["account"]?["username"]?.GetValue<string>()==username,"REAL_ORACLE_CLIENT_LOGIN_AND_AUTOMATIC_ENROLLMENT");
            var account=login["account"]!;long used=account["used_bytes"]!.GetValue<long>();int devices=account["device_count"]!.GetValue<int>();
            long? limit=account["limit_bytes"]?.GetValue<long>();
            Console.WriteLine("REAL_ACCOUNT_TEST_LIMIT_BYTES="+(limit?.ToString() ?? "unlimited"));
            Console.WriteLine("REAL_ACCOUNT_TEST_REMAINING_BYTES="+(limit is null?"unlimited":Math.Max(0,limit.Value-used).ToString()));
            Check(account["status"]?.GetValue<string>()=="active" && used>=0 && (limit is null || limit.Value-used>=4*1024*1024),"REAL_ACCOUNT_HAS_AVAILABLE_TEST_BUDGET");
            _runUsageStart=used;
            stage="UU_MAINTENANCE_CONCURRENCY";
            using(UuAclRepair.AcquireMaintenance()){
                var blocked=await ControlPipe.Send("Connect");
                Check(blocked["ok"]?.GetValue<bool>()==false && blocked["error"]?.GetValue<string>()=="UU_MAINTENANCE_BUSY" && blocked["mode"]?.GetValue<string>()=="disconnected" && blocked["intent"]?.GetValue<bool>()==false,"REAL_CONNECT_REFUSED_DURING_ELEVATED_UU_MAINTENANCE");
            }
            stage="FORCED_COLD_PROTOCOLS";
            foreach(string preference in new[]{"PreferUdp","PreferQuic"}){
                string wanted=preference=="PreferUdp"?"wireguard-udp":"wireguard-quic";
                for(int cycle=0;cycle<3;cycle++){
                    await Send("Disconnect");var selected=await Send(preference);
                    Check(selected["core_pid"]?.GetValue<uint>()==0,"REAL_SELECTION_STOPS_OLD_CORE_"+wanted+"_"+cycle);
                    using var primaryLoss=preference=="PreferUdp" && cycle==1?new InitialUdpLoss(primaryOnly:true):null;
                    using var returnLoss=preference=="PreferUdp" && cycle==2?new InitialUdpLoss(primaryRepliesOnly:true):null;
                    var timer=Stopwatch.StartNew();await Send("Connect");var cold=await Connected();long elapsed=timer.ElapsedMilliseconds;
                    Console.WriteLine("REAL_COLD_READY_MS_"+wanted+"_"+cycle+"="+elapsed);
                    Check(cold["transport"]?.GetValue<string>()==wanted && elapsed<(preference=="PreferUdp" && cycle>0?12000:6000) && await ExitIp()=="152.67.156.100" && await FreshDns(),"REAL_FORCED_COLD_PROTOCOL_HTTP_DNS_"+wanted+"_"+cycle);
                    Check(await AdminThroughVPN() && await CarrierDirectBlocked(),"REAL_ADMIN_VIA_VPN_WITH_PHYSICAL_BYPASS_BLOCKED_"+wanted+"_"+cycle);
                    var metered=await Send("Status");
                    Check(metered["verified_exit_ip"]?.GetValue<string>()=="152.67.156.100" && metered["traffic"]?["sample_ms"]?.GetValue<long>()>0 && metered["traffic"]?["rx_bytes"]?.GetValue<long>()>0 && metered["traffic"]?["tx_bytes"]?.GetValue<long>()>0,"REAL_LOCAL_TUN_UPLOAD_DOWNLOAD_COUNTERS_AND_VERIFIED_EXIT_"+wanted+"_"+cycle);
                    if(preference=="PreferUdp" && cycle==1)Check(cold["native_udp_selected_port"]?.GetValue<int>()==443,"REAL_NATIVE_WIREGUARD_UDP443_WHILE_51820_IS_BLOCKED");
                    if(preference=="PreferUdp" && cycle==2){
                        Check(cold["native_udp_selected_port"]?.GetValue<int>()==443,"REAL_NATIVE_UDP443_FRESH_HANDSHAKE_WHILE_ONLY_51820_REPLIES_ARE_DROPPED");
                        await Send("Disconnect");var portMemory=Stopwatch.StartNew();await Send("Connect");var reused=await Connected();
                        Console.WriteLine("REAL_RETURN_LOSS_CACHED_UDP443_RECONNECT_MS="+portMemory.ElapsedMilliseconds);
                        Check(reused["transport"]?.GetValue<string>()==wanted && reused["native_udp_selected_port"]?.GetValue<int>()==443 && portMemory.ElapsedMilliseconds<1500 && await ExitIp()=="152.67.156.100","REAL_CACHED_NATIVE_443_RECONNECT_WITHOUT_PRIMARY_TIMEOUT");
                        portMemory.Restart();uint oldCore=await ColdCore();var newCore=await Connected();
                        Console.WriteLine("REAL_RETURN_LOSS_CACHED_UDP443_NEW_CORE_MS="+portMemory.ElapsedMilliseconds);
                        Check(newCore["core_pid"]?.GetValue<uint>()!=oldCore && newCore["native_udp_selected_port"]?.GetValue<int>()==443 && newCore["transport"]?.GetValue<string>()==wanted && portMemory.ElapsedMilliseconds<4500 && await ExitIp()=="152.67.156.100","REAL_NEW_CORE_STARTS_WITH_VERIFIED_NATIVE_PORT_MEMORY");
                    }
                    if(preference=="PreferQuic"){
                        Check(cold["carrier_stage"]?.GetValue<string>()=="CARRIER_H3_READY","REAL_STANDARD_HTTP3_AUTHENTICATED_"+cycle);
                        timer.Restart();uint prior=await ColdCore();var restored=await Connected();
                        Check(restored["core_pid"]?.GetValue<uint>()!=prior && restored["transport"]?.GetValue<string>()==wanted && timer.ElapsedMilliseconds<8000 && await ExitIp()=="152.67.156.100","REAL_HTTP3_HARD_CORE_LOSS_REPLACEMENT_WITHOUT_HTTPS_"+cycle);
                    }
                }
            }
            await Send("Disconnect");await Send("PreferAuto");
            stage="INITIAL_TRANSIENT_UDP_LOSS";uint initialPid;
            // The acceptance target has a fixed deployed WireGuard port. The
            // ordinary GUI IPC deliberately never exposes the tunnel profile.
            stage="WARM_PREPARATION";
            await Send("Prepare");JsonObject prepared=new();
            for(int attempt=0;attempt<60;attempt++){
                prepared=await Send("Prepare");if(prepared["quick_ready"]?.GetValue<bool>()==true)break;
                await Task.Delay(500);
            }
            Check(prepared["quick_ready"]?.GetValue<bool>()==true && prepared["guard"]?.GetValue<bool>()==false && prepared["tun_permitted"]?.GetValue<bool>()==false && VpnRuntime.TunnelInactive() && NativeGuard.TunDormant && await ExitIp()!="152.67.156.100","REAL_PREPARATION_HAS_DORMANT_TUN_WITHOUT_ADDRESSES_ROUTES_SESSION_OR_ORDINARY_APP_PROXY");
            Check(prepared["transport"]?.GetValue<string>()=="wireguard-udp" && prepared["native_udp_attempt"]?["endpoint_port"]?.GetValue<int>()==51820 && prepared["native_udp_attempt"]?["socket_binding"]?.GetValue<string>()=="native_udp_dual_port" && prepared["native_udp_attempt"]?["started_without_tun"]?.GetValue<bool>()==true && prepared["native_udp_attempt"]?["probe_result"]?.GetValue<string>()=="oracle_egress_verified","REAL_NATIVE_UDP_51820_PREPARATION_VERIFIED_BEFORE_TUN");
            if(Environment.GetEnvironmentVariable("ORACLE_REQUIRE_QUIC")=="true")Check(prepared["quic_available"]?.GetValue<bool>()==true,"REAL_QUIC_RELEASE_CONFIGURATION_AND_SERVER_METADATA_IN_SYNC");
            var warmPid=prepared["core_pid"]!.GetValue<uint>();var click=Stopwatch.StartNew();
            var quick=await Send("Connect");long clickMs=click.ElapsedMilliseconds;
            Console.WriteLine("REAL_WARM_CONNECT_CLICK_MS="+clickMs);
            foreach(string phase in new[]{"uu_discovery_ms","state_saved_ms","guard_installed_ms","tun_active_ms","complete_ms"})Console.WriteLine("REAL_WARM_"+phase.ToUpperInvariant()+"="+quick["switch_timings"]?[phase]);
            Check(quick["mode"]?.GetValue<string>()=="connected" && quick["core_pid"]?.GetValue<uint>()==warmPid && quick["guard"]?.GetValue<bool>()==true && quick["tun_permitted"]?.GetValue<bool>()==true && await ExitIp()=="152.67.156.100" && await FreshDns(),"REAL_PREPARED_CORE_SWITCH_AND_FRESH_WINDOWS_HTTP_UDP_DNS");
            Check(clickMs<1000,"REAL_WARM_CLICK_TO_GUARDED_PROXY_UNDER_ONE_SECOND");
            await Send("Disconnect");
            using(var loss=new InitialUdpLoss()){
                await ColdCore();
                var waiting=await ControlPipe.Send("Connect");
                // Same fixed, credential-free fields as the public diagnostic
                // report; never print the response object or exception message.
                foreach(string field in new[]{"mode","error","guard","tun_permitted","core_stage","core_pid","connection_stage"})Console.WriteLine("INITIAL_LOSS_"+field.ToUpperInvariant()+"="+waiting[field]);
                if(waiting["failure"] is JsonObject failure)foreach(string field in new[]{"category","hresult","native_error","socket_error","http_error","http_status"})Console.WriteLine("INITIAL_LOSS_FAILURE_"+field.ToUpperInvariant()+"="+failure[field]);
                for(int attempt=0;attempt<12 && waiting["error"]?.GetValue<string>() is not ("ORACLE_PROBE_TIMEOUT" or "ORACLE_PROBE_HTTP_FAILED");attempt++){await Task.Delay(500);waiting=await Send("Status");}
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
            stage="AUTOMATIC_QUIC_FALLBACK";await Send("Disconnect");
            if(prepared["quic_available"]?.GetValue<bool>()==true){
                using(var nativeLoss=new InitialUdpLoss()){
                    uint previousPid=await ColdCore();JsonObject replacement=new();
                    // Deliberately let the background actor replace the dead
                    // prepared core before Connect. Its old successful probe
                    // must not authorize the new blocked-UDP generation.
                    for(int attempt=0;attempt<20;attempt++){
                        replacement=await Send("Prepare");
                        if(replacement["core_pid"]?.GetValue<uint>() is >0 && replacement["core_pid"]!.GetValue<uint>()!=previousPid)break;
                        await Task.Delay(200);
                    }
                    Check(previousPid>0 && replacement["core_pid"]?.GetValue<uint>() is >0 && replacement["quick_ready"]?.GetValue<bool>()==false && replacement["verified_at"] is null && replacement["transport"]?.GetValue<string>()=="wireguard-udp","REAL_REPLACEMENT_CORE_CANNOT_INHERIT_OLD_EXIT_VERIFICATION");
                    await Send("Connect");var quic=await Connected();
                    Check(quic["transport"]?.GetValue<string>()=="wireguard-quic" && await ExitIp()=="152.67.156.100" && await FreshDns(),"REAL_NATIVE_UDP_LOSS_SELECTS_QUIC_BEFORE_HTTPS_WITH_HTTP_AND_UDP_DNS");
                    Check(quic["native_udp_attempt"]?["endpoint_port"]?.GetValue<int>()==51820 && quic["native_udp_attempt"]?["probe_failures"]?.GetValue<int>()>=2 && quic["native_udp_attempt"]?["probe_result"]?.GetValue<string>() is "egress_probe_timeout" or "egress_probe_http_failed","REAL_QUIC_DIAGNOSTICS_RETAIN_NATIVE_UDP_FAILURE_EVIDENCE");
                    Check(await CarrierDirectBlocked() && await AdminThroughVPN(),"REAL_QUIC_ADMIN_THROUGH_VPN_AND_PHYSICAL_DIRECT_BLOCKED");
                    uint quicPid=quic["core_pid"]!.GetValue<uint>();
                    for(int cycle=0;cycle<3;cycle++){
                        var off=await Send("Disconnect");
                        Check(off["quick_ready"]?.GetValue<bool>()==true && off["core_pid"]?.GetValue<uint>()==quicPid && VpnRuntime.TunnelInactive() && await ExitIp()!="152.67.156.100","REAL_QUIC_OFF_PRESERVES_PREPARED_CORE_AND_RESTORES_DIRECT_"+cycle);
                        var restart=Stopwatch.StartNew();var fast=await Send("Connect");long elapsed=restart.ElapsedMilliseconds;
                        Console.WriteLine("REAL_BLOCKED_UDP_QUIC_RECONNECT_CLICK_MS_"+cycle+"="+elapsed);
                        foreach(string phase in new[]{"uu_discovery_ms","state_saved_ms","guard_installed_ms","tun_active_ms","complete_ms"})Console.WriteLine("REAL_QUIC_RECONNECT_"+cycle+"_"+phase.ToUpperInvariant()+"="+fast["switch_timings"]?[phase]);
                        Check(elapsed<1000 && fast["click_to_ready_ms"]?.GetValue<long>() is >=0 and <1000 && fast["mode"]?.GetValue<string>()=="connected" && fast["core_pid"]?.GetValue<uint>()==quicPid && fast["transport"]?.GetValue<string>()=="wireguard-quic" && await ExitIp()=="152.67.156.100" && await FreshDns(),"REAL_BLOCKED_UDP_REPEATED_QUIC_RECONNECT_UNDER_ONE_SECOND_"+cycle);
                    }
                    await Send("Disconnect");
                    await ColdCore();var learned=await Send("Connect");
                    Check(learned["transport"]?.GetValue<string>()=="wireguard-quic","REAL_SAME_NETWORK_REMEMBERS_FAILED_UDP_AFTER_CORE_LOSS");
                    await Connected();await Send("Disconnect");
                }
            }else Console.WriteLine("REAL_QUIC_CARRIER=SERVER_NOT_ADVERTISED_YET");
            stage="AUTOMATIC_HTTPS_FALLBACK";await Send("Disconnect");
            using(var loss=new InitialUdpLoss(blockQuic:true)){
                await ColdCore();
                var pending=await ControlPipe.Send("Connect");
                Check(pending["mode"]?.GetValue<string>()=="protected" && pending["guard"]?.GetValue<bool>()==true,"REAL_UDP_LOSS_STARTS_WITH_PROTECTED_NATIVE_ATTEMPT");
                var carrier=await Connected();
                Check(carrier["transport"]?.GetValue<string>()=="wireguard-https" && await ExitIp()=="152.67.156.100","REAL_AUTOMATIC_HTTPS_WIREGUARD_ORACLE_EXIT_WITH_NATIVE_UDP_BLOCKED");
                Check(await FreshDns(),"REAL_HTTPS_WIREGUARD_FRESH_UDP_DNS");
                Check(await CarrierDirectBlocked() && await AdminThroughVPN(),"REAL_HTTPS_ADMIN_THROUGH_VPN_AND_PHYSICAL_DIRECT_BLOCKED");
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
        }catch(Exception error){try{await ControlPipe.Send("Disconnect");}catch{}Console.WriteLine("REAL_ORACLE_STAGE="+stage);if(_lastAssertion.Length>0)Console.WriteLine("REAL_ORACLE_ASSERTION="+_lastAssertion);Console.WriteLine("REAL_ORACLE_ERROR_TYPE="+error.GetType().Name);if(error.Message is "INCOMPLETE_FRAME" or "SERVICE_IDENTITY_NOT_VERIFIED" or "INVALID_SERVICE_RESPONSE" or "FRAME_TOO_LARGE" or "ORACLE_SERVICE_COMMAND_FAILED")Console.WriteLine("REAL_ORACLE_FIXED_ERROR="+error.Message);Console.WriteLine("REAL_ORACLE_HRESULT="+error.HResult.ToString("X8"));if(error is Win32Exception native)Console.WriteLine("REAL_ORACLE_NATIVE_ERROR="+native.NativeErrorCode);Console.WriteLine("REAL_ORACLE_CLIENT_END_TO_END=FAIL");return 1;}
    }
}
