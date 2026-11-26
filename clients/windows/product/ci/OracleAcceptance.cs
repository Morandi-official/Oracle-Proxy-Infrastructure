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
        [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_old_ingress_loss_begin(out IntPtr engine);
        [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_443_only_loss_begin(out IntPtr engine);
        [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_8443_only_loss_begin(out IntPtr engine);
        internal InitialUdpLoss(bool blockQuic=false,bool primaryOnly=false,bool primaryRepliesOnly=false,bool oldIngressOnly=false,bool native443Only=false,bool native8443Only=false)
        {
            uint code=native443Only?fixture_udp_443_only_loss_begin(out _engine):native8443Only?fixture_udp_8443_only_loss_begin(out _engine):oldIngressOnly?fixture_udp_old_ingress_loss_begin(out _engine):primaryRepliesOnly?fixture_udp_primary_reply_loss_begin(out _engine):primaryOnly?fixture_udp_primary_loss_begin(out _engine):blockQuic?fixture_udp_all_loss_begin(out _engine):fixture_udp_loss_begin(out _engine);
            if(code!=0){Console.WriteLine("INITIAL_UDP_NATIVE_ERROR="+code);throw new Win32Exception((int)code);}
        }
        public void Dispose()
        {
            if(_engine==IntPtr.Zero)return;
            long begin=Stopwatch.GetTimestamp();
            Console.WriteLine("INITIAL_UDP_LOSS_DISPOSE_BEGIN_TICKS="+begin);
            uint code=fixture_udp_loss_end(_engine);_engine=IntPtr.Zero;
            long end=Stopwatch.GetTimestamp();
            Console.WriteLine("INITIAL_UDP_LOSS_DISPOSE_END_TICKS="+end);
            Console.WriteLine("INITIAL_UDP_LOSS_DISPOSE_ELAPSED_MS="+(long)Stopwatch.GetElapsedTime(begin,end).TotalMilliseconds);
            Console.WriteLine("INITIAL_UDP_LOSS_DISPOSE_NATIVE_ERROR="+code);
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
    [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_diagnostic_primary_replies_begin(out IntPtr engine);
    [DllImport("OracleProxy.Fault.dll",CallingConvention=CallingConvention.Cdecl)]private static extern uint fixture_udp_loss_end(IntPtr engine);
    private static async Task<JsonObject> AwaitDiagnostic()
    {
        var timer=Stopwatch.StartNew();
        while(timer.Elapsed<TimeSpan.FromSeconds(175)){
            var state=await Send("Status");
            Check(state["mode"]?.GetValue<string>()=="disconnected" && state["guard"]?.GetValue<bool>()==false && state["intent"]?.GetValue<bool>()==false,"DIAGNOSTIC_REMAINS_DISCONNECTED_WITHOUT_BASELINE_GUARD");
            if(state["udp_diagnostic"] is JsonObject report && report["running"]?.GetValue<bool>()==false)return state;
            await Task.Delay(800);
        }
        throw new IOException("DIAGNOSTIC_ACCEPTANCE_DEADLINE");
    }
    private static async Task<JsonObject> AwaitAccount(Func<bool>? afterRefresh=null)
    {
        var timer=Stopwatch.StartNew();
        while(timer.Elapsed<TimeSpan.FromSeconds(20)){
            var state=await Send("Status");
            if(state["login_authenticated"]?.GetValue<bool>()==true && state["account"] is JsonObject &&
                (afterRefresh is null || afterRefresh()))return state;
            await Task.Delay(250);
        }
        throw new IOException("REMEMBERED_ACCOUNT_REFRESH_DEADLINE");
    }

    private static async Task VerifyDiagnostics(int devices,bool extended=true)
    {
        await Send("Disconnect");await StoppedService();await Send("AttachClient");
        var before=await AwaitAccount();
        var start=Stopwatch.StartNew();await Send("StartUdpDiagnostics");
        Check(start.Elapsed<TimeSpan.FromSeconds(8),"DIAGNOSTIC_START_DOES_NOT_HOLD_RUNTIME_GATE_FOR_PROBES");
        var result=await AwaitDiagnostic();var report=result["udp_diagnostic"]!.AsObject();
        Check(report["phase"]?.GetValue<string>()=="complete" && report["server_capture_closed"]?.GetValue<bool>()==true,"REAL_DIAGNOSTIC_COMPLETES_AND_CLOSES_SERVER_CAPTURE");
        int expected=(before["account"]?["ingress"]?["access"]?.GetValue<string>() is "primary" or "backup")?3:6;
        var rows=report["trials"]!.AsArray();
        Check(rows.Count==expected && rows.All(r=>r?["verdict"]?.GetValue<string>()=="PASSED" && r?["server"]?["capture"]?["rx_initiations"]?.GetValue<long>()>0 && r?["server"]?["capture"]?["tx_responses"]?.GetValue<long>()>0),"REAL_AUTHORIZED_UDP_EGRESS_AND_PAIRED_SERVER_HEADERS");
        foreach(string field in new[]{"transport_preference","native_udp_adaptive","native_udp_port_preference"})Check(JsonNode.DeepEquals(before[field],result[field]),"DIAGNOSTIC_PRESERVES_"+field.ToUpperInvariant());
        Check(result["account"]?["device_count"]?.GetValue<int>()==devices,"DIAGNOSTIC_USES_EXISTING_DEVICE_SLOT");
        Directory.CreateDirectory("dist/review");File.WriteAllText("dist/review/udp-six-acceptance.json",report.ToJsonString());
        if(!extended){await Send("Disconnect");await StoppedService();await Send("AttachClient");return;}
        IntPtr fault=IntPtr.Zero;
        try{
            Check(fixture_udp_diagnostic_primary_replies_begin(out fault)==0,"DIAGNOSTIC_DISPOSABLE_PRIMARY_RETURN_FAULT_CREATED");
            await Send("StartUdpDiagnostics");result=await AwaitDiagnostic();report=result["udp_diagnostic"]!.AsObject();
            rows=report["trials"]!.AsArray();
            Check(report["phase"]?.GetValue<string>()=="complete" && rows.Count==expected && rows.Take(3).All(r=>r?["verdict"]?.GetValue<string>()=="RETURN_OR_LOCAL_RECEIVE_PATH") && rows.Skip(3).All(r=>r?["verdict"]?.GetValue<string>()=="PASSED"),"REAL_DIAGNOSTIC_IDENTIFIES_REPLY_LOSS_WITHOUT_BLAMING_SERVER_OR_OTHER_ENTRANCES");
            File.WriteAllText("dist/review/udp-six-return-fault.json",report.ToJsonString());
        }finally{if(fault!=IntPtr.Zero)Check(fixture_udp_loss_end(fault)==0,"DIAGNOSTIC_DISPOSABLE_RETURN_FAULT_REMOVED");}
        await Send("StartUdpDiagnostics");await Task.Delay(1000);await Send("CancelUdpDiagnostics");
        result=await AwaitDiagnostic();report=result["udp_diagnostic"]!.AsObject();
        Check(report["phase"]?.GetValue<string>()=="cancelled" && report["server_capture_closed"]?.GetValue<bool>()==true,"REAL_DIAGNOSTIC_CANCEL_CLOSES_CORE_AND_SERVER_CAPTURE");
        await Send("Disconnect");await StoppedService();await Send("AttachClient");
    }
    private static long? _deviceUsageStart;
    private static string _lastAssertion="";
    private static void Check(bool condition,string code){if(!condition){_lastAssertion=code;throw new IOException("ORACLE_ASSERTION_FAILED");}Console.WriteLine(code+"=PASS");}
    private static JsonObject RequireSuccess(string command,JsonObject value)
    {
        if(value["ok"]?.GetValue<bool>()!=true){
            foreach(string field in new[]{"mode","error","intent","guard","transport","connection_stage","core_stage","core_pid","tun_permitted","quick_ready","preparing"})Console.WriteLine("FAILED_"+command.ToUpperInvariant()+"_"+field.ToUpperInvariant()+"="+value[field]);
            if(value["failure"] is JsonObject failure)foreach(string field in new[]{"stage","category","hresult","native_error","socket_error","core_stage"})Console.WriteLine("FAILED_COMMAND_"+field.ToUpperInvariant()+"="+failure[field]);
            throw new IOException("ORACLE_SERVICE_COMMAND_FAILED");
        }
        if(_deviceUsageStart is long start && !WithinDeviceBudget(value,start)){
            _lastAssertion="REAL_DEVICE_RUN_USAGE_WITHIN_16_MIB";throw new IOException("ORACLE_ASSERTION_FAILED");
        }
        return value;
    }
    internal static bool WithinDeviceBudget(JsonObject value,long start)
    {
        try{
            long rx=value["peer_rx_bytes"]?.GetValue<long>()??-1,tx=value["peer_tx_bytes"]?.GetValue<long>()??-1;
            return start>=0 && rx>=0 && tx>=0 && rx<=long.MaxValue-tx && rx+tx>=start && rx+tx-start<=RunBudgetBytes;
        }catch(InvalidOperationException){return false;}
    }
    internal static bool CanCloseDeviceBudget(JsonObject value,long start)=>WithinDeviceBudget(value,start) && value["mode"]?.GetValue<string>()=="disconnected" && value["intent"]?.GetValue<bool>()==false && value["core_pid"]?.GetValue<uint>()==0;
    internal static void VerifyDeviceBudgetFixture()
    {
        var state=new JsonObject{["peer_rx_bytes"]=40L,["peer_tx_bytes"]=60L,["account"]=new JsonObject{["used_bytes"]=1_000_000_000L}};
        Check(WithinDeviceBudget(state,100),"CI_BUDGET_IGNORES_OTHER_DEVICES_ACCOUNT_USAGE");
        state["peer_tx_bytes"]=RunBudgetBytes+101;
        Check(!WithinDeviceBudget(state,100),"CI_BUDGET_REFUSES_THIS_DEVICE_OVER_16_MIB");
        Check(!WithinDeviceBudget(new JsonObject(),0),"CI_BUDGET_REFUSES_MISSING_DEVICE_COUNTERS");
        state["peer_rx_bytes"]=0L;state["peer_tx_bytes"]=0L;
        Check(!WithinDeviceBudget(state,100),"CI_BUDGET_REFUSES_COUNTER_REGRESSION");
        state["peer_rx_bytes"]=40L;state["peer_tx_bytes"]=60L;state["mode"]="disconnected";state["intent"]=false;state["core_pid"]=0u;
        Check(CanCloseDeviceBudget(state,100),"CI_BUDGET_CLOSES_WITH_STOPPED_CORE_AND_VALID_FINAL_COUNTERS");
        state["core_pid"]=1u;
        Check(!CanCloseDeviceBudget(state,100),"CI_BUDGET_CANNOT_CLOSE_WHILE_CORE_EXISTS");
        state["core_pid"]=0u;state["intent"]=true;
        Check(!CanCloseDeviceBudget(state,100),"CI_BUDGET_CANNOT_CLOSE_WHILE_CONNECTION_INTENT_EXISTS");
    }
    private static async Task<JsonObject> Send(string command)
    {
        var timer=Stopwatch.StartNew();var result=RequireSuccess(command,await ControlPipe.Send(command));
        if(command is "Connect" or "Disconnect"){
            Console.WriteLine("REAL_CONTROL_"+command.ToUpperInvariant()+"_ROUNDTRIP_MS="+timer.ElapsedMilliseconds);
            if(result["disconnect_timings"] is JsonObject timings && command=="Disconnect")
                foreach(string phase in new[]{"core_stopped_ms","tunnel_audited_ms","state_saved_ms","complete_ms"})Console.WriteLine("REAL_DISCONNECT_"+phase.ToUpperInvariant()+"="+timings[phase]);
        }
        return result;
    }
    private static async Task<string> ExitIp()
    {
        using var client=new HttpClient(new SocketsHttpHandler{UseProxy=false,UseCookies=false,AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(10)};
        string value=await client.GetStringAsync("https://1.1.1.1/cdn-cgi/trace");
        string? ip=value.Split('\n').FirstOrDefault(v=>v.StartsWith("ip="))?[3..];
        if(value.Length>8192 || !IPAddress.TryParse(ip,out _))throw new IOException("EXIT_PROBE_FAILED");
        return ip;
    }
    private static async Task<bool> DualStackExit()
    {
        using var client=new HttpClient(new SocketsHttpHandler{UseProxy=false,UseCookies=false,AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(10)};
        string trace=await client.GetStringAsync("https://[2606:4700:4700::1111]/cdn-cgi/trace");
        return trace.Length<8192 && trace.Split('\n').Any(line=>line=="ip=2603:c020:c015:8100::10");
    }
    private static async Task<bool> Ipv6Stun()
    {
        var addresses=await Dns.GetHostAddressesAsync("stun.cloudflare.com");
        var target=addresses.First(address=>address.AddressFamily==AddressFamily.InterNetworkV6);
        using var socket=new UdpClient(AddressFamily.InterNetworkV6);
        socket.Connect(target,3478);
        byte[] transaction=System.Security.Cryptography.RandomNumberGenerator.GetBytes(12);
        byte[] message=new byte[20];message[1]=1;message[4]=0x21;message[5]=0x12;message[6]=0xa4;message[7]=0x42;transaction.CopyTo(message,8);
        await socket.SendAsync(message);
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(6));
        byte[] response=(await socket.ReceiveAsync(timeout.Token)).Buffer;
        if(response.Length<20 || response[0]!=1 || response[1]!=1 || !response.AsSpan(4,16).SequenceEqual(message.AsSpan(4,16)))return false;
        int end=20+(response[2]<<8|response[3]);if(end>response.Length)return false;
        for(int offset=20;offset+4<=end;){
            int type=response[offset]<<8|response[offset+1],length=response[offset+2]<<8|response[offset+3];offset+=4;
            if(offset+length>end)return false;
            if(type==0x20 && length==20 && response[offset+1]==2){
                byte[] mapped=new byte[16];for(int i=0;i<16;i++)mapped[i]=(byte)(response[offset+4+i]^message[4+i]);
                return new IPAddress(mapped).ToString()=="2603:c020:c015:8100::10";
            }
            offset+=(length+3)&~3;
        }
        return false;
    }
    private static async Task<bool> NoUnexpectedIpv6Exit()
    {
        try{return await DualStackExit();}
        catch(Exception error) when(error is HttpRequestException or TaskCanceledException or IOException){return true;}
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
    private static IPv4InterfaceProperties PhysicalIPv4()=>NetworkInterface.GetAllNetworkInterfaces()
        .Where(n=>n.Name!="OracleProxy" && n.OperationalStatus==OperationalStatus.Up && n.NetworkInterfaceType!=NetworkInterfaceType.Loopback)
        .Where(n=>n.Supports(NetworkInterfaceComponent.IPv4))
        .Where(n=>n.GetIPProperties().GatewayAddresses.Any(a=>a.Address.AddressFamily==AddressFamily.InterNetwork && !a.Address.Equals(IPAddress.Any)))
        .Select(n=>n.GetIPProperties().GetIPv4Properties()).First()
        ?? throw new IOException("DISPOSABLE_PHYSICAL_IPV4_PROPERTIES_REQUIRED");
    private static int PhysicalIndex()=>PhysicalIPv4().Index;
    private static int TunnelIndex()=>NetworkInterface.GetAllNetworkInterfaces()
        .Single(n=>n.Name=="OracleProxy" && n.OperationalStatus==OperationalStatus.Up).GetIPProperties().GetIPv4Properties().Index;
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
    private static async Task<bool> FreshDns(int padding=0)
    {
        byte[] id=System.Security.Cryptography.RandomNumberGenerator.GetBytes(2);
        var query=new List<byte>{id[0],id[1],1,0,0,1,0,0,0,0,0,(byte)(padding>0?1:0)};
        foreach(string part in ("opx-"+Guid.NewGuid().ToString("N")+".example.com").Split('.')){query.Add((byte)part.Length);query.AddRange(System.Text.Encoding.ASCII.GetBytes(part));}
        query.AddRange(new byte[]{0,0,1,0,1});
        if(padding>0){int length=padding+4;query.AddRange(new byte[]{0,0,41,16,0,0,0,0,0,(byte)(length>>8),(byte)length,0,12,(byte)(padding>>8),(byte)padding});query.AddRange(new byte[padding]);}
        // Quad9's alternate DNS port bypasses the product's port-53 DNS hijack,
        // so the padded datagram itself must traverse the WireGuard data path.
        using var udp=new UdpClient();udp.Connect(padding>0?"9.9.9.9":"1.1.1.1",padding>0?9953:53);
        await udp.SendAsync(query.ToArray());using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var reply=(await udp.ReceiveAsync(timeout.Token)).Buffer;
        return reply.Length>=12 && reply[0]==id[0] && reply[1]==id[1] && (reply[2]&128)!=0 && (padding>0 || (reply[3]&15) is 0 or 3);
    }
    private sealed class PhysicalMtuFixture : IDisposable
    {
        private readonly int _index,_original;
        private static void Set(int index,int mtu){
            using var process=Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"netsh.exe")){
                UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,
                ArgumentList={"interface","ipv4","set","subinterface",index.ToString(),"mtu="+mtu,"store=active"}})!;
            process.BeginOutputReadLine();process.BeginErrorReadLine();
            if(!process.WaitForExit(10000)||process.ExitCode!=0)throw new IOException("DISPOSABLE_PHYSICAL_MTU_CHANGE_FAILED");
        }
        internal PhysicalMtuFixture(){
            if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted" || !Platform.IsAdmin)throw new IOException("DISPOSABLE_ADMIN_REQUIRED");
            // Only query the selected IPv4-capable gateway interface. Asking
            // an unrelated IPv6-only interface for IPv4 properties can throw.
            var physical=PhysicalIPv4();_index=physical.Index;_original=physical.Mtu;
            try{Set(_index,1280);}catch{Set(_index,_original);throw;}
        }
        public void Dispose()=>Set(_index,_original);
    }
    private static async Task SampleDownload(string path,OracleNetworkPerformance.TransferWindow? window=null)
    {
        bool complete=false;
        try{
            const int limit=2*1024*1024;
            using var handler=new SocketsHttpHandler{UseProxy=false,UseCookies=false,AllowAutoRedirect=false};
            using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(12)};
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(12));
            var stopwatch=Stopwatch.StartNew();
            using var response=await client.GetAsync("https://speed.cloudflare.com/__down?bytes="+limit,HttpCompletionOption.ResponseHeadersRead,timeout.Token);
            response.EnsureSuccessStatusCode();
            await using var stream=await response.Content.ReadAsStreamAsync(timeout.Token);
            byte[] buffer=new byte[32768];int total=0,read;
            while((read=await stream.ReadAsync(buffer.AsMemory(0,Math.Min(buffer.Length,limit+1-total)),timeout.Token))>0){
                window?.Progress();total+=read;if(total>limit)break;
            }
            if(total!=limit)throw new IOException("THROUGHPUT_SAMPLE_SIZE_MISMATCH");
            complete=true;
            Console.WriteLine("WINDOWS_DOWNLOAD_"+path+"_BYTES="+total+";ELAPSED_MS="+stopwatch.ElapsedMilliseconds);
        }catch(Exception error)when(error is HttpRequestException or IOException or OperationCanceledException){
            Console.WriteLine("WINDOWS_DOWNLOAD_"+path+"=UNAVAILABLE");
        }finally{window?.Finish(complete);}
    }
    private static async Task MeasureNetwork(OracleNetworkPerformance.Target[] targets,IReadOnlySet<string> allowedExits,
        bool tunneled,uint expectedCore=0,OracleNetworkPerformance.TransferOrigin? origin=null)
    {
        bool PathMatches(JsonObject state)=>state["mode"]?.GetValue<string>()==(tunneled?"connected":"disconnected") &&
            state["intent"]?.GetValue<bool>()==tunneled && state["guard"]?.GetValue<bool>()==tunneled &&
            state["tun_permitted"]?.GetValue<bool>()==tunneled && (!tunneled || expectedCore>0 &&
                state["core_pid"]?.GetValue<uint>()==expectedCore && state["transport"]?.GetValue<string>()=="wireguard-udp" &&
                state["tun_route_mask"]?.GetValue<uint>()==15 &&
                state["verified_exit_ip"]?.GetValue<string>() is string exit && allowedExits.Contains(exit));
        string route=tunneled?"WIREGUARD_UDP":"DIRECT";
        Check(PathMatches(await Send("Status")),"REAL_NETWORK_RTT_"+route+"_STATE_BEFORE");
        int index=tunneled?TunnelIndex():PhysicalIndex();
        await OracleNetworkPerformance.Measure(targets,allowedExits,tunneled,index);
        // Reuse the existing bounded download so loaded sampling costs only
        // small STUN packets rather than another bulk transfer.
        var window=new OracleNetworkPerformance.TransferWindow();
        await Task.WhenAll(SampleDownload(route,window),OracleNetworkPerformance.Measure(targets,allowedExits,tunneled,index,window));
        if(tunneled)await OracleNetworkPerformance.MeasureTransfers(targets,allowedExits,index,
            origin??throw new InvalidOperationException("TUNNELED_TRANSFER_ORIGIN_REQUIRED"),tunneled:true);
        Check(PathMatches(await Send("Status")),"REAL_NETWORK_RTT_"+route+"_STATE_AFTER");
    }

    private static async Task MeasureDirectTransferAfterDisconnect(OracleNetworkPerformance.Target[] targets,
        IReadOnlySet<string> allowedExits,string directExit,OracleNetworkPerformance.TransferOrigin origin)
    {
        await Send("Disconnect");await StoppedService();
        Check(await ExitIp()==directExit,"REAL_PERF_DISCONNECT_RESTORES_PHYSICAL_EXIT");
        if(origin.Address is null)return;
        try{
            await OracleNetworkPerformance.MeasureTransfers(targets,allowedExits,PhysicalIndex(),origin,tunneled:false);
        }catch(Exception error)when(error is HttpRequestException or IOException or OperationCanceledException or SocketException){
            Console.WriteLine("WINDOWS_PERF_DIRECT_TRANSFER_CONTROL_UNAVAILABLE="+error.GetType().Name);
        }
    }
    // Failure evidence from the existing attested session only. Both account
    // data and peer counters are the service's most recent server observation.
    private static async Task ReportNetworkFailure(JsonObject before)
    {
        try{
            var state=await ControlPipe.Send("Status").WaitAsync(TimeSpan.FromSeconds(3));
            if(state["ok"]?.GetValue<bool>()!=true)return;
            var account=state["account"];
            bool sameCore=before["core_pid"]?.GetValue<uint>() is uint core && core!=0 && state["core_pid"]?.GetValue<uint>()==core;
            bool? Advanced(string field)=>sameCore && before[field]?.GetValue<long>() is long start &&
                state[field]?.GetValue<long>() is long end && end>=start?end>start:null;
            long now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long? handshake=state["server_handshake_at"]?.GetValue<long>();
            Console.WriteLine("WINDOWS_PERF_FAILURE_STATUS="+System.Text.Json.JsonSerializer.Serialize(new{
                same_core=sameCore,tunnel_verified=state["mode"]?.GetValue<string>()=="connected" && state["guard"]?.GetValue<bool>()==true,
                observed_account_active=account?["status"]?.GetValue<string>() is string status?(bool?)(status=="active"):null,
                observed_quota_exhausted=account?["limit_bytes"]?.GetValue<long>() is long limit &&
                    account?["used_bytes"]?.GetValue<long>() is long used?(bool?)(used>=limit):null,
                observed_handshake_within_180s=handshake is long at?(bool?)(at>0 && at<=now && now-at<=180):null,
                observed_rx_advanced=Advanced("peer_rx_bytes"),observed_tx_advanced=Advanced("peer_tx_bytes"),
            }));
        }catch(Exception){Console.WriteLine("WINDOWS_PERF_FAILURE_STATUS_UNAVAILABLE=true");}
    }
    private static async Task BulkDownload()
    {
        using var client=new HttpClient(new SocketsHttpHandler{UseProxy=false,UseCookies=false}){Timeout=TimeSpan.FromSeconds(20)};
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var response=await client.GetAsync("https://speed.cloudflare.com/__down?bytes=524288",HttpCompletionOption.ResponseHeadersRead,timeout.Token);
        response.EnsureSuccessStatusCode();await using var stream=await response.Content.ReadAsStreamAsync();
        byte[] buffer=new byte[32768];int read,total=0;
        while((read=await stream.ReadAsync(buffer,timeout.Token))>0){total+=read;if(total>524288)throw new IOException("BULK_RESPONSE_LIMIT_EXCEEDED");}
        Check(total==524288,"REAL_LOW_MTU_BULK_DOWNLOAD_512_KIB");
    }
    private static void SafeNativeState(JsonObject state,string prefix="STABILITY")
    {
        foreach(string key in new[]{"mode","error","transport","connection_stage","carrier_stage","core_stage","core_pid","tun_permitted","guard","intent","quick_ready","verified_at"})Console.WriteLine(prefix+"_"+key.ToUpperInvariant()+"="+state[key]);
        if(state["native_udp_attempt"] is JsonObject attempt){
            foreach(string key in new[]{"endpoint_port","preferred_port","selected_port","started_at","started_without_tun","inner_mtu","probe_result","probe_failures","core_age_ms","verified_after_start_ms"})Console.WriteLine(prefix+"_NATIVE_"+key.ToUpperInvariant()+"="+attempt[key]);
            foreach(string number in new[]{"51820","443","8443"})
                if(attempt["ports"]?[number] is JsonObject port)
                    foreach(string key in new[]{"tx_initiations","rx_responses","rx_cookies","rx_invalid","rx_obsolete","read_errors","write_errors","last_read_error","last_write_error"})Console.WriteLine(prefix+"_PORT_"+number+"_"+key.ToUpperInvariant()+"="+port[key]);
        }

    }
    private static void RequireStableNative(JsonObject state,uint pid)
    {
        var counters=state["native_udp_attempt"]?["ports"]?["8443"];
        Check(state["mode"]?.GetValue<string>()=="connected" && state["transport"]?.GetValue<string>()=="wireguard-udp" && state["native_udp_selected_port"]?.GetValue<int>()==8443 && state["core_pid"]?.GetValue<uint>()==pid && (counters?["write_errors"]?.GetValue<int>()??0)==0 && (counters?["read_errors"]?.GetValue<int>()??0)==0 && (counters?["rx_obsolete"]?.GetValue<int>()??0)==0,"REAL_LOW_MTU_NATIVE_STAYS_ON_SAME_CORE_WITHOUT_MESSAGE_SIZE_ERROR_OR_FALLBACK");
    }
    private static async Task<bool> DatagramRoundTrip(uint pid)
    {
        for(int attempt=0;attempt<2;attempt++){
            try{if(await FreshDns(64))return true;}catch(Exception error)when(error is SocketException or OperationCanceledException){}
            // Oracle direct controls also lose padded large public DNS requests.
            // Use a small real UDP control here; bulk HTTPS exercises the MTU,
            // and deterministic socket tests cover oversized writes and rebinds.
            // UDP is best-effort. Retry one datagram only while the actual
            // tunnel, process and error counters are still demonstrably healthy.
            var state=await Send("Status");SafeNativeState(state);RequireStableNative(state,pid);
            Console.WriteLine("UDP9953_BOUNDED_RETRY="+(attempt+1));
        }
        return false;
    }
    private static async Task StableNative8443(JsonObject initial)
    {
        uint pid=initial["core_pid"]!.GetValue<uint>();
        using(var mtu=new PhysicalMtuFixture()){
            var timer=Stopwatch.StartNew();int round=0;
            do{
                if(round%4==0)await BulkDownload();
                Console.WriteLine("LOW_MTU_PHASE=HTTPS_EXIT");Check(await ExitIp()=="152.67.156.100","REAL_LOW_MTU_HTTPS_EXIT");
                Check(await DualStackExit(),"REAL_LOW_MTU_IPV6_HTTPS_ORACLE_EGRESS");
                Check(await Ipv6Stun(),"REAL_LOW_MTU_IPV6_UDP_STUN_PUBLIC_IP_IS_ORACLE");
                Console.WriteLine("LOW_MTU_PHASE=NORMAL_DNS");Check(await FreshDns(),"REAL_LOW_MTU_NORMAL_DNS");
                Console.WriteLine("LOW_MTU_PHASE=UDP9953");Check(await DatagramRoundTrip(pid),"REAL_LOW_MTU_NON_HIJACKED_UDP9953_DATAGRAM_RESPONSE");
                var state=await Send("Status");RequireStableNative(state,pid);
                round++;await Task.Delay(10000);
            }while(timer.Elapsed<TimeSpan.FromSeconds(120));
            Console.WriteLine("REAL_NATIVE_8443_LOW_MTU_STABLE_MS="+timer.ElapsedMilliseconds);
        }
        Check(await ExitIp()=="152.67.156.100","REAL_PHYSICAL_MTU_RESTORED_AFTER_SUSTAINED_NATIVE_TEST");
    }
    [StructLayout(LayoutKind.Sequential)]private struct FailureActions { public uint Reset;public IntPtr Reboot,Command;public uint Count;public IntPtr Actions; }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool QueryServiceConfig2(IntPtr service,uint level,IntPtr buffer,uint length,out uint needed);
    [DllImport("advapi32.dll")]private static extern bool CloseServiceHandle(IntPtr handle);
    private static void RecoveryPolicy()
    {
        IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception();
        IntPtr service=IntPtr.Zero,buffer=IntPtr.Zero;
        try{
            service=OpenService(manager,Platform.Service,1);if(service==IntPtr.Zero)throw new Win32Exception();
            QueryServiceConfig2(service,2,IntPtr.Zero,0,out uint needed);
            if(needed<40 || needed>4096)throw new IOException("SCM_RECOVERY_QUERY_SIZE_INVALID");
            buffer=Marshal.AllocHGlobal((int)needed);
            if(!QueryServiceConfig2(service,2,buffer,needed,out _))throw new Win32Exception();
            var actions=Marshal.PtrToStructure<FailureActions>(buffer);
            Check(actions.Reset==300 && actions.Count==3 && actions.Actions!=IntPtr.Zero &&
                Enumerable.Range(0,3).All(i=>Marshal.ReadInt32(actions.Actions,i*8)==1 && Marshal.ReadInt32(actions.Actions,i*8+4)==new[]{3000,5000,10000}[i]),"REAL_SCM_RESTART_BACKOFF_3_5_10_SECONDS_WITH_FIVE_MINUTE_RESET");
        }finally{if(buffer!=IntPtr.Zero)Marshal.FreeHGlobal(buffer);if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
    }
    internal static async Task<int> LifetimeController()
    {
        try{
            string line=await Console.In.ReadLineAsync()??throw new IOException();
            var credentials=JsonNode.Parse(line)!;
            await Send("AttachClient");
            var timer=Stopwatch.StartNew();
            var login=RequireSuccess("Login",await ControlPipe.Send("Login",credentials["username"]!.GetValue<string>(),credentials["password"]!.GetValue<string>()));credentials=null;
            if(login["login_authenticated"]?.GetValue<bool>()==true && login["device_registered"]?.GetValue<bool>()==true)
                Console.WriteLine("WINDOWS_PERF_LOGIN_FIRST_DEVICE_SERVICE_MS="+timer.ElapsedMilliseconds);
            await Send("PreferUdp443");timer.Restart();await Send("Connect");var connected=await Connected();
            if(connected["verified_exit_ip"]?.GetValue<string>() is string ipv4 &&
                login["network_endpoints"]?["egress_ipv4"] is JsonArray exits && exits.Any(exit=>exit?.GetValue<string>()==ipv4) &&
                connected["verified_exit_ipv6"]?.GetValue<string>()=="2603:c020:c015:8100::10")
                Console.WriteLine("WINDOWS_PERF_CONNECT_FIRST_DEVICE_SERVICE_MS="+timer.ElapsedMilliseconds);
            Console.WriteLine("CONTROLLER_CONNECTED");Console.Out.Flush();
            await Task.Delay(Timeout.Infinite);return 0;
        }catch{return 1;}
    }
    private static Task StoppedService()=>ControlPipe.WaitStopped(CancellationToken.None);
    private static async Task CrashController(string username,string password)
    {
        var start=new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        start.ArgumentList.Add("--lifetime-controller");
        start.Environment.Remove("ORACLE_CLIENT_ACCEPTANCE_USERNAME");start.Environment.Remove("ORACLE_CLIENT_ACCEPTANCE_PASSWORD");
        using var controller=Process.Start(start)??throw new IOException("CONTROLLER_NOT_STARTED");
        try{
            await controller.StandardInput.WriteLineAsync(new JsonObject{["username"]=username,["password"]=password}.ToJsonString());await controller.StandardInput.FlushAsync();
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(80));bool connected=false;
            while(await controller.StandardOutput.ReadLineAsync(deadline.Token) is string line){
                if(line=="CONTROLLER_CONNECTED"){connected=true;break;}
                foreach(string metric in new[]{"WINDOWS_PERF_LOGIN_FIRST_DEVICE_SERVICE_MS=","WINDOWS_PERF_CONNECT_FIRST_DEVICE_SERVICE_MS="})
                    if(line.StartsWith(metric,StringComparison.Ordinal) && long.TryParse(line.AsSpan(metric.Length),out long duration) && duration>=0)
                        Console.WriteLine(metric+duration);
            }
            Check(connected,"LIFETIME_REAL_CONTROLLER_CONNECTED");
            controller.Kill(true);await controller.WaitForExitAsync();await StoppedService();
            Check(!VpnRuntime.TunnelInactive() ? false : await ExitIp()!="152.67.154.225","LIFETIME_CONTROLLER_CRASH_STOPS_BACKGROUND_AND_RESTORES_DIRECT");
        }finally{if(!controller.HasExited){controller.Kill(true);await controller.WaitForExitAsync();}}
    }
    internal static async Task<int> CheckParkedGui()
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
        using var service=new System.ServiceProcess.ServiceController(Platform.Service);
        if(service.Status!=System.ServiceProcess.ServiceControllerStatus.Running){
            Console.WriteLine("ACTUAL_PARK_WITNESS_SERVICE_NOT_RUNNING=True");return 1;
        }
        var state=RequireSuccess("Status",await ControlPipe.Send("Status"));
        foreach(string field in new[]{"mode","error","core_stage","adapter_parked","adapter_preparing","park_error","park_stage"}){
            string? value=state[field]?.ToString();
            if(value is {Length:>0 and <=80} && value.All(c=>char.IsAsciiLetterOrDigit(c) || c=='_'))
                Console.WriteLine("ACTUAL_PARK_WITNESS_"+field.ToUpperInvariant()+"="+value);
        }
        if(state["adapter_parked"]?.GetValue<bool>()!=true || state["mode"]?.GetValue<string>()!="disconnected" ||
            state["intent"]?.GetValue<bool>()!=false || state["guard"]?.GetValue<bool>()!=false ||
            state["tun_permitted"]?.GetValue<bool>()!=false || state["tun_route_mask"]?.GetValue<uint>()!=0 ||
            state["client_handshake_reply"]?.GetValue<bool>()!=false || state["preparing"]?.GetValue<bool>()!=false ||
            state["quick_ready"]?.GetValue<bool>()!=false || state["verified_exit_ip"] is not null || state["verified_exit_ipv6"] is not null ||
            state["transport_port"] is not null || state["core_pid"]?.GetValue<uint>() is not uint holder || holder==0 ||
            state["network_endpoints"]?["egress_ipv4"] is not JsonArray allowed || allowed.Count==0)return 1;
        using var process=Process.GetProcessById(checked((int)holder));
        if(process.SessionId!=0 || !string.Equals(process.MainModule?.FileName,Platform.Core,StringComparison.OrdinalIgnoreCase))return 1;
        string direct=await ExitIp();
        if(direct!=Environment.GetEnvironmentVariable("ORACLE_CI_DIRECT_EXIT") || allowed.Any(ip=>ip?.GetValue<string>()==direct))return 1;
        Console.WriteLine("ACTUAL_PARKED_HOLDER_PID="+holder);
        Console.WriteLine("ACTUAL_GUI_OFF_DIRECT_EGRESS_AND_NO_PEER=PASS");
        return 0;
    }
    internal static async Task<int> PrintLiveTimings()
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
        var state=RequireSuccess("Status",await ControlPipe.Send("Status"));
        if(state["mode"]?.GetValue<string>()!="connected" || state["intent"]?.GetValue<bool>()!=true ||
            state["guard"]?.GetValue<bool>()!=true || state["tun_permitted"]?.GetValue<bool>()!=true ||
            state["tun_route_mask"]?.GetValue<uint>()!=15 || state["client_handshake_reply"]?.GetValue<bool>()!=true ||
            state["verified_exit_ip"]?.GetValue<string>() is not string exit || state["network_endpoints"]?["egress_ipv4"] is not JsonArray allowed ||
            !allowed.Any(ip=>ip?.GetValue<string>()==exit) || state["verified_exit_ipv6"]?.GetValue<string>()!="2603:c020:c015:8100::10" ||
            state["core_pid"]?.GetValue<uint>() is not uint pid || pid==0)return 1;
        Console.WriteLine("ACTUAL_CONNECTED_HOLDER_PID="+pid);
        Console.WriteLine("ACTUAL_SERVICE_WORKER_MINIMUM="+state["service_worker_minimum"]);
        Console.WriteLine("ACTUAL_SERVICE_WORKER_THREADS="+state["service_worker_threads"]);
        Console.WriteLine("ACTUAL_SERVICE_EGRESS_PROBE_PROTOCOL="+state["egress_probe_protocol"]);
        if(state["core_start_timings"] is JsonObject coreTimings)foreach(string key in new[]{"bundle_ms","process_ms","private_probe_ready_ms","adapter_create_begin_ms","adapter_pnp_begin_ms","adapter_ready_ms","receipt_ms","adapter_create_ms","adapter_audit_ms","empty_audited"})
            if(coreTimings[key] is JsonValue timing && timing.TryGetValue<long>(out long elapsed))Console.WriteLine("ACTUAL_SERVICE_CORE_"+key.ToUpperInvariant()+"="+elapsed);
        Console.WriteLine("ACTUAL_SERVICE_RECENT_ACCOUNT_PROOF_RESTORED="+(state["recent_account_proof_restored"]?.GetValue<bool>()==true));
        foreach(string key in new[]{"click_to_ready_ms","connect_switch_ms"})if(state[key] is JsonValue value && value.TryGetValue<long>(out long ms))Console.WriteLine("ACTUAL_SERVICE_"+key.ToUpperInvariant()+"="+ms);
        foreach(string key in new[]{"adapter_preparing_at_click","adapter_parked_at_click"}){
            if(state["switch_timings"]?[key] is JsonValue value && value.TryGetValue<bool>(out bool flag))
                Console.WriteLine("ACTUAL_SERVICE_"+key.ToUpperInvariant()+"="+flag);
        }
        if(state["switch_timings"] is JsonObject phases)foreach(string key in new[]{"uu_discovery_ms","state_saved_ms","guard_installed_ms","core_process_ms","protection_joined_ms","core_active_and_authorized_ms","initial_probe_ms","complete_ms"})
            if(phases[key] is JsonValue value && value.TryGetValue<long>(out long ms))Console.WriteLine("ACTUAL_SERVICE_"+key.ToUpperInvariant()+"="+ms);
        return 0;
    }
    private static async Task<bool> LiveGuiUdpToggle(string directExit,bool closeConnectedOnly=false)
    {
        string script=Path.GetFullPath("clients/windows/product/ci/test-live-udp-toggle.ps1");
        string client=Path.GetFullPath("dist/product/Proxy.exe");
        if(!File.Exists(script) || !File.Exists(client))throw new IOException("LIVE_GUI_FIXTURE_UNAVAILABLE");
        var start=new ProcessStartInfo("powershell.exe"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(string value in new[]{"-NoProfile","-STA","-ExecutionPolicy","Bypass","-File",script,"-Client",client,"-SnapshotReader",Environment.ProcessPath!})start.ArgumentList.Add(value);
        start.Environment.Remove("ORACLE_CLIENT_ACCEPTANCE_USERNAME");start.Environment.Remove("ORACLE_CLIENT_ACCEPTANCE_PASSWORD");
        if(closeConnectedOnly)start.ArgumentList.Add("-CloseConnectedOnly");
        start.Environment["ORACLE_CI_DIRECT_EXIT"]=directExit;
        using var process=Process.Start(start)??throw new IOException("LIVE_GUI_FIXTURE_START_FAILED");
        var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
        try{
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromMinutes(3));
            string evidence=await output;await error;
            if(evidence.Length>16384)throw new IOException("LIVE_GUI_EVIDENCE_TOO_LARGE");
            var lines=evidence.Split('\n',StringSplitOptions.TrimEntries);
            foreach(string line in lines)if(line.StartsWith("ACTUAL_",StringComparison.Ordinal))Console.WriteLine(line);
            bool slow=!closeConnectedOnly && process.ExitCode==17 &&
                lines.Contains("ACTUAL_PRODUCT_GUI_CLOSED_WITHOUT_SERVICE_HOLDER_OR_ADAPTER=PASS") &&
                lines.Contains("ACTUAL_PROXY_GUI_VERIFIED_CONNECT_TARGET_MISSED=true");
            Check(process.ExitCode==0 || slow,"REAL_PRODUCT_GUI_UDP_ON_OFF_AND_SHUTDOWN");
            Check(await ExitIp()==directExit,"REAL_GUI_CLOSE_RESTORES_VERIFIED_PHYSICAL_EXIT");
            return !slow;
        }finally{
            if(!process.HasExited){process.Kill(true);await process.WaitForExitAsync();}
        }
    }
    internal static bool IngressCatalogMatchesPolicy(JsonObject login,JsonObject expected)
    {
        try{
            string? access=login["account"]?["ingress"]?["access"]?.GetValue<string>(),preferred=login["account"]?["ingress"]?["preferred"]?.GetValue<string>();
            if(access is not ("primary" or "backup" or "both") || preferred is not ("primary" or "backup") || access!="both" && access!=preferred)return false;
            string[] roles=access=="both"?[preferred,preferred=="primary"?"backup":"primary"]:[access];
            string Address(string role)=>expected[role]!["public_ipv4"]!.GetValue<string>();
            string Private(string role)=>expected[role]!["private_ipv4"]!.GetValue<string>();
            if(login["network_endpoints"] is not JsonObject catalog || catalog["primary"]?.GetValue<string>()!=Address(roles[0]) ||
                catalog["schema"]?.GetValue<int>()!=(roles.Length==2?1:2) ||
                (roles.Length==1?catalog["backup"] is not null:catalog["backup"]?.GetValue<string>()!=Address(roles[1])))return false;
            if(catalog["private_ipv4"] is not JsonObject addresses || addresses.Count!=roles.Length || roles.Any(role=>addresses[Address(role)]?.GetValue<string>()!=Private(role)))return false;
            return catalog["egress_ipv4"] is JsonArray exits && exits.Select(value=>value?.GetValue<string>()).SequenceEqual(roles.Select(Address));
        }catch(Exception error) when(error is InvalidOperationException or FormatException){return false;}
    }

    private static async Task<int> RunEndpointMigration()
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
        string? username=Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_USERNAME"),password=Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD");
        if(string.IsNullOrWhiteSpace(username)||string.IsNullOrEmpty(password))return 2;
        string? ownedCiDevice=null;
        string phase="CLIENT_ADMISSION";
        try{
            await CrashController(username,password);
            await Send("AttachClient");
            var loginTimer=Stopwatch.StartNew();
            var login=RequireSuccess("Login",await ControlPipe.Send("Login",username,password));password=null;
            long loginMs=loginTimer.ElapsedMilliseconds;
            Check(login["device_registered"]?.GetValue<bool>()==true,"MIGRATION_DEVICE_ADMISSION");
            Console.WriteLine("WINDOWS_PERF_LOGIN_REGISTERED_AFTER_RESTART_SERVICE_MS="+loginMs);
            ownedCiDevice=login["registration"]!["device_id"]!.GetValue<string>();
            Console.WriteLine("CI_OWNED_DEVICE_FINGERPRINT="+ownedCiDevice);
            // Exact identities observed in failed main runs 43574325984,
            // 43575513345, 44271623029 and 45759719017. Never
            // delete by account-wide, name-prefix or age-based heuristics.
            foreach(string priorFailedCi in new[]{"82cd151654c7","d8a1b9adf004","b0eb3ba5c647","7880b679ca14"}){
                if(priorFailedCi!=ownedCiDevice && login["devices"] is JsonArray devicesBefore && devicesBefore.Any(d=>d?["id"]?.GetValue<string>()==priorFailedCi && d?["current"]?.GetValue<bool>()==false)){
                    login=RequireSuccess("DeleteDevice",await ControlPipe.Send("DeleteDevice",priorFailedCi));
                    Check(login["devices"] is JsonArray remaining && remaining.All(d=>d?["id"]?.GetValue<string>()!=priorFailedCi),"PRIOR_EXACT_FAILED_CI_DEVICE_RETIRED");
                }
            }
            string primary=login["network_endpoints"]!["primary"]!.GetValue<string>();
            Console.WriteLine("MIGRATION_SCOPED_INGRESS_POLICY="+login["account"]?["ingress"]?["access"]?.GetValue<string>()+"/"+login["account"]?["ingress"]?["preferred"]?.GetValue<string>()+";DEFAULT="+primary);
            var expectedEndpoints=JsonNode.Parse(File.ReadAllText("ops/network/endpoints.json"))!.AsObject();
            Check(IngressCatalogMatchesPolicy(login,expectedEndpoints),"MIGRATION_AUTHENTICATED_ACCOUNT_SCOPED_ENDPOINT_CATALOG");
            int devices=login["account"]!["device_count"]!.GetValue<int>();
            var allowed=login["network_endpoints"]!["egress_ipv4"]!.AsArray().Select(x=>x!.GetValue<string>()).ToHashSet();
            phase="DIRECT_EXIT";
            string directExit=await ExitIp();
            Check(!allowed.Contains(directExit),"REAL_PHYSICAL_EXIT_BEFORE_GUI_TEST");
            phase="CONNECT";
            await Send("PreferUdp443");await Send("Connect");var connected=await Connected();
            using var runningUu=Process.GetProcessById(int.Parse(Environment.GetEnvironmentVariable("ORACLE_CI_RUNNING_UU_PID")!));
            Check(!runningUu.HasExited && connected["uu_candidates"]?.GetValue<int>()>0 &&
                connected["uu_rejected"]?.GetValue<int>()>0 && connected["uu_verified_programs"]?.GetValue<int>()==0 &&
                connected["guard"]?.GetValue<bool>()==true && connected["tun_permitted"]?.GetValue<bool>()==true,
                "REAL_FIRST_CONNECT_WITH_RUNNING_UNVERIFIED_UU_AND_NO_DIRECT_EXCEPTION");
            Check(connected["transport_address"]?.GetValue<string>()==primary && connected["transport_port"]?.GetValue<int>()==443 && connected["transport_private_address"]?.GetValue<string>()==login["network_endpoints"]!["private_ipv4"]![primary]!.GetValue<string>() && allowed.Contains(await ExitIp()),"MIGRATION_NORMAL_CONNECT_ACTUAL_PRIMARY_PRIVATE_AND_PORT_WITH_VERIFIED_EXIT");
            // Connection admission already requires the IPv6 exit probe as well.
            Check(connected["verified_exit_ipv6"]?.GetValue<string>()=="2603:c020:c015:8100::10","MIGRATION_IPV6_EXIT");
            Check(connected["tun_route_mask"]?.GetValue<uint>()==15,"ORDINARY_ROUTE_BOTH_IPV4_AND_IPV6_HALVES_USE_OWNED_TUN");
            Check(connected["observed_at"]?.GetValue<long>()>0 && connected["account"]?["used_bytes"]?.GetValue<long>()>=0,
                "REAL_AUTHENTICATED_USAGE_AND_SERVER_OBSERVATION_AVAILABLE_TO_UI");
            phase="GUI_TOGGLE";
            // Start the first visible click with a freshly launched GUI and no
            // previously retained holder. Allow only its ordinary startup work.
            await Send("Disconnect");
            await StoppedService();
            Check(NetworkInterface.GetAllNetworkInterfaces().All(n=>n.Name!="OracleProxy" &&
                (!Guid.TryParse(n.Id,out var id) || id!=Guid.Parse(TunReceipt.AdapterGuid))) && await ExitIp()==directExit,
                "REAL_GUI_COLD_LAUNCH_WITHOUT_PREVIOUS_ADAPTER");
            bool guiConnectWithinTarget=await LiveGuiUdpToggle(directExit);
            // X intentionally clears a non-remembered login. Reauthenticate the
            // same durable key; never allocate a second CI device for GUI timing.
            phase="ACCOUNT_AND_DIAGNOSTICS";
            await Send("AttachClient");
            loginTimer.Restart();
            var resumed=RequireSuccess("Login",await ControlPipe.Send("Login",username,Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD")));
            loginMs=loginTimer.ElapsedMilliseconds;
            Check(resumed["registration"]?["device_id"]?.GetValue<string>()==login["registration"]?["device_id"]?.GetValue<string>() && resumed["account"]?["device_count"]?.GetValue<int>()==devices,"LIVE_GUI_TIMING_REUSES_EXISTING_CI_DEVICE_IDENTITY");
            Console.WriteLine("WINDOWS_PERF_LOGIN_REGISTERED_AFTER_GUI_QUIT_SERVICE_MS="+loginMs);
            await Send("Connect");await Connected();
            var off=await Send("Disconnect");await StoppedService();
            Check(off["core_pid"]?.GetValue<uint>()==0 && off["preparing"]?.GetValue<bool>()==false && await ExitIp()!=primary,"DISCONNECT_STOPS_CORE_AND_SERVICE_AND_RESTORES_DIRECT");
            await Send("AttachClient");
            Check((await Send("Status"))["login_authenticated"]?.GetValue<bool>()==true,"LIVE_GUI_NONREMEMBERED_LOGIN_SURVIVES_ON_DEMAND_SERVICE_RESTART");
            await Send("Connect");await Connected();await Send("Disconnect");await StoppedService();
            await Send("AttachClient");await VerifyDiagnostics(devices,extended:false);
            var remembered=RequireSuccess("LoginRemembered",await ControlPipe.Send("LoginRemembered",username,Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD")));
            Check(remembered["login_remembered_until"]?.GetValue<long>()>DateTimeOffset.UtcNow.ToUnixTimeSeconds(),"COLD_LOGIN_PROOF_SAVED");
            await Send("Connect");await Connected();
            await LiveGuiUdpToggle(directExit,closeConnectedOnly:true);
            Platform.VerifyProtected(Platform.StateRoot);
            string cache=Path.Combine(Platform.StateRoot,"api-addresses.json");
            const string staleCache="""["152.67.154.225","150.230.113.158"]""";
            Platform.WriteAtomic(cache,System.Text.Encoding.ASCII.GetBytes(staleCache));
            loginTimer.Restart();
            await Send("AttachClient");
            // A local recent-account snapshot can render first. The rewritten
            // address cache proves a fresh authenticated request also completed.
            var restored=await AwaitAccount(()=>File.ReadAllText(cache)!=staleCache);
            loginMs=loginTimer.ElapsedMilliseconds;
            Check(restored["registration"]?["device_id"]?.GetValue<string>()==ownedCiDevice &&
                restored["account"]?["device_count"]?.GetValue<int>()==devices &&
                restored["network_endpoints"]?["primary"]?.GetValue<string>()==primary,
                "REAL_COLD_START_RESTORES_REMEMBERED_LOGIN_FROM_PRE_MIGRATION_IP_CACHE");
            Console.WriteLine("WINDOWS_PERF_REMEMBERED_FRESH_REFRESH_AFTER_COLD_START_MS="+loginMs);

            // Exercise the actual first GUI click and exit before opening the
            // throughput origin. Keep both direct and tunneled baselines together,
            // with fresh authenticated route/exit checks on this new connection.
            Check(await ExitIp()==directExit,"REAL_PERF_STARTS_ON_VERIFIED_PHYSICAL_EXIT");
            IPAddress? performanceTarget=await OraclePerformance.ResolveTarget();
            var networkTargets=await OracleNetworkPerformance.ResolveTargets();
            phase="DIRECT_NETWORK";
            await OraclePerformance.MeasureHttps(performanceTarget,allowed,tunneled:false);
            await MeasureNetwork(networkTargets,allowed,tunneled:false);
            phase="PERFORMANCE_RECONNECT";
            await Send("PreferUdp443");await Send("Connect");
            connected=await Connected();
            Check(connected["transport"]?.GetValue<string>()=="wireguard-udp" &&
                connected["transport_address"]?.GetValue<string>()==primary && connected["transport_port"]?.GetValue<int>()==443 &&
                connected["transport_private_address"]?.GetValue<string>()==login["network_endpoints"]!["private_ipv4"]![primary]!.GetValue<string>() &&
                connected["guard"]?.GetValue<bool>()==true && connected["tun_permitted"]?.GetValue<bool>()==true &&
                connected["tun_route_mask"]?.GetValue<uint>()==15 && allowed.Contains(await ExitIp()) &&
                connected["verified_exit_ipv6"]?.GetValue<string>()=="2603:c020:c015:8100::10","REAL_PERFORMANCE_RECONNECT_VERIFIES_REQUESTED_ROUTE_AND_DUAL_STACK_EXIT");
            phase="TUNNELED_NETWORK";
            await OraclePerformance.MeasureHttps(performanceTarget,allowed,tunneled:true);
            var meterStart=await Send("Status");
            var transferOrigin=new OracleNetworkPerformance.TransferOrigin();
            try{await MeasureNetwork(networkTargets,allowed,tunneled:true,connected["core_pid"]!.GetValue<uint>(),transferOrigin);}
            catch{
                string failedAssertion=_lastAssertion;
                await ReportNetworkFailure(meterStart);
                try{await MeasureDirectTransferAfterDisconnect(networkTargets,allowed,directExit,transferOrigin);}
                catch(Exception error){Console.WriteLine("WINDOWS_PERF_FAILED_RUN_DIRECT_CONTROL_UNAVAILABLE="+error.GetType().Name);}
                finally{_lastAssertion=failedAssertion;}
                throw;
            }
            phase="BROWSER";
            await BrowserRouteAcceptance.Run(allowed,"2603:c020:c015:8100::10");
            var meterEnd=await Send("Status");
            uint core=meterStart["core_pid"]?.GetValue<uint>()??0;
            var first=meterStart["traffic"];var last=meterEnd["traffic"];
            Check(core>0 && meterEnd["core_pid"]?.GetValue<uint>()==core && meterStart["mode"]?.GetValue<string>()=="connected" &&
                meterEnd["mode"]?.GetValue<string>()=="connected" && first?["sample_ms"]?.GetValue<long>() is long start && start>=0 &&
                last?["sample_ms"]?.GetValue<long>()>start && first["rx_bytes"]?.GetValue<long>() is long rx && rx>=0 &&
                first["tx_bytes"]?.GetValue<long>() is long tx && tx>=0 && last?["rx_bytes"]?.GetValue<long>()>rx && last?["tx_bytes"]?.GetValue<long>()>tx,
                "REAL_LOCAL_TUN_COUNTERS_ADVANCE_IN_BOTH_DIRECTIONS_DURING_BROWSER_TRAFFIC");
            await MeasureDirectTransferAfterDisconnect(networkTargets,allowed,directExit,transferOrigin);
            await Send("AttachClient");
            phase="DEVICE_RETIREMENT";
            var deleted=RequireSuccess("DeleteDevice",await ControlPipe.Send("DeleteDevice",login["registration"]!["device_id"]!.GetValue<string>()));
            Check(deleted["login_authenticated"]?.GetValue<bool>()==false && deleted["account"] is null && deleted["core_pid"]?.GetValue<uint>()==0 && deleted["intent"]?.GetValue<bool>()==false,"MIGRATION_DEVICE_SELF_DELETE_CLEARS_LOGIN_AND_RETIRES_ONLY_THIS_CI_SLOT");
            ownedCiDevice=null;
            phase="GUI_TIMING";
            Check(guiConnectWithinTarget,"REAL_GUI_VERIFIED_CONNECT_EACH_UNDER_1000_MS");
            Console.WriteLine("REAL_ORACLE_CLIENT_END_TO_END=PASS");return 0;
        }catch(Exception error){
            Console.WriteLine("MIGRATION_FAILURE_PHASE="+phase);
            Console.WriteLine("MIGRATION_ERROR_TYPE="+error.GetType().Name);
            Console.WriteLine("MIGRATION_ASSERTION="+_lastAssertion);
            // Reattach only after the all-off service has finished stopping.
            try{await Send("Disconnect");await StoppedService();}
            catch(Exception stopError){Console.WriteLine("MIGRATION_FAILURE_STOP_TYPE="+stopError.GetType().Name);}
            return 1;
        }
        finally{
            if(ownedCiDevice is not null){
                string retirementPhase="ATTACH";
                try{
                    await Send("AttachClient");
                    retirementPhase="AUTHENTICATE";
                    var cleanupLogin=RequireSuccess("Login",await ControlPipe.Send("Login",username,Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD")));
                    retirementPhase="MATCH_IDENTITY";
                    if(cleanupLogin["registration"]?["device_id"]?.GetValue<string>()!=ownedCiDevice)throw new IOException("CI_CLEANUP_DEVICE_IDENTITY_CHANGED");
                    retirementPhase="DELETE";
                    var retired=await ControlPipe.Send("DeleteDevice",ownedCiDevice).WaitAsync(TimeSpan.FromSeconds(15));
                    Console.WriteLine("FAILED_RUN_OWN_CI_DEVICE_RETIREMENT="+(retired["ok"]?.GetValue<bool>()==true && retired["login_authenticated"]?.GetValue<bool>()==false?"PASS":"UNCONFIRMED"));
                }catch(Exception error){
                    Console.WriteLine($"FAILED_RUN_OWN_CI_DEVICE_RETIREMENT_PHASE={retirementPhase};TYPE={error.GetType().Name}");
                    Console.WriteLine("FAILED_RUN_OWN_CI_DEVICE_RETIREMENT=UNCONFIRMED");
                }
            }
        }
    }
    internal static async Task<int> Run()
    {
        if(Environment.GetEnvironmentVariable("ORACLE_ACCEPTANCE_SCOPE")=="endpoint-migration")return await RunEndpointMigration();
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
        string? username=Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_USERNAME"),password=Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD");
        if(string.IsNullOrWhiteSpace(username)||string.IsNullOrEmpty(password)){Console.WriteLine("ORACLE_ACCEPTANCE_CREDENTIALS_MISSING");return 2;}
        string deviceName=Environment.MachineName;
        if(!System.Text.RegularExpressions.Regex.IsMatch(deviceName,@"\A[A-Za-z0-9_.-]{1,64}\z"))return 3;
        Console.WriteLine("REAL_DISPOSABLE_DEVICE_NAME="+deviceName);
        string stage="BASELINE";
        try{
            VerifyDeviceBudgetFixture();RecoveryPolicy();
            Check(await ExitIp()!="152.67.156.100","REAL_RUNNER_DIRECT_BASELINE");
            stage="LOGIN";var login=RequireSuccess("Login",await ControlPipe.Send("Login",username,password));
            Check(login["login_authenticated"]?.GetValue<bool>()==true && login["login_remembered_until"]?.GetValue<long>()==0,"REAL_NON_REMEMBERED_PASSWORD_LOGIN_HAS_NO_PERSISTED_REMEMBER_PROOF");
            Check(login["device_registered"]?.GetValue<bool>()==true && login["registration"]?["confirmed_at"]?.GetValue<long>()>0 && login["intent"]?.GetValue<bool>()==false,"REAL_PASSWORD_LOGIN_COMPLETES_DEVICE_ADMISSION_BEFORE_DASHBOARD");
            int registeredCount=login["account"]!["device_count"]!.GetValue<int>();
            string registeredId=login["registration"]!["device_id"]!.GetValue<string>();
            long registeredAt=login["registration"]!["confirmed_at"]!.GetValue<long>();
            var signedOut=await Send("Quit");
            Check(signedOut["login_authenticated"]?.GetValue<bool>()==false && signedOut["account"] is null && signedOut["core_pid"]?.GetValue<uint>()==0,"REAL_NON_REMEMBERED_EXPLICIT_QUIT_REQUIRES_LOGIN_NEXT_TIME");
            login=RequireSuccess("LoginRemembered",await ControlPipe.Send("LoginRemembered",username,password));password=null;
            Check(login["login_authenticated"]?.GetValue<bool>()==true && login["login_remembered_until"]?.GetValue<long>() is long until && until>DateTimeOffset.UtcNow.ToUnixTimeSeconds() && until<=DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds(),"REAL_REMEMBERED_PASSWORD_LOGIN_RETURNS_BOUNDED_THIRTY_DAY_PROOF");
            Check(login["ok"]?.GetValue<bool>()==true && login["account"]?["username"]?.GetValue<string>()==username && login["device_registered"]?.GetValue<bool>()==true && login["account"]?["device_count"]?.GetValue<int>()==registeredCount && login["registration"]?["device_id"]?.GetValue<string>()==registeredId && login["registration"]?["confirmed_at"]?.GetValue<long>()==registeredAt,"REAL_RELOGIN_REUSES_REGISTERED_IDENTITY_WITHOUT_EXTRA_SLOT");
            // The legacy explicit command remains compatible and idempotent.
            var repeated=RequireSuccess("ConfirmDevice",await ControlPipe.Send("ConfirmDevice",Environment.MachineName,"confirmed"));
            Check(repeated["account"]?["device_count"]?.GetValue<int>()==registeredCount && repeated["registration"]?["confirmed_at"]?.GetValue<long>()==registeredAt,"REAL_REPEATED_CONFIRMATION_PRESERVES_IDENTITY_SLOT_AND_TIMESTAMP");
            var account=login["account"]!;long used=account["used_bytes"]!.GetValue<long>();int devices=account["device_count"]!.GetValue<int>();
            long? limit=account["limit_bytes"]?.GetValue<long>();
            Console.WriteLine("REAL_ACCOUNT_TEST_REGISTERED_DEVICES="+devices);
            Console.WriteLine("REAL_ACCOUNT_TEST_LIMIT_BYTES="+(limit?.ToString() ?? "unlimited"));
            Console.WriteLine("REAL_ACCOUNT_TEST_REMAINING_BYTES="+(limit is null?"unlimited":Math.Max(0,limit.Value-used).ToString()));
            Check(account["status"]?.GetValue<string>()=="active" && used>=0 && (limit is null || limit.Value-used>=4*1024*1024),"REAL_ACCOUNT_HAS_AVAILABLE_TEST_BUDGET");
            _deviceUsageStart=checked(login["peer_rx_bytes"]!.GetValue<long>()+login["peer_tx_bytes"]!.GetValue<long>());
            Check(WithinDeviceBudget(login,_deviceUsageStart.Value),"REAL_DEVICE_BUDGET_BASELINE_PRESENT");
            stage="UU_MAINTENANCE_CONCURRENCY";
            using(UuAclRepair.AcquireMaintenance()){
                var blocked=await ControlPipe.Send("Connect");
                Check(blocked["ok"]?.GetValue<bool>()==false && blocked["error"]?.GetValue<string>()=="UU_MAINTENANCE_BUSY" && blocked["mode"]?.GetValue<string>()=="disconnected" && blocked["intent"]?.GetValue<bool>()==false,"REAL_CONNECT_REFUSED_DURING_ELEVATED_UU_MAINTENANCE");
            }
            stage="ADAPTIVE_UDP443_WITH_8443_BLOCKED";
            await Send("Disconnect");var adaptive=await Send("PreferUdpAdaptive");
            Check(adaptive["transport_preference"]?.GetValue<string>()=="auto" && adaptive["native_udp_adaptive"]?.GetValue<bool>()==true && adaptive["native_udp_port_preference"]?.GetValue<int>()==0,"REAL_AUTO_POLICY_HAS_NO_FIXED_NATIVE_PORT_PIN");
            using(var alternateLoss=new InitialUdpLoss(native8443Only:true)){
                var timer=Stopwatch.StartNew();await Send("Connect");var connected=await Connected();
                SafeNativeState(connected,"ADAPTIVE_443");
                Check(connected["transport"]?.GetValue<string>()=="wireguard-udp" && connected["native_udp_selected_port"]?.GetValue<int>()==443 && connected["transport_address"]?.GetValue<string>()=="141.147.78.44" && timer.ElapsedMilliseconds<6000 && await ExitIp()=="152.67.156.100" && await FreshDns() && await DualStackExit() && await Ipv6Stun(),"REAL_ADAPTIVE_NATIVE_UDP443_WHEN_UDP8443_IS_BLOCKED_WITH_DUALSTACK_EXIT_AND_DNS");
                Check(connected["native_udp_attempt"]?["transport_address"]?.GetValue<string>()=="141.147.78.44" && connected["native_udp_attempt"]?["port_order"]?.GetValue<string>()=="443,8443","REAL_ADAPTIVE_NATIVE_DIAGNOSTICS_REPORT_ACTUAL_ADDRESS_AND_PORT_ORDER");
            }
            stage="ADAPTIVE_UDP8443_AFTER_FRESH_443_RETRY";
            await Send("Disconnect");await Send("PreferUdpAdaptive");
            using(var primaryLoss=new InitialUdpLoss(native443Only:true)){
                var timer=Stopwatch.StartNew();await Send("Connect");var connected=await Connected();
                Check(connected["transport"]?.GetValue<string>()=="wireguard-udp" && connected["native_udp_selected_port"]?.GetValue<int>()==8443 && timer.ElapsedMilliseconds<12000 && await ExitIp()=="152.67.156.100" && await FreshDns(),"REAL_ADAPTIVE_FRESH_WIREGUARD_HANDSHAKE_SELECTS_8443_WHEN_443_IS_BLOCKED");
                timer.Restart();uint prior=await ColdCore();var cached=await Connected();
                Check(cached["core_pid"]?.GetValue<uint>()!=prior && cached["native_udp_selected_port"]?.GetValue<int>()==8443 && cached["native_udp_attempt"]?["port_order"]?.GetValue<string>()=="8443,443" && timer.ElapsedMilliseconds<4500 && await ExitIp()=="152.67.156.100","REAL_ADAPTIVE_NATIVE_PORT_MEMORY_SURVIVES_CORE_REPLACEMENT");
            }
            stage="EXPLICIT_AUTO_NATIVE8443_POLICY";
            await Send("Disconnect");var automatic8443=await Send("PreferUdp8443");
            Check(automatic8443["transport_preference"]?.GetValue<string>()=="auto" && automatic8443["native_udp_port_preference"]?.GetValue<int>()==8443 && automatic8443["native_udp_8443_available"]?.GetValue<bool>()==true,"REAL_NORMAL_AUTO_NATIVE_8443_SELECTION_IS_SERVER_ADVERTISED_AND_PRESERVES_AUTO_POLICY");
            using(var oldIngressLoss=new InitialUdpLoss(oldIngressOnly:true)){
            stage="FIXED_NATIVE_UDP8443";
            await Send("Disconnect");await Send("PreferUdp8443");
            var native8443Timer=Stopwatch.StartNew();await Send("Connect");var native8443=await Connected();
            Console.WriteLine("REAL_NATIVE_WIREGUARD_UDP8443_COLD_MS="+native8443Timer.ElapsedMilliseconds);
            Check(native8443["transport_address"]?.GetValue<string>()=="141.147.78.44" && native8443["transport"]?.GetValue<string>()=="wireguard-udp" && native8443["native_udp_selected_port"]?.GetValue<int>()==8443 && native8443Timer.ElapsedMilliseconds<6000 && await ExitIp()=="152.67.156.100" && await FreshDns(),"REAL_NATIVE_WIREGUARD_UDP8443_HTTP_AND_DNS_NO_QUIC_WRAPPER");
            var nativeBuffers=native8443["native_udp_attempt"]?["ports"]?["8443"];
            Check(nativeBuffers?["rcvbuf_after"]?.GetValue<uint>()>=7*1024*1024 && nativeBuffers?["sndbuf_after"]?.GetValue<uint>()>=7*1024*1024,"REAL_OWNED_WINDOWS_UDP_BUFFERS_MATCH_WIREGUARD_POLICY");
            foreach(string key in new[]{"rcvbuf_before","sndbuf_before","rcvbuf_after","sndbuf_after"})Console.WriteLine("REAL_NATIVE_8443_"+key.ToUpperInvariant()+"="+nativeBuffers?[key]);
            Check(native8443["ipv6_policy"]?.GetValue<string>()=="tunnel" && await DualStackExit() && await Ipv6Stun(),"REAL_NATIVE_DUALSTACK_IPV6_HTTPS_AND_UDP_STUN");
            stage="NATIVE_8443_LOW_MTU_STABILITY";await StableNative8443(native8443);
            Check(true,"REAL_SECONDARY_NATIVE_UDP8443_WHILE_ALL_OLD_INGRESS_UDP_PORTS_ARE_BLOCKED");
            }
            await Send("Disconnect");
            stage="FORCED_COLD_PROTOCOLS";
            for(int cycle=0;cycle<3;cycle++){
                await Send("Disconnect");var selected=await Send("PreferUdp");
                Check(selected["core_pid"]?.GetValue<uint>()==0,"REAL_SELECTION_STOPS_OLD_CORE_"+"wireguard-udp"+"_"+cycle);
                using var primaryLoss=cycle==1?new InitialUdpLoss(primaryOnly:true):null;
                using var returnLoss=cycle==2?new InitialUdpLoss(primaryRepliesOnly:true):null;
                var timer=Stopwatch.StartNew();await Send("Connect");var cold=await Connected();long elapsed=timer.ElapsedMilliseconds;
                Console.WriteLine("REAL_COLD_READY_MS_"+"wireguard-udp"+"_"+cycle+"="+elapsed);
                Check(cold["transport_address"]?.GetValue<string>()=="141.147.78.44" && cold["transport"]?.GetValue<string>()=="wireguard-udp" && elapsed<(cycle>0?12000:6000) && await ExitIp()=="152.67.156.100" && await FreshDns(),"REAL_FORCED_COLD_PROTOCOL_HTTP_DNS_"+"wireguard-udp"+"_"+cycle);
                Check(await DualStackExit() && await Ipv6Stun(),"REAL_FORCED_CARRIER_IPV6_HTTPS_AND_STUN_"+"wireguard-udp"+"_"+cycle);
                Check(await AdminThroughVPN() && await CarrierDirectBlocked(),"REAL_ADMIN_VIA_VPN_WITH_PHYSICAL_BYPASS_BLOCKED_"+"wireguard-udp"+"_"+cycle);
                var metered=await Send("Status");
                Check(metered["verified_exit_ip"]?.GetValue<string>()=="152.67.156.100" && metered["traffic"]?["sample_ms"]?.GetValue<long>()>0 && metered["traffic"]?["rx_bytes"]?.GetValue<long>()>0 && metered["traffic"]?["tx_bytes"]?.GetValue<long>()>0,"REAL_LOCAL_TUN_UPLOAD_DOWNLOAD_COUNTERS_AND_VERIFIED_EXIT_"+"wireguard-udp"+"_"+cycle);
                if(cycle==1)Check(cold["native_udp_selected_port"]?.GetValue<int>()==443,"REAL_NATIVE_WIREGUARD_UDP443_WHILE_51820_IS_BLOCKED");
                if(cycle==2){
                    Check(cold["native_udp_selected_port"]?.GetValue<int>()==443,"REAL_NATIVE_UDP443_FRESH_HANDSHAKE_WHILE_ONLY_51820_REPLIES_ARE_DROPPED");
                    await Send("Disconnect");var portMemory=Stopwatch.StartNew();await Send("Connect");var reused=await Connected();
                    Console.WriteLine("REAL_RETURN_LOSS_CACHED_UDP443_RECONNECT_MS="+portMemory.ElapsedMilliseconds);
                    Check(reused["transport"]?.GetValue<string>()=="wireguard-udp" && reused["native_udp_selected_port"]?.GetValue<int>()==443 && portMemory.ElapsedMilliseconds<1500 && await ExitIp()=="152.67.156.100","REAL_CACHED_NATIVE_443_RECONNECT_WITHOUT_PRIMARY_TIMEOUT");
                    portMemory.Restart();uint oldCore=await ColdCore();var newCore=await Connected();
                    Console.WriteLine("REAL_RETURN_LOSS_CACHED_UDP443_NEW_CORE_MS="+portMemory.ElapsedMilliseconds);
                    Check(newCore["core_pid"]?.GetValue<uint>()!=oldCore && newCore["native_udp_selected_port"]?.GetValue<int>()==443 && newCore["transport"]?.GetValue<string>()=="wireguard-udp" && portMemory.ElapsedMilliseconds<4500 && await ExitIp()=="152.67.156.100","REAL_NEW_CORE_STARTS_WITH_VERIFIED_NATIVE_PORT_MEMORY");
                }
            }
            await Send("Disconnect");await Send("PreferUdp");
            stage="INITIAL_TRANSIENT_UDP_LOSS";uint initialPid;
            // The acceptance target has a fixed deployed WireGuard port. The
            // ordinary GUI IPC deliberately never exposes the tunnel profile.
            stage="WARM_PREPARATION";
            await Send("Prepare");JsonObject prepared=new();
            for(int attempt=0;attempt<60;attempt++){
                prepared=await Send("Prepare");if(prepared["quick_ready"]?.GetValue<bool>()==true)break;
                await Task.Delay(500);
            }
            // This owner process must not call the SYSTEM-only guard DLL.
            // ProductTests independently audits dormant kernel routes as SYSTEM;
            // here observe interface/IP inactivity, denied TUN permission from
            // authenticated service IPC, and an actual ordinary direct exit.
            Check(prepared["quick_ready"]?.GetValue<bool>()==true && prepared["guard"]?.GetValue<bool>()==false && prepared["tun_permitted"]?.GetValue<bool>()==false && VpnRuntime.TunnelInactive() && await ExitIp()!="152.67.156.100","REAL_PREPARATION_INACTIVE_TUN_AND_ORDINARY_DIRECT_EXIT_WITHOUT_PRIVILEGED_OWNER_CALLS");
            Check(prepared["transport"]?.GetValue<string>()=="wireguard-udp" && prepared["native_udp_attempt"]?["endpoint_port"]?.GetValue<int>()==51820 && prepared["native_udp_attempt"]?["socket_binding"]?.GetValue<string>()=="native_udp_dual_port" && prepared["native_udp_attempt"]?["started_without_tun"]?.GetValue<bool>()==true && prepared["native_udp_attempt"]?["probe_result"]?.GetValue<string>()=="oracle_egress_verified","REAL_NATIVE_UDP_51820_PREPARATION_VERIFIED_BEFORE_TUN");
            var warmPid=prepared["core_pid"]!.GetValue<uint>();var click=Stopwatch.StartNew();
            var quick=await Send("Connect");long clickMs=click.ElapsedMilliseconds;
            Console.WriteLine("REAL_WARM_CONNECT_CLICK_MS="+clickMs);
            foreach(string phase in new[]{"uu_discovery_ms","uu_signature_verifications","state_saved_ms","guard_installed_ms","tun_active_ms","complete_ms"})Console.WriteLine("REAL_WARM_"+phase.ToUpperInvariant()+"="+quick["switch_timings"]?[phase]);
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
                SafeNativeState(waiting,"INITIAL_LOSS_OBSERVED");
                string code=waiting["error"]?.GetValue<string>() ?? "";
                Check(waiting["mode"]?.GetValue<string>()=="protected" && waiting["guard"]?.GetValue<bool>()==true && waiting["tun_permitted"]?.GetValue<bool>()==true && waiting["core_stage"]?.GetValue<string>()=="READY" && code is "ORACLE_PROBE_TIMEOUT" or "ORACLE_PROBE_HTTP_FAILED","REAL_INITIAL_PROBE_FAILURE_RETAINS_LIVE_GUARDED_TUNNEL");
                initialPid=waiting["core_pid"]!.GetValue<uint>();Check(initialPid>0,"REAL_INITIAL_HANDSHAKE_CORE_STAYS_ALIVE");
            }
            stage="CONNECT_AFTER_TRANSIENT_LOSS";var stable=await Connected();
            SafeNativeState(stable,"INITIAL_LOSS_RECOVERED");
            Check(stable["core_pid"]?.GetValue<uint>()==initialPid,"REAL_ORACLE_HANDSHAKE_RECOVERS_WITHOUT_CORE_RESTART");
            Check((await Send("Status"))["uu_verified_programs"]?.GetValue<int>()==19,"REAL_ORACLE_CONNECTION_WITH_NINETEEN_VERIFIED_NETEASE_PATHS");
            Check(await ExitIp()=="152.67.156.100","REAL_ORDINARY_WINDOWS_HTTP_THROUGH_ORACLE_WIREGUARD_EXIT");
            // The real public GUI is an ordinary process; closing/crashing it must
            // not control the SYSTEM tunnel lifetime.
            stage="GUI_PROCESS_LOSS";using(var gui=Process.Start(new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory,"..","product","Proxy.exe")){UseShellExecute=false})!){await Task.Delay(1500);if(!gui.HasExited)gui.Kill(true);}
            Check((await Send("Status"))["mode"]?.GetValue<string>()=="connected" && await ExitIp()=="152.67.156.100","REAL_GUI_PROCESS_LOSS_KEEPS_SYSTEM_TUNNEL");
            stage="SERVICE_CRASH_RECOVERY";var service=Process.GetProcessesByName(Path.GetFileNameWithoutExtension(Platform.Exe)).Single(p=>p.SessionId==0 && p.MainModule?.FileName==Platform.Exe);
            using(service){service.Kill(true);await service.WaitForExitAsync();}
            // Recovery may finish during this probe. Any successful probe must
            // still use Oracle; a direct runner exit is always a failure.
            try{Check(await ExitIp()=="152.67.156.100","REAL_SERVICE_CRASH_PROBE_HAS_NO_DIRECT_EXIT");}
            catch(IOException){throw;}catch{Console.WriteLine("REAL_SERVICE_CRASH_PROBE_BLOCKED=PASS");}
            var recovered=await Connected();
            Check(recovered["login_authenticated"]?.GetValue<bool>()==true && recovered["account"]?["device_count"]?.GetValue<int>()==devices,"REAL_SCM_RECOVERY_REUSES_EXISTING_DEVICE_IDENTITY");
            Check(await ExitIp()=="152.67.156.100","REAL_SCM_RECOVERY_ORACLE_EXIT");
            stage="UDP_UNAVAILABLE_STAYS_PROTECTED";
            await Send("Disconnect");
            using(var loss=new InitialUdpLoss(blockQuic:true)){
                await Send("Connect");
                var deadline=Stopwatch.StartNew();
                while(deadline.Elapsed<TimeSpan.FromSeconds(15)){
                    var pending=await Send("Status");
                    Check(pending["mode"]?.GetValue<string>()=="protected" &&
                        pending["guard"]?.GetValue<bool>()==true &&
                        pending["transport"]?.GetValue<string>()=="wireguard-udp" &&
                        pending["verified_at"] is null,"REAL_UNAVAILABLE_UDP_REMAINS_PROTECTED");
                    await Task.Delay(500);
                }
                Check(await NoUnexpectedIpv6Exit(),"REAL_UNAVAILABLE_UDP_NO_DIRECT_IPV6");
                await Send("Disconnect");
            }
            await Send("Connect");await Connected();
            stage="USAGE_LINKAGE";await Task.Delay(6000);var after=await Send("Status");
            Check(after["account"]?["used_bytes"]?.GetValue<long>()>used,"REAL_SERVER_ACCOUNT_USAGE_LINKAGE");
            Check(checked(after["peer_rx_bytes"]!.GetValue<long>()+after["peer_tx_bytes"]!.GetValue<long>())>_deviceUsageStart!.Value,"REAL_SERVER_THIS_DEVICE_USAGE_LINKAGE");
            stage="DISCONNECT";Check((await Send("Disconnect"))["mode"]?.GetValue<string>()=="disconnected" && await ExitIp()!="152.67.156.100","REAL_EXPLICIT_DISCONNECT_RESTORES_DIRECT_EXIT");
            stage="EXPLICIT_QUIT";
            var quit=await Send("Quit");
            Check(quit["intent"]?.GetValue<bool>()==false && quit["core_pid"]?.GetValue<uint>()==0 && quit["preparing"]?.GetValue<bool>()==false && quit["mode"]?.GetValue<string>()=="disconnected","REAL_QUIT_STOPS_PREPARED_CORE_AND_RETAINS_ACCOUNT");
            await Task.Delay(1000);var idle=await Send("Status");
            Check(idle["core_pid"]?.GetValue<uint>()==0 && idle["preparing"]?.GetValue<bool>()==false && idle["account"]?["device_count"]?.GetValue<int>()==devices && await ExitIp()!="152.67.156.100","REAL_QUIT_LEAVES_AUTHENTICATED_SERVICE_IDLE_WITHOUT_CORE_RESTART");
            await Send("Connect");await Connected();
            Check((await Send("Quit"))["core_pid"]?.GetValue<uint>()==0 && await ExitIp()!="152.67.156.100","REAL_QUIT_WHILE_CONNECTED_STOPS_CORE_AND_RESTORES_DIRECT");
            stage="SIX_UDP_PAIRED_DIAGNOSTICS";await VerifyDiagnostics(devices);
            stage="FINAL_DEVICE_BUDGET";var finalUsage=await Send("Status");
            Check(_deviceUsageStart is long start && CanCloseDeviceBudget(finalUsage,start),"REAL_DEVICE_BUDGET_CLOSED_ONLY_AFTER_CORE_STOPPED");
            Console.WriteLine("REAL_DEVICE_RUN_USED_BYTES="+(checked(finalUsage["peer_rx_bytes"]!.GetValue<long>()+finalUsage["peer_tx_bytes"]!.GetValue<long>())-_deviceUsageStart!.Value));
            _deviceUsageStart=null;
            stage="LOGOUT";var loggedOut=await Send("Logout");
            Check(loggedOut["login_authenticated"]?.GetValue<bool>()==false && loggedOut["login_remembered_until"]?.GetValue<long>()==0 && loggedOut["account"] is null && loggedOut["core_pid"]?.GetValue<uint>()==0 && loggedOut["intent"]?.GetValue<bool>()==false,"REAL_LOGOUT_CLEARS_ACCOUNT_AFTER_FINAL_DEVICE_BUDGET");
            Console.WriteLine("REAL_ORACLE_CLIENT_END_TO_END=PASS");return 0;
        }catch(Exception error){try{SafeNativeState(await ControlPipe.Send("Status"));}catch{}try{await ControlPipe.Send("Disconnect");}catch{}Console.WriteLine("REAL_ORACLE_STAGE="+stage);if(_lastAssertion.Length>0)Console.WriteLine("REAL_ORACLE_ASSERTION="+_lastAssertion);Console.WriteLine("REAL_ORACLE_ERROR_TYPE="+error.GetType().Name);if(error.Message is "INCOMPLETE_FRAME" or "SERVICE_IDENTITY_NOT_VERIFIED" or "INVALID_SERVICE_RESPONSE" or "FRAME_TOO_LARGE" or "ORACLE_SERVICE_COMMAND_FAILED")Console.WriteLine("REAL_ORACLE_FIXED_ERROR="+error.Message);Console.WriteLine("REAL_ORACLE_HRESULT="+error.HResult.ToString("X8"));if(error is Win32Exception native)Console.WriteLine("REAL_ORACLE_NATIVE_ERROR="+native.NativeErrorCode);Console.WriteLine("REAL_ORACLE_CLIENT_END_TO_END=FAIL");return 1;}
    }
}
