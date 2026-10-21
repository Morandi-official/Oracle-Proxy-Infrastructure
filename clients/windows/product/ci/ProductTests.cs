using System.Security.AccessControl;
// Non-shipped disposable Windows SCM/packet fixture. Never accesses production
// accounts or Oracle. Dedicated opt-in Oracle acceptance is in OracleAcceptance.cs.
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.IO.Pipes;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Math.EC.Rfc7748;
using OracleProxy.Product;

internal static class ProductTests
{
    internal const string Name="OracleProxyCandidateFixture";
    internal static string Root=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),Name);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Unicode)]private delegate uint Apply(string service,string core,string uu,ulong luid,uint corePid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate uint Clear();
    private static readonly List<string> Evidence=[];
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string,int> CoreEvents=new();
    private static void Require(bool condition,string message){if(!condition)throw new IOException(message);Evidence.Add(message+"=PASS");}
    [STAThread]internal static int Main(string[] args)
    {
        if(args.SequenceEqual(new[]{"--uu-trust-signed"}))return UuTrustSigned();
        if(args.SequenceEqual(new[]{"--oracle-client"}))return OracleAcceptance.Run().GetAwaiter().GetResult();
        if(args.SequenceEqual(new[]{"--ui-self-test"}))return Ui();
        if(args.SequenceEqual(new[]{"--native-denial"})){
            IntPtr module=NativeLibrary.Load(Platform.Guard);return Marshal.GetDelegateForFunctionPointer<Clear>(NativeLibrary.GetExport(module,"OpGuardClear"))()==5?0:1;
        }
        if(args.SequenceEqual(new[]{"--nonowner-pipe"})){
            try{ControlPipe.Send("Status").GetAwaiter().GetResult();return 1;}
            catch(UnauthorizedAccessException){return 0;}catch{return 2;}
        }
        if(args.SequenceEqual(new[]{"--rogue-pipe"}))return RoguePipe().GetAwaiter().GetResult();
        if(args.SequenceEqual(new[]{"--malformed-pipe"}))return MalformedPipe().GetAwaiter().GetResult();
        if(args.SequenceEqual(new[]{"--owner-control"})){
            if(Platform.IsAdmin || Platform.IsSystem)return 2;
            bool cacheDenied=false;try{Directory.GetFiles(Platform.BundleCache);}catch(UnauthorizedAccessException){cacheDenied=true;}
            if(!cacheDenied)return 2;
            try{var refresh=ControlPipe.Send("RefreshUu").GetAwaiter().GetResult();var off=ControlPipe.Send("Disconnect").GetAwaiter().GetResult();return refresh["ok"]?.GetValue<bool>()==true && off["mode"]?.GetValue<string>()=="disconnected"?0:1;}catch{return 1;}
        }
        if(args.SequenceEqual(new[]{"--owner-protected"})){
            try{var state=ControlPipe.Send("Status").GetAwaiter().GetResult();return state["mode"]?.GetValue<string>()=="recovery" && state["guard"]?.GetValue<bool>()==true && state["error"]?.GetValue<string>()=="STATE_MISSING_RECOVERY_REQUIRED"?0:1;}catch{return 1;}
        }
        if(args.SequenceEqual(new[]{"--owner-status"})){
            try{var state=ControlPipe.Send("Status").GetAwaiter().GetResult();return state["mode"]?.GetValue<string>()=="disconnected"?0:1;}catch{return 1;}
        }
        if(!Platform.IsSystem || !File.Exists(Path.Combine(Root,"authorized")))return 3;
        if(args.SequenceEqual(new[]{"--verify-recovered"})){
            var value=DurableState.Load();string digest=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value.PublicKey)));
            bool valid=!value.ConnectIntent && !value.RecoveryRequired && value.Token=="" && value.PrivateKey.Length==44 && digest==File.ReadAllText(Path.Combine(Root,"public-sha256")) && !NativeGuard.Active;
            File.WriteAllText(Path.Combine(Root,"recovery-verified"),valid?"KEY_AND_SAFE_OFF_PRESERVED":"FAIL");return valid?0:1;
        }
        if(args.SequenceEqual(new[]{"--watchdog"})){
            Thread.Sleep(TimeSpan.FromMinutes(2));Rescue();return 0;
        }
        if(args.SequenceEqual(new[]{"--rescue"})){Rescue();return 0;}
        if(args.SequenceEqual(new[]{"--service"})){ServiceBase.Run(new Fixture());return 0;}
        return 2;
    }
    private static int UuTrustSigned()
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted" || !Platform.IsAdmin)return 3;
        string root=Path.Combine(Platform.Root,"UU-Trust-Fixture"),path=Path.Combine(root,"GameViewerInstaller.exe");
        if(!Directory.Exists(root)||!File.Exists(path))return 2;
        Platform.Protect(root,true);
        var acl=new System.Security.AccessControl.FileSecurity();acl.SetAccessRuleProtection(true,false);
        acl.SetOwner(new System.Security.Principal.SecurityIdentifier("S-1-5-32-544"));
        foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid),System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-5-32-545"),System.Security.AccessControl.FileSystemRights.ReadAndExecute,System.Security.AccessControl.AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(acl);
        try{
            if(!UuDiscovery.Trusted(path))return 1;
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"),System.Security.AccessControl.FileSystemRights.WriteData,System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);
            if(UuDiscovery.Trusted(path))return 1;
            Console.WriteLine("REAL_NETEASE_SIGNATURE_ACCEPTED_AND_WRITABLE_EXECUTABLE_EXCEPTION_DENIED=PASS");return 0;
        }finally{File.Delete(path);Directory.Delete(root);}
    }
    private static int Ui()
    {
        Application.EnableVisualStyles();using var form=new MainForm();
        var account=new JsonObject{["username"]="synthetic-user",["used_bytes"]=2147483648L,["limit_bytes"]=5368709120L,["expires_at"]=1893456000L,["device_count"]=1,["device_limit"]=3,["status"]="active"};
        var snapshot=new JsonObject{["mode"]="protected",["guard"]=true,["error"]="",["account"]=account,["received_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),["observed_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),["period"]="2026-10",["uu_verified_programs"]=0};
        form.Display(snapshot);if(form.UsageProgress!=400||!form.UsageFresh)return 1;
        using(var image=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(image,form.ClientRectangle);Directory.CreateDirectory("dist/review");image.Save("dist/review/windows-client-synthetic.png");}
        snapshot["observed_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds()-60;form.Display(snapshot);if(form.UsageFresh)return 1;
        return 0;
    }
    private static async Task<int> RoguePipe()
    {
        using var server=new NamedPipeServerStream(Platform.Pipe,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly);
        var client=Task.Run(async()=>{try{await ControlPipe.Send("Login","SYNTHETIC_ACCOUNT","SYNTHETIC_PASSWORD");return false;}catch(IOException e){return e.Message=="SERVICE_IDENTITY_NOT_VERIFIED";}catch{return false;}});
        await server.WaitForConnectionAsync().WaitAsync(TimeSpan.FromSeconds(5));
        byte[] bytes=new byte[1];int count=await server.ReadAsync(bytes).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        return await client && count==0?0:1;
    }
    private static async Task<int> MalformedPipe()
    {
        foreach(string frame in new[]{"{\"version\":1,\"command\":\"Status\",\"path\":\"C:\\\\Windows\"}","{\"version\":1,\"command\":\"Status\",\"command\":\"Run\"}",new string('x',9000)}){
            using var pipe=new NamedPipeClientStream(".",Platform.Pipe,PipeDirection.InOut,PipeOptions.Asynchronous,System.Security.Principal.TokenImpersonationLevel.Impersonation);
            await pipe.ConnectAsync(3000);byte[] data=Encoding.UTF8.GetBytes(frame+"\n");
            try{await pipe.WriteAsync(data);byte[] response=new byte[1];int n=await pipe.ReadAsync(response).AsTask().WaitAsync(TimeSpan.FromSeconds(5));if(n!=0)return 1;}catch(IOException){}
        }
        return 0;
    }
    private static void Rescue()
    {
        try{using var service=new ServiceController(Platform.Service);if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(15));}}catch{}
        try{foreach(var p in Process.GetProcessesByName("OracleProxy.Core"))using(p){if(p.MainModule?.FileName==Platform.Core)p.Kill(true);}}catch{}
        try{IntPtr module=NativeLibrary.Load(Platform.Guard);uint result=Marshal.GetDelegateForFunctionPointer<Clear>(NativeLibrary.GetExport(module,"OpGuardClear"))();if(result==0)File.WriteAllText(Path.Combine(Root,"rescued"),"OWNED_FILTERS_CLEARED");}catch{}
    }
    private sealed class Fixture:ServiceBase
    {
        internal Fixture(){ServiceName=Name;AutoLog=false;}
        protected override void OnStart(string[] args)=>Task.Run(async()=>{
            bool success=false;string result;
            try{await ProductTests.Run();success=true;result=string.Join('\n',Evidence)+"\nRESULT=PASS\n";}
            catch(Exception e){result=string.Join('\n',Evidence)+"\nRESULT=FAIL\nCATEGORY="+e.GetType().Name+"\nSTAGE="+e.Message.Replace('\n',' ')+"\n";}
            finally{if(!success)Rescue();}
            File.WriteAllText(Path.Combine(Root,"result.txt"),result);Stop();
        });
    }
    private static async Task<bool> Tcp()
    {
        using var client=new TcpClient();try{await client.ConnectAsync("1.1.1.1",443).WaitAsync(TimeSpan.FromSeconds(3));return true;}catch{return false;}
    }
    private static async Task<bool> Dns()
    {
        using var client=new UdpClient();client.Client.ReceiveTimeout=2500;
        // A cached answer after peer loss is legitimate and says nothing about
        // leakage. Use a fresh question for every actual packet-path assertion.
        byte[] id=RandomNumberGenerator.GetBytes(2);
        byte[] query=id.Concat(Convert.FromHexString("01000001000000000000")).Concat(new byte[]{32}).Concat(Encoding.ASCII.GetBytes(Guid.NewGuid().ToString("N"))).Concat(Convert.FromHexString("076578616d706c6503636f6d0000010001")).ToArray();
        try{await client.SendAsync(query,new IPEndPoint(IPAddress.Parse("1.1.1.1"),53));var r=await client.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3));return r.Buffer.Length>12&&r.Buffer[0]==id[0]&&r.Buffer[1]==id[1];}catch{return false;}
    }
    private static (string Private,string Public) KeyPair(){byte[] k=RandomNumberGenerator.GetBytes(32),p=new byte[32];k[0]&=248;k[31]&=127;k[31]|=64;try{X25519.GeneratePublicKey(k,0,p,0);return(Convert.ToBase64String(k),Convert.ToBase64String(p));}finally{CryptographicOperations.ZeroMemory(k);CryptographicOperations.ZeroMemory(p);}}
    private static async Task<Process> Launch(JsonObject config)
    {
        var start=new ProcessStartInfo(Platform.Core){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Platform.Root};
        config["log"]=new JsonObject{["level"]="debug",["timestamp"]=false};
        var p=Process.Start(start)!;p.ErrorDataReceived+=(_,line)=>{
            string value=(line.Data ?? "").ToLowerInvariant();
            foreach(string category in new[]{"handshake","completed","timeout","no route","unreachable","denied","refused","bind","listen","loopback","invalid","error","outbound connection","inbound connection"})
                if(value.Contains(category))CoreEvents.AddOrUpdate(category,1,(_,count)=>count+1);
        };p.BeginErrorReadLine();
        await p.StandardInput.WriteLineAsync(config.ToJsonString());await p.StandardInput.FlushAsync();
        if(await p.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20))!="READY")throw new IOException("SYNTHETIC_CORE_START_FAILED");return p;
    }
    private static async Task Stop(Process? p)
    {
        if(p is null)return;
        if(!p.HasExited){p.StandardInput.Close();try{await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));}catch{p.Kill(true);await p.WaitForExitAsync();}}p.Dispose();
    }
    private static async Task Run()
    {
        Require(!NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name=="OracleProxy"),"DISPOSABLE_NO_PREEXISTING_PRODUCT_TUN");
        Require(await Tcp(),"BASELINE_REAL_PHYSICAL_TCP");Require(await Dns(),"BASELINE_REAL_PHYSICAL_UDP_DNS");
        var synthetic=KeyPair();var saved=new DurableState{Token="synthetic-not-a-production-token",PrivateKey=synthetic.Private,PublicKey=synthetic.Public};saved.Save();
        Require(File.ReadAllBytes(Path.Combine(Platform.StateRoot,"state.dpapi")).AsSpan().IndexOf(Encoding.UTF8.GetBytes(synthetic.Private))<0,"REAL_KEY_FILE_HAS_NO_PLAINTEXT_PRIVATE_KEY");
        Require(DurableState.Load().Token==saved.Token,"REAL_SYSTEM_DPAPI_STATE_ROUNDTRIP");
        NativeGuard.Apply([]);
        Require(NativeGuard.Active,"REAL_OWNED_PERSISTENT_AND_BOOT_FILTERS");
        Require(!await Tcp(),"REAL_ALL_APP_PHYSICAL_TCP_BLOCK");Require(!await Dns(),"REAL_ALL_APP_PHYSICAL_UDP_DNS_BLOCK");
        File.WriteAllText(Path.Combine(Root,"public-sha256"),Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(saved.PublicKey))));
        var serverKey=KeyPair();var clientKey=KeyPair();
        string loopback=NetworkInterface.GetAllNetworkInterfaces().First(n=>n.NetworkInterfaceType==NetworkInterfaceType.Loopback).Name;
        var server=new JsonObject{
            ["log"]=new JsonObject{["disabled"]=true},
            ["endpoints"]=new JsonArray(new JsonObject{["type"]="wireguard",["tag"]="wg-server",["bind_interface"]=loopback,["system"]=false,["address"]=new JsonArray("10.200.0.1/24"),["private_key"]=serverKey.Private,["listen_port"]=59999,["peers"]=new JsonArray(new JsonObject{["public_key"]=clientKey.Public,["allowed_ips"]=new JsonArray("10.200.0.2/32")})}),
            ["outbounds"]=new JsonArray(new JsonObject{["type"]="direct",["tag"]="exit"}),["route"]=new JsonObject{["auto_detect_interface"]=true,["final"]="exit"}
        };
        var state=new JsonObject{["tunnel"]=new JsonObject{["endpoint"]="152.67.156.100:59999",["server_public_key"]=serverKey.Public,["addresses"]=new JsonArray("10.200.0.2/32"),["ipv6_policy"]="block"}};
        var config=CoreConfig.Build(state,new DurableState{PrivateKey=clientKey.Private},"synthetic-probe-only");
        // The released service cannot do this: CI changes its *own* in-memory
        // synthetic configuration to loopback, never a production response.
        config["endpoints"]![0]!["peers"]![0]!["address"]="127.0.0.1";
        config["endpoints"]![0]!["bind_interface"]=loopback;
        Process? exit=null,client=null;
        try{
            exit=await Launch(server);
            Require(IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Any(p=>p.Port==59999),"REAL_ISOLATED_WIREGUARD_UDP_LISTENER");
            client=await Launch(config);
            ulong luid=NativeGuard.TunLuid();bool wrongCoreDenied=false;
            try{NativeGuard.Apply([],luid,(uint)Environment.ProcessId);}catch(IOException error){wrongCoreDenied=error.Message.StartsWith("WFP_APPLY_5_",StringComparison.Ordinal);}
            Require(wrongCoreDenied && NativeGuard.Active && !NativeGuard.TunPermitted,"REAL_TUN_PERMISSION_REJECTS_WRONG_SYSTEM_PROCESS_IMAGE");
            NativeGuard.Apply([],luid,(uint)client.Id);
            Require(NativeGuard.TunPermitted,"REAL_CURRENT_TUN_DYNAMIC_SESSION_PERMIT_AUDITED");
            bool tunneled=await Tcp();
            if(!tunneled){
                var proxy=new WebProxy("socks5://127.0.0.1:28083"){Credentials=new NetworkCredential("service","synthetic-probe-only")};
                using var probe=new HttpClient(new SocketsHttpHandler{Proxy=proxy,UseProxy=true,AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(8)};
                try{using var response=await probe.GetAsync("https://1.1.1.1/cdn-cgi/trace");Evidence.Add("SYNTHETIC_WG_SOCKS_PATH="+(response.IsSuccessStatusCode?"PASS":"FAIL"));}catch{Evidence.Add("SYNTHETIC_WG_SOCKS_PATH=FAIL");}
                foreach(var item in CoreEvents.OrderBy(p=>p.Key))Evidence.Add("SYNTHETIC_CORE_EVENT_"+item.Key.Replace(' ','_').ToUpperInvariant()+"="+item.Value);
                NativeGuard.Clear();Evidence.Add("SYNTHETIC_TUN_WITHOUT_OWNED_GUARD="+(await Tcp()?"PASS":"FAIL"));
            }
            Require(tunneled,"REAL_TUN_USERSPACE_WIREGUARD_TCP_TO_ISOLATED_PEER");
            Require(await Dns(),"REAL_TUN_USERSPACE_WIREGUARD_UDP_DNS_TO_ISOLATED_PEER");
            await Stop(exit);exit=null;
            Require(!await Tcp(),"REAL_ENCRYPTED_PEER_LOSS_NO_DIRECT_TCP_FALLBACK");
            Require(!await Dns(),"REAL_ENCRYPTED_PEER_LOSS_NO_DIRECT_DNS_FALLBACK");
            client.Kill(true);await client.WaitForExitAsync();client.Dispose();client=null;
            Require(NativeGuard.Active,"REAL_CORE_CRASH_PERSISTENT_GUARD_SURVIVES");
            Require(!NativeGuard.TunPermitted,"REAL_DEAD_TUN_CANNOT_AUTHORIZE_A_STALE_PERMIT");
            Require(!await Tcp(),"REAL_CORE_CRASH_NO_DIRECT_TCP_FALLBACK");
            Require(!await Dns(),"REAL_CORE_CRASH_NO_DIRECT_DNS_FALLBACK");
        }finally{await Stop(client);await Stop(exit);}
        NativeGuard.Clear();
        Require(await Tcp(),"REAL_EXPLICIT_OFF_PHYSICAL_TCP_RESTORED");Require(await Dns(),"REAL_EXPLICIT_OFF_PHYSICAL_UDP_DNS_RESTORED");
        Require(!UuDiscovery.Trusted(Environment.ProcessPath!),"UU_UNSIGNED_TEST_EXECUTABLE_REJECTED");
        // No IPv6 or GameViewer proof is manufactured from IPv4 loopback tests.
        saved.Token="";saved.ConnectIntent=true;saved.RecoveryRequired=true;saved.Save();NativeGuard.Apply([]);
        Evidence.Add("PRODUCT_RECOVERY_FIXTURE_GUARDED_WITH_ENCRYPTED_KEY=PASS");
        Evidence.Add("REAL_GAMEVIEWER_CONTINUITY=NOT_TESTED");Evidence.Add("ACTUAL_OS_REBOOT=NOT_TESTED");Evidence.Add("PHYSICAL_IPV6=NOT_TESTED");
    }
}
