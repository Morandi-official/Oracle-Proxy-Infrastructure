// Non-shipped disposable Windows SCM/packet fixture. Never accesses production
// accounts, Oracle, user keys, arbitrary config files or the public API.
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Unicode)]private delegate uint Apply(string service,string core,string uu,ulong luid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate uint Clear();
    private static readonly List<string> Evidence=[];
    private static void Require(bool condition,string message){if(!condition)throw new IOException(message);Evidence.Add(message+"=PASS");}
    internal static int Main(string[] args)
    {
        if(args.SequenceEqual(new[]{"--owner-status"})){
            try{var state=ControlPipe.Send("Status").GetAwaiter().GetResult();return state["mode"]?.GetValue<string>()=="disconnected"?0:1;}catch{return 1;}
        }
        if(!Platform.IsSystem || !File.Exists(Path.Combine(Root,"authorized")))return 3;
        if(args.SequenceEqual(new[]{"--watchdog"})){
            Thread.Sleep(TimeSpan.FromMinutes(2));Rescue();return 0;
        }
        if(args.SequenceEqual(new[]{"--rescue"})){Rescue();return 0;}
        if(args.SequenceEqual(new[]{"--service"})){ServiceBase.Run(new Fixture());return 0;}
        return 2;
    }
    private static void Rescue()
    {
        try{foreach(var p in Process.GetProcessesByName("OracleProxy.Core"))using(p){if(p.MainModule?.FileName==Platform.Core)p.Kill(true);}}catch{}
        try{IntPtr module=NativeLibrary.Load(Platform.Guard);uint result=Marshal.GetDelegateForFunctionPointer<Clear>(NativeLibrary.GetExport(module,"OpGuardClear"))();if(result==0)File.WriteAllText(Path.Combine(Root,"rescued"),"OWNED_FILTERS_CLEARED");}catch{}
    }
    private sealed class Fixture:ServiceBase
    {
        internal Fixture(){ServiceName=Name;AutoLog=false;}
        protected override void OnStart(string[] args)=>Task.Run(async()=>{
            try{await Run();File.WriteAllText(Path.Combine(Root,"result.txt"),string.Join('\n',Evidence)+"\nRESULT=PASS\n");}
            catch(Exception e){File.WriteAllText(Path.Combine(Root,"result.txt"),string.Join('\n',Evidence)+"\nRESULT=FAIL\nCATEGORY="+e.GetType().Name+"\nSTAGE="+e.Message.Replace('\n',' ') +"\n");}
            finally{Rescue();Stop();}
        });
    }
    private static async Task<bool> Tcp()
    {
        using var client=new TcpClient();try{await client.ConnectAsync("1.1.1.1",443).WaitAsync(TimeSpan.FromSeconds(3));return true;}catch{return false;}
    }
    private static async Task<bool> Dns()
    {
        using var client=new UdpClient();client.Client.ReceiveTimeout=2500;
        try{await client.SendAsync(Convert.FromHexString("123401000001000000000000076578616d706c6503636f6d0000010001"),new IPEndPoint(IPAddress.Parse("1.1.1.1"),53));var r=await client.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3));return r.Buffer.Length>12&&r.Buffer[0]==0x12&&r.Buffer[1]==0x34;}catch{return false;}
    }
    private static (string Private,string Public) KeyPair(){byte[] k=RandomNumberGenerator.GetBytes(32),p=new byte[32];k[0]&=248;k[31]&=127;k[31]|=64;try{X25519.GeneratePublicKey(k,0,p,0);return(Convert.ToBase64String(k),Convert.ToBase64String(p));}finally{CryptographicOperations.ZeroMemory(k);CryptographicOperations.ZeroMemory(p);}}
    private static async Task<Process> Launch(JsonObject config)
    {
        var start=new ProcessStartInfo(Platform.Core){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Platform.Root};
        var p=Process.Start(start)!;p.ErrorDataReceived+=(_,_)=>{};p.BeginErrorReadLine();
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
        var saved=new DurableState{Token="synthetic-not-a-production-token"};saved.Save();
        Require(DurableState.Load().Token==saved.Token,"REAL_SYSTEM_DPAPI_STATE_ROUNDTRIP");
        NativeGuard.Apply([]);
        Require(NativeGuard.Active,"REAL_OWNED_PERSISTENT_AND_BOOT_FILTERS");
        Require(!await Tcp(),"REAL_ALL_APP_PHYSICAL_TCP_BLOCK");Require(!await Dns(),"REAL_ALL_APP_PHYSICAL_UDP_DNS_BLOCK");
        var serverKey=KeyPair();var clientKey=KeyPair();
        var server=new JsonObject{
            ["log"]=new JsonObject{["disabled"]=true},
            ["endpoints"]=new JsonArray(new JsonObject{["type"]="wireguard",["tag"]="wg-server",["system"]=false,["address"]=new JsonArray("10.200.0.1/24"),["private_key"]=serverKey.Private,["listen_port"]=59999,["peers"]=new JsonArray(new JsonObject{["public_key"]=clientKey.Public,["allowed_ips"]=new JsonArray("10.200.0.2/32")})}),
            ["outbounds"]=new JsonArray(new JsonObject{["type"]="direct",["tag"]="exit"}),["route"]=new JsonObject{["auto_detect_interface"]=true,["final"]="exit"}
        };
        var state=new JsonObject{["tunnel"]=new JsonObject{["endpoint"]="152.67.156.100:59999",["server_public_key"]=serverKey.Public,["addresses"]=new JsonArray("10.200.0.2/32"),["ipv6_policy"]="block"}};
        var config=CoreConfig.Build(state,new DurableState{PrivateKey=clientKey.Private},"synthetic-probe-only");
        // The released service cannot do this: CI changes its *own* in-memory
        // synthetic configuration to loopback, never a production response.
        config["endpoints"]![0]!["peers"]![0]!["address"]="127.0.0.1";
        Process? exit=null,client=null;
        try{
            exit=await Launch(server);client=await Launch(config);
            ulong luid=NativeGuard.TunLuid();NativeGuard.Apply([],luid);
            Require(await Tcp(),"REAL_TUN_USERSPACE_WIREGUARD_TCP_TO_ISOLATED_PEER");
            Require(await Dns(),"REAL_TUN_USERSPACE_WIREGUARD_UDP_DNS_TO_ISOLATED_PEER");
            await Stop(exit);exit=null;
            Require(!await Tcp(),"REAL_ENCRYPTED_PEER_LOSS_NO_DIRECT_TCP_FALLBACK");
            Require(!await Dns(),"REAL_ENCRYPTED_PEER_LOSS_NO_DIRECT_DNS_FALLBACK");
            client.Kill(true);await client.WaitForExitAsync();client.Dispose();client=null;
            Require(NativeGuard.Active,"REAL_CORE_CRASH_PERSISTENT_GUARD_SURVIVES");
            Require(!await Tcp(),"REAL_CORE_CRASH_NO_DIRECT_TCP_FALLBACK");
        }finally{await Stop(client);await Stop(exit);}
        NativeGuard.Clear();
        Require(await Tcp(),"REAL_EXPLICIT_OFF_PHYSICAL_TCP_RESTORED");Require(await Dns(),"REAL_EXPLICIT_OFF_PHYSICAL_UDP_DNS_RESTORED");
        Require(!UuDiscovery.Trusted(Environment.ProcessPath!),"UU_UNSIGNED_TEST_EXECUTABLE_REJECTED");
        // No IPv6 or GameViewer proof is manufactured from IPv4 loopback tests.
        Evidence.Add("REAL_GAMEVIEWER_CONTINUITY=NOT_TESTED");Evidence.Add("ACTUAL_OS_REBOOT=NOT_TESTED");Evidence.Add("PHYSICAL_IPV6=NOT_TESTED");
    }
}
