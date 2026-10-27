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
        if(args.SequenceEqual(new[]{"--uu-maintenance-probe"})){
            if(!Platform.IsAdmin)return 3;
            try{using var lease=UuAclRepair.AcquireMaintenance();return 0;}
            catch(IOException error) when(error.Message=="UU_MAINTENANCE_BUSY"){return 4;}
        }
        if(args.SequenceEqual(new[]{"--oracle-client"}))return OracleAcceptance.Run().GetAwaiter().GetResult();
        if(args.SequenceEqual(new[]{"--udp-loss-self-test"}))return OracleAcceptance.VerifyUdpFaultSession();
        if(args.SequenceEqual(new[]{"--tun-presence-diagnostic"})){
            var value=new JsonArray(NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.Name=="OracleProxy").Select(n=>(JsonNode?)new JsonObject{
                ["name"]=n.Name,["status"]=n.OperationalStatus.ToString(),["type"]=n.NetworkInterfaceType.ToString()}).ToArray());
            Console.WriteLine("DOTNET_TUN_PRESENCE="+value.ToJsonString());return 0;
        }
        if(args.SequenceEqual(new[]{"--ui-self-test"}))return Ui();
        if(args.SequenceEqual(new[]{"--probe-self-test"}))return ProbeDeadlines().GetAwaiter().GetResult();
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
            bool valid=!value.ConnectIntent && !value.RecoveryRequired && value.Token=="" && value.PrivateKey.Length==44 && digest==File.ReadAllText(Path.Combine(Root,"public-sha256")) && !NativeGuard.Active && !NativeGuard.TunPresent;
            File.WriteAllText(Path.Combine(Root,"recovery-verified"),valid?"KEY_AND_SAFE_OFF_PRESERVED":"FAIL");return valid?0:1;
        }
        if(args.SequenceEqual(new[]{"--oracle-watchdog"})){Thread.Sleep(TimeSpan.FromMinutes(9));Rescue();return 0;}
        if(args.SequenceEqual(new[]{"--watchdog"})){
            Thread.Sleep(TimeSpan.FromMinutes(4));Rescue();return 0;
        }
        if(args.SequenceEqual(new[]{"--rescue"})){Rescue();return 0;}
        if(args.SequenceEqual(new[]{"--service"})){ServiceBase.Run(new Fixture());return 0;}
        return 2;
    }
    private sealed class SlowTrace(bool correct) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token){
            await Task.Delay(4200,token);
            return new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(correct?"ip=152.67.156.100\n":"ip=192.0.2.1\n")};
        }
    }
    private sealed class IgnoringCancellationTrace : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token){
            await Task.Delay(8000);
            return new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("ip=152.67.156.100\n")};
        }
    }
    private static async Task<int> ProbeDeadlines()
    {
        if(!await OrphanLogDrain(false) || !await OrphanLogDrain(true))return 1;
        Console.WriteLine("ORPHAN_STDERR_DRAINS_LARGE_UNKNOWN_OR_INVALID_LOGS_WITHOUT_PREFIX_MATCH_OR_EARLY_EXIT=PASS");
        foreach(string reason in new[]{"DORMANT_ROUTE_PROTOCOL_NOT_LOCAL","DORMANT_ROUTE_NEXT_HOP_UNSAFE","DORMANT_ROUTE_DESTINATION_UNSAFE"}){
            using var exact=new MemoryStream(Encoding.ASCII.GetBytes(reason+"\n"));
            if(await TunReceipt.ReadErrors(exact,CancellationToken.None)!="TUN_OWNER_"+reason)return 1;
            using var untrusted=new MemoryStream(Encoding.ASCII.GetBytes("prefix "+reason+"\n"+reason+" tail\n"));
            if(await TunReceipt.ReadErrors(untrusted,CancellationToken.None) is not null)return 1;
        }
        Console.WriteLine("DORMANT_ROUTE_DIAGNOSTIC_CODES_REQUIRE_EXACT_ALLOWLISTED_LINES=PASS");
        using var client=new HttpClient(new SlowTrace(true)){Timeout=Timeout.InfiniteTimeSpan};
        bool reply=false;var ready=Task.Run(async()=>{await Task.Delay(500);Volatile.Write(ref reply,true);});
        long elapsed=await EgressProbe.Verify(client,3,()=>Volatile.Read(ref reply),CancellationToken.None);await ready;
        if(elapsed<4000 || elapsed>12000)return 1;
        try{await EgressProbe.Verify(client,3,()=>false,CancellationToken.None);return 1;}catch(IOException error) when(error.Message=="ORACLE_PROBE_TIMEOUT"){}
        using var wrong=new HttpClient(new SlowTrace(false)){Timeout=Timeout.InfiniteTimeSpan};
        try{await EgressProbe.Verify(wrong,3,()=>true,CancellationToken.None);return 1;}catch(IOException error) when(error.Message=="ORACLE_EGRESS_NOT_VERIFIED"){}
        using var ignoring=new HttpClient(new IgnoringCancellationTrace()){Timeout=Timeout.InfiniteTimeSpan};
        var bound=Stopwatch.StartNew();
        try{await EgressProbe.Verify(ignoring,3,()=>false,CancellationToken.None);return 1;}catch(IOException error) when(error.Message=="ORACLE_PROBE_TIMEOUT"){}
        if(bound.Elapsed>TimeSpan.FromSeconds(4))return 1;
        using var stopping=new CancellationTokenSource(100);bound.Restart();
        try{await EgressProbe.Verify(ignoring,3,()=>true,stopping.Token);return 1;}catch(OperationCanceledException)when(stopping.IsCancellationRequested){}
        if(bound.Elapsed>TimeSpan.FromSeconds(1))return 1;
        Console.WriteLine("PROBE_IGNORING_HTTP_CANCELLATION_CANNOT_EXCEED_DEADLINE_OR_DELAY_STOP=PASS");
        Console.WriteLine("REAL_ASYNC_SLOW_EXIT_PROBE_RETAINED_ONLY_AFTER_WG_REPLY_AND_REJECTS_WRONG_EXIT=PASS");return 0;
    }
    private static async Task<bool> OrphanLogDrain(bool knownReason)
    {
        // A real bounded pipe catches early-return readers: the producer would
        // fill its buffer and hit the deadline instead of silently losing logs.
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        string name="OracleProxy-Log-"+Guid.NewGuid().ToString("N");
        using var input=new NamedPipeServerStream(name,PipeDirection.In,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,4096,4096);
        using var output=new NamedPipeClientStream(".",name,PipeDirection.Out,PipeOptions.Asynchronous);
        var accepted=input.WaitForConnectionAsync(deadline.Token);
        await output.ConnectAsync(3000,deadline.Token);await accepted;
        Task<string?> reader=TunReceipt.ReadErrors(input,deadline.Token);
        async Task Produce()
        {
            try{
                await output.WriteAsync("native-log-prefix ORPHAN_IDENTITY_FAILED\nORPHAN_VERIFY_FAILED trailing-data\n"u8.ToArray(),deadline.Token);
                await output.WriteAsync(new byte[]{0xff,0xfe,0xc0,0xaf},deadline.Token);
                await output.WriteAsync("ORPHAN_ROUTE_CLEANUP_FAILED\n"u8.ToArray(),deadline.Token);
                // Reuse a small block; the test never constructs a giant log.
                byte[] noise=Enumerable.Repeat((byte)'x',8192).ToArray();
                for(int i=0;i<128;i++)await output.WriteAsync(noise,deadline.Token);
                await output.WriteAsync("\n"u8.ToArray(),deadline.Token);
                if(knownReason){
                    await output.WriteAsync("ORPHAN_VERIFY_FAILED\r\n"u8.ToArray(),deadline.Token);
                    // Even a recognized reason must not stop stderr draining.
                    for(int i=0;i<128;i++)await output.WriteAsync(noise,deadline.Token);
                }
                await output.WriteAsync("\nordinary Wintun informational output\n"u8.ToArray(),deadline.Token);
            }finally{output.Dispose();}
        }
        Task producer=Produce();
        await Task.WhenAll(producer,reader).WaitAsync(deadline.Token);
        return await reader==(knownReason?"TUN_OWNER_ORPHAN_VERIFY_FAILED":null);
    }
    private static int UuTrustSigned()
    {
        if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted" || !Platform.IsAdmin)return 3;
        string root=Path.Combine(Platform.Root,"GameViewer-Trust-Fixture"),path=Path.Combine(root,"GameViewer.exe");
        if(!Directory.Exists(root)||!File.Exists(path))return 2;
        Platform.Protect(root,true);
        var acl=new System.Security.AccessControl.FileSecurity();acl.SetAccessRuleProtection(true,false);
        acl.SetOwner(new System.Security.Principal.SecurityIdentifier("S-1-5-32-544"));
        foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid),System.Security.AccessControl.FileSystemRights.FullControl,System.Security.AccessControl.AccessControlType.Allow));
        acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-5-32-545"),System.Security.AccessControl.FileSystemRights.ReadAndExecute,System.Security.AccessControl.AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(acl);
        try{
            if(!UuDiscovery.Trusted(path))return 1;
            DateTime originalWrite=File.GetLastWriteTimeUtc(path);int originalByte;
            using(var file=new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.Read)){file.Position=1024;originalByte=file.ReadByte();file.Position=1024;file.WriteByte((byte)(originalByte^1));file.Flush(true);}
            File.SetLastWriteTimeUtc(path,originalWrite);
            bool tamperedTrusted=UuDiscovery.Trusted(path);
            using(var file=new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.Read)){file.Position=1024;file.WriteByte((byte)originalByte);file.Flush(true);}
            File.SetLastWriteTimeUtc(path,originalWrite);
            if(tamperedTrusted || !UuDiscovery.Trusted(path))return 1;
            Console.WriteLine("REAL_SIGNATURE_CACHE_REJECTS_MODIFIED_FILE_WITH_RESTORED_LENGTH_AND_WRITE_TIME=PASS");
            acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"),System.Security.AccessControl.FileSystemRights.WriteData,System.Security.AccessControl.AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);
            if(UuDiscovery.Trusted(path) || UuDiscovery.Inspect(path)?.Code!="UU_EXECUTABLE_WRITABLE")return 1;
            acl.RemoveAccessRuleSpecific(new FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"),FileSystemRights.WriteData,AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(acl);
            UuAclRoundtrip(root,path);
            Console.WriteLine("REAL_NETEASE_SIGNATURE_ACCEPTED_AND_WRITABLE_EXECUTABLE_EXCEPTION_DENIED=PASS");return 0;
        }finally{File.Delete(path);Directory.Delete(root);}
    }
    private static void UuAclRoundtrip(string root,string executable)
    {
        int Probe(){using var process=Process.Start(new ProcessStartInfo(Environment.ProcessPath!){UseShellExecute=false,ArgumentList={"--uu-maintenance-probe"}})!;process.WaitForExit();return process.ExitCode;}
        using(UuAclRepair.AcquireMaintenance())if(Probe()!=4)throw new IOException("UU_MAINTENANCE_CROSS_PROCESS_NOT_EXCLUSIVE");
        if(Probe()!=0)throw new IOException("UU_MAINTENANCE_NOT_RELEASED");
        Console.WriteLine("REAL_UU_MAINTENANCE_EXCLUSIVE_ACROSS_PROCESSES_AND_RELEASED=PASS");
        string keyPath=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OracleProxy.GameViewerAclFixture";
        using(var existing=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(keyPath))if(existing is not null)throw new IOException("PREEXISTING_FIXTURE_REFUSED");
        string backup=Path.Combine(Platform.StateRoot,"uu-permissions-backup.json");
        if(File.Exists(backup))throw new IOException("PREEXISTING_BACKUP_REFUSED");
        string child=Path.Combine(root,"mutable.txt"),saved=child+".saved",link=Path.Combine(root,"link"),outside=Path.Combine(Platform.Root,"fixture-outside.txt");
        if(File.Exists(outside))throw new IOException("PREEXISTING_FIXTURE_REFUSED");
        File.WriteAllText(child,"synthetic configuration; no passwords");
        string content=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable)));
        using(var key=Microsoft.Win32.Registry.LocalMachine.CreateSubKey(keyPath)){
            key.SetValue("DisplayName","GameViewer ACL fixture");key.SetValue("InstallLocation",root+Path.DirectorySeparatorChar);
        }
        string Descriptor(string name,bool directory)=>(directory?(System.Security.AccessControl.FileSystemSecurity)new DirectoryInfo(name).GetAccessControl():new FileInfo(name).GetAccessControl()).GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        try{
            var directory=new DirectoryInfo(root);var original=directory.GetAccessControl();
            foreach(string sid in new[]{"S-1-5-11","S-1-5-32-545"})original.AddAccessRule(new FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier(sid),FileSystemRights.Modify,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            directory.SetAccessControl(original);string before=Descriptor(root,true),protectedBefore=Descriptor(executable,false),childBefore=Descriptor(child,false);
            if(UuDiscovery.Inspect(executable)?.Code!="UU_DIRECTORY_WRITABLE" || !UuAclRepair.EligibleRoots().Contains(root,StringComparer.OrdinalIgnoreCase))throw new IOException("UU_ACL_REPRODUCTION_FAILED");
            UuAclRepair.Apply([root]);string after=Descriptor(root,true);
            if(!UuDiscovery.Trusted(executable) || protectedBefore!=Descriptor(executable,false))throw new IOException("UU_ACL_REPAIR_FAILED");
            // Another administrator/updater's object replacement must not receive
            // permissions from an old backup, even at exactly the same path.
            File.Move(child,saved);File.WriteAllText(child,"replacement");
            bool denied=false;try{UuAclRepair.Restore();}catch(IOException error) when(error.Message=="UU_REPAIR_OBJECT_CHANGED"){denied=true;}
            if(!denied||Descriptor(root,true)!=after)throw new IOException("UU_ACL_REPLACEMENT_NOT_DENIED");
            File.Delete(child);File.Move(saved,child);
            var changed=new FileInfo(child).GetAccessControl();changed.AddAccessRule(new FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-5-19"),FileSystemRights.ReadAttributes,AccessControlType.Allow));new FileInfo(child).SetAccessControl(changed);
            denied=false;try{UuAclRepair.Restore();}catch(IOException error) when(error.Message=="UU_REPAIR_ACL_CHANGED"){denied=true;}
            if(!denied||Descriptor(root,true)!=after)throw new IOException("UU_ACL_CONCURRENT_CHANGE_NOT_DENIED");
            changed.RemoveAccessRuleSpecific(new FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-5-19"),FileSystemRights.ReadAttributes,AccessControlType.Allow));new FileInfo(child).SetAccessControl(changed);
            UuAclRepair.Restore();
            if(Descriptor(root,true)!=before || Descriptor(child,false)!=childBefore || Descriptor(executable,false)!=protectedBefore || content!=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(executable))))throw new IOException("UU_ACL_ROUNDTRIP_FAILED");
            Console.WriteLine("REAL_UU_MODIFY_DIRECTORY_REPRODUCED_FIXED_AND_EXACT_ACL_ROLLBACK=PASS");
            Console.WriteLine("REAL_UU_ROLLBACK_REJECTS_REPLACED_OBJECT_AND_CONCURRENT_ACL_CHANGE=PASS");
            // Refuse broader unexpected grants without changing the directory.
            var unsafeAcl=directory.GetAccessControl();unsafeAcl.AddAccessRule(new FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"),FileSystemRights.FullControl,AccessControlType.Allow));directory.SetAccessControl(unsafeAcl);
            string unexpected=Descriptor(root,true);denied=false;
            try{UuAclRepair.Restricted(directory.GetAccessControl());}catch(IOException error) when(error.Message=="UU_REPAIR_PERMISSIONS_REFUSED"){denied=true;}
            if(!denied||Descriptor(root,true)!=unexpected)throw new IOException("UU_ACL_UNEXPECTED_GRANT_NOT_DENIED");
            unsafeAcl.RemoveAccessRuleSpecific(new FileSystemAccessRule(new System.Security.Principal.SecurityIdentifier("S-1-1-0"),FileSystemRights.FullControl,AccessControlType.Allow));directory.SetAccessControl(unsafeAcl);
            System.IO.Directory.CreateSymbolicLink(link,Platform.Root);denied=false;
            try{UuAclRepair.Apply([root]);}catch(IOException error) when(error.Message=="REPARSE_POINT_REJECTED" || error.Message=="UU_REPAIR_LINK_REFUSED"){denied=true;}
            System.IO.Directory.Delete(link);
            if(!denied||Descriptor(root,true)!=before)throw new IOException("UU_ACL_REPARSE_NOT_DENIED");
            File.WriteAllText(outside,"synthetic outside target");string outsideBefore=Descriptor(outside,false);
            if(!CreateHardLink(Path.Combine(root,"hardlink.txt"),outside,IntPtr.Zero))throw new IOException("UU_ACL_HARDLINK_FIXTURE_FAILED");
            denied=false;try{UuAclRepair.Apply([root]);}catch(IOException error) when(error.Message=="UU_REPAIR_LINK_REFUSED"){denied=true;}
            File.Delete(Path.Combine(root,"hardlink.txt"));
            if(!denied||Descriptor(outside,false)!=outsideBefore||Descriptor(root,true)!=before)throw new IOException("UU_ACL_HARDLINK_NOT_DENIED");
            Console.WriteLine("REAL_UU_REPAIR_REJECTS_UNEXPECTED_GRANTS_REPARSE_AND_HARDLINKS=PASS");
        }finally{
            if(System.IO.Directory.Exists(link))System.IO.Directory.Delete(link);
            foreach(string name in new[]{child,saved,outside,Path.Combine(root,"hardlink.txt"),backup})if(File.Exists(name))File.Delete(name);
            Microsoft.Win32.Registry.LocalMachine.DeleteSubKeyTree(keyPath,false);
        }
    }
    [DllImport("kernel32.dll",EntryPoint="CreateHardLinkW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool CreateHardLink(string path,string existing,IntPtr security);
    private static int Ui()
    {
        OracleAcceptance.VerifyDeviceBudgetFixture();
        var nativeEvents=new NativeUdpEvidence();
        if(!nativeEvents.Record("NATIVE_UDP_443_SEND_INIT") || !nativeEvents.Record("NATIVE_UDP_443_READ_ERROR_10054") || nativeEvents.Record("NATIVE_UDP_443_READ_ERROR_9999999999") || nativeEvents.Record("NATIVE_UDP_443_RECV_REPLY SYNTHETIC_SECRET") || nativeEvents.Record("NATIVE_UDP_22_SEND_INIT") || nativeEvents.Record("NATIVE_UDP_443_SEND_INIT\n"))return 1;
        if(!nativeEvents.Record("NATIVE_UDP_8443_RECV_REPLY") || !nativeEvents.Record("NATIVE_UDP_8443_SNDBUF_AFTER_7340032") || nativeEvents.Record("NATIVE_UDP_8443_RCVBUF_AFTER_999999999") || nativeEvents.Record("NATIVE_UDP_8443_RCVBUF_AFTER_7340032 SYNTHETIC_SECRET"))return 1;
        var savedNative=nativeEvents.Snapshot();nativeEvents.Clear();
        if(savedNative["8443"]?["sndbuf_after"]?.GetValue<uint>()!=7340032 || savedNative["8443"]?["rx_responses"]?.GetValue<int>()!=1 || savedNative["443"]?["tx_initiations"]?.GetValue<int>()!=1 || savedNative["443"]?["last_read_error"]?.GetValue<uint>()!=10054 || nativeEvents.Snapshot().Count!=0)return 1;
        Console.WriteLine("NATIVE_UDP_PORT_COUNTERS_STRICT_NUMERIC_VOCABULARY_AND_IMMUTABLE_SNAPSHOT=PASS");
        var carriers=new CarrierMemory();var relayState=new JsonObject{["tunnel"]=new JsonObject{["https_relay"]=true}};
        carriers.Observe("synthetic-network-a");carriers.Failed(TunnelTransport.WireGuardUdp);
        if(carriers.Preferred(relayState)!=TunnelTransport.WireGuardHttps || carriers.Observe("synthetic-network-a"))return 1;
        if(!carriers.Observe("synthetic-network-b") || carriers.Preferred(relayState)!=TunnelTransport.WireGuardUdp)return 1;
        Console.WriteLine("NETWORK_CHANGE_RESTORES_NATIVE_UDP_PREFERENCE=PASS");
        Application.EnableVisualStyles();
        var account=new JsonObject{["username"]="synthetic-user",["used_bytes"]=2147483648L,["limit_bytes"]=5368709120L,["expires_at"]=1893456000L,["device_count"]=1,["device_limit"]=3,["status"]="active"};
        var snapshot=new JsonObject{["mode"]="protected",["guard"]=true,["error"]="",["account"]=account,["received_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),["observed_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),["period"]="2026-10",["uu_verified_programs"]=0};
        snapshot["device_registered"]=true;
        snapshot["registration"]=new JsonObject{["status"]="registered",["device_id"]="aabbccddeeff",["device_name"]="Known test PC",["confirmed_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds(),["requires_slot"]=false};
        snapshot["devices"]=new JsonArray(new JsonObject{["id"]="aabbccddeeff",["name"]="Known test PC",["current"] = true,["revoked"] = false});
        snapshot["uu_candidates"]=1;snapshot["uu_rejected"]=1;
        snapshot["uu_diagnostics"]=new JsonArray(new JsonObject{["path"]=@"E:\Apps\GameViewer",["code"]="UU_DIRECTORY_WRITABLE",["detail"]=""});
        snapshot["password"]="SYNTHETIC_PASSWORD_DO_NOT_COPY";snapshot["token"]="SYNTHETIC_TOKEN_DO_NOT_COPY";
        snapshot["native_udp_attempt"]=new JsonObject{["endpoint_port"]=51820,["probe_result"]="egress_probe_timeout",["password"]="SYNTHETIC_NATIVE_SECRET_DO_NOT_COPY"};
        snapshot["failure"]=ConnectionFailure.Capture("ORACLE_EGRESS_PROBE",new HttpRequestException(HttpRequestError.ProxyTunnelError,"SYNTHETIC_SECRET_URL_PASSWORD",new SocketException((int)SocketError.ConnectionRefused)),"READY");
        if(snapshot["failure"]!["socket_error"]?.GetValue<string>()!="ConnectionRefused" || snapshot["failure"]!.ToJsonString().Contains("SYNTHETIC_SECRET_URL_PASSWORD"))return 1;
        using var form=new MainForm((_,_,_)=>Task.FromResult((JsonObject)snapshot.DeepClone()));
        form.Display(snapshot);if(form.UsageProgress!=400||!form.UsageFresh)return 1;
        if(!form.ConnectionReport.Contains("native_udp.endpoint_port: 51820") || !form.ConnectionReport.Contains("egress_probe_timeout") || form.ConnectionReport.Contains("SYNTHETIC_NATIVE_SECRET_DO_NOT_COPY") || !form.ConnectionReport.Contains("ORACLE_EGRESS_PROBE") || !form.ConnectionReport.Contains("ConnectionRefused") || form.ConnectionReport.Contains("synthetic-user") || form.ConnectionReport.Contains("SYNTHETIC_PASSWORD_DO_NOT_COPY") || form.ConnectionReport.Contains("SYNTHETIC_TOKEN_DO_NOT_COPY") || form.ConnectionReport.Contains("SYNTHETIC_SECRET_URL_PASSWORD"))return 1;
        Console.WriteLine("CONNECTION_FAILURE_STAGE_AND_ENUMS_EXPORTED_WITHOUT_MESSAGES_OR_CREDENTIALS=PASS");
        if(!form.UuReport.Contains("UU_DIRECTORY_WRITABLE") || !form.UuReport.Contains(@"E:\Apps\GameViewer") ||
           form.UuReport.Contains("synthetic-user") || form.UuReport.Contains("SYNTHETIC_PASSWORD_DO_NOT_COPY") || form.UuReport.Contains("SYNTHETIC_TOKEN_DO_NOT_COPY"))return 1;
        Console.WriteLine("UU_DIAGNOSTIC_ACTIONABLE_WITHOUT_ACCOUNT_OR_CREDENTIALS=PASS");
        snapshot["mode"]="connected";snapshot["transport"]="wireguard-quic";snapshot["verified_exit_ip"]="152.67.156.100";snapshot["latency_ms"]=186L;snapshot["core_pid"]=123U;
        snapshot["traffic"]=new JsonObject{["sample_ms"]=1000L,["rx_bytes"]=10000L,["tx_bytes"]=20000L};form.Display(snapshot);
        snapshot["traffic"]=new JsonObject{["sample_ms"]=2000L,["rx_bytes"]=12048L,["tx_bytes"]=21024L};form.Display(snapshot);
        if(form.DownloadRate!="2.0 KiB/s" || form.UploadRate!="1.0 KiB/s")return 1;
        snapshot["traffic"]=new JsonObject{["sample_ms"]=3000L,["rx_bytes"]=0L,["tx_bytes"]=0L};form.Display(snapshot);
        if(form.DownloadRate!="采样中…" || form.UploadRate!="采样中…")return 1;
        snapshot["mode"]="protected";form.Display(snapshot);if(form.DownloadRate!="—" || form.UploadRate!="—")return 1;
        Console.WriteLine("LOCAL_TUN_RATES_USE_MONOTONIC_DELTAS_RESET_ON_COUNTER_RESTART_AND_NEVER_USE_BILLING_TOTALS=PASS");
        foreach(var size in new[]{new Size(1120,860),new Size(900,620)}){
            form.ClientSize=size;form.Show();Application.DoEvents();form.PerformLayout();
            using var image=new Bitmap(form.Width,form.Height);form.DrawToBitmap(image,new Rectangle(Point.Empty,form.Size));
            var viewport=Descendants(form).Single(c=>c.Name=="viewport");
            var sections=Descendants(form).OfType<GroupBox>().Where(c=>c.Name.EndsWith("Section",StringComparison.Ordinal)).OrderBy(c=>c.Top).ToArray();
            if(sections.Length!=3 || !viewport.Visible || sections.Any(c=>!c.Visible || c.Width>viewport.ClientSize.Width || c.Left!=sections[0].Left) || sections.Zip(sections.Skip(1)).Any(pair=>pair.First.Bottom>pair.Second.Top))return 1;
            if(viewport is ScrollableControl scroller && scroller.HorizontalScroll.Visible)return 1;
            Directory.CreateDirectory("dist/review");image.Save($"dist/review/windows-client-{size.Width}x{size.Height}-synthetic.png");
        }
        Console.WriteLine("THREE_ALIGNED_SECTIONS_FIT_NORMAL_AND_MINIMUM_WINDOW_WITHOUT_HORIZONTAL_SCROLL=PASS");
        var toolsViewport=(ScrollableControl)Descendants(form).Single(c=>c.Name=="viewport");
        toolsViewport.ScrollControlIntoView(Descendants(form).Single(c=>c.Name=="toolsSection"));Application.DoEvents();
        using(var toolImage=new Bitmap(form.Width,form.Height)){form.DrawToBitmap(toolImage,new Rectangle(Point.Empty,form.Size));toolImage.Save("dist/review/windows-client-tools-synthetic.png");}
        form.Hide();
        snapshot["observed_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds()-60;form.Display(snapshot);if(form.UsageFresh)return 1;
        snapshot["mode"]="disconnected";snapshot["guard"]=false;snapshot["preparing"]=true;snapshot["quick_ready"]=true;
        snapshot["error"]="";snapshot["transport"]="wireguard-quic";
        using var idle=new MainForm((_,_,_)=>Task.FromResult((JsonObject)snapshot.DeepClone()));
        idle.Display(snapshot);idle.CreateControl();idle.PerformLayout();
        IEnumerable<Control> Descendants(Control parent){foreach(Control control in parent.Controls){yield return control;foreach(var child in Descendants(control))yield return child;}}
        var protocolChoices=Descendants(idle).OfType<ComboBox>().Single();
        if(protocolChoices.Items.Count!=3 || protocolChoices.Items.Cast<string>().Any(x=>x.Contains("HTTPS",StringComparison.Ordinal)) || !protocolChoices.Items.Cast<string>().Any(x=>x.Contains("HTTP/3",StringComparison.Ordinal)))return 1;
        Console.WriteLine("PROTOCOL_CHOICES_ARE_AUTO_NATIVE_UDP_HTTP3_WITHOUT_HTTPS_OPTION=PASS");
        int textChanges=0,buttonChanges=0,layouts=0;
        foreach(var control in Descendants(idle)){
            control.TextChanged+=(_,_)=>textChanges++;
            control.Layout+=(_,_)=>layouts++;
            if(control is Button)control.EnabledChanged+=(_,_)=>buttonChanges++;
        }
        for(int i=0;i<20;i++)idle.Act("Status").GetAwaiter().GetResult();
        if(textChanges!=0 || buttonChanges!=0 || layouts!=0 || idle.PollInterval!=3000){Console.WriteLine($"IDLE_POLL_MUTATION text={textChanges} buttons={buttonChanges} layouts={layouts} interval={idle.PollInterval}");return 1;}
        snapshot["quick_ready"]=false;idle.Display(snapshot);if(idle.PollInterval!=250)return 1;
        int preparingChanges=textChanges;
        for(int i=0;i<20;i++)idle.Act("Status").GetAwaiter().GetResult();
        if(textChanges!=preparingChanges || buttonChanges!=0){Console.WriteLine($"PREPARING_POLL_MUTATION text={textChanges} before={preparingChanges} buttons={buttonChanges}");return 1;}
        Console.WriteLine("IDLE_AND_PREPARING_POLLS_DO_NOT_REWRITE_TEXT_OR_TOGGLE_BUTTONS=PASS");
        var pendingRead=new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls=new List<string>();
        using var queued=new MainForm((command,_,_)=>{calls.Add(command);return command=="Prepare"?pendingRead.Task:Task.FromResult((JsonObject)snapshot.DeepClone());});
        Task read=queued.Act("Status"),click=queued.Act("Connect");
        if(calls.Count!=1 || click.IsCompleted)return 1;
        pendingRead.SetResult((JsonObject)snapshot.DeepClone());
        var deadline=Stopwatch.StartNew();
        while((!read.IsCompleted || !click.IsCompleted) && deadline.Elapsed<TimeSpan.FromSeconds(5)){Application.DoEvents();Thread.Sleep(5);}
        if(!read.IsCompletedSuccessfully || !click.IsCompletedSuccessfully || !calls.SequenceEqual(new[]{"Prepare","Connect"}))return 1;
        Console.WriteLine("CONNECT_CLICK_DURING_PASSIVE_READ_IS_QUEUED_AND_EXECUTED=PASS");
        var preferenceState=(JsonObject)snapshot.DeepClone();preferenceState["transport_preference"]="udp";preferenceState["native_udp_8443_available"]=true;
        var preferenceCalls=new List<string>();
        using var reselect=new MainForm((command,_,_)=>{preferenceCalls.Add(command);return Task.FromResult((JsonObject)preferenceState.DeepClone());});
        reselect.Display(preferenceState);
        var sameChoice=Descendants(reselect).OfType<ComboBox>().Single();
        typeof(ComboBox).GetMethod("OnSelectionChangeCommitted",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.Invoke(sameChoice,[EventArgs.Empty]);
        if(!preferenceCalls.SequenceEqual(new[]{"PreferUdp8443"}))return 1;
        Console.WriteLine("RESELECTING_NORMAL_UDP_RETAINS_ADVERTISED_NATIVE_8443=PASS");
        typeof(Button).GetMethod("OnClick",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.Invoke(Descendants(reselect).OfType<Button>().Single(b=>b.Text=="原生 UDP 8443 测试"),[EventArgs.Empty]);
        if(!preferenceCalls.SequenceEqual(new[]{"PreferUdp8443","PreferUdp8443"}))return 1;
        Console.WriteLine("NATIVE_UDP8443_DIAGNOSTIC_BUTTON_USES_FIXED_AUTHENTICATED_COMMAND=PASS");
        preferenceState["intent"]=true;reselect.Display(preferenceState);
        if(Descendants(reselect).OfType<Button>().Single(b=>b.Text=="原生 UDP 8443 测试").Enabled)return 1;
        foreach(string preference in new[]{"auto","udp"}){
            var defaults=(JsonObject)snapshot.DeepClone();defaults["intent"]=false;defaults["transport_preference"]=preference;defaults["native_udp_8443_available"]=true;defaults["native_udp_port_preference"]=0;defaults["ok"]=true;
            var selectionCalls=new List<string>();
            using var normal=new MainForm((command,_,_)=>{selectionCalls.Add(command);if(command.EndsWith("8443",StringComparison.Ordinal))defaults["native_udp_port_preference"]=8443;return Task.FromResult((JsonObject)defaults.DeepClone());});
            normal.Display(defaults);normal.Act("Connect").GetAwaiter().GetResult();
            if(!selectionCalls.SequenceEqual(new[]{preference=="auto"?"PreferAuto8443":"PreferUdp8443","Connect"}))return 1;
        }
        var denied=(JsonObject)preferenceState.DeepClone();denied["intent"]=false;denied["native_udp_port_preference"]=0;denied["ok"]=false;
        var deniedCalls=new List<string>();using(var rejected=new MainForm((command,_,_)=>{deniedCalls.Add(command);return Task.FromResult((JsonObject)denied.DeepClone());})){
            rejected.Display(denied);rejected.Act("Connect").GetAwaiter().GetResult();
            if(!deniedCalls.SequenceEqual(new[]{"PreferUdp8443"}))return 1;
        }
        if(TransportPolicy.ClientSelection(1,false)!="PreferUdp" || TransportPolicy.ClientSelection(0,false)!="PreferAuto" || TransportPolicy.ClientSelection(2,true)!="PreferQuic")return 1;
        Console.WriteLine("NORMAL_UDP_AND_AUTO_CONNECT_SELECT_NATIVE_8443_BEFORE_CONNECT_AND_REFUSE_FAILED_SELECTION=PASS");
        var pending=(JsonObject)snapshot.DeepClone();pending["observed_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds();pending["received_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds();pending["device_registered"]=false;pending["intent"]=false;pending["mode"]="disconnected";pending["guard"]=false;pending["ok"]=true;
        pending["registration"]=new JsonObject{["status"]="pending",["device_id"]="112233aabbcc",["device_name"]="DESKTOP-NEW",["requires_slot"]=true};pending["devices"]=new JsonArray();
        var registrationCalls=new List<(string Command,string? Name,string? Consent)>();
        using(var registrationForm=new MainForm((command,name,consent)=>{
            registrationCalls.Add((command,name,consent));
            if(command=="ConfirmDevice" && consent=="confirmed"){
                pending["device_registered"]=true;pending["registration"]!["status"]="registered";pending["registration"]!["device_name"]=name;pending["registration"]!["confirmed_at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds();pending["account"]!["device_count"]=2;
            }
            return Task.FromResult((JsonObject)pending.DeepClone());
        })){
            if(Descendants(registrationForm).OfType<Button>().Single(b=>b.Text=="连接").Enabled || Descendants(registrationForm).OfType<Button>().Single(b=>b.Name=="register-device").Enabled)return 1;
            registrationForm.Display(pending);
            var connectButton=Descendants(registrationForm).OfType<Button>().Single(b=>b.Text=="连接");
            var register=Descendants(registrationForm).OfType<Button>().Single(b=>b.Name=="register-device");
            var name=Descendants(registrationForm).OfType<TextBox>().Single(b=>b.Name=="device-name");
            var consent=Descendants(registrationForm).OfType<CheckBox>().Single(b=>b.Name=="device-confirm");
            if(connectButton.Enabled || register.Enabled)return 1;
            name.Text="My own study PC";consent.Checked=true;registrationForm.Display(pending);
            if(name.Text!="My own study PC" || !consent.Checked || !register.Enabled)return 1;
            pending["account"]!["device_count"]=3;registrationForm.Display(pending);if(register.Enabled)return 1;
            pending["registration"]!["requires_slot"]=false;registrationForm.Display(pending);if(!register.Enabled)return 1;
            pending["account"]!["device_count"]=1;
            registrationForm.Act("ConfirmDevice").GetAwaiter().GetResult();
            if(registrationCalls.Count!=1 || registrationCalls[0]!=("ConfirmDevice","My own study PC","confirmed") || !connectButton.Enabled || register.Enabled)return 1;
        }
        var unconfirmed=new JsonObject{["account"]=new JsonObject{["status"]="active"},["registration"]=new JsonObject{["status"]="pending"},["device"]=new JsonObject{["registered"]=false},["tunnel"]=null};
        if(DeviceRegistration.Confirmed(unconfirmed) || DeviceRegistration.ReportMode("connected",false,false)!="pending")return 1;
        unconfirmed["registration"]!["status"]="registered";unconfirmed["device"]!["registered"]=true;
        if(DeviceRegistration.Confirmed(unconfirmed))return 1;
        unconfirmed["tunnel"]=new JsonObject();if(!DeviceRegistration.Confirmed(unconfirmed))return 1;
        Console.WriteLine("DEVICE_CONFIRMATION_UI_BLOCKS_CONNECT_REQUIRES_EXPLICIT_CONSENT_PRESERVES_TYPED_NAME_AND_ENFORCES_SLOTS=PASS");
        var quitState=new JsonObject{["ok"]=true,["intent"]=false,["core_pid"]=0U,["mode"]="disconnected"};
        var exitCalls=new List<string>();
        using var exitForm=new MainForm((command,_,_)=>{exitCalls.Add(command);return Task.FromResult((JsonObject)quitState.DeepClone());});
        if(!exitForm.QuitClient().GetAwaiter().GetResult() || !exitForm.IsDisposed || !exitCalls.SequenceEqual(new[]{"Quit"}))return 1;
        using var refusedExit=new MainForm((_,_,_)=>Task.FromResult(new JsonObject{["ok"]=false,["intent"]=true,["core_pid"]=123U,["mode"]="protected"}));
        if(refusedExit.QuitClient().GetAwaiter().GetResult() || refusedExit.IsDisposed)return 1;
        Console.WriteLine("EXPLICIT_UI_QUIT_REQUESTS_FIXED_SERVICE_OPERATION_AND_REFUSES_UNVERIFIED_DISCONNECT=PASS");
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
    private static async Task<Process> Launch(JsonObject config,bool standby=false)
    {
        bool createsTun=standby || config["inbounds"] is JsonArray inbounds && inbounds.Any(item=>item?["type"]?.GetValue<string>()=="tun" && item?["interface_name"]?.GetValue<string>()=="OracleProxy");
        if(createsTun)Require(!NativeGuard.TunPresent,"FRESH_FIXTURE_TUN_LAUNCH_REQUIRES_NATIVE_ABSENCE");
        var start=new ProcessStartInfo(Platform.Core){UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Platform.Root};
        if(standby)start.ArgumentList.Add("--standby");
        config["log"]=new JsonObject{["level"]="debug",["timestamp"]=false};
        var p=Process.Start(start)!;p.ErrorDataReceived+=(_,line)=>{
            string value=(line.Data ?? "").ToLowerInvariant();
            foreach(string category in new[]{"handshake","completed","timeout","no route","unreachable","denied","refused","bind","listen","loopback","invalid","error","outbound connection","inbound connection"})
                if(value.Contains(category))CoreEvents.AddOrUpdate(category,1,(_,count)=>count+1);
        };p.BeginErrorReadLine();
        await p.StandardInput.WriteLineAsync(config.ToJsonString());await p.StandardInput.FlushAsync();
        try{
            if(await p.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20))!="READY")throw new IOException("SYNTHETIC_CORE_START_FAILED");
            if(createsTun){TunReceipt.Record(p);Require(File.Exists(TunReceipt.ReceiptPath),"FRESH_SYSTEM_TUN_CREATOR_RECEIPT_RECORDED");}
            return p;
        }catch{await Stop(p);throw;}
    }
    private static async Task Stop(Process? p)
    {
        if(p is null)return;
        if(!p.HasExited){p.StandardInput.Close();try{await p.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(8));}catch{p.Kill(true);await p.WaitForExitAsync();}}p.Dispose();
    }
    private static async Task RejectOrphanReceipt(JsonObject modified,ulong expectedLuid,string evidence)
    {
        byte[] original=File.ReadAllBytes(TunReceipt.ReceiptPath);bool dormant=NativeGuard.TunDormant;
        try{
            Platform.WriteAtomic(TunReceipt.ReceiptPath,Encoding.UTF8.GetBytes(modified.ToJsonString()));
            bool denied=false;
            try{await TunReceipt.RecoverOrphan();}
            catch(IOException error)when(error.Message=="TUN_OWNER_RECEIPT_INVALID"){denied=true;}
            Require(denied && NativeGuard.Active && NativeGuard.TunPresent && NativeGuard.TunLuid()==expectedLuid && NativeGuard.TunDormant==dormant,evidence);
        }finally{Platform.WriteAtomic(TunReceipt.ReceiptPath,original);}
    }
    private static async Task FixtureDormantAddress(bool remove)
    {
        var start=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"netsh.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        var args=remove?new[]{"interface","ipv4","delete","address","name=OracleProxy","address=198.18.0.2","store=active"}:
            new[]{"interface","ipv4","add","address","name=OracleProxy","address=198.18.0.2","mask=255.255.255.255","store=active"};
        foreach(string arg in args)start.ArgumentList.Add(arg);
        using var process=Process.Start(start)!;
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        Require(process.ExitCode==0,remove?"OFF_DORMANT_FIXTURE_EXACT_IPV4_REMOVED":"OFF_DORMANT_FIXTURE_EXACT_IPV4_ADDED");
    }
    private static string FixtureTunAddresses()=>string.Join('|',NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.Name=="OracleProxy")
        .SelectMany(n=>n.GetIPProperties().UnicastAddresses).Select(a=>a.Address.ToString()).Order(StringComparer.Ordinal));
    private static bool OffUnchanged(byte[] cipher)
    {
        var state=DurableState.Load();
        return !state.ConnectIntent && !state.RecoveryRequired && !NativeGuard.Active && !NativeGuard.TunPermitted &&
            File.ReadAllBytes(Path.Combine(Platform.StateRoot,"state.dpapi")).AsSpan().SequenceEqual(cipher);
    }
    private static async Task OffDormantRecovery(JsonObject config,string[] uuPaths)
    {
        string statePath=Path.Combine(Platform.StateRoot,"state.dpapi");byte[] original=File.ReadAllBytes(statePath);
        Process? creator=null;
        try{
            NativeGuard.Clear();var off=DurableState.Load();off.Token="";off.ConnectIntent=false;off.RecoveryRequired=false;off.Save();
            byte[] offCipher=File.ReadAllBytes(statePath);
            Require(!NativeGuard.TunPresent && OffUnchanged(offCipher) && await Tcp() && await Dns(),"REAL_OFF_DORMANT_BASELINE_HAS_DURABLE_OFF_NO_GUARD_AND_DIRECT_TCP_DNS");
            creator=await Launch(config,standby:true);
            Require(NativeGuard.TunPresent && NativeGuard.TunDormant && VpnRuntime.TunnelInactive() && OffUnchanged(offCipher),"REAL_OFF_PREPARED_ADAPTER_IS_UNCONFIGURED_WITH_FRESH_CREATOR_RECEIPT");
            creator.Kill(true);await creator.WaitForExitAsync();creator.Dispose();creator=null;
            Require(NativeGuard.TunPresent && NativeGuard.TunDormant && OffUnchanged(offCipher),"REAL_OFF_HARD_KILL_LEAVES_PRESENT_UNCONFIGURED_ORPHAN_WITHOUT_INSTALLING_GUARD");
            ulong emptyLuid=NativeGuard.TunLuid();byte[] emptyReceipt=File.ReadAllBytes(TunReceipt.ReceiptPath);
            bool guardedDenied=false;
            try{await TunReceipt.RecoverOrphan();}
            catch(IOException error)when(error.Message=="TUN_OWNER_GUARD_REQUIRED"){guardedDenied=true;}
            Require(guardedDenied && NativeGuard.TunPresent && NativeGuard.TunLuid()==emptyLuid && OffUnchanged(offCipher) &&
                File.ReadAllBytes(TunReceipt.ReceiptPath).AsSpan().SequenceEqual(emptyReceipt) && await Tcp() && await Dns(),"REAL_GUARDED_ORPHAN_RECOVERY_STILL_REFUSES_PERSISTENT_OFF_WITHOUT_GUARD");
            Task<bool> duringTcp=Tcp(),duringDns=Dns();
            await TunReceipt.RecoverDormantOrphan();
            Require(await duringTcp && await duringDns && !NativeGuard.TunPresent && OffUnchanged(offCipher) && await Tcp() && await Dns(),
                "REAL_EMPTY_DORMANT_ORPHAN_RECOVERY_REMOVES_NATIVE_ROW_PRESERVES_OFF_AND_DIRECT_TCP_DNS_BEFORE_DURING_AFTER");

            creator=await Launch(config,standby:true);
            await FixtureDormantAddress(false);
            Require(FixtureTunAddresses().Split('|').Contains("198.18.0.2") && OffUnchanged(offCipher),"REAL_OFF_DORMANT_DIRTY_IPV4_IS_INSTALLED_ONLY_ON_FRESH_OWNED_ADAPTER");
            creator.Kill(true);await creator.WaitForExitAsync();creator.Dispose();creator=null;
            ulong dirtyLuid=NativeGuard.TunLuid();string dirtyAddresses=FixtureTunAddresses();bool dirtyDormant=NativeGuard.TunDormant;
            byte[] dirtyReceipt=File.ReadAllBytes(TunReceipt.ReceiptPath);
            Require(NativeGuard.TunPresent && dirtyAddresses.Split('|').Contains("198.18.0.2") && OffUnchanged(offCipher),"REAL_OFF_DIRTY_ORPHAN_RETAINS_ROUTABLE_IPV4_AFTER_CREATOR_EXIT");
            bool dirtyDenied=false;duringTcp=Tcp();duringDns=Dns();
            try{await TunReceipt.RecoverDormantOrphan();}
            catch(IOException error)when(error.Message=="TUN_OWNER_DORMANT_IP_NOT_EMPTY"){dirtyDenied=true;}
            Require(dirtyDenied && NativeGuard.TunPresent && NativeGuard.TunLuid()==dirtyLuid && NativeGuard.TunDormant==dirtyDormant &&
                FixtureTunAddresses()==dirtyAddresses && File.ReadAllBytes(TunReceipt.ReceiptPath).AsSpan().SequenceEqual(dirtyReceipt) &&
                OffUnchanged(offCipher) && await duringTcp && await duringDns && await Tcp() && await Dns(),
                "REAL_OFF_DIRTY_DORMANT_ORPHAN_IS_REFUSED_WITHOUT_FLUSH_OR_IDENTITY_POLICY_RECEIPT_CHANGES");
            // Remove only this fixture's exact injected address. The product's
            // unguarded recovery itself is forbidden to flush dirty settings.
            await FixtureDormantAddress(true);
            await TunReceipt.RecoverDormantOrphan();
            Require(!NativeGuard.TunPresent && OffUnchanged(offCipher) && await Tcp() && await Dns(),"REAL_OFF_DORMANT_FIXTURE_TEARDOWN_LEAVES_NO_NATIVE_INTERFACE_AND_DIRECT_NETWORK");
        }finally{
            await Stop(creator);
            Platform.WriteAtomic(statePath,original);NativeGuard.Apply(uuPaths);
        }
    }
    private static async Task Run()
    {
        Require(!NetworkInterface.GetAllNetworkInterfaces().Any(n=>n.Name=="OracleProxy"),"DISPOSABLE_NO_PREEXISTING_PRODUCT_TUN");
        Require(!NativeGuard.TunPresent,"REAL_NATIVE_INTERFACE_TABLE_HAS_NO_PREEXISTING_PRODUCT_TUN");
        Require(await Tcp(),"BASELINE_REAL_PHYSICAL_TCP");Require(await Dns(),"BASELINE_REAL_PHYSICAL_UDP_DNS");
        string[] uuPaths=UuDiscovery.Discover().Paths;
        Require(uuPaths.Length==19,"REAL_SYSTEM_TRUSTS_NINETEEN_SIGNED_NETEASE_PATHS");
        var synthetic=KeyPair();var saved=new DurableState{Token="synthetic-not-a-production-token",PrivateKey=synthetic.Private,PublicKey=synthetic.Public};saved.Save();
        Require(File.ReadAllBytes(Path.Combine(Platform.StateRoot,"state.dpapi")).AsSpan().IndexOf(Encoding.UTF8.GetBytes(synthetic.Private))<0,"REAL_KEY_FILE_HAS_NO_PLAINTEXT_PRIVATE_KEY");
        Require(DurableState.Load().Token==saved.Token,"REAL_SYSTEM_DPAPI_STATE_ROUNDTRIP");
        NativeGuard.Apply(uuPaths);
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
        var config=CoreConfig.Build(state,new DurableState{PrivateKey=clientKey.Private,UuPaths=uuPaths},"synthetic-probe-only");
        var diagnosticState=(JsonObject)state.DeepClone();diagnosticState["tunnel"]!["endpoint"]="152.67.156.100:51820";
        var diagnosticSecret=new DurableState{PrivateKey=clientKey.Private,NativeUdpPortPreference=8443};
        bool diagnosticRefused=false;try{CoreConfig.Build(diagnosticState,diagnosticSecret,"synthetic-probe-only");}catch(IOException error)when(error.Message=="NATIVE_UDP8443_NOT_AVAILABLE"){diagnosticRefused=true;}
        Require(diagnosticRefused,"UNADVERTISED_NATIVE_8443_REFUSED");
        diagnosticState["tunnel"]!["native_udp_ports"]=new JsonArray(51820,443,8443);
        var diagnosticConfig=CoreConfig.Build(diagnosticState,diagnosticSecret,"synthetic-probe-only");
        Require(diagnosticConfig["outbounds"]![1]!["ports"]!.ToJsonString()=="[8443]" && diagnosticConfig["endpoints"]![0]!["peers"]![0]!["port"]!.GetValue<int>()==51820,"FIXED_NATIVE_8443_HAS_SINGLE_UNWRAPPED_PORT_AND_UNCHANGED_WG_PEER");
        Require(config["inbounds"]![0]!["mtu"]!.GetValue<int>()==1280 && config["endpoints"]![0]!["mtu"]!.GetValue<int>()==1200,"WINDOWS_TUN_IPV6_MINIMUM_WITH_IPV4_WG_1232_BYTE_OUTER_DATAGRAM_BUDGET");
        // The released service cannot do this: CI changes its *own* in-memory
        // synthetic configuration to loopback, never a production response.
        config["endpoints"]![0]!["peers"]![0]!["address"]="127.0.0.1";
        // Non-shipped fixture only: its synthetic server is on loopback. The
        // production configuration separately pins the physical carrier IP.
        config["outbounds"]![1]!.AsObject().Remove("address");

        await OffDormantRecovery(config,uuPaths);
        Require(NativeGuard.Active,"REAL_EXISTING_GUARDED_FIXTURE_POLICY_RESTORED_AFTER_OFF_DORMANT_CASES");

        Process? exit=null,client=null;
        try{
            exit=await Launch(server);
            Require(IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Any(p=>p.Port==59999),"REAL_ISOLATED_WIREGUARD_UDP_LISTENER");
            NativeGuard.Clear();
            client=await Launch(config,standby:true);
            Require(NativeGuard.TunPresent,"REAL_NATIVE_INTERFACE_TABLE_DETECTS_CREATED_STANDBY_ADAPTER");
            bool presentRefused=false;
            try{await VpnRuntime.EnsureTunnelRemoved();}
            catch(IOException error)when(error.Message=="OWNED_TUNNEL_REMOVAL_NOT_VERIFIED"){presentRefused=true;}
            Require(presentRefused,"REAL_COLD_REMOVAL_PROOF_REJECTS_PRESENT_SESSIONLESS_ADAPTER");
            Require(VpnRuntime.TunnelInactive() && NativeGuard.TunDormant && !NativeGuard.TunPermitted && await Tcp() && await Dns(),"REAL_STANDBY_DORMANT_ADAPTER_HAS_NO_FORWARDING_ROUTES_OR_ROUTABLE_ADDRESSES_AND_ORDINARY_TRAFFIC_REMAINS_DIRECT");
            var warmProxy=new WebProxy("socks5://127.0.0.1:28083"){Credentials=new NetworkCredential("service","synthetic-probe-only")};
            using(var probe=new HttpClient(new SocketsHttpHandler{Proxy=warmProxy,UseProxy=true,AllowAutoRedirect=false}){Timeout=TimeSpan.FromSeconds(8)}){
                using var response=await probe.GetAsync("https://1.1.1.1/cdn-cgi/trace");
                Require(response.IsSuccessStatusCode,"REAL_STANDBY_AUTHENTICATED_SOCKS_ESTABLISHES_ENCRYPTED_WIREGUARD");
            }
            var switchTimer=Stopwatch.StartNew();NativeGuard.Apply(uuPaths);
            await client.StandardInput.WriteLineAsync("ACTIVATE");await client.StandardInput.FlushAsync();
            Require(await client.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))=="TUN_ACTIVE","REAL_PRIVATE_CORE_ACTIVATE_ACKNOWLEDGED");
            NativeGuard.AuthorizeTun((uint)client.Id);
            Require(NativeGuard.TunPresent,"REAL_NATIVE_INTERFACE_TABLE_DETECTS_ACTIVE_ADAPTER");
            Evidence.Add("REAL_ISOLATED_PREPARED_SWITCH_MS="+switchTimer.ElapsedMilliseconds);
            Require(await Tcp() && await Dns(),"REAL_PREPARED_DYNAMIC_TUN_HAS_TCP_AND_FRESH_UDP_DNS");
            ulong preparedLuid=NativeGuard.TunLuid();
            bool liveCreatorDenied=false;
            try{await TunReceipt.RecoverOrphan();}
            catch(IOException error)when(error.Message=="TUN_OWNER_CREATOR_STILL_RUNNING"){liveCreatorDenied=true;}
            Require(liveCreatorDenied && NativeGuard.Active && NativeGuard.TunPresent && NativeGuard.TunLuid()==preparedLuid,"REAL_ORPHAN_RECOVERY_REJECTS_LIVE_CREATOR_WITH_GUARD_AND_DEVICE_PRESERVED");
            NativeGuard.SuspendTun();await client.StandardInput.WriteLineAsync("DEACTIVATE");await client.StandardInput.FlushAsync();
            Require(await client.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))=="STANDBY_READY","REAL_PRIVATE_CORE_DEACTIVATE_ACKNOWLEDGED");
            await VpnRuntime.EnsureTunnelInactive();
            Require(await VpnRuntime.AuditDisconnectedTunnel(true,()=>throw new IOException("UNEXPECTED_COLD_CLEANUP")),"REAL_CLEAN_DORMANT_DISCONNECT_PRESERVES_WARM_CORE");
            Require(NativeGuard.TunDormant && !NativeGuard.TunPermitted,"REAL_DORMANT_ADAPTER_HAS_NO_LIVE_LEASE_OR_NONLOCAL_ROUTES");
            Require(!await Tcp() && NativeGuard.Active,"REAL_DEACTIVATION_REMOVES_TUN_AND_RETAINS_GUARD");
            await client.StandardInput.WriteLineAsync("ACTIVATE");await client.StandardInput.FlushAsync();
            Require(await client.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))=="TUN_ACTIVE" && NativeGuard.TunLuid()==preparedLuid,"REAL_REACTIVATION_REUSES_EXACT_PREPARED_ADAPTER");
            NativeGuard.AuthorizeTun((uint)client.Id);
            Require(await Tcp() && await Dns(),"REAL_REUSED_ADAPTER_HAS_FRESH_TCP_AND_UDP_DNS");
            // Reproduce a retained adapter acquiring an unexpected address.
            // Only this fixture-owned dormant TUN is changed, never a physical NIC.
            NativeGuard.SuspendTun();await client.StandardInput.WriteLineAsync("DEACTIVATE");await client.StandardInput.FlushAsync();
            Require(await client.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(5))=="STANDBY_READY","REAL_DIRTY_DORMANT_FIXTURE_DEACTIVATE_ACKNOWLEDGED");
            var dirtyAddress=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"netsh.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
            foreach(string arg in new[]{"interface","ipv4","add","address","name=OracleProxy","address=198.18.0.2","mask=255.255.255.255","store=active"})dirtyAddress.ArgumentList.Add(arg);
            using(var fault=Process.Start(dirtyAddress)!){await fault.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));Require(fault.ExitCode==0,"REAL_OWNED_DORMANT_ADDRESS_FAULT_INSTALLED");}
            Require(!VpnRuntime.TunnelInactive() && NativeGuard.Active && !NativeGuard.TunPermitted,"REAL_DIRTY_DORMANT_ADAPTER_IS_REJECTED_WITH_GUARD_RETAINED");
            bool refused=false;
            try{await VpnRuntime.AuditDisconnectedTunnel(true,()=>throw new IOException("SYNTHETIC_STOP_FAILED"));}
            catch(IOException error)when(error.Message=="SYNTHETIC_STOP_FAILED"){refused=true;}
            Require(refused && NativeGuard.Active && !await Tcp(),"REAL_FAILED_COLD_CLEANUP_CANNOT_CLEAR_GUARD");
            bool retained=await VpnRuntime.AuditDisconnectedTunnel(true,async()=>{await Stop(client);client=null;});
            Require(!retained && client is null && NativeGuard.Active && !await Tcp(),"REAL_DIRTY_DORMANT_COLD_CLEANUP_REMOVES_ADAPTER_BEFORE_CLEARING_GUARD");
            NativeGuard.Clear();Require(await Tcp() && await Dns(),"REAL_VERIFIED_COLD_DISCONNECT_RESTORES_DIRECT_TCP_AND_DNS");NativeGuard.Apply(uuPaths);
            client=await Launch(config);
            ulong luid=NativeGuard.TunLuid();bool wrongCoreDenied=false;
            NativeGuard.Clear();bool missingGuardDenied=false;
            try{NativeGuard.AuthorizeTun((uint)client.Id);}catch(IOException){missingGuardDenied=true;}
            Require(missingGuardDenied && !NativeGuard.TunPermitted,"REAL_LEASE_ONLY_AUTHORIZATION_REQUIRES_EXISTING_GUARD");
            NativeGuard.Apply(uuPaths);
            bool wrongLeaseDenied=false;
            try{NativeGuard.AuthorizeTun((uint)Environment.ProcessId);}catch(IOException){wrongLeaseDenied=true;}
            Require(wrongLeaseDenied && NativeGuard.Active && !NativeGuard.TunPermitted,"REAL_LEASE_ONLY_AUTHORIZATION_REJECTS_WRONG_SYSTEM_IMAGE");
            try{NativeGuard.Apply(uuPaths,luid,(uint)Environment.ProcessId);}catch(IOException error){wrongCoreDenied=error.Message.StartsWith("WFP_APPLY_5_",StringComparison.Ordinal);}
            Require(wrongCoreDenied && NativeGuard.Active && !NativeGuard.TunPermitted,"REAL_TUN_PERMISSION_REJECTS_WRONG_SYSTEM_PROCESS_IMAGE");
            NativeGuard.Apply(uuPaths,luid,(uint)client.Id);
            Require(NativeGuard.TunPermitted && NativeGuard.CoreLifecycle==3,"REAL_CURRENT_TUN_DYNAMIC_SESSION_PERMIT_AUDITED");
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
            Evidence.Add("REAL_CORE_EXIT_LIFECYCLE_FLAGS="+NativeGuard.CoreLifecycle);
            Require((NativeGuard.CoreLifecycle&1)==0 && !NativeGuard.TunPermitted,"REAL_DEAD_TUN_CANNOT_AUTHORIZE_A_STALE_PERMIT");
            Require(!await Tcp(),"REAL_CORE_CRASH_NO_DIRECT_TCP_FALLBACK");
            Require(!await Dns(),"REAL_CORE_CRASH_NO_DIRECT_DNS_FALLBACK");
            Require(NativeGuard.TunPresent,"REAL_HARD_KILLED_CREATOR_LEAVES_NATIVE_ORPHAN_FOR_FIXED_RECOVERY");
            ulong orphanLuid=NativeGuard.TunLuid();
            var recorded=JsonNode.Parse(File.ReadAllBytes(TunReceipt.ReceiptPath))!.AsObject();
            var foreign=(JsonObject)recorded.DeepClone();foreign["guid"]="11223344-5566-7788-99aa-bbccddeeff00";
            await RejectOrphanReceipt(foreign,orphanLuid,"REAL_ORPHAN_RECOVERY_REJECTS_FOREIGN_GUID_WITH_GUARD_AND_DEVICE_PRESERVED");
            var unknown=(JsonObject)recorded.DeepClone();unknown["unexpected_command"]="not-an-interface-operation";
            await RejectOrphanReceipt(unknown,orphanLuid,"REAL_ORPHAN_RECOVERY_REJECTS_UNKNOWN_RECEIPT_FIELDS_WITH_GUARD_AND_DEVICE_PRESERVED");
        }finally{await Stop(client);await Stop(exit);}
        NativeGuard.Clear();
        Require(await Tcp(),"REAL_EXPLICIT_OFF_PHYSICAL_TCP_RESTORED");Require(await Dns(),"REAL_EXPLICIT_OFF_PHYSICAL_UDP_DNS_RESTORED");
        Require(!UuDiscovery.Trusted(Environment.ProcessPath!),"UU_UNSIGNED_TEST_EXECUTABLE_REJECTED");
        // No IPv6 or GameViewer proof is manufactured from IPv4 loopback tests.
        saved.Token="";saved.ConnectIntent=true;saved.RecoveryRequired=true;saved.Save();NativeGuard.Apply([]);
        Evidence.Add("PRODUCT_RECOVERY_FIXTURE_GUARDED_WITH_ENCRYPTED_KEY=PASS");
        uint presenceError=NativeGuard.QueryTunPresence(out uint presence);
        Evidence.Add("SYSTEM_NATIVE_TUN_PRESENCE_ERROR="+presenceError);
        Evidence.Add("SYSTEM_NATIVE_TUN_PRESENCE_VALUE="+presence);
        var metadata=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.Name=="OracleProxy").ToArray();
        Evidence.Add("SYSTEM_TUN_METADATA_COUNT="+metadata.Length);
        foreach(var nic in metadata)
            Evidence.Add("SYSTEM_TUN_METADATA_NAME_OracleProxy_STATUS_"+nic.OperationalStatus+"_TYPE_"+nic.NetworkInterfaceType);
        Evidence.Add("REAL_GAMEVIEWER_CONTINUITY=NOT_TESTED");Evidence.Add("ACTUAL_OS_REBOOT=NOT_TESTED");Evidence.Add("PHYSICAL_IPV6=NOT_TESTED");
    }
}
