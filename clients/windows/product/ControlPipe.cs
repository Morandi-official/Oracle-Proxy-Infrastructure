using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;

namespace OracleProxy.Product;
internal static class ControlPipe
{
    internal static async Task<string> ReadFrame(Stream stream,int maximum,CancellationToken token)
    {
        var data=new byte[maximum+1];int count=0;
        while(count<=maximum){int n=await stream.ReadAsync(data.AsMemory(count,1),token);if(n==0)throw new IOException("INCOMPLETE_FRAME");if(data[count]==10)return new UTF8Encoding(false,true).GetString(data,0,count);count++;}
        throw new IOException("FRAME_TOO_LARGE");
    }
    internal static async Task Serve(VpnRuntime runtime,CancellationToken cancel)
    {
        var owner=new SecurityIdentifier(File.ReadAllText(Path.Combine(Platform.Root,"owner.sid")).Trim());
        while(!cancel.IsCancellationRequested){
            var acl=new PipeSecurity();acl.SetAccessRuleProtection(true,false);
            acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid,null),PipeAccessRights.FullControl,AccessControlType.Deny));
            foreach(var sid in new[]{owner,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null)})
                acl.AddAccessRule(new PipeAccessRule(sid,PipeAccessRights.ReadWrite,AccessControlType.Allow));
            acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),PipeAccessRights.FullControl,AccessControlType.Allow));
            using var pipe=NamedPipeServerStreamAcl.Create(Platform.Pipe,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous|PipeOptions.FirstPipeInstance,8192,8192,acl);
            await pipe.WaitForConnectionAsync(cancel);
            try{
                using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel);deadline.CancelAfter(TimeSpan.FromSeconds(4));
                string frame=await ReadFrame(pipe,8192,deadline.Token);bool authorized=false;
                pipe.RunAsClient(()=>{using var identity=WindowsIdentity.GetCurrent();var principal=new WindowsPrincipal(identity);authorized=identity.IsAuthenticated && !principal.IsInRole(new SecurityIdentifier(WellKnownSidType.NetworkSid,null)) && (identity.User==owner || principal.IsInRole(WindowsBuiltInRole.Administrator));});
                if(!authorized)throw new UnauthorizedAccessException();
                using var document=JsonDocument.Parse(frame,new JsonDocumentOptions{MaxDepth=3});
                if(document.RootElement.ValueKind!=JsonValueKind.Object)throw new IOException("INVALID_FRAME");
                var names=new HashSet<string>();foreach(var field in document.RootElement.EnumerateObject())if(!names.Add(field.Name))throw new IOException("DUPLICATE_FIELD");
                var value=JsonNode.Parse(frame)!.AsObject();
                var response=await runtime.Command(value);
                await using var writer=new StreamWriter(pipe,new UTF8Encoding(false),8192,true){AutoFlush=true};
                await writer.WriteLineAsync(response.ToJsonString());
            }catch{ /* Drop malformed/unauthorized frames; never echo secrets. */ }
        }
    }
    internal static async Task<JsonObject> Send(string command,string? username=null,string? password=null)
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(60));
        using var pipe=new NamedPipeClientStream(".",Platform.Pipe,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(3000,timeout.Token);
        // Authenticate the server through the SCM-owned process, before sending
        // credentials. A pipe DACL alone authenticates only its client.
        if(!BoundToService(pipe))throw new IOException("SERVICE_IDENTITY_NOT_VERIFIED");
        var frame=new JsonObject{["version"]=1,["command"]=command};if(command=="Login"){frame["username"]=username;frame["password"]=password;}else if(command=="ConfirmDevice"){frame["device_name"]=username;frame["confirm"]=password=="confirmed";}
        await using var writer=new StreamWriter(pipe,new UTF8Encoding(false),8192,true){AutoFlush=true};await writer.WriteLineAsync(frame.ToJsonString());
        var result=JsonNode.Parse(await ReadFrame(pipe,65536,timeout.Token))!.AsObject();
        if(result["schema"]?.GetValue<int>()!=1)throw new IOException("INVALID_SERVICE_RESPONSE");return result;
    }
    internal static bool ServiceAbsent()
    {
        IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)return false;
        try{
            IntPtr service=OpenService(manager,Platform.Service,4);
            if(service==IntPtr.Zero)return Marshal.GetLastWin32Error()==1060;
            CloseServiceHandle(service);return false;
        }finally{CloseServiceHandle(manager);}
    }
    private static bool BoundToService(NamedPipeClientStream pipe)
    {
        if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out uint pid)||pid==0)return false;
        IntPtr manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)return false;
        try{IntPtr service=OpenService(manager,Platform.Service,4);if(service==IntPtr.Zero)return false;
            try{return QueryServiceStatusEx(service,0,out var status,(uint)Marshal.SizeOf<ServiceStatus>(),out _)&&status.Pid==pid&&status.Type==0x10&&status.State==4;}
            finally{CloseServiceHandle(service);}}
        finally{CloseServiceHandle(manager);}
    }
    [StructLayout(LayoutKind.Sequential)]private struct ServiceStatus{public uint Type,State,Accepted,Exit,Specific,Checkpoint,Wait,Pid,Flags;}
    [DllImport("kernel32.dll")]private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]private static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll")]private static extern bool QueryServiceStatusEx(IntPtr service,int kind,out ServiceStatus status,uint size,out uint needed);
    [DllImport("advapi32.dll")]private static extern bool CloseServiceHandle(IntPtr handle);
}
