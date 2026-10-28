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
    internal static async Task WriteFrame(Stream stream,string frame,int maximum,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        byte[] data=new UTF8Encoding(false,true).GetBytes(frame+"\n");
        if(data.Length>maximum+1)throw new IOException("FRAME_TOO_LARGE");
        // Pipe writes are unbuffered: no uncancellable writer disposal flush.
        await stream.WriteAsync(data,token);
    }
    internal static async Task ObserveClientEnd(Stream stream,CancellationTokenSource admission,CancellationToken stop)
    {
        try{
            var extra=new byte[1];
            int received=await stream.ReadAsync(extra,stop);
            if(received is <0 or >1)throw new IOException("INVALID_PIPE_READ");
            // One frame per connection. EOF or appended bytes revoke only a
            // queued request; an admitted mutation still completes in order.
            if(!stop.IsCancellationRequested)admission.Cancel();
        }catch(OperationCanceledException)when(stop.IsCancellationRequested){}
        catch(IOException){if(!stop.IsCancellationRequested)admission.Cancel();}
        catch(ObjectDisposedException){if(!stop.IsCancellationRequested)admission.Cancel();}
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
                using var admission=CancellationTokenSource.CreateLinkedTokenSource(cancel);
                admission.CancelAfter(TimeSpan.FromSeconds(55));
                using var observing=CancellationTokenSource.CreateLinkedTokenSource(cancel);
                Task observer=ObserveClientEnd(pipe,admission,observing.Token);
                JsonObject response;
                try{
                    // Cancellation withdraws queued admission, not a mutation
                    // already executing. Never detach a timed-out command.
                    response=await runtime.Command(value,admission.Token);
                }finally{
                    observing.Cancel();
                    await observer;
                }
                using var responseDeadline=CancellationTokenSource.CreateLinkedTokenSource(cancel);
                responseDeadline.CancelAfter(TimeSpan.FromSeconds(4));
                await WriteFrame(pipe,response.ToJsonString(),65536,responseDeadline.Token);
            }catch{ /* Drop malformed/unauthorized frames; never echo secrets. */ }
        }
    }
    internal static Task<JsonObject> Send(string command,string? username=null,string? password=null)=>
        Send(command,username,password,CancellationToken.None);
    internal static async Task<JsonObject> Send(string command,string? username,string? password,CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancel);
        timeout.CancelAfter(TimeSpan.FromSeconds(60));
        using var pipe=new NamedPipeClientStream(".",Platform.Pipe,PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation);
        await pipe.ConnectAsync(3000,timeout.Token);
        // Authenticate the server through the SCM-owned process, before sending
        // credentials. A pipe DACL alone authenticates only its client.
        if(!BoundToService(pipe))throw new IOException("SERVICE_IDENTITY_NOT_VERIFIED");
        var frame=new JsonObject{["version"]=1,["command"]=command};if(command=="Login"){frame["username"]=username;frame["password"]=password;}else if(command=="ConfirmDevice"){frame["device_name"]=username;frame["confirm"]=password=="confirmed";}
        await WriteFrame(pipe,frame.ToJsonString(),8192,timeout.Token);
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
