using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
namespace OracleProxy.Product;

// A receipt is evidence of this product's successful fresh adapter creation,
// not permission to adopt any adapter bearing the same cosmetic name.
internal static class TunReceipt
{
    internal const string AdapterGuid="62e2af98-7089-6f2c-246b-4a5960cfc978";
    internal static string ReceiptPath=>Path.Combine(Platform.StateRoot,"tun-owner.json");
    private sealed record Owner(ulong Luid,uint Pid,long Started);

    // The caller must have observed READY from a newly launched --standby core.
    // That private path calls CreateAdapter and refuses a preexisting adapter.
    internal static void Record(Process creator)
    {
        VerifyEnvironment();
        if(!OwnedCore(creator,out long started) || creator.HasExited)throw new IOException("TUN_OWNER_CREATOR_NOT_VERIFIED");
        ulong luid=CurrentLuid();
        VerifyFileIfPresent(ReceiptPath);VerifyFileIfPresent(ReceiptPath+".pending");
        Platform.WriteAtomic(ReceiptPath,JsonSerializer.SerializeToUtf8Bytes(new{
            schema=1,guid=AdapterGuid,luid,creator_pid=checked((uint)creator.Id),creator_started_at_filetime=started}));
        VerifyFileIfPresent(ReceiptPath);
    }

    internal static async Task RecoverOrphan(CancellationToken cancel=default)
    {
        VerifyEnvironment();cancel.ThrowIfCancellationRequested();
        if(!NativeGuard.TunPresent)return; // Old installations need no receipt when no adapter exists.
        if(!NativeGuard.Active)throw new IOException("TUN_OWNER_GUARD_REQUIRED");
        Owner owner=Read();
        if(CurrentLuid()!=owner.Luid)throw new IOException("TUN_OWNER_IDENTITY_MISMATCH");
        VerifyCreatorExited(owner);
        foreach(var process in Process.GetProcessesByName("OracleProxy.Core"))using(process){
            if(OwnedCore(process,out _))throw new IOException("TUN_OWNER_LIVE_CORE_PRESENT");
        }
        // A fixed pinned child receives only its already-verified adapter identity.
        // No shell, path, executable choice, route or destination comes from the receipt.
        Platform.VerifyBundle(Platform.Root);
        var start=new ProcessStartInfo(Platform.Core){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=Platform.Root,
            RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true};
        start.ArgumentList.Add("--recover-adapter");
        using var child=Process.Start(start)??throw new IOException("TUN_OWNER_HELPER_START_FAILED");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        Task<string?> errors=ReadErrors(child.StandardError.BaseStream,deadline.Token);
        try{
            await child.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new{guid=AdapterGuid,luid=owner.Luid})).WaitAsync(deadline.Token);
            child.StandardInput.Close();
            string response=await ControlPipe.ReadFrame(child.StandardOutput.BaseStream,32,deadline.Token);
            await child.WaitForExitAsync(deadline.Token);
            var trailing=new byte[1];
            if(child.ExitCode!=0 || response!="ADAPTER_RECOVERED" ||
                await child.StandardOutput.BaseStream.ReadAsync(trailing,deadline.Token)!=0)
                throw new IOException(await errors??"TUN_OWNER_HELPER_NOT_VERIFIED");
            if(await errors is string reason)throw new IOException(reason);
            if(NativeGuard.TunPresent)throw new IOException("TUN_OWNER_REMOVAL_NOT_VERIFIED");
        }catch(OperationCanceledException error){throw new IOException("TUN_OWNER_HELPER_TIMEOUT",error);}
        catch(IOException error){
            // EOF may precede process exit by a few milliseconds. Collect only
            // exact bounded helper stage codes, never relay raw stderr text.
            try{
                await child.WaitForExitAsync(deadline.Token);
                if(await errors is string reason)throw new IOException(reason,error);
            }catch(OperationCanceledException){throw new IOException("TUN_OWNER_HELPER_TIMEOUT",error);}
            throw;
        }
        finally{
            if(!child.HasExited){child.Kill();try{await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2));}catch{}}
            deadline.Cancel();try{await errors;}catch{}
        }
    }

    // Stderr is diagnostic only: native Wintun may write informational logs.
    // Keep draining to EOF with bounded memory; never echo or authorize from it.
    internal static async Task<string?> ReadErrors(Stream source,CancellationToken token)
    {
        var input=new byte[1024];var line=new byte[128];int length=0;bool skip=false;string? reason=null;
        while(true){
            int count=await source.ReadAsync(input,token);
            if(count==0)break;
            for(int i=0;i<count;i++){
                byte value=input[i];
                if(value is 10 or 13){
                    if(!skip && length>0)reason??=DiagnosticCode(line.AsSpan(0,length));
                    length=0;skip=false;
                }else if(value is <32 or >126 || length==line.Length){skip=true;length=0;}
                else if(!skip)line[length++]=value;
            }
        }
        if(!skip && length>0)reason??=DiagnosticCode(line.AsSpan(0,length));
        return reason;
    }
    private static string? DiagnosticCode(ReadOnlySpan<byte> line)
    {
        if(line.SequenceEqual("ORPHAN_IDENTITY_FAILED"u8))return "TUN_OWNER_ORPHAN_IDENTITY_FAILED";
        if(line.SequenceEqual("ORPHAN_IP_CLEANUP_FAILED"u8))return "TUN_OWNER_ORPHAN_IP_CLEANUP_FAILED";
        if(line.SequenceEqual("ORPHAN_ROUTE_CLEANUP_FAILED"u8))return "TUN_OWNER_ORPHAN_ROUTE_CLEANUP_FAILED";
        if(line.SequenceEqual("ORPHAN_DNS_CLEANUP_FAILED"u8))return "TUN_OWNER_ORPHAN_DNS_CLEANUP_FAILED";
        if(line.SequenceEqual("ORPHAN_RECREATE_FAILED"u8))return "TUN_OWNER_ORPHAN_RECREATE_FAILED";
        if(line.SequenceEqual("ORPHAN_VERIFY_FAILED"u8))return "TUN_OWNER_ORPHAN_VERIFY_FAILED";
        return null;
    }
    private static void VerifyEnvironment()
    {
        if(!Platform.IsSystem)throw new UnauthorizedAccessException();
        Platform.VerifyProtected(Platform.Root);Platform.VerifyProtected(Platform.StateRoot);Platform.VerifyBundle(Platform.Root);
    }
    private static ulong CurrentLuid()
    {
        if(!NativeGuard.TunPresent)throw new IOException("TUN_OWNER_ADAPTER_MISSING");
        ulong luid=NativeGuard.TunLuid();
        if(ConvertInterfaceLuidToGuid(ref luid,out var guid)!=0 || guid!=new Guid(AdapterGuid))
            throw new IOException("TUN_OWNER_IDENTITY_MISMATCH");
        return luid;
    }
    private static void VerifyFileIfPresent(string path)
    {
        FileAttributes attributes;
        try{attributes=File.GetAttributes(path);}
        catch(FileNotFoundException){return;}catch(DirectoryNotFoundException){return;}
        var file=new FileInfo(path);
        if((attributes&(FileAttributes.ReparsePoint|FileAttributes.Directory))!=0 || file.Length>4096)throw new IOException("TUN_OWNER_RECEIPT_INVALID");
        var security=file.GetAccessControl();
        if((security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value is not ("S-1-5-18" or "S-1-5-32-544"))
            throw new IOException("TUN_OWNER_RECEIPT_INVALID");
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544") &&
                (rule.FileSystemRights&(FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership))!=0)
                throw new IOException("TUN_OWNER_RECEIPT_INVALID");
    }
    private static Owner Read()
    {
        VerifyFileIfPresent(ReceiptPath);
        if(!File.Exists(ReceiptPath))throw new IOException("TUN_OWNER_RECEIPT_REQUIRED");
        using var input=new FileStream(ReceiptPath,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(input.Length is <=0 or >4096)throw new IOException("TUN_OWNER_RECEIPT_INVALID");
        var bytes=new byte[checked((int)input.Length)];input.ReadExactly(bytes);
        if(input.ReadByte()!=-1)throw new IOException("TUN_OWNER_RECEIPT_INVALID");
        try{
            using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=2});
            var value=document.RootElement;var names=new HashSet<string>(StringComparer.Ordinal);
            if(value.ValueKind!=JsonValueKind.Object)throw new IOException("TUN_OWNER_RECEIPT_INVALID");
            foreach(var item in value.EnumerateObject())if(!names.Add(item.Name))throw new IOException("TUN_OWNER_RECEIPT_INVALID");
            if(!names.SetEquals(new[]{"schema","guid","luid","creator_pid","creator_started_at_filetime"}) ||
                !value.GetProperty("schema").TryGetInt32(out int schema) || schema!=1 ||
                value.GetProperty("guid").ValueKind!=JsonValueKind.String || value.GetProperty("guid").GetString()!=AdapterGuid ||
                !value.GetProperty("luid").TryGetUInt64(out ulong luid) || luid==0 ||
                !value.GetProperty("creator_pid").TryGetUInt32(out uint pid) || pid==0 || pid>int.MaxValue ||
                !value.GetProperty("creator_started_at_filetime").TryGetInt64(out long started) || started<=0)
                throw new IOException("TUN_OWNER_RECEIPT_INVALID");
            return new(luid,pid,started);
        }catch(Exception error)when(error is JsonException or InvalidOperationException){throw new IOException("TUN_OWNER_RECEIPT_INVALID",error);}
    }
    private static void VerifyCreatorExited(Owner owner)
    {
        Process creator;
        try{creator=Process.GetProcessById(checked((int)owner.Pid));}
        catch(ArgumentException){return;}
        using(creator){
            if(creator.HasExited)return;
            if(!GetProcessTimes(creator.SafeHandle,out long started,out _,out _,out _))throw new IOException("TUN_OWNER_CREATOR_QUERY_FAILED");
            // A reused PID with another creation time proves the recorded creator exited.
            if(started==owner.Started && !creator.HasExited)throw new IOException("TUN_OWNER_CREATOR_STILL_RUNNING");
        }
    }
    internal static bool IsOwnedCore(Process process)=>OwnedCore(process,out _);
    private static bool OwnedCore(Process process,out long started)
    {
        started=0;
        try{
            if(process.HasExited)return false;
            SafeProcessHandle handle=process.SafeHandle;uint pid=GetProcessId(handle);
            if(pid==0 || pid!=checked((uint)process.Id) || !ProcessIdToSessionId(pid,out uint session))throw new IOException("TUN_OWNER_PROCESS_QUERY_FAILED");
            if(session!=0)return false;
            if(!OpenProcessToken(handle,8,out var token))throw new IOException("TUN_OWNER_PROCESS_QUERY_FAILED");
            using(token)using(var identity=new WindowsIdentity(token.DangerousGetHandle()))
                if(identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid)!=true)return false;
            var image=new char[32768];uint length=checked((uint)image.Length);
            if(!QueryFullProcessImageName(handle,0,image,ref length) || length==0 || length>=image.Length)throw new IOException("TUN_OWNER_PROCESS_QUERY_FAILED");
            if(!string.Equals(new string(image,0,checked((int)length)),Platform.Core,StringComparison.OrdinalIgnoreCase))return false;
            if(!GetProcessTimes(handle,out started,out _,out _,out _) || started<=0)throw new IOException("TUN_OWNER_PROCESS_QUERY_FAILED");
            return !process.HasExited;
        }catch(InvalidOperationException)when(process.HasExited){return false;}
    }
    [DllImport("iphlpapi.dll",ExactSpelling=true)]private static extern uint ConvertInterfaceLuidToGuid(ref ulong luid,out Guid guid);
    [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle process,uint access,out SafeAccessTokenHandle token);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern uint GetProcessId(SafeProcessHandle process);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool ProcessIdToSessionId(uint process,out uint session);
    [DllImport("kernel32.dll",EntryPoint="QueryFullProcessImageNameW",CharSet=CharSet.Unicode,SetLastError=true)]
    [return:MarshalAs(UnmanagedType.Bool)]private static extern bool QueryFullProcessImageName(SafeProcessHandle process,uint flags,[Out]char[] image,ref uint length);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessTimes(SafeProcessHandle process,out long created,out long exited,out long kernel,out long user);
}
