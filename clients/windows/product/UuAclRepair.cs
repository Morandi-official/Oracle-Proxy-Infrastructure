using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace OracleProxy.Product;

// Explicit, elevated maintenance only. Never invoked by the control pipe or
// connection path. Only discovered, signed UU roots with the exact known ACE
// pattern are eligible. No executables, services, owners or firewall are changed.
internal static class UuAclRepair
{
    internal sealed record Entry(string Path,bool Directory,string Identity,string Before,string After);
    internal sealed record Journal(int Schema,string Phase,string[] Roots,Entry[] Entries);
    private static string Backup=>Path.Combine(Platform.StateRoot,"uu-permissions-backup.json");
    private const int MaximumObjects=2048,MaximumBytes=8*1024*1024;
    private static readonly HashSet<string> KnownGroups=["S-1-5-11","S-1-5-32-545"];
    internal static FileStream AcquireMaintenance()
    {
        Platform.VerifyProtected(Platform.StateRoot);
        string path=Path.Combine(Platform.StateRoot,"uu-maintenance.lock");
        if(File.Exists(path) && File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");
        try{return new FileStream(path,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None,1,FileOptions.DeleteOnClose);}
        catch(Exception error) when(error is IOException or UnauthorizedAccessException){throw new IOException("UU_MAINTENANCE_BUSY");}
    }
    private static string Sddl(FileSystemSecurity acl)=>acl.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
    // Hold every original object and directory open without FILE_SHARE_DELETE.
    // Writes use those same handles; a path swap must never redirect an elevated
    // rollback onto another object. Multi-link files and reparse points fail closed.
    private sealed class Locked : IDisposable
    {
        private readonly SafeFileHandle _handle;
        internal string Path {get;}
        internal bool Directory {get;}
        internal string Identity {get;}
        internal Locked(string path,bool directory)
        {
            Path=path;Directory=directory;Platform.NoLinks(directory?path:System.IO.Path.GetDirectoryName(path)!);
            _handle=CreateFile(path,0x00060000,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            if(_handle.IsInvalid){_handle.Dispose();throw new IOException("UU_REPAIR_OBJECT_LOCK_FAILED");}
            try{
                if(!GetFileInformationByHandle(_handle,out var info))throw new IOException("UU_REPAIR_OBJECT_LOCK_FAILED");
                if((info.Attributes&0x400)!=0 || ((info.Attributes&0x10)!=0)!=directory || !directory && info.Links!=1)throw new IOException("UU_REPAIR_LINK_REFUSED");
                Identity=$"{info.Volume:X8}:{info.IndexHigh:X8}{info.IndexLow:X8}";
            }catch{_handle.Dispose();throw;}
        }
        internal FileSystemSecurity Read()
        {
            uint error=GetSecurityInfo(_handle,1,7,out _,out _,out _,out _,out var descriptor);
            if(error!=0)throw new IOException("UU_REPAIR_ACL_READ_FAILED");
            try{
                var bytes=new byte[GetSecurityDescriptorLength(descriptor)];Marshal.Copy(descriptor,bytes,0,bytes.Length);
                FileSystemSecurity acl=Directory?new DirectorySecurity():new FileSecurity();acl.SetSecurityDescriptorBinaryForm(bytes);return acl;
            }finally{LocalFree(descriptor);}
        }
        internal void Write(string descriptor)
        {
            FileSystemSecurity acl=Directory?new DirectorySecurity():new FileSecurity();acl.SetSecurityDescriptorSddlForm(descriptor,AccessControlSections.Access);
            byte[] bytes=acl.GetSecurityDescriptorBinaryForm();IntPtr buffer=Marshal.AllocHGlobal(bytes.Length);
            try{
                Marshal.Copy(bytes,0,buffer,bytes.Length);
                if(!GetSecurityDescriptorDacl(buffer,out bool present,out var dacl,out _) || !present || dacl==IntPtr.Zero)throw new IOException("UU_REPAIR_ACL_WRITE_REFUSED");
                uint flags=4u|(acl.AreAccessRulesProtected?0x80000000u:0x20000000u);
                if(SetSecurityInfo(_handle,1,flags,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero)!=0)throw new IOException("UU_REPAIR_ACL_WRITE_FAILED");
            }finally{Marshal.FreeHGlobal(buffer);}
        }
        public void Dispose()=>_handle.Dispose();
    }
    [StructLayout(LayoutKind.Sequential)]private struct FileInfoNative{public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfoNative information);
    [DllImport("advapi32.dll")]private static extern uint GetSecurityInfo(SafeFileHandle handle,int type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")]private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")]private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,[MarshalAs(UnmanagedType.Bool)]out bool present,out IntPtr dacl,[MarshalAs(UnmanagedType.Bool)]out bool defaulted);
    [DllImport("advapi32.dll")]private static extern uint SetSecurityInfo(SafeFileHandle handle,int type,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DllImport("kernel32.dll")]private static extern IntPtr LocalFree(IntPtr memory);
    internal static DirectorySecurity Restricted(DirectorySecurity original)
    {
        if(!UuDiscovery.TrustedOwner(original))throw new IOException("UU_REPAIR_OWNER_REFUSED");
        var result=new DirectorySecurity();result.SetSecurityDescriptorSddlForm(original.GetSecurityDescriptorSddlForm(AccessControlSections.All));int removed=0;
        foreach(FileSystemAccessRule rule in original.GetAccessRules(true,true,typeof(SecurityIdentifier))){
            if(!rule.IsInherited && rule.AccessControlType==AccessControlType.Allow && KnownGroups.Contains(rule.IdentityReference.Value) &&
               (rule.FileSystemRights & ~FileSystemRights.Synchronize)==FileSystemRights.Modify &&
               rule.InheritanceFlags==(InheritanceFlags.ObjectInherit|InheritanceFlags.ContainerInherit) && rule.PropagationFlags==PropagationFlags.None){
                result.RemoveAccessRuleSpecific(rule);
                result.AddAccessRule(new FileSystemAccessRule(rule.IdentityReference,FileSystemRights.ReadAndExecute,rule.InheritanceFlags,rule.PropagationFlags,AccessControlType.Allow));removed++;
            }
        }
        // Do not broaden the operation to arbitrary principals, inheritance,
        // ownership, full-control grants, custom-drive parents or file ACLs.
        if(removed==0 || UuDiscovery.UnsafeWriter(result))throw new IOException("UU_REPAIR_PERMISSIONS_REFUSED");
        return result;
    }
    internal static string[] EligibleRoots()
    {
        var roots=new List<string>();
        foreach(string root in UuDiscovery.InstallationRoots()){
            try{
                Platform.NoLinks(root);var directory=new DirectoryInfo(root);
                if(directory.Parent is null)continue;
                // Never modify shared ancestor directories or broaden parent trust.
                bool safe=true;for(var parent=directory.Parent;parent.Parent is not null;parent=parent.Parent){var acl=parent.GetAccessControl();if(!UuDiscovery.TrustedOwner(acl)||UuDiscovery.UnsafeWriter(acl)){safe=false;break;}}
                if(!safe)continue;
                _=Restricted(directory.GetAccessControl());
                var options=new EnumerationOptions{RecurseSubdirectories=true,MaxRecursionDepth=4,IgnoreInaccessible=false,AttributesToSkip=FileAttributes.ReparsePoint};
                bool signed=false;int count=0;
                foreach(string main in Directory.EnumerateFiles(root,"GameViewer.exe",options)){
                    if(++count>32)break;
                    var issue=UuDiscovery.Inspect(main);
                    if(issue?.Code=="UU_DIRECTORY_WRITABLE" && string.Equals(issue.Path,root,StringComparison.OrdinalIgnoreCase) && UuDiscovery.SignatureIssue(main) is null){signed=true;break;}
                }
                if(signed)roots.Add(root);
            }catch{ /* unsupported installations remain blocked and untouched */ }
        }
        // Refuse overlapping discovered roots rather than mutate an ancestor twice.
        var unique=roots.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray();
        if(unique.Length>4 || unique.Any(a=>unique.Any(b=>a!=b && a.StartsWith(b+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))))throw new IOException("UU_REPAIR_ROOTS_REFUSED");
        return unique;
    }
    private static Entry[] Capture(string[] roots,List<Locked> locks)
    {
        var entries=new List<Entry>();
        void Add(string path,bool directory){
            if(entries.Count>=MaximumObjects)throw new IOException("UU_REPAIR_TREE_LIMIT");
            var item=new Locked(path,directory);locks.Add(item);
            entries.Add(new(path,directory,item.Identity,Sddl(item.Read()),""));
        }
        foreach(string root in roots){
            Add(root,true);
            // Include protected descendants too: rollback restores the original
            // access descriptor of each existing object, in parent-first order.
            var options=new EnumerationOptions{RecurseSubdirectories=true,IgnoreInaccessible=false,AttributesToSkip=0,MaxRecursionDepth=16};
            foreach(string path in Directory.EnumerateFileSystemEntries(root,"*",options)){
                bool directory=Directory.Exists(path);Add(path,directory);
                if(directory && Path.GetRelativePath(root,path).Count(c=>c==Path.DirectorySeparatorChar)>=15 && Directory.EnumerateFileSystemEntries(path).Any())throw new IOException("UU_REPAIR_TREE_LIMIT");
            }
        }
        return entries.OrderBy(e=>e.Path.Count(c=>c==Path.DirectorySeparatorChar)).ThenBy(e=>e.Path,StringComparer.OrdinalIgnoreCase).ToArray();
    }
    private static void Save(Journal journal)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(journal);
        if(bytes.Length>MaximumBytes)throw new IOException("UU_REPAIR_BACKUP_LIMIT");
        Platform.VerifyProtected(Platform.StateRoot);Platform.WriteAtomic(Backup,bytes);
    }
    private static Journal Load()
    {
        Platform.VerifyProtected(Platform.StateRoot);var file=new FileInfo(Backup);
        if(file.Attributes.HasFlag(FileAttributes.ReparsePoint)||file.Length>MaximumBytes)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        var journal=JsonSerializer.Deserialize<Journal>(File.ReadAllBytes(Backup)) ?? throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        var roots=UuDiscovery.InstallationRoots();
        if(journal.Schema!=1 || journal.Phase is not ("pending" or "applied" or "restoring" or "restored") || journal.Roots.Length is <1 or >4 || journal.Entries.Length is <1 or >MaximumObjects || journal.Roots.Any(root=>!roots.Contains(root,StringComparer.OrdinalIgnoreCase)))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        foreach(var entry in journal.Entries){
            string full=Path.GetFullPath(entry.Path);
            if(full!=entry.Path || !journal.Roots.Any(root=>string.Equals(root,full,StringComparison.OrdinalIgnoreCase)||full.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
            Platform.NoLinks(entry.Directory?entry.Path:Path.GetDirectoryName(entry.Path)!);
            if(File.Exists(entry.Path)||Directory.Exists(entry.Path))if(File.GetAttributes(entry.Path).HasFlag(FileAttributes.ReparsePoint))throw new IOException("REPARSE_POINT_REJECTED");
        }
        return journal;
    }
    internal static void Apply(string[] roots)
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        if(roots.Length==0 || !roots.Order(StringComparer.OrdinalIgnoreCase).SequenceEqual(EligibleRoots().Order(StringComparer.OrdinalIgnoreCase),StringComparer.OrdinalIgnoreCase))throw new IOException("UU_REPAIR_SELECTION_CHANGED");
        if(File.Exists(Backup) && Load().Phase!="restored")throw new IOException("UU_REPAIR_BACKUP_EXISTS");
        ApplyVerified(roots);
    }
    // Used directly only by the non-shipped ACL fixture; production uses Apply.
    internal static void ApplyVerified(string[] roots)
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        var locks=new List<Locked>();
        try{
        var entries=Capture(roots,locks);var byPath=locks.ToDictionary(item=>item.Path,StringComparer.OrdinalIgnoreCase);
        var changes=roots.ToDictionary(root=>root,root=>Sddl(Restricted((DirectorySecurity)byPath[root].Read())),StringComparer.OrdinalIgnoreCase);
        var journal=new Journal(1,"pending",roots,entries.Select(e=>e with{After=changes.GetValueOrDefault(e.Path,"")}).ToArray());Save(journal);
        bool mutated=false;
        try{
            // Full preflight before the first write. Do not overwrite concurrent
            // updater/administrator changes noticed during plan capture.
            foreach(var entry in entries)if(Sddl(byPath[entry.Path].Read())!=entry.Before)throw new IOException("UU_REPAIR_ACL_CHANGED");
            foreach(var entry in journal.Entries.Where(e=>changes.ContainsKey(e.Path))){mutated=true;byPath[entry.Path].Write(entry.After);}
            foreach(string root in roots)if(UuDiscovery.UnsafeWriter(byPath[root].Read()))throw new IOException("UU_REPAIR_NOT_VERIFIED");
            Save(journal with{Phase="applied",Entries=entries.Select(e=>e with{After=Sddl(byPath[e.Path].Read())}).ToArray()});
        }catch{
            if(mutated)RestoreEntries(journal,byPath);Save(journal with{Phase="restored"});throw;
        }
        }finally{foreach(var item in locks)item.Dispose();}
    }
    private static void RestoreEntries(Journal journal,Dictionary<string,Locked> locks)
    {
        foreach(var entry in journal.Entries)if(locks.TryGetValue(entry.Path,out var item))item.Write(entry.Before);
        foreach(var entry in journal.Entries)if(locks.TryGetValue(entry.Path,out var item))if(Sddl(item.Read())!=entry.Before)throw new IOException("UU_REPAIR_ROLLBACK_NOT_VERIFIED");
    }
    internal static void Restore()
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();var journal=Load();
        if(journal.Phase=="restored")throw new IOException("UU_REPAIR_ALREADY_RESTORED");
        var locks=new Dictionary<string,Locked>(StringComparer.OrdinalIgnoreCase);
        try{
        foreach(var entry in journal.Entries){
            if(!File.Exists(entry.Path)&&!Directory.Exists(entry.Path)){if(journal.Roots.Contains(entry.Path,StringComparer.OrdinalIgnoreCase))throw new IOException("UU_REPAIR_OBJECT_CHANGED");continue;}
            var item=new Locked(entry.Path,entry.Directory);locks.Add(entry.Path,item);
            if(item.Identity!=entry.Identity)throw new IOException("UU_REPAIR_OBJECT_CHANGED");
            string current=Sddl(item.Read());
            if(journal.Phase=="restoring" && current!=entry.Before && current!=entry.After || journal.Phase=="applied" && current!=entry.After || journal.Phase=="pending" && journal.Roots.Contains(entry.Path,StringComparer.OrdinalIgnoreCase) && current!=entry.Before && current!=entry.After)throw new IOException("UU_REPAIR_ACL_CHANGED");
        }
        Save(journal with{Phase="restoring"});RestoreEntries(journal,locks);Save(journal with{Phase="restored"});
        }finally{foreach(var item in locks.Values)item.Dispose();}
    }
    internal static void RunInteractive(bool restore)
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        string[] roots=restore?Load().Roots:EligibleRoots();
        if(roots.Length==0)throw new IOException("UU_REPAIR_NO_MATCH");
        string message=(restore?"将恢复下列 UU 目录备份的权限，并保持 VPN 断开。恢复后连接检查可能再次拦截。":"将备份下列 UU 目录及现有子项的权限，仅将 Users/Authenticated Users 的额外“修改”授权收紧为“读取和执行”，保留系统、管理员和读取权限。不会停止 UU 或改写程序文件。普通用户写入安装目录或自动更新可能受到影响；可使用“恢复 UU 权限”回滚。请仅在可本地操作的测试机进行。")+"\r\n\r\n"+string.Join("\r\n",roots);
        if(MessageBox.Show(message,"UU 权限维护（UAC）",MessageBoxButtons.OKCancel,MessageBoxIcon.Warning)!=DialogResult.OK)return;
        using(AcquireMaintenance()){
            var state=Task.Run(()=>ControlPipe.Send(restore?"Disconnect":"Status")).GetAwaiter().GetResult();
            if(state["ok"]?.GetValue<bool>()!=true || state["mode"]?.GetValue<string>()!="disconnected" || state["guard"]?.GetValue<bool>()==true || state["intent"]?.GetValue<bool>()==true)throw new IOException("UU_REPAIR_DISCONNECT_REQUIRED");
            if(restore)Restore();else Apply(roots);
        }
        MessageBox.Show(restore?"原权限已恢复，VPN 保持断开。":"权限修复已核验。请先确认 UU 正常，再返回客户端点击“重新识别 UU”。","UU 权限维护");
    }
}
