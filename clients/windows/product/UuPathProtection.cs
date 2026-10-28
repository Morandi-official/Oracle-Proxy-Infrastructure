using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace OracleProxy.Product;

// Explicit UAC maintenance only. There is no path-bearing control-pipe command.
// Unlike the legacy root-only repair, every v2 write is object-local: the
    // MAXIMUM_ALLOWED directory handles suppress child propagation; files use
    // READ_DATA/READ_CONTROL/WRITE_DAC because they have no child propagation.
internal static partial class UuAclRepair
{
    private sealed record PathObject(string Role,string Path,bool Directory,string Volume,string Identity,string Before,string After);
    private sealed record PathJournal(int Schema,string Phase,string Root,PathObject SourceParent,PathObject[] Ancestors,PathObject[] Entries);
    private static readonly JsonSerializerOptions PathJson=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=16};
    private const FileSystemRights AnyWrite=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
    private static readonly Regex KnownLayout=new(@"^[A-Za-z]:\\Program Files(?: \(x86\))?\\(?:Netease|UUNetease)\\GameViewer$",RegexOptions.CultureInvariant|RegexOptions.IgnoreCase);
    private static bool TrustedSid(SecurityIdentifier? sid)=>sid?.Value is "S-1-5-18" or "S-1-5-32-544" or "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    internal static string[] AdvancedAncestors(string root)
    {
        string full=Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if(root!=full || !KnownLayout.IsMatch(full) || string.Equals(Path.GetPathRoot(full),Path.GetPathRoot(Environment.SystemDirectory),StringComparison.OrdinalIgnoreCase))throw new IOException("UU_PATH_LAYOUT_REFUSED");
        string vendor=Path.GetDirectoryName(full)!,programs=Path.GetDirectoryName(vendor)!;
        return [programs,vendor];
    }

    private static int BackupSchema()
    {
        Platform.VerifyProtected(Platform.StateRoot);
        FileAttributes attributes;
        try{attributes=File.GetAttributes(Backup);}
        catch(FileNotFoundException){return 0;}catch(DirectoryNotFoundException){return 0;}
        var file=new FileInfo(Backup);
        if((attributes&(FileAttributes.ReparsePoint|FileAttributes.Directory))!=0 || file.Length is <2 or >MaximumBytes)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        using var document=JsonDocument.Parse(ReadFixedMetadata(Backup),new JsonDocumentOptions{MaxDepth=16});
        if(!document.RootElement.TryGetProperty("Schema",out var schema) || !schema.TryGetInt32(out int value) || value is not (1 or 2))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        return value;
    }
    private static bool BackupActive()=>BackupSchema()==2?LoadAdvanced().Phase!="restored":Load().Phase!="restored";

    // The journal authorizes elevated rollback. Its own file must be safe,
    // not merely its parent directory. These are the only two accepted paths.
    private static FileStream OpenFixedMetadata(string path)
    {
        if(path!=Backup && path!=Backup+".pending")throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        Platform.VerifyProtected(Platform.StateRoot);
        var handle=CreateFile(path,0x00020001u,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(handle.IsInvalid){handle.Dispose();throw new IOException("UU_REPAIR_BACKUP_REFUSED");}
        try{
            if(!GetFileInformationByHandle(handle,out var info) || (info.Attributes&0x410)!=0 || info.Links!=1 || ((ulong)info.SizeHigh<<32|info.SizeLow)>MaximumBytes)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
            if(GetSecurityInfo(handle,1,7,out _,out _,out _,out _,out var pointer)!=0)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
            try{
                byte[] bytes=new byte[GetSecurityDescriptorLength(pointer)];Marshal.Copy(pointer,bytes,0,bytes.Length);
                var security=new RawSecurityDescriptor(bytes,0);
                if(!TrustedSid(security.Owner) || security.DiscretionaryAcl is null)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
                foreach(GenericAce item in security.DiscretionaryAcl){
                    if(item is not CommonAce ace || ace.IsCallback)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
                    if(ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AceFlags.HasFlag(AceFlags.InheritOnly) || TrustedSid(ace.SecurityIdentifier))continue;
                    uint mask=unchecked((uint)ace.AccessMask);
                    if((mask&0x50000000)!=0 || (mask&(uint)AnyWrite)!=0)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
                }
            }finally{LocalFree(pointer);}
            return new FileStream(handle,FileAccess.Read);
        }catch{handle.Dispose();throw;}
    }
    private static byte[] ReadFixedMetadata(string path)
    {
        using var stream=OpenFixedMetadata(path);
        byte[] bytes=new byte[checked((int)stream.Length)];stream.ReadExactly(bytes);
        if(stream.ReadByte()!=-1)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        return bytes;
    }
    private static void VerifyMetadataIfPresent(string path)
    {
        try{_=File.GetAttributes(path);}
        catch(FileNotFoundException){return;}catch(DirectoryNotFoundException){return;}
        using var stream=OpenFixedMetadata(path);
    }

    [StructLayout(LayoutKind.Sequential)]private struct PathId{public ulong Volume;public Guid FileId;}
    [DllImport("kernel32.dll",EntryPoint="GetFileInformationByHandleEx",SetLastError=true)]private static extern bool PathIdInformation(SafeFileHandle handle,int kind,out PathId id,uint size);
    [DllImport("kernel32.dll",EntryPoint="GetFinalPathNameByHandleW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern uint FinalPath(SafeFileHandle handle,StringBuilder path,uint size,uint flags);
    [DllImport("kernel32.dll",EntryPoint="GetVolumeInformationByHandleW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool VolumeInformation(SafeFileHandle handle,StringBuilder? name,uint nameSize,out uint serial,out uint maximumComponent,out uint flags,StringBuilder fileSystem,uint fileSystemSize);
    [DllImport("kernel32.dll",EntryPoint="GetVolumeNameForVolumeMountPointW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool VolumeName(string root,StringBuilder name,uint size);
    [DllImport("kernel32.dll",EntryPoint="GetDriveTypeW",CharSet=CharSet.Unicode)]private static extern uint DriveType(string root);

    private static string PathVolume(string root)
    {
        var name=new StringBuilder(64);
        if(DriveType(root)!=3 || !VolumeName(root,name,64) || !Regex.IsMatch(name.ToString(),@"^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$",RegexOptions.CultureInvariant))throw new IOException("UU_PATH_VOLUME_REFUSED");
        return name.ToString().ToUpperInvariant();
    }

    private sealed class PathLocked : IDisposable
    {
        private readonly SafeFileHandle _handle;
        internal string Path {get;}
        internal bool Directory {get;}
        internal string Identity {get;}
        internal string Volume {get;}
        private readonly bool _writable;
        internal PathLocked(string path,bool directory,bool writable,string volume)
        {
            Path=path;Directory=directory;Volume=volume;_writable=writable;
            Platform.NoLinks(directory?path:System.IO.Path.GetDirectoryName(path)!);
            // A different directory access mask would re-enable inheritance
            // propagation. Never fall back if this documented mode is refused.
            // READ_DATA is required for Windows data-sharing checks to reject
            // an already-open WRITE_DATA handle; READ_CONTROL/WRITE_DAC alone
            // do not participate. No data-write permission is requested.
            // Tightening a DACL cannot revoke an existing writer's rights.
            uint share=writable && !directory?1u:3u;
            _handle=CreateFile(path,writable?(directory?0x02000000u:0x00060001u):0x00020000u,share,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
            if(_handle.IsInvalid){
                int error=Marshal.GetLastWin32Error();_handle.Dispose();
                throw new IOException(error is 32 or 33?"UU_PATH_FILES_IN_USE":error==5?"UU_PATH_ACCESS_DENIED":"UU_PATH_OBJECT_LOCK_FAILED");
            }
            try{
                Identity=IdentityNow();
                var fs=new StringBuilder(32);
                if(!VolumeInformation(_handle,null,0,out _,out _,out _,fs,32) || fs.ToString()!="NTFS")throw new IOException("UU_PATH_VOLUME_REFUSED");
                CheckPath();
            }catch{_handle.Dispose();throw;}
        }
        private string IdentityNow()
        {
            if(!GetFileInformationByHandle(_handle,out var info) || !PathIdInformation(_handle,18,out var id,(uint)Marshal.SizeOf<PathId>()))throw new IOException("UU_PATH_IDENTITY_UNAVAILABLE");
            if((info.Attributes&0x400)!=0 || ((info.Attributes&0x10)!=0)!=Directory || !Directory && info.Links!=1)throw new IOException("UU_REPAIR_LINK_REFUSED");
            return $"{id.Volume:X16}:{id.FileId:D}";
        }
        private void CheckPath()
        {
            var path=new StringBuilder(32768);uint count=FinalPath(_handle,path,32768,0);
            if(count==0 || count>=32768 || !path.ToString().StartsWith(@"\\?\",StringComparison.Ordinal) || !string.Equals(path.ToString()[4..],Path,StringComparison.OrdinalIgnoreCase))throw new IOException("UU_PATH_FINAL_PATH_MISMATCH");
        }
        internal void Revalidate()
        {
            if(IdentityNow()!=Identity)throw new IOException("UU_REPAIR_OBJECT_CHANGED");
            CheckPath();
        }
        internal string Read()
        {
            uint error=GetSecurityInfo(_handle,1,7,out _,out _,out _,out _,out var descriptor);
            if(error!=0)throw new IOException("UU_REPAIR_ACL_READ_FAILED");
            try{
                byte[] bytes=new byte[GetSecurityDescriptorLength(descriptor)];Marshal.Copy(descriptor,bytes,0,bytes.Length);
                return EncodeDescriptor(new RawSecurityDescriptor(bytes,0));
            }finally{LocalFree(descriptor);}
        }
        internal void Write(string sddl)
        {
            if(!_writable)throw new IOException("UU_PATH_READ_ONLY_OBJECT");
            var descriptor=DecodeDescriptor(sddl);byte[] bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);
            IntPtr buffer=Marshal.AllocHGlobal(bytes.Length);
            try{
                Marshal.Copy(bytes,0,buffer,bytes.Length);
                if(!GetSecurityDescriptorDacl(buffer,out bool present,out var dacl,out _) || !present || dacl==IntPtr.Zero)throw new IOException("UU_REPAIR_ACL_WRITE_REFUSED");
                uint flags=4u|(descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected)?0x80000000u:0x20000000u);
                if(SetSecurityInfo(_handle,1,flags,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero)!=0)throw new IOException("UU_REPAIR_ACL_WRITE_FAILED");
            }finally{Marshal.FreeHGlobal(buffer);}
        }
        public void Dispose()=>_handle.Dispose();
    }

    private static string EncodeDescriptor(RawSecurityDescriptor descriptor)
    {
        byte[] bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);string value=Convert.ToBase64String(bytes);
        if(value.Length>65536)throw new IOException("UU_PATH_DESCRIPTOR_LIMIT");
        return value;
    }
    private static RawSecurityDescriptor DecodeDescriptor(string value)
    {
        try{return new RawSecurityDescriptor(Convert.FromBase64String(value),0);}
        catch(Exception error) when(error is ArgumentException or FormatException){throw new IOException("UU_PATH_DESCRIPTOR_INVALID");}
    }
    private static RawSecurityDescriptor CheckedDescriptor(string sddl)
    {
        var descriptor=DecodeDescriptor(sddl);
        if(EncodeDescriptor(descriptor)!=sddl)throw new IOException("UU_PATH_DESCRIPTOR_INVALID");
        if(!TrustedSid(descriptor.Owner) || !descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent) || descriptor.DiscretionaryAcl is null)throw new IOException("UU_REPAIR_OWNER_REFUSED");
        return descriptor;
    }
    private static void CheckVolumeSource(string sddl)
    {
        var descriptor=CheckedDescriptor(sddl);
        foreach(GenericAce entry in descriptor.DiscretionaryAcl!){
            if(entry is not CommonAce ace || ace.IsCallback)throw new IOException("UU_PATH_ACL_PATTERN_REFUSED");
            if(ace.AceQualifier!=AceQualifier.AccessAllowed || ace.AceFlags.HasFlag(AceFlags.InheritOnly) || TrustedSid(ace.SecurityIdentifier))continue;
            uint mask=unchecked((uint)ace.AccessMask);
            if((mask&0x50000000)!=0 || (mask&(uint)(FileSystemRights.DeleteSubdirectoriesAndFiles|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership))!=0)throw new IOException("UU_PATH_VOLUME_AUTHORITY_REFUSED");
        }
    }
    private static string NarrowDescriptor(string sddl,bool ancestor)
    {
        var descriptor=CheckedDescriptor(sddl);var original=descriptor.DiscretionaryAcl!;var result=new RawAcl(original.Revision,original.Count);
        if((descriptor.ControlFlags&(ControlFlags.DiscretionaryAclDefaulted|ControlFlags.DiscretionaryAclAutoInheritRequired))!=0)throw new IOException("UU_PATH_ACL_PATTERN_REFUSED");
        foreach(GenericAce entry in original){
            if(entry is not CommonAce current || current.IsCallback || current.AceQualifier is not (AceQualifier.AccessAllowed or AceQualifier.AccessDenied))throw new IOException("UU_PATH_ACL_PATTERN_REFUSED");
            byte[] bytes=new byte[current.BinaryLength];current.GetBinaryForm(bytes,0);var ace=(CommonAce)GenericAce.CreateFromBinaryForm(bytes,0);
            if((ace.AceFlags&~(AceFlags.ObjectInherit|AceFlags.ContainerInherit|AceFlags.InheritOnly|AceFlags.Inherited))!=0)throw new IOException("UU_PATH_ACL_PATTERN_REFUSED");
            uint mask=unchecked((uint)ace.AccessMask);
            if(ace.AceQualifier==AceQualifier.AccessAllowed && !TrustedSid(ace.SecurityIdentifier)){
                bool writes=(mask&0x50000000)!=0 || (mask&(uint)AnyWrite)!=0;
                bool known=KnownGroups.Contains(ace.SecurityIdentifier.Value) && (mask&~(uint)FileSystemRights.Synchronize)==(uint)FileSystemRights.Modify;
                if(writes && !known)throw new IOException("UU_PATH_ACL_PATTERN_REFUSED");
                if(known && (!ancestor || !ace.AceFlags.HasFlag(AceFlags.InheritOnly))){
                    // Shared ancestors may only have the exact separate
                    // current-object M and inherit-only OI/CI M layout.
                    if(ancestor && (ace.AceFlags&~AceFlags.Inherited)!=AceFlags.None)throw new IOException("UU_PATH_ANCESTOR_PATTERN_REFUSED");
                    ace.AccessMask=(int)FileSystemRights.ReadAndExecute|(ace.AccessMask&(int)FileSystemRights.Synchronize);
                }
                if(ancestor && known && ace.AceFlags.HasFlag(AceFlags.InheritOnly) &&
                    (ace.AceFlags&~AceFlags.Inherited)!=(AceFlags.ObjectInherit|AceFlags.ContainerInherit|AceFlags.InheritOnly))throw new IOException("UU_PATH_ANCESTOR_PATTERN_REFUSED");
            }
            ace.AceFlags&=~AceFlags.Inherited;result.InsertAce(result.Count,ace);
        }
        if(ancestor && !HasEffectiveWrite(sddl))return sddl;
        descriptor.DiscretionaryAcl=result;
        descriptor.SetFlags((descriptor.ControlFlags|ControlFlags.DiscretionaryAclProtected)&~ControlFlags.DiscretionaryAclAutoInheritRequired);
        return EncodeDescriptor(descriptor);
    }

    private sealed class PathCapture : IDisposable
    {
        internal PathJournal Journal {get;}
        internal Dictionary<string,PathLocked> Objects {get;}=new(StringComparer.OrdinalIgnoreCase);
        internal PathCapture(string root,bool writable)
        {
            string[] ancestors=AdvancedAncestors(root);string drive=System.IO.Path.GetPathRoot(root)!;string volume=PathVolume(drive);
            if(volume==PathVolume(System.IO.Path.GetPathRoot(Environment.SystemDirectory)!))throw new IOException("UU_PATH_VOLUME_REFUSED");
            PathObject Add(string path,string role,bool directory,bool write,bool narrow){
                var item=new PathLocked(path,directory,write,volume);Objects.Add(path,item);
                string before=item.Read();CheckedDescriptor(before);
                return new(role,path,directory,volume,item.Identity,before,narrow?NarrowDescriptor(before,role is "program-files" or "vendor"):before);
            }
            try{
                var source=Add(drive,"volume-root",true,false,false);CheckVolumeSource(source.Before);
                var parents=ancestors.Select((path,index)=>Add(path,index==0?"program-files":"vendor",true,writable,true)).ToArray();
                if(parents.All(item=>!HasEffectiveWrite(item.Before)))throw new IOException("UU_PATH_ANCESTORS_ALREADY_SAFE");
                var tree=TreePaths(root).Select(path=>Add(path,path==root?"uu-root":Directory.Exists(path)?"uu-directory":"uu-file",Directory.Exists(path),writable,true)).ToArray();
                if(!SignedMain(root))throw new IOException("UU_PATH_SIGNED_MAIN_REQUIRED");
                Journal=new(2,"pending",root,source,parents,tree);
            }catch{Dispose();throw;}
        }
        public void Dispose(){foreach(var item in Objects.Values)item.Dispose();}
    }
    private static bool HasEffectiveWrite(string sddl)
    {
        var security=new DirectorySecurity();var descriptor=DecodeDescriptor(sddl);byte[] bytes=new byte[descriptor.BinaryLength];descriptor.GetBinaryForm(bytes,0);security.SetSecurityDescriptorBinaryForm(bytes);return UuDiscovery.UnsafeWriter(security);
    }
    private static string[] TreePaths(string root)
    {
        var paths=new List<string>{root};
        var options=new EnumerationOptions{RecurseSubdirectories=true,IgnoreInaccessible=false,AttributesToSkip=0,MaxRecursionDepth=16};
        foreach(string path in Directory.EnumerateFileSystemEntries(root,"*",options)){
            if(paths.Count>=MaximumObjects || path.Length>2048)throw new IOException("UU_REPAIR_TREE_LIMIT");
            if(File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))throw new IOException("UU_REPAIR_LINK_REFUSED");
            paths.Add(path);
            if(Directory.Exists(path) && Path.GetRelativePath(root,path).Count(c=>c==Path.DirectorySeparatorChar)>=15 && Directory.EnumerateFileSystemEntries(path).Any())throw new IOException("UU_REPAIR_TREE_LIMIT");
        }
        return paths.OrderBy(path=>path.Count(c=>c==Path.DirectorySeparatorChar)).ThenBy(path=>path,StringComparer.OrdinalIgnoreCase).ToArray();
    }
    private static bool SignedMain(string root)
    {
        int count=0;var options=new EnumerationOptions{RecurseSubdirectories=true,MaxRecursionDepth=4,IgnoreInaccessible=false,AttributesToSkip=FileAttributes.ReparsePoint};
        foreach(string path in Directory.EnumerateFiles(root,"GameViewer.exe",options)){
            if(++count>32)throw new IOException("UU_INVENTORY_LIMIT");
            if(UuDiscovery.SignatureIssue(path) is null)return true;
        }
        return false;
    }
    internal static string[] EligibleAdvancedRoots()=>EligibleAdvancedRoots(out _);
    private static string[] EligibleAdvancedRoots(out string? refusal)
    {
        var roots=new List<string>();refusal=null;
        foreach(string root in UuDiscovery.InstallationRoots().Distinct(StringComparer.OrdinalIgnoreCase)){
            try{AdvancedAncestors(root);}catch{continue;}
            try{using var plan=new PathCapture(root,false);roots.Add(root);}
            catch(UnauthorizedAccessException){refusal??="UU_PATH_ACCESS_DENIED";}
            catch(IOException error){refusal??=PathRefusal(error.Message);}
            catch{refusal??="UU_PATH_INSPECTION_FAILED";}
        }
        if(roots.Count>1)throw new IOException("UU_PATH_ROOTS_REFUSED");
        return roots.ToArray();
    }
    private static string PathRefusal(string value)=>value switch{
        "UU_PATH_FILES_IN_USE" or "UU_PATH_ACCESS_DENIED" or "UU_PATH_OBJECT_LOCK_FAILED" or
        "UU_PATH_VOLUME_REFUSED" or "UU_PATH_VOLUME_AUTHORITY_REFUSED" or "UU_REPAIR_OWNER_REFUSED" or
        "UU_PATH_ACL_PATTERN_REFUSED" or "UU_PATH_ANCESTOR_PATTERN_REFUSED" or "UU_PATH_SIGNED_MAIN_REQUIRED" or
        "UU_REPAIR_LINK_REFUSED" or "UU_REPAIR_TREE_LIMIT" or "UU_PATH_DESCRIPTOR_LIMIT" or "UU_PATH_DESCRIPTOR_INVALID" or
        "UU_PATH_FINAL_PATH_MISMATCH" or "UU_PATH_IDENTITY_UNAVAILABLE" or "UU_PATH_ANCESTORS_ALREADY_SAFE" or
        "REPARSE_POINT_REJECTED"=>value,
        _=>"UU_PATH_INSPECTION_FAILED"};
    private static IEnumerable<PathObject> MutableObjects(PathJournal journal)=>journal.Ancestors.Concat(journal.Entries);
    private static void SaveAdvanced(PathJournal journal)
    {
        ValidateAdvanced(journal);
        byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(journal,PathJson);
        if(bytes.Length>MaximumBytes)throw new IOException("UU_REPAIR_BACKUP_LIMIT");
        VerifyMetadataIfPresent(Backup);VerifyMetadataIfPresent(Backup+".pending");
        Platform.VerifyProtected(Platform.StateRoot);Platform.WriteAtomic(Backup,bytes);
        using var verified=OpenFixedMetadata(Backup);
    }
    private static void CheckUniqueJson(JsonElement item)
    {
        if(item.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);foreach(var p in item.EnumerateObject()){if(!names.Add(p.Name))throw new IOException("UU_REPAIR_BACKUP_REFUSED");CheckUniqueJson(p.Value);}}
        else if(item.ValueKind==JsonValueKind.Array)foreach(var value in item.EnumerateArray())CheckUniqueJson(value);
    }
    private static void RequireFields(JsonElement item,params string[] names)
    {
        if(item.ValueKind!=JsonValueKind.Object || item.EnumerateObject().Count()!=names.Length || names.Any(name=>!item.TryGetProperty(name,out _)))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
    }
    private static PathJournal LoadAdvanced()
    {
        if(BackupSchema()!=2)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        byte[] bytes=ReadFixedMetadata(Backup);using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=16});CheckUniqueJson(document.RootElement);
        var top=document.RootElement;RequireFields(top,"Schema","Phase","Root","SourceParent","Ancestors","Entries");
        RequireFields(top.GetProperty("SourceParent"),"Role","Path","Directory","Volume","Identity","Before","After");
        foreach(string name in new[]{"Ancestors","Entries"}){
            var values=top.GetProperty(name);
            if(values.ValueKind!=JsonValueKind.Array)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
            foreach(var item in values.EnumerateArray())RequireFields(item,"Role","Path","Directory","Volume","Identity","Before","After");
        }
        var journal=JsonSerializer.Deserialize<PathJournal>(bytes,PathJson) ?? throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        return ValidateAdvanced(journal);
    }
    private static PathJournal ValidateAdvanced(PathJournal journal)
    {
        if(journal.Schema!=2 || journal.Phase is not ("pending" or "applied" or "restoring" or "restored") || journal.Ancestors is not {Length:2} || journal.Entries is not {Length:>0 and <=MaximumObjects} || journal.SourceParent is null || journal.Ancestors.Any(item=>item is null) || journal.Entries.Any(item=>item is null))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        string[] ancestors=AdvancedAncestors(journal.Root);string drive=Path.GetPathRoot(journal.Root)!;
        var source=journal.SourceParent;
        if(source.Role!="volume-root" || source.Path!=drive || !source.Directory || source.Before is not {Length:>0 and <=65536} || source.Before!=source.After || journal.Ancestors[0].Role!="program-files" || journal.Ancestors[0].Path!=ancestors[0] || journal.Ancestors[1].Role!="vendor" || journal.Ancestors[1].Path!=ancestors[1])throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        CheckVolumeSource(source.Before);
        var paths=new HashSet<string>(StringComparer.OrdinalIgnoreCase){source.Path};
        var entries=journal.Entries;
        if(entries[0].Path!=journal.Root || entries[0].Role!="uu-root" || !entries[0].Directory)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        if(source.Volume is not {Length:49} || !source.Volume.StartsWith(@"\\?\VOLUME{",StringComparison.Ordinal) || !source.Volume.EndsWith(@"}\",StringComparison.Ordinal) || !Guid.TryParseExact(source.Volume.Substring(11,36),"D",out var volumeId) || source.Volume!=@"\\?\VOLUME{"+volumeId.ToString("D").ToUpperInvariant()+@"}\" || !ValidPathIdentity(source.Identity) || source.Volume==PathVolume(Path.GetPathRoot(Environment.SystemDirectory)!))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        if(!journal.Entries.Select(item=>item.Path).SequenceEqual(journal.Entries.Select(item=>item.Path).OrderBy(path=>path.Count(c=>c==Path.DirectorySeparatorChar)).ThenBy(path=>path,StringComparer.OrdinalIgnoreCase),StringComparer.OrdinalIgnoreCase))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        foreach(var item in MutableObjects(journal)){
            if(item is null || string.IsNullOrEmpty(item.Path) || !paths.Add(item.Path) || item.Path!=Path.GetFullPath(item.Path) || item.Path.Length>2048 || item.Volume!=source.Volume || !ValidPathIdentity(item.Identity))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
            bool ancestor=item.Role is "program-files" or "vendor";
            if(ancestor){int index=item.Role=="program-files"?0:1;if(!item.Directory || item.Path!=ancestors[index] || journal.Ancestors[index]!=item)throw new IOException("UU_REPAIR_BACKUP_REFUSED");}
            else if(item.Path!=journal.Root && (!item.Path.StartsWith(journal.Root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase) || item.Role!=(item.Directory?"uu-directory":"uu-file")))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
            if(item.Before is not {Length:>0 and <=65536} || item.After is not {Length:>0 and <=65536} || NarrowDescriptor(item.Before,ancestor)!=item.After)throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        }
        foreach(var item in journal.Entries.Skip(1))if(!journal.Entries.Any(parent=>parent.Directory && string.Equals(parent.Path,Path.GetDirectoryName(item.Path),StringComparison.OrdinalIgnoreCase)))throw new IOException("UU_REPAIR_BACKUP_REFUSED");
        return journal;
    }
    private static bool ValidPathIdentity(string value)=>value is {Length:53} && value[16]==':' && ulong.TryParse(value[..16],System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out _) && Guid.TryParseExact(value[17..],"D",out _);

#if ORACLE_PRODUCT_TESTS
    internal static Action<string>? AdvancedTestHook;
#endif
    private static void AdvancedStage(string stage)
    {
#if ORACLE_PRODUCT_TESTS
        AdvancedTestHook?.Invoke(stage);
#endif
    }
    private static void VerifyObject(PathLocked handle,PathObject item,string expected)
    {
        handle.Revalidate();
        if(handle.Identity!=item.Identity || handle.Volume!=item.Volume)throw new IOException("UU_REPAIR_OBJECT_CHANGED");
        if(handle.Read()!=expected)throw new IOException("UU_REPAIR_ACL_CHANGED");
    }
    private static void VerifySource(PathJournal journal,Dictionary<string,PathLocked> objects)
    {
        if(PathVolume(journal.SourceParent.Path)!=journal.SourceParent.Volume)throw new IOException("UU_PATH_VOLUME_REFUSED");
        VerifyObject(objects[journal.SourceParent.Path],journal.SourceParent,journal.SourceParent.Before);
    }
    private static void RollbackAdvanced(PathJournal journal,Dictionary<string,PathLocked> objects,List<PathObject> written)
    {
        VerifySource(journal,objects);
        var changed=new List<PathObject>();
        foreach(var item in written){
            var handle=objects[item.Path];handle.Revalidate();
            if(handle.Identity!=item.Identity)throw new IOException("UU_REPAIR_OBJECT_CHANGED");
            string current=handle.Read();
            if(current==item.After)changed.Add(item);
            else if(current!=item.Before)throw new IOException("UU_REPAIR_ACL_CHANGED");
        }
        var changedPaths=changed.Select(item=>item.Path).ToHashSet(StringComparer.OrdinalIgnoreCase);
        // A source directory changed by another actor cannot be used to
        // re-enable inheritance during rollback. Do not overwrite that change.
        foreach(var item in MutableObjects(journal).Where(item=>item.Directory))VerifyObject(objects[item.Path],item,changedPaths.Contains(item.Path)?item.After:item.Before);
        foreach(var item in changed){
            VerifySource(journal,objects);
            string parentPath=Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(item.Path))!;
            var parent=parentPath==Path.TrimEndingDirectorySeparator(journal.SourceParent.Path)?journal.SourceParent:MutableObjects(journal).FirstOrDefault(candidate=>string.Equals(candidate.Path,parentPath,StringComparison.OrdinalIgnoreCase));
            if(parent is null)throw new IOException("UU_PATH_SOURCE_PARENT_CHANGED");
            VerifyObject(objects[parent.Path],parent,parent.Before);
            VerifyObject(objects[item.Path],item,item.After);objects[item.Path].Write(item.Before);VerifyObject(objects[item.Path],item,item.Before);
        }
        foreach(var item in changed)VerifyObject(objects[item.Path],item,item.Before);
    }
    internal static void ApplyAdvanced(string[] roots)
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();
        if(roots.Length!=1 || !roots.SequenceEqual(EligibleAdvancedRoots(),StringComparer.OrdinalIgnoreCase))throw new IOException("UU_REPAIR_SELECTION_CHANGED");
        if(BackupSchema()!=0 && BackupActive())throw new IOException("UU_REPAIR_BACKUP_EXISTS");
        using var capture=new PathCapture(roots[0],true);var journal=capture.Journal;var objects=capture.Objects;var written=new List<PathObject>();
        SaveAdvanced(journal);
        try{
            AdvancedStage("before_first_write");VerifySource(journal,objects);
            foreach(var item in MutableObjects(journal))VerifyObject(objects[item.Path],item,item.Before);
            if(!TreePaths(journal.Root).SequenceEqual(journal.Entries.Select(item=>item.Path),StringComparer.OrdinalIgnoreCase) || !SignedMain(journal.Root))throw new IOException("UU_PATH_TREE_CHANGED");
            int parent=0;
            foreach(var item in MutableObjects(journal)){
                VerifySource(journal,objects);VerifyObject(objects[item.Path],item,item.Before);
                if(item.Before!=item.After){written.Add(item);objects[item.Path].Write(item.After);VerifyObject(objects[item.Path],item,item.After);}
                AdvancedStage(item.Role is "program-files" or "vendor"?$"ancestor_{parent++}_written":"uu_object_written");
            }
            AdvancedStage("before_commit");VerifySource(journal,objects);
            if(!TreePaths(journal.Root).SequenceEqual(journal.Entries.Select(item=>item.Path),StringComparer.OrdinalIgnoreCase))throw new IOException("UU_PATH_TREE_CHANGED");
            foreach(var item in MutableObjects(journal))VerifyObject(objects[item.Path],item,item.After);
            if(!UuDiscovery.Discover().Paths.Any(path=>path.StartsWith(journal.Root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)))throw new IOException("UU_REPAIR_NOT_VERIFIED");
            SaveAdvanced(journal with{Phase="applied"});
        }catch{
            try{RollbackAdvanced(journal,objects,written);SaveAdvanced(journal with{Phase="restored"});}
            catch{throw new IOException("UU_PATH_ROLLBACK_NOT_VERIFIED");}
            throw;
        }
    }
    private static void RestoreAdvanced()
    {
        if(!Platform.IsAdmin)throw new UnauthorizedAccessException();var journal=LoadAdvanced();
        if(journal.Phase=="restored")throw new IOException("UU_REPAIR_ALREADY_RESTORED");
        var objects=new Dictionary<string,PathLocked>(StringComparer.OrdinalIgnoreCase);var written=new List<PathObject>();
        try{
            foreach(var item in new[]{journal.SourceParent}.Concat(MutableObjects(journal))){
                var handle=new PathLocked(item.Path,item.Directory,item.Role!="volume-root",item.Volume);objects.Add(item.Path,handle);handle.Revalidate();
                if(handle.Identity!=item.Identity)throw new IOException("UU_REPAIR_OBJECT_CHANGED");
                string current=handle.Read();
                if(item.Role=="volume-root" ? current!=item.Before : journal.Phase=="applied" ? current!=item.After : current!=item.Before && current!=item.After)throw new IOException("UU_REPAIR_ACL_CHANGED");
                if(item.Before!=item.After && current==item.After)written.Add(item);
            }
            VerifySource(journal,objects);SaveAdvanced(journal with{Phase="restoring"});
            RollbackAdvanced(journal,objects,written);SaveAdvanced(journal with{Phase="restored"});
        }finally{foreach(var item in objects.Values)item.Dispose();}
    }
}
