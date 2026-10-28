// Non-shipped native NTFS fixture. Only the disposable VHD created by the
// accompanying GitHub-hosted script is accepted. Downloaded UU is never run.
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using OracleProxy.Product;

internal static class UuPathProtectionTests
{
    private const string Digest="64F918B80A99A570DD43A0CA0C8C4FAC5B9B734AD6308E0F5C69BC0BE6CE5167";
    private const string RegistryPath=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OracleProxy.GameViewerPathFixture";
    private static readonly SecurityIdentifier Admin=new("S-1-5-32-544");
    private static readonly string[] Known={"S-1-5-11","S-1-5-32-545"};
    private sealed record State(string Identity,string Binary,string Dacl,int Flags,string Owner,string Group);
    private static string _volume="",_root="",_programs="",_vendor="",_uu="",_exe="",_other="";
    private static string Backup=>Path.Combine(Platform.StateRoot,"uu-permissions-backup.json");
    private static void Check(bool value,string code){if(!value)throw new IOException(code);}
    private static void Pass(string code)=>Console.WriteLine(code+"=PASS");
    internal static int Run(string drive,string expectedVolume)
    {
        bool madeState=false,registered=false;FileStream? maintenance=null;
        try{
            VerifyOwnedVolume(drive,expectedVolume);
            if(File.Exists(Backup))throw new IOException("PREEXISTING_JOURNAL_REFUSED");
            if(!Directory.Exists(Platform.StateRoot)){Directory.CreateDirectory(Platform.StateRoot);Platform.Protect(Platform.StateRoot,false);madeState=true;}
            Platform.VerifyProtected(Platform.StateRoot);maintenance=UuAclRepair.AcquireMaintenance();
            using(var old=Registry.LocalMachine.OpenSubKey(RegistryPath))Check(old is null,"PREEXISTING_REGISTRY_FIXTURE_REFUSED");
            BuildTree();
            using(var key=Registry.LocalMachine.CreateSubKey(RegistryPath)){key.SetValue("DisplayName","GameViewer path protection fixture");key.SetValue("InstallLocation",_uu);}
            registered=true;
            Check(ReadOnlyGenericIoPresent(_programs) && ReadOnlyGenericIoPresent(_vendor),"REAL_PARENT_RAW_GENERIC_READ_EXECUTE_IO_NOT_REPRODUCED");
            Check(UuDiscovery.SignatureIssue(_exe) is null,"FIXED_OFFICIAL_NETEASE_SIGNATURE_NOT_ACCEPTED");
            Check(UuDiscovery.UnsafeWriter(new DirectoryInfo(_programs).GetAccessControl()) && UuDiscovery.UnsafeWriter(new DirectoryInfo(_vendor).GetAccessControl()),"REAL_PROGRAM_FILES_AND_VENDOR_MODIFY_NOT_REPRODUCED");
            string? initialIssue=UuDiscovery.Inspect(_exe)?.Code;
            Console.WriteLine("INITIAL_UU_UNSAFE_CODE="+(initialIssue is "UU_EXECUTABLE_WRITABLE" or "UU_DIRECTORY_WRITABLE"?initialIssue:"UNEXPECTED"));
            Check(initialIssue is "UU_EXECUTABLE_WRITABLE" or "UU_DIRECTORY_WRITABLE" && !UuDiscovery.Trusted(_exe),"INHERITED_PARENT_MODIFY_NOT_REPRODUCED");
            Check(UuAclRepair.EligibleRoots().Length==0,"LEGACY_REPAIR_UNEXPECTEDLY_ACCEPTED_UNSAFE_ANCESTORS");
            Check(UuAclRepair.EligibleAdvancedRoots().SequenceEqual(new[]{_uu},StringComparer.OrdinalIgnoreCase),"ADVANCED_ROOT_NOT_ELIGIBLE");
            Check(UuAclRepair.AdvancedAncestors(_uu).SequenceEqual(new[]{_programs,_vendor},StringComparer.OrdinalIgnoreCase),"ADVANCED_ANCESTORS_NOT_EXACT");
            Pass("REAL_CUSTOM_DRIVE_PARENT_INHERITED_MODIFY_REPRODUCED_WITH_SIGNED_NEVER_EXECUTED_UU");
            NativePropagationContract();
            var before=CaptureTree();
            OccupiedDirectoryRefusal(before);
            ZeroWriteRefusals(before);
            UuAclRepair.ApplyAdvanced(new[]{_uu});
            Check(ReadOnlyGenericIoPresent(_programs) && ReadOnlyGenericIoPresent(_vendor),"READONLY_GENERIC_IO_WAS_MAPPED_OR_REMOVED");
            Check(UuDiscovery.Trusted(_exe),"LEGACY_UU_TRUST_DID_NOT_PASS_AFTER_ADVANCED_PROTECTION");
            SameSiblings(before,"ADVANCED_APPLY_CHANGED_SIBLING_SECURITY");
            Check(Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(_exe)))==Digest,"UU_BYTES_CHANGED");
            OrdinaryUserProof();
            UuAclRepair.Restore();SameTree(before,"ADVANCED_EXACT_ROLLBACK_FAILED");RemoveOwnedJournal();
            Pass("REAL_APPLY_PASSES_EXISTING_UU_TRUST_PRESERVES_SIBLING_BINARY_SECURITY_AND_ROLLS_BACK_EXACTLY");
            FaultAndCasProof(before);
            MetadataProtectionProof(before);
            UnprotectedAncestorProof(before);
            Pass("REAL_OWNED_VHD_NTFS_ADVANCED_UU_PATH_PROTECTION_COMPLETE");return 0;
        }catch(Exception error){Console.Error.WriteLine("UU_PATH_FIXTURE_FAILED="+error.GetType().Name+":"+error.Message);return 1;}
        finally{
            UuAclRepair.AdvancedTestHook=null;
            if(registered)Registry.LocalMachine.DeleteSubKeyTree(RegistryPath,false);
            // Every journal in this process was created only after a verified
            // empty starting path; never delete someone else's preexisting file.
            if(maintenance is not null && File.Exists(Backup))File.Delete(Backup);
            maintenance?.Dispose();
            if(madeState && Directory.Exists(Platform.StateRoot) && !Directory.EnumerateFileSystemEntries(Platform.StateRoot).Any())Directory.Delete(Platform.StateRoot);
        }
    }
    private static void VerifyOwnedVolume(string drive,string expected)
    {
        Check(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")=="true" && Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")=="github-hosted" && Platform.IsAdmin,"DISPOSABLE_GITHUB_HOSTED_ADMIN_REQUIRED");
        _volume=Path.GetFullPath(drive);Check(_volume==Path.GetPathRoot(_volume) && _volume.Length==3,"ONLY_DRIVE_ROOT_ALLOWED");
        Check(!string.Equals(_volume,Path.GetPathRoot(Environment.SystemDirectory),StringComparison.OrdinalIgnoreCase),"SYSTEM_VOLUME_REFUSED");
        var actual=new StringBuilder(128);Check(GetVolumeNameForVolumeMountPoint(_volume,actual,actual.Capacity),"VOLUME_GUID_QUERY_FAILED");
        Check(actual.ToString().Equals(expected.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase),"OWNED_VOLUME_GUID_MISMATCH");
        var system=new StringBuilder(128);Check(GetVolumeNameForVolumeMountPoint(Path.GetPathRoot(Environment.SystemDirectory)!,system,system.Capacity) && !actual.ToString().Equals(system.ToString(),StringComparison.OrdinalIgnoreCase),"SYSTEM_VOLUME_ALIAS_REFUSED");
        var label=new StringBuilder(128);var format=new StringBuilder(128);Check(GetVolumeInformation(_volume,label,label.Capacity,out _,out _,out _,format,format.Capacity) && format.ToString()=="NTFS","NATIVE_NTFS_VOLUME_REQUIRED");
        string marker=Path.Combine(_volume,".oracle-uu-vhd-fixture.json");Check(File.Exists(marker) && !File.GetAttributes(marker).HasFlag(FileAttributes.ReparsePoint),"OWNED_VOLUME_MARKER_REQUIRED");
        using var json=JsonDocument.Parse(File.ReadAllText(marker));var value=json.RootElement;
        string token=value.GetProperty("token").GetString()??"";
        Check(value.GetProperty("schema").GetInt32()==1 && Guid.TryParseExact(token,"N",out _) && label.ToString()=="OPUPTEST_"+token[..12] && value.GetProperty("label").GetString()==label.ToString() && string.Equals(value.GetProperty("volume").GetString(),actual.ToString(),StringComparison.OrdinalIgnoreCase),"OWNED_VOLUME_MARKER_MISMATCH");
        VerifyVirtualDisk(value.GetProperty("disk").GetUInt32());
        var target=new StringBuilder(1024);Check(QueryDosDevice(_volume[..2],target,target.Capacity)>0 && !target.ToString().StartsWith(@"\??\",StringComparison.Ordinal),"SUBST_FIXTURE_ROOT_REFUSED");
        _root=Path.Combine(_volume,"Program Files (x86)");_programs=_root;_vendor=Path.Combine(_root,"Netease");_uu=Path.Combine(_vendor,"GameViewer");_exe=Path.Combine(_uu,"GameViewer.exe");_other=Path.Combine(_root,"OtherApp");
        Check(!Directory.Exists(_root),"EXISTING_FIXTURE_TREE_REFUSED");
        Check(Platform.Pinned(Path.Combine(_volume,"official.exe"),Digest),"PINNED_OFFICIAL_BYTES_REQUIRED");
    }
    private static void VerifyVirtualDisk(uint expectedDisk)
    {
        // Read-only SDK storage queries on the already GUID-checked volume.
        // STORAGE_DEVICE_DESCRIPTOR.BusType is a DWORD at offset 28; version,
        // size and returned length are checked before consuming that field.
        using var volume=CreateFile(@"\\.\"+_volume[..2],0,7,IntPtr.Zero,3,0,IntPtr.Zero);
        Check(!volume.IsInvalid,"FIXTURE_VOLUME_DEVICE_QUERY_FAILED");
        var number=new byte[12];Check(DeviceIoControl(volume,0x002D1080,null,0,number,number.Length,out uint size,IntPtr.Zero) && size>=12 && BitConverter.ToUInt32(number,0)==7 && BitConverter.ToUInt32(number,4)==expectedDisk && BitConverter.ToUInt32(number,8)>0,"VOLUME_DEVICE_NUMBER_MISMATCH");
        var query=new byte[12];var descriptor=new byte[4096];
        Check(DeviceIoControl(volume,0x002D1400,query,query.Length,descriptor,descriptor.Length,out size,IntPtr.Zero) && size>=36 && BitConverter.ToUInt32(descriptor,0)>=36 && BitConverter.ToUInt32(descriptor,4)>=36 && BitConverter.ToUInt32(descriptor,4)<=size && BitConverter.ToUInt32(descriptor,28)==15,"NATIVE_FILE_BACKED_VIRTUAL_DISK_REQUIRED");
    }
    private static DirectorySecurity RootAcl(bool writable)
    {
        var acl=new DirectorySecurity();acl.SetOwner(Admin);acl.SetAccessRuleProtection(true,false);
        foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        foreach(string sid in Known)acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),writable?FileSystemRights.Modify:FileSystemRights.ReadAndExecute,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        return acl;
    }
    private static State AncestorTemplate(State original)
    {
        // Reproduce the user's real native ACL, including raw GR|GE on the
        // inherited, inherit-only Users ACE. DirectorySecurity access rules
        // would map generic masks and miss this important preflight boundary.
        var raw=new RawSecurityDescriptor(Convert.FromBase64String(original.Binary),0);var acl=new RawAcl(2,8);
        const AceFlags inherited=AceFlags.Inherited;const AceFlags io=AceFlags.Inherited|AceFlags.InheritOnly|AceFlags.ObjectInherit|AceFlags.ContainerInherit;
        void Add(string sid,int mask,AceFlags flags)=>acl.InsertAce(acl.Count,new CommonAce(flags,AceQualifier.AccessAllowed,mask,new SecurityIdentifier(sid),false,null));
        foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"}){Add(sid,(int)FileSystemRights.FullControl,inherited);Add(sid,(int)FileSystemRights.FullControl,io);}
        Add(Known[0],(int)(FileSystemRights.Modify|FileSystemRights.Synchronize),inherited);Add(Known[0],(int)(FileSystemRights.Modify|FileSystemRights.Synchronize),io);
        Add(Known[1],(int)(FileSystemRights.ReadAndExecute|FileSystemRights.Synchronize),inherited);Add(Known[1],unchecked((int)0xA0000000),io);
        raw.DiscretionaryAcl=acl;raw.SetFlags(raw.ControlFlags|ControlFlags.DiscretionaryAclProtected);var bytes=new byte[raw.BinaryLength];raw.GetBinaryForm(bytes,0);return original with{Binary=Convert.ToBase64String(bytes)};
    }
    private static bool ReadOnlyGenericIoPresent(string path)
    {
        var raw=new RawSecurityDescriptor(Convert.FromBase64String(Read(path).Binary),0);
        return raw.DiscretionaryAcl!.OfType<CommonAce>().Any(ace=>ace.SecurityIdentifier.Value==Known[1] && unchecked((uint)ace.AccessMask)==0xA0000000 && (ace.AceFlags&(AceFlags.ObjectInherit|AceFlags.ContainerInherit|AceFlags.InheritOnly))==(AceFlags.ObjectInherit|AceFlags.ContainerInherit|AceFlags.InheritOnly));
    }
    private static void SetOwner(string path,SecurityIdentifier owner)
    {
        if(Directory.Exists(path)){var acl=new DirectorySecurity();acl.SetOwner(owner);new DirectoryInfo(path).SetAccessControl(acl);}
        else{var acl=new FileSecurity();acl.SetOwner(owner);new FileInfo(path).SetAccessControl(acl);}
    }
    private static void BuildTree()
    {
        Write(_volume,WithAcl(Read(_volume),RootAcl(true)));
        // Construct each source policy before creating its children. Otherwise
        // current-only writes leave stale inherited ACEs whose provenance would
        // change when rollback genuinely re-enables inheritance.
        Directory.CreateDirectory(_programs);Write(_programs,AncestorTemplate(Read(_programs)));
        Directory.CreateDirectory(_vendor);Write(_vendor,AncestorTemplate(Read(_vendor)));
        Directory.CreateDirectory(Path.Combine(_uu,"config"));Directory.CreateDirectory(Path.Combine(_other,"nested"));Directory.CreateDirectory(Path.Combine(_volume,"OtherRootApp"));
        string source=Path.Combine(_volume,"official.exe");File.Copy(source,_exe);File.Delete(source);
        File.WriteAllText(Path.Combine(_uu,"config","remote.ini"),"synthetic config; no credentials");File.WriteAllText(Path.Combine(_other,"nested","data.txt"),"sibling");File.WriteAllText(Path.Combine(_volume,"OtherRootApp","data.txt"),"other root sibling");
        foreach(string path in Paths())SetOwner(path,Admin);
        var markerAcl=new FileSecurity();markerAcl.SetOwner(Admin);markerAcl.SetAccessRuleProtection(true,false);
        foreach(string sid in new[]{"S-1-5-18","S-1-5-32-544"})markerAcl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,AccessControlType.Allow));
        new FileInfo(Path.Combine(_volume,".oracle-uu-vhd-fixture.json")).SetAccessControl(markerAcl);
    }
    private static IEnumerable<string> Paths()
    {
        // Never traverse or alter NTFS's own System Volume Information or any
        // other OS-created metadata. Only these explicitly created fixture
        // trees and the ownership marker belong to this test.
        yield return _volume;string marker=Path.Combine(_volume,".oracle-uu-vhd-fixture.json");if(File.Exists(marker))yield return marker;
        var queue=new Queue<string>();foreach(string owned in new[]{_programs,Path.Combine(_volume,"OtherRootApp")})if(Directory.Exists(owned)){yield return owned;queue.Enqueue(owned);}
        while(queue.TryDequeue(out string? parent))foreach(string path in Directory.EnumerateFileSystemEntries(parent)){
            yield return path;
            if(Directory.Exists(path) && !File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))queue.Enqueue(path);
        }
    }
    private static Dictionary<string,State> CaptureTree()=>Paths().ToDictionary(path=>path,Read,StringComparer.OrdinalIgnoreCase);
    private static void SameTree(Dictionary<string,State> expected,string failure)
    {
        var actual=CaptureTree();Check(actual.Count==expected.Count && expected.All(entry=>actual.TryGetValue(entry.Key,out var found) && found==entry.Value),failure);
    }
    private static void SameSiblings(Dictionary<string,State> expected,string failure)
    {
        foreach(var entry in expected.Where(entry=>entry.Key.Equals(_volume,StringComparison.OrdinalIgnoreCase) || entry.Key.StartsWith(_other,StringComparison.OrdinalIgnoreCase) || entry.Key.StartsWith(Path.Combine(_volume,"OtherRootApp"),StringComparison.OrdinalIgnoreCase)))Check(Read(entry.Key)==entry.Value,failure);
    }
    private static SafeFileHandle Open(string path,uint access,uint share=3)
    {
        var handle=CreateFile(path,access,share,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(handle.IsInvalid){handle.Dispose();throw new IOException("NATIVE_FIXTURE_OPEN_FAILED_"+Marshal.GetLastWin32Error());}return handle;
    }
    private static State Read(string path)
    {
        using var handle=Open(path,0x00020000,7);
        Check(GetFileInformationByHandle(handle,out var info),"NATIVE_FIXTURE_IDENTITY_FAILED");
        Check(GetSecurityInfo(handle,1,7,out _,out _,out _,out _,out var descriptor)==0,"NATIVE_FIXTURE_SECURITY_READ_FAILED");
        try{
            var bytes=new byte[GetSecurityDescriptorLength(descriptor)];Marshal.Copy(descriptor,bytes,0,bytes.Length);var raw=new RawSecurityDescriptor(bytes,0);
            var normalized=new byte[raw.BinaryLength];raw.GetBinaryForm(normalized,0);var dacl=new byte[raw.DiscretionaryAcl!.BinaryLength];raw.DiscretionaryAcl.GetBinaryForm(dacl,0);
            return new($"{info.Volume:X8}:{info.IndexHigh:X8}{info.IndexLow:X8}",Convert.ToBase64String(normalized),Convert.ToBase64String(dacl),(int)raw.ControlFlags,raw.Owner!.Value,raw.Group!.Value);
        }finally{LocalFree(descriptor);}
    }
    private static void Write(string path,State state,uint access=0x02000000)
    {
        using var handle=Open(path,access);byte[] bytes=Convert.FromBase64String(state.Binary);var raw=new RawSecurityDescriptor(bytes,0);IntPtr buffer=Marshal.AllocHGlobal(bytes.Length);
        try{Marshal.Copy(bytes,0,buffer,bytes.Length);Check(GetSecurityDescriptorDacl(buffer,out bool present,out var dacl,out _) && present && dacl!=IntPtr.Zero,"NATIVE_FIXTURE_DACL_REQUIRED");uint flags=4u|((raw.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0?0x80000000u:0x20000000u);Check(SetSecurityInfo(handle,1,flags,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero)==0,"NATIVE_FIXTURE_DACL_WRITE_FAILED");}
        finally{Marshal.FreeHGlobal(buffer);}
    }
    private static State WithAcl(State original,DirectorySecurity acl)
    {
        var raw=new RawSecurityDescriptor(Convert.FromBase64String(original.Binary),0);var modified=new RawSecurityDescriptor(acl.GetSecurityDescriptorSddlForm(AccessControlSections.Access));
        raw.DiscretionaryAcl=modified.DiscretionaryAcl;raw.SetFlags((raw.ControlFlags&~ControlFlags.DiscretionaryAclProtected)|ControlFlags.DiscretionaryAclProtected);
        var bytes=new byte[raw.BinaryLength];raw.GetBinaryForm(bytes,0);return original with{Binary=Convert.ToBase64String(bytes)};
    }
    private static void RestoreTree(Dictionary<string,State> before)
    {
        foreach(var entry in before.OrderBy(entry=>entry.Key.Length))Write(entry.Key,entry.Value);
    }
    private static void NativePropagationContract()
    {
        var before=CaptureTree();State restricted=WithAcl(before[_programs],RootAcl(false));
        Write(_programs,restricted,0x00060000);
        Check(before.Where(entry=>entry.Key.StartsWith(_other,StringComparison.OrdinalIgnoreCase)).Any(entry=>Read(entry.Key)!=entry.Value),"NORMAL_HANDLE_NEGATIVE_CONTROL_DID_NOT_DETECT_REAL_INHERITANCE_PROPAGATION");
        RestoreTree(before);SameTree(before,"NEGATIVE_CONTROL_RESTORE_NOT_EXACT");
        Write(_programs,restricted);SameSiblings(before,"MAXIMUM_ALLOWED_CURRENT_ONLY_PROPAGATED_TO_SIBLINGS");
        Write(_programs,before[_programs]);SameTree(before,"MAXIMUM_ALLOWED_CURRENT_ONLY_ROUNDTRIP_NOT_EXACT");
        Pass("REAL_NTFS_MAXIMUM_ALLOWED_PRESERVES_SIBLING_NATIVE_DESCRIPTOR_OWNER_FLAGS_NORMAL_HANDLE_DETECTS_PROPAGATION");
    }
    private static void RemoveOwnedJournal(){if(File.Exists(Backup))File.Delete(Backup);}
    private static void RefusedWithoutWrites(Dictionary<string,State> expected,string code,string? expectedCode=null)
    {
        State? backup=File.Exists(Backup)?Read(Backup):null;string? content=backup is null?null:Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Backup)));DateTime written=backup is null?default:File.GetLastWriteTimeUtc(Backup);bool refused=false;
        try{UuAclRepair.ApplyAdvanced(new[]{_uu});}catch(IOException error){refused=true;if(expectedCode is not null)Check(error.Message==expectedCode,code+"_WRONG_REFUSAL_REASON");}
        Check(refused,code+"_NOT_REFUSED");SameTree(expected,code+"_MODIFIED_OBJECTS");
        Check(backup is null?!File.Exists(Backup):File.Exists(Backup) && Read(Backup)==backup && File.GetLastWriteTimeUtc(Backup)==written && Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Backup)))==content,code+"_MODIFIED_JOURNAL");
    }
    private static void OccupiedDirectoryRefusal(Dictionary<string,State> before)
    {
        using(var occupied=Open(Path.Combine(_uu,"config"),0x00020001)){
            Check(UuAclRepair.EligibleAdvancedRoots().SequenceEqual(new[]{_uu},StringComparer.OrdinalIgnoreCase),"OCCUPIED_DIRECTORY_READONLY_PREVIEW_FAILED");
            RefusedWithoutWrites(before,"OCCUPIED_NO_DELETE_SHARE_DIRECTORY","UU_PATH_FILES_IN_USE");
        }
        using(var occupied=Open(Path.Combine(_uu,"config","remote.ini"),0x00000002)){
            Check(UuAclRepair.EligibleAdvancedRoots().SequenceEqual(new[]{_uu},StringComparer.OrdinalIgnoreCase),"HELD_WRITE_DATA_READONLY_PREVIEW_FAILED");
            RefusedWithoutWrites(before,"HELD_WRITE_DATA_FILE","UU_PATH_FILES_IN_USE");
        }
        Pass("REAL_OCCUPIED_UU_DIRECTORY_REFUSED_BEFORE_WRITES_WITHOUT_FALLBACK_OR_PROCESS_TERMINATION");
        Pass("REAL_EXISTING_WRITE_DATA_HANDLE_REFUSED_BEFORE_WRITES_OR_JOURNAL_CREATION");
    }
    private static void ZeroWriteRefusals(Dictionary<string,State> before)
    {
        foreach(var rule in new[]{new FileSystemAccessRule(new SecurityIdentifier("S-1-1-0"),FileSystemRights.Modify,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow),new FileSystemAccessRule(new SecurityIdentifier(Known[1]),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow)}){
            var acl=new DirectoryInfo(_uu).GetAccessControl();acl.AddAccessRule(rule);Write(_uu,WithAcl(before[_uu],acl));RefusedWithoutWrites(CaptureTree(),"UNKNOWN_PRINCIPAL_OR_FULL_CONTROL");Write(_uu,before[_uu]);
        }
        foreach(uint genericWrite in new[]{0x40000000u,0x10000000u}){
            var raw=new RawSecurityDescriptor(Convert.FromBase64String(before[_programs].Binary),0);
            raw.DiscretionaryAcl!.InsertAce(raw.DiscretionaryAcl.Count,new CommonAce(AceFlags.ObjectInherit|AceFlags.ContainerInherit|AceFlags.InheritOnly|AceFlags.Inherited,AceQualifier.AccessAllowed,unchecked((int)genericWrite),new SecurityIdentifier(Known[1]),false,null));
            var bytes=new byte[raw.BinaryLength];raw.GetBinaryForm(bytes,0);Write(_programs,before[_programs] with{Binary=Convert.ToBase64String(bytes)});
            RefusedWithoutWrites(CaptureTree(),"RAW_GENERIC_WRITE_OR_ALL_INHERIT_ONLY");Write(_programs,before[_programs]);
        }
        Check(ReadOnlyGenericIoPresent(_programs) && ReadOnlyGenericIoPresent(_vendor),"READONLY_GENERIC_IO_LOST_AFTER_REFUSAL_TESTS");
        SetOwner(_vendor,WindowsIdentity.GetCurrent().User!);RefusedWithoutWrites(CaptureTree(),"UNKNOWN_ANCESTOR_OWNER");SetOwner(_vendor,Admin);SameTree(before,"OWNER_TEST_RESTORE_FAILED");
        string link=Path.Combine(_uu,"linked");Directory.CreateSymbolicLink(link,_other);RefusedWithoutWrites(CaptureTree(),"REPARSE_TREE");Directory.Delete(link);SameTree(before,"REPARSE_TEST_RESTORE_FAILED");
        string unexpected=Path.Combine(_volume,"Other Program Files","Netease","GameViewer");bool layoutRefused=false;
        try{_ = UuAclRepair.AdvancedAncestors(unexpected);}catch(IOException){layoutRefused=true;}
        Check(layoutRefused,"UNKNOWN_ANCESTOR_LAYOUT_ACCEPTED");SameTree(before,"UNKNOWN_ANCESTOR_LAYOUT_WROTE_OBJECTS");
        SubstRefusal(before);
        var old=new UuAclRepair.Journal(1,"applied",new[]{_uu},new[]{new UuAclRepair.Entry(_uu,true,before[_uu].Identity,new RawSecurityDescriptor(Convert.FromBase64String(before[_uu].Binary),0).GetSddlForm(AccessControlSections.Access),"")});
        Platform.WriteAtomic(Backup,JsonSerializer.SerializeToUtf8Bytes(old));RefusedWithoutWrites(before,"OLD_ACTIVE_JOURNAL");RemoveOwnedJournal();
        Pass("REAL_ADVANCED_PREFLIGHT_REJECTS_UNKNOWN_OWNER_PRINCIPAL_FULL_CONTROL_REPARSE_AND_ACTIVE_V1_JOURNAL_WITH_ZERO_WRITES");
    }
    private static void SubstRefusal(Dictionary<string,State> before)
    {
        string? letter=null;var query=new StringBuilder(1024);
        for(char candidate='Z';candidate>='G';candidate--){if(candidate==char.ToUpperInvariant(_volume[0]))continue;if(QueryDosDevice(candidate+":",query,query.Capacity)==0 && Marshal.GetLastWin32Error()==2){letter=candidate+":";break;}}
        Check(letter is not null,"NO_UNUSED_SUBST_FIXTURE_LETTER");string target=@"\??\"+_volume;
        Check(DefineDosDevice(1,letter!,target),"SUBST_FIXTURE_CREATE_FAILED");
        try{
            string alias=letter+_uu[2..];using(var key=Registry.LocalMachine.OpenSubKey(RegistryPath,true)!)key.SetValue("InstallLocation",alias);
            bool refused=false;try{UuAclRepair.ApplyAdvanced(new[]{alias});}catch(IOException){refused=true;}
            Check(refused && !File.Exists(Backup),"SUBST_ALIAS_NOT_REFUSED_WITH_ZERO_JOURNAL_WRITES");SameTree(before,"SUBST_ALIAS_MODIFIED_OBJECTS");
        }finally{
            using(var key=Registry.LocalMachine.OpenSubKey(RegistryPath,true)!)key.SetValue("InstallLocation",_uu);
            query.Clear();Check(QueryDosDevice(letter!,query,query.Capacity)>0 && query.ToString()==target,"SUBST_MAPPING_CHANGED_REFUSE_REMOVAL");
            Check(DefineDosDevice(1|2|4,letter!,target),"OWNED_SUBST_REMOVE_FAILED");
        }
        Pass("REAL_SUBST_DRIVE_ALIAS_REJECTED_WITHOUT_WRITES_OR_TOUCHING_OTHER_MAPPINGS");
    }
    private static void OrdinaryUserProof()
    {
        string name=Environment.GetEnvironmentVariable("ORACLE_UU_PATH_FIXTURE_USERNAME")??"",password=Environment.GetEnvironmentVariable("ORACLE_UU_PATH_FIXTURE_PASSWORD")??"";
        Check(name.StartsWith("opuu",StringComparison.Ordinal) && name.Length==14 && password.Length>=40,"ORDINARY_FIXTURE_ACCOUNT_REQUIRED");
        Check(LogonUser(name,".",password,2,0,out var token),"ORDINARY_FIXTURE_LOGON_FAILED");
        using(token)WindowsIdentity.RunImpersonated(token,()=>{
            Check(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator),"ORDINARY_USER_IS_ADMIN");
            string allowed=Path.Combine(_other,"ordinary-created.txt");File.WriteAllText(allowed,"ordinary app write remains allowed");File.Delete(allowed);
            bool Denied(Action operation){try{operation();return false;}catch(UnauthorizedAccessException){return true;}catch(IOException){return true;}}
            Check(Denied(()=>File.WriteAllText(_exe,"must never replace signed UU")),"ORDINARY_USER_REPLACED_UU");
            Check(Denied(()=>Directory.Move(_vendor,_vendor+"-must-not-move")),"ORDINARY_USER_RENAMED_PROTECTED_PARENT");
            Check(Denied(()=>Directory.CreateDirectory(Path.Combine(_vendor,"must-not-create"))),"ORDINARY_USER_CREATED_PROTECTED_PARENT_CHILD");
        });
        Pass("REAL_ORDINARY_LOCAL_USER_CAN_WRITE_OTHERAPP_BUT_CANNOT_REPLACE_UU_OR_RENAME_CREATE_PROTECTED_PARENTS");
    }
    private static void FaultAndCasProof(Dictionary<string,State> before)
    {
        foreach(string failure in new[]{"before_first_write","ancestor_0_written","ancestor_1_written","uu_object_written","before_commit"}){
            bool reached=false;UuAclRepair.AdvancedTestHook=stage=>{if(stage==failure){reached=true;throw new IOException("SYNTHETIC_UU_PATH_FAULT");}};
            bool refused=false;try{UuAclRepair.ApplyAdvanced(new[]{_uu});}catch(IOException){refused=true;}finally{UuAclRepair.AdvancedTestHook=null;}
            Check(reached && refused,"FAULT_STAGE_NOT_EXERCISED_"+failure);SameTree(before,"FAULT_ROLLBACK_NOT_EXACT_"+failure);RemoveOwnedJournal();
        }
        bool locksProved=false;UuAclRepair.AdvancedTestHook=stage=>{if(stage!="before_first_write")return;bool a=false,b=false;try{Directory.Move(_vendor,_vendor+"-swap");}catch(IOException){a=true;}try{File.Move(_exe,_exe+".swap");}catch(IOException){b=true;}Check(a&&b,"CAPTURED_OBJECTS_NOT_LOCKED_AGAINST_DELETE_RENAME");locksProved=true;};
        try{UuAclRepair.ApplyAdvanced(new[]{_uu});}finally{UuAclRepair.AdvancedTestHook=null;}
        Check(locksProved,"LOCK_PROOF_HOOK_NOT_REACHED");UuAclRepair.Restore();SameTree(before,"LOCK_PROOF_ROLLBACK_FAILED");RemoveOwnedJournal();
        UuAclRepair.ApplyAdvanced(new[]{_uu});var after=CaptureTree();string file=Path.Combine(_uu,"config","remote.ini");
        var changed=new FileInfo(file).GetAccessControl();changed.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-19"),FileSystemRights.ReadAttributes,AccessControlType.Allow));new FileInfo(file).SetAccessControl(changed);
        var external=CaptureTree();State journal=Read(Backup);string hash=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Backup)));bool cas=false;
        try{UuAclRepair.Restore();}catch(IOException){cas=true;}
        Check(cas && Read(Backup)==journal && Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Backup)))==hash,"EXTERNAL_ACL_THIRD_STATE_ROLLBACK_NOT_ZERO_WRITE_REFUSED");SameTree(external,"EXTERNAL_ACL_THIRD_STATE_WAS_OVERWRITTEN");
        Write(file,after[file],0x00060000);UuAclRepair.Restore();SameTree(before,"CAS_MANUAL_RECONCILE_ROLLBACK_FAILED");RemoveOwnedJournal();
        UuAclRepair.ApplyAdvanced(new[]{_uu});
        var sourceAcl=RootAcl(true);sourceAcl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(Known[1]),FileSystemRights.DeleteSubdirectoriesAndFiles,AccessControlType.Allow));
        Write(_volume,WithAcl(before[_volume],sourceAcl));RestoreRefusedWithoutWrites("VOLUME_SOURCE_DACL_CHANGED","UU_REPAIR_ACL_CHANGED");
        Write(_volume,before[_volume]);UuAclRepair.Restore();SameTree(before,"SOURCE_RECONCILE_ROLLBACK_FAILED");RemoveOwnedJournal();
        UuAclRepair.ApplyAdvanced(new[]{_uu});string swapped=_vendor+"-fixture-saved";
        Directory.Move(_vendor,swapped);Directory.CreateDirectory(_uu);File.Copy(Path.Combine(swapped,"GameViewer","GameViewer.exe"),_exe);
        RestoreRefusedWithoutWrites("ANCESTOR_NATIVE_FILE_ID_CHANGED","UU_REPAIR_OBJECT_CHANGED");
        Directory.Delete(_vendor,true);Directory.Move(swapped,_vendor);UuAclRepair.Restore();SameTree(before,"FILE_ID_RECONCILE_ROLLBACK_FAILED");RemoveOwnedJournal();
        // Inject an external file ACL change after planning but before the
        // production CAS. It must survive; this process did not authorize the
        // plan to overwrite a third state, even though it owns the test VHD.
        UuAclRepair.AdvancedTestHook=stage=>{
            if(stage!="before_first_write")return;
            var acl=new FileInfo(file).GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-19"),FileSystemRights.ReadAttributes,AccessControlType.Allow));new FileInfo(file).SetAccessControl(acl);
        };
        bool planCas=false;try{UuAclRepair.ApplyAdvanced(new[]{_uu});}catch(IOException){planCas=true;}finally{UuAclRepair.AdvancedTestHook=null;}
        Check(planCas && Read(file)!=before[file],"PLANNED_CAS_OVERWROTE_EXTERNAL_FILE_ACL");
        foreach(var entry in before.Where(entry=>!entry.Key.Equals(file,StringComparison.OrdinalIgnoreCase)))Check(Read(entry.Key)==entry.Value,"PLANNED_CAS_WROTE_UNAUTHORIZED_OBJECT");
        Write(file,before[file],0x00060000);SameTree(before,"PLAN_CAS_RECONCILE_FAILED");RemoveOwnedJournal();
        Pass("REAL_NATIVE_NO_DELETE_LOCKS_AND_EACH_MUTATION_STAGE_FAULT_RECOVER_EXACTLY");
        Pass("REAL_EXTERNAL_ACL_THIRD_STATE_REFUSES_ROLLBACK_WITH_ZERO_OBJECT_OR_JOURNAL_WRITES");
        Pass("REAL_VOLUME_SOURCE_NATIVE_FILE_ID_AND_PLANNED_CAS_REFUSE_EXTERNAL_CHANGES_WITHOUT_OVERWRITE");
    }
    private static void RestoreRefusedWithoutWrites(string code,string expectedCode)
    {
        var before=CaptureTree();State journal=Read(Backup);string content=Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Backup)));DateTime written=File.GetLastWriteTimeUtc(Backup);bool refused=false;
        try{UuAclRepair.Restore();}catch(IOException error){refused=true;Check(error.Message==expectedCode,code+"_WRONG_REFUSAL_REASON");}
        Check(refused,code+"_NOT_REFUSED");SameTree(before,code+"_OVERWROTE_OBJECTS");
        Check(Read(Backup)==journal && File.GetLastWriteTimeUtc(Backup)==written && Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Backup)))==content,code+"_OVERWROTE_JOURNAL");
    }
    private static void MetadataProtectionProof(Dictionary<string,State> before)
    {
        UuAclRepair.ApplyAdvanced(new[]{_uu});var applied=CaptureTree();State trusted=Read(Backup);
        var acl=new FileInfo(Backup).GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(Known[1]),FileSystemRights.WriteData,AccessControlType.Allow));new FileInfo(Backup).SetAccessControl(acl);
        Check(Read(Backup)!=trusted,"WRITABLE_METADATA_FIXTURE_DID_NOT_CHANGE_SECURITY");
        RestoreRefusedWithoutWrites("WRITABLE_FIXED_METADATA_LOAD","UU_REPAIR_BACKUP_REFUSED");
        SameTree(applied,"WRITABLE_METADATA_LOAD_CHANGED_APPLIED_UU");
        Write(Backup,trusted,0x00060000);Check(Read(Backup)==trusted,"FIXTURE_METADATA_SECURITY_RESTORE_NOT_EXACT");
        UuAclRepair.Restore();SameTree(before,"METADATA_RECONCILIATION_PREVENTED_NORMAL_ROLLBACK");
        // The restored v2 journal is still valid and the original unsafe UU
        // pattern is eligible again, so Apply must reach metadata validation
        // rather than merely refusing an already-safe installation.
        trusted=Read(Backup);acl=new FileInfo(Backup).GetAccessControl();acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(Known[1]),FileSystemRights.WriteData,AccessControlType.Allow));new FileInfo(Backup).SetAccessControl(acl);
        RefusedWithoutWrites(before,"WRITABLE_FIXED_METADATA_APPLY","UU_REPAIR_BACKUP_REFUSED");
        Write(Backup,trusted,0x00060000);Check(Read(Backup)==trusted,"FIXTURE_RESTORED_METADATA_SECURITY_NOT_EXACT");
        UuAclRepair.ApplyAdvanced(new[]{_uu});UuAclRepair.Restore();SameTree(before,"SAFE_METADATA_DID_NOT_RESUME_NORMAL_APPLY_ROLLBACK");RemoveOwnedJournal();
        Pass("REAL_WRITABLE_FIXED_JOURNAL_REFUSES_APPLY_AND_RESTORE_WITH_ZERO_UU_OR_METADATA_OVERWRITE");
    }
    private static void UnprotectedAncestorProof(Dictionary<string,State> original)
    {
        // One real unprotected shared ancestor is enough to exercise the hard
        // rollback path. Its volume source is read-only and consistent. Vendor
        // remains protected so UU's own inherited policy retains its source.
        Write(_volume,WithAcl(original[_volume],RootAcl(false)));
        State template=AncestorTemplate(Read(_programs));var raw=new RawSecurityDescriptor(Convert.FromBase64String(template.Binary),0);
        foreach(CommonAce ace in raw.DiscretionaryAcl!)ace.AceFlags&=~AceFlags.Inherited;
        raw.SetFlags(raw.ControlFlags&~(ControlFlags.DiscretionaryAclProtected|ControlFlags.DiscretionaryAclAutoInheritRequired));
        var bytes=new byte[raw.BinaryLength];raw.GetBinaryForm(bytes,0);Write(_programs,template with{Binary=Convert.ToBase64String(bytes)});
        var before=CaptureTree();var actual=new RawSecurityDescriptor(Convert.FromBase64String(before[_programs].Binary),0);
        Check(!actual.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected),"NATIVE_UNPROTECTED_PARENT_WAS_NOT_CONSTRUCTED");
        Check(actual.DiscretionaryAcl!.OfType<CommonAce>().Any(ace=>ace.AceFlags.HasFlag(AceFlags.Inherited)),"NATIVE_UNPROTECTED_PARENT_DID_NOT_INHERIT_SOURCE");
        Check(ReadOnlyGenericIoPresent(_programs),"UNPROTECTED_PARENT_LOST_RAW_READONLY_GENERIC_IO");
        Console.WriteLine($"UNPROTECTED_PARENT_BEFORE_FLAGS={(int)actual.ControlFlags:X4};P=false;INHERITED_ACES={actual.DiscretionaryAcl!.OfType<CommonAce>().Count(ace=>ace.AceFlags.HasFlag(AceFlags.Inherited))}");
        Check(UuAclRepair.EligibleAdvancedRoots().SequenceEqual(new[]{_uu},StringComparer.OrdinalIgnoreCase),"REAL_UNPROTECTED_PARENT_NATIVE_PATTERN_NOT_SUPPORTED");
        UuAclRepair.ApplyAdvanced(new[]{_uu});Check(UuDiscovery.Trusted(_exe),"UNPROTECTED_PARENT_APPLY_DID_NOT_PASS_TRUST");SameSiblings(before,"UNPROTECTED_PARENT_APPLY_CHANGED_SIBLINGS");
        UuAclRepair.Restore();SameTree(before,"UNPROTECTED_PARENT_REINHERITANCE_ROLLBACK_NOT_NATIVE_EXACT");RemoveOwnedJournal();
        Write(_volume,original[_volume]);Write(_programs,original[_programs]);SameTree(original,"UNPROTECTED_PARENT_FIXTURE_RESET_NOT_EXACT");
        Pass("REAL_UNPROTECTED_PARENT_APPLY_AND_REENABLE_INHERITANCE_ROLLBACK_PRESERVE_NATIVE_DESCRIPTOR_AND_FLAGS_EXACTLY");
    }
    [StructLayout(LayoutKind.Sequential)]private struct FileInfoNative{public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInfoNative info);
    [DllImport("advapi32.dll")]private static extern uint GetSecurityInfo(SafeFileHandle handle,int type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")]private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("advapi32.dll")]private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,[MarshalAs(UnmanagedType.Bool)]out bool present,out IntPtr dacl,[MarshalAs(UnmanagedType.Bool)]out bool defaulted);
    [DllImport("advapi32.dll")]private static extern uint SetSecurityInfo(SafeFileHandle handle,int type,uint information,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DllImport("kernel32.dll")]private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll",EntryPoint="GetVolumeNameForVolumeMountPointW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool GetVolumeNameForVolumeMountPoint(string root,StringBuilder volume,int length);
    [DllImport("kernel32.dll",EntryPoint="GetVolumeInformationW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool GetVolumeInformation(string root,StringBuilder label,int labelLength,out uint serial,out uint maximum,out uint flags,StringBuilder format,int formatLength);
    [DllImport("kernel32.dll",EntryPoint="QueryDosDeviceW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern uint QueryDosDevice(string name,StringBuilder target,int length);
    [DllImport("kernel32.dll",EntryPoint="DefineDosDeviceW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool DefineDosDevice(uint flags,string name,string target);
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool DeviceIoControl(SafeFileHandle handle,uint code,byte[]? input,int inputSize,byte[] output,int outputSize,out uint returned,IntPtr overlapped);
    [DllImport("advapi32.dll",EntryPoint="LogonUserW",CharSet=CharSet.Unicode,SetLastError=true)]private static extern bool LogonUser(string name,string domain,string password,int type,int provider,out SafeAccessTokenHandle token);
}
