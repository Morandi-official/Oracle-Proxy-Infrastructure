using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace OracleProxy.Product;

internal sealed record DirectApplication(string Path,string Sha256);

// An explicit, fingerprinted local choice is only used inside the live TUN.
// Keep the image and its parent names pinned while the process-path rule exists.
internal sealed class DirectApplicationLease : IDisposable
{
    internal const int Limit=12;
    private readonly List<SafeFileHandle> _directories=[];
    private FileStream? _file;
    internal DirectApplication Application{get;}

    internal static string Normalize(string path)
    {
        if(path.Length is <7 or >480 || !char.IsAsciiLetter(path[0]) || path[1]!=':' || path[2]!='\\' ||
            path.AsSpan(2).Contains(':') || path.Any(char.IsControl) || !Path.IsPathFullyQualified(path))
            throw new IOException("DIRECT_APP_LOCAL_EXE_REQUIRED");
        string full=Path.GetFullPath(path);
        if(!Path.GetExtension(full).Equals(".exe",StringComparison.OrdinalIgnoreCase) ||
            new DriveInfo(Path.GetPathRoot(full)!).DriveType!=DriveType.Fixed)
            throw new IOException("DIRECT_APP_LOCAL_EXE_REQUIRED");
        return full;
    }

    internal DirectApplicationLease(string path)
    {
        path=Normalize(path);
        try{
            var parents=new Stack<string>();
            for(var directory=new DirectoryInfo(Path.GetDirectoryName(path)!);directory.Parent is not null;directory=directory.Parent)
                parents.Push(directory.FullName);
            foreach(string directory in parents){
                var handle=OpenExact(directory,0x81,3,0x02200000,out _);
                _directories.Add(handle);
            }
            var image=OpenExact(path,0x80000000,1,0x08200000,out var canonicalPath);
            try{_file=new FileStream(image,FileAccess.Read,128*1024);}catch{image.Dispose();throw;}
            if(_file.Length is <1024 or >300_000_000 || _file.ReadByte()!=0x4d || _file.ReadByte()!=0x5a)
                throw new IOException("DIRECT_APP_LOCAL_EXE_REQUIRED");
            _file.Position=0;
            Application=new(canonicalPath,Convert.ToHexString(SHA256.HashData(_file)));
        }catch{Dispose();throw;}
    }

    internal static DirectApplicationLease? TryAcquire(DirectApplication application)
    {
        try{
            var lease=new DirectApplicationLease(application.Path);
            if(lease.Application.Sha256==application.Sha256)return lease;
            lease.Dispose();
        }catch(Exception error)when(error is IOException or UnauthorizedAccessException or ArgumentException){}
        return null;
    }

    private static SafeFileHandle OpenExact(string path,uint access,uint share,uint flags,out string canonicalPath)
    {
        var handle=CreateFile(@"\\?\"+path,access,share,IntPtr.Zero,3,flags,IntPtr.Zero);
        if(handle.IsInvalid){handle.Dispose();throw new IOException("DIRECT_APP_FILE_UNAVAILABLE");}
        try{
            var actual=new StringBuilder(1050);
            uint length=FinalPath(handle,actual,(uint)actual.Capacity,0);
            string finalPath=actual.ToString();
            if(length==0 || length>=actual.Capacity ||
                !finalPath.Equals(@"\\?\"+path,StringComparison.OrdinalIgnoreCase) ||
                !FileInformation(handle,9,out var attributes,8) || (attributes&0x400)!=0 ||
                ((attributes&0x10)!=0 && (!FileInformation(handle,23,out var caseSensitive,4) || (caseSensitive&1)!=0)))
                throw new IOException("DIRECT_APP_LOCAL_EXE_REQUIRED");
            canonicalPath=finalPath[4..];
            return handle;
        }catch{handle.Dispose();throw;}
    }

    public void Dispose()
    {
        _file?.Dispose();
        foreach(var handle in _directories)handle.Dispose();
    }

    [DllImport("kernel32.dll",EntryPoint="CreateFileW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
    [DllImport("kernel32.dll",EntryPoint="GetFinalPathNameByHandleW",CharSet=CharSet.Unicode,SetLastError=true)]
    private static extern uint FinalPath(SafeFileHandle handle,StringBuilder path,uint size,uint flags);
    [DllImport("kernel32.dll",EntryPoint="GetFileInformationByHandleEx",SetLastError=true)]
    private static extern bool FileInformation(SafeFileHandle handle,int kind,out ulong information,uint size);
}
