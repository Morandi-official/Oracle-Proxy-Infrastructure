using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
namespace OracleProxy.Product;

// A digest remains valid only while Windows denies writes/deletes to that
// exact file. Re-open the current path and compare volume/file identities at
// every reuse, so a renamed parent or replacement directory cannot inherit it.
internal sealed class BundleLease : IDisposable
{
    private readonly FileStream[] _files;
    private readonly string[] _paths;
    private readonly Identity[] _identities;
    private bool _disposed;
    private BundleLease(string[] paths,FileStream[] files,Identity[] identities){_paths=paths.ToArray();_files=files;_identities=identities;}
    internal static BundleLease Open(string[] paths,string[] hashes)
    {
        if(paths.Length!=2 || hashes.Length!=2 || hashes.Any(hash=>hash.Length!=64 || !hash.All(Uri.IsHexDigit)))throw new IOException("BUNDLE_INTEGRITY_FAILED");
        var files=new List<FileStream>();var identities=new List<Identity>();
        try{
            for(int i=0;i<paths.Length;i++){
                Platform.NoLinks(Path.GetDirectoryName(paths[i])!);
                if(File.GetAttributes(paths[i]).HasFlag(FileAttributes.ReparsePoint))throw new IOException("BUNDLE_INTEGRITY_FAILED");
                var file=new FileStream(paths[i],FileMode.Open,FileAccess.Read,FileShare.Read);files.Add(file);
                if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(file),Convert.FromHexString(hashes[i])))throw new IOException("BUNDLE_INTEGRITY_FAILED");
                identities.Add(ReadIdentity(file.SafeFileHandle));
            }
            return new(paths,files.ToArray(),identities.ToArray());
        }catch{foreach(var file in files)file.Dispose();throw;}
    }
    internal bool Current()
    {
        if(_disposed)return false;
        for(int i=0;i<_paths.Length;i++){
            Platform.NoLinks(Path.GetDirectoryName(_paths[i])!);
            if(File.GetAttributes(_paths[i]).HasFlag(FileAttributes.ReparsePoint))return false;
            using var current=new FileStream(_paths[i],FileMode.Open,FileAccess.Read,FileShare.Read);
            if(ReadIdentity(current.SafeFileHandle)!=_identities[i])return false;
        }
        return true;
    }
    public void Dispose(){if(_disposed)return;_disposed=true;foreach(var file in _files)file.Dispose();}
    private readonly record struct Identity(uint Volume,uint High,uint Low);
    private static Identity ReadIdentity(SafeFileHandle handle){
        if(!GetFileInformationByHandle(handle,out var value))throw new IOException("BUNDLE_FILE_IDENTITY_UNAVAILABLE");
        return new(value.Volume,value.IndexHigh,value.IndexLow);
    }
    [StructLayout(LayoutKind.Sequential)]private struct FileInformation{
        public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Created,Accessed,Written;
        public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;
    }
    [DllImport("kernel32.dll",SetLastError=true)]private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out FileInformation information);
}
