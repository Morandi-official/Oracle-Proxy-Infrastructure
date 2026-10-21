using System.Runtime.InteropServices;
namespace OracleProxy.Product;
internal static class NativeGuard
{
    private static IntPtr _module;
    [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Unicode)]private delegate uint ApplyDelegate(string service,string core,string uu,ulong luid,uint corePid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate uint ClearDelegate();
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate uint CountDelegate(out uint persistent,out uint boot);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]private delegate uint LuidDelegate(out ulong value);
    private static T Function<T>(string name)where T:Delegate
    {
        if(!Platform.IsSystem)throw new UnauthorizedAccessException();
        if(_module==IntPtr.Zero){Platform.VerifyProtected(Platform.Root);Platform.VerifyBundle(Platform.Root);_module=NativeLibrary.Load(Platform.Guard);}
        return Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(_module,name));
    }
    internal static void Apply(string[] uu,ulong luid=0,uint corePid=0)
    {
        foreach(string path in uu)if(!UuDiscovery.Trusted(path))throw new IOException("UU_SIGNATURE_OR_DIRECTORY_CHANGED");
        uint result=Function<ApplyDelegate>("OpGuardApply")(Platform.Exe,Platform.Core,string.Join('\0',uu)+"\0\0",luid,corePid);
        if(result!=0)throw new IOException("WFP_APPLY_"+result+"_S"+Function<ClearDelegate>("OpGuardStage")());
        if(!Active)throw new IOException("WFP_AUDIT_FAILED");
    }
    internal static uint CoreLifecycle=>Function<ClearDelegate>("OpGuardCoreState")();
    internal static bool TunPermitted=>Function<ClearDelegate>("OpGuardTunReady")()==1;
    internal static void SuspendTun(){if(Function<ClearDelegate>("OpGuardSuspendTun")()!=0)throw new IOException("TUN_PERMIT_RELEASE_FAILED");}
    internal static bool Active{
        get{uint e=Function<CountDelegate>("OpGuardCount")(out uint persistent,out uint boot);return e==0 && persistent>=16 && boot>=8;}
    }
    internal static void Clear(){uint result=Function<ClearDelegate>("OpGuardClear")();if(result!=0)throw new IOException("WFP_CLEAR_"+result);if(Function<CountDelegate>("OpGuardCount")(out uint persistent,out uint boot)!=0 || persistent!=0 || boot!=0)throw new IOException("WFP_CLEAR_NOT_VERIFIED");}
    internal static ulong TunLuid(){uint e=Function<LuidDelegate>("OpTunLuid")(out ulong value);if(e!=0||value==0)throw new IOException("TUN_NOT_READY");return value;}
}
