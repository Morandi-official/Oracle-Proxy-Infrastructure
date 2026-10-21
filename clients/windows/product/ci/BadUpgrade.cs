using OracleProxy.Product;
// CI-only bad startup payload for the actual reversible installer. No
// conditional privileged entrypoint is added to the distributable program.
internal static class BadUpgrade
{
    private static int Main(string[] args)
    {
        if(args.Length!=2||args[0]!="--install"||!Platform.IsAdmin)return 3;
        try{Installer.Install(args[1]).GetAwaiter().GetResult();return 0;}catch{return 3;}
    }
}
