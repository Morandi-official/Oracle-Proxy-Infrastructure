using System.ServiceProcess;
namespace OracleProxy.Product;
internal static class Program
{
    [STAThread]private static int Main(string[] args)
    {
        try{
            if(args.SequenceEqual(new[]{"--self-test"}))return ProductSelfTests.Run()?0:1;
            if(args.SequenceEqual(new[]{"--service"})){
                if(!Platform.IsSystem)return 3;
                ServiceBase.Run(new VpnService());return 0;
            }
            if(args.Length==2 && args[0]=="--install"){
                if(!Platform.IsAdmin)return 3;
                Installer.Install(args[1]).GetAwaiter().GetResult();return 0;
            }
            if(args.SequenceEqual(new[]{"--uninstall"})){
                if(!Platform.IsAdmin)return 3;
                Installer.Remove().GetAwaiter().GetResult();return 0;
            }
            if(args.Length!=0)return 2;
            ApplicationConfiguration.Initialize();Application.Run(new MainForm());return 0;
        }catch{
            if(Environment.UserInteractive)MessageBox.Show("操作未完成，已有保护与密钥保留。请使用完整便携包，并检查系统服务状态。","Oracle Proxy");
            return 3;
        }
    }
}
