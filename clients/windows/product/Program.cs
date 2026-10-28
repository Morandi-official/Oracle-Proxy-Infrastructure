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
            if(args.SequenceEqual(new[]{"--install-interactive"})){
                if(!Platform.IsAdmin)return 3;
                Installer.InstallInteractive().GetAwaiter().GetResult();return 0;
            }
            if(args.Length==2 && args[0]=="--install-desktop"){
                if(!Platform.IsAdmin)return 3;
                Installer.InstallDesktop(args[1]).GetAwaiter().GetResult();return 0;
            }
            if(args.Length==2 && args[0]=="--install"){
                if(!Platform.IsAdmin)return 3;
                Installer.Install(args[1]).GetAwaiter().GetResult();return 0;
            }
            if(args.SequenceEqual(new[]{"--recovery-service"})){
                if(!Platform.IsSystem)return 3;
                ServiceBase.Run(new RecoveryService());return 0;
            }
            if(args.SequenceEqual(new[]{"--recover"})){
                if(!Platform.IsAdmin)return 3;
                Installer.Recover().GetAwaiter().GetResult();return 0;
            }
            if(args.SequenceEqual(new[]{"--repair-uu-permissions"}) || args.SequenceEqual(new[]{"--restore-uu-permissions"})){
                if(!Platform.IsAdmin)return 3;
                return UuAclRepair.RunInteractive(args[0]=="--restore-uu-permissions")?0:4;
            }
            if(args.SequenceEqual(new[]{"--uninstall"})){
                if(!Platform.IsAdmin)return 3;
                Installer.Remove().GetAwaiter().GetResult();return 0;
            }
            if(args.Length!=0 || Path.GetFileName(Environment.ProcessPath)=="OracleProxy.Service.exe")return 2;
            ApplicationConfiguration.Initialize();Application.Run(new MainForm());return 0;
        }catch(Exception error){
            if(Platform.IsAdmin)Platform.RecordFailure("setup",error);
            if(Environment.UserInteractive && args.Length==1 && args[0] is "--repair-uu-permissions" or "--restore-uu-permissions"){
                string reason=error.Message switch{
                    "UU_PATH_FILES_IN_USE"=>"UU 的文件或目录正被占用，本次未写入 UU 权限。请在本地退出 UU 后重试。程序不会自动停止 UU。",
                    "UU_PATH_ACCESS_DENIED"=>"当前权限不足，本次未写入 UU 权限。请确认已完成管理员授权。",
                    "UU_PATH_VOLUME_AUTHORITY_REFUSED"=>"盘根权限不满足安全保护条件；本工具不会修改盘根。",
                    "UU_REPAIR_OWNER_REFUSED"=>"存在不受信任的目录或文件拥有者；本工具不会更改拥有者。",
                    "UU_PATH_ROLLBACK_NOT_VERIFIED"=>"尚未确认权限回滚完成。请保留备份，不要重复修复，并提供下面的诊断。",
                    _=>"请保留现有保护，复制以下诊断给维护者。"
                };
                MessageBox.Show("UU 权限维护未完成。\r\n"+reason+"\r\n\r\n"+(error.Message.All(c=>c is >= 'A' and <= 'Z' or '_')?error.Message:error.HResult.ToString("X8")),"UU 权限维护");
            }
            if(args.Length==0 && Environment.UserInteractive)MessageBox.Show("操作未完成，已有保护与密钥保留。请使用完整便携包，并检查系统服务状态。","Oracle Proxy");
            return 3;
        }
    }
}
