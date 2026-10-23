using System.Text;
using System.Text.Json;
using System.Drawing;

namespace OracleProxy.WgAlpha;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
#if ENABLE_R113_CI_TRIAL
        // This is a separate CI-only compilation and must NEVER be present
        // in any downloadable R112/R113 GUI or real field build.
        if (args.Length == 2 && args[0] == "--ci-r113-native-service-trial")
            return CiEmbeddedServiceTrial.Run(args[1]);
#endif
#if ENABLE_R114_KEY_CI_TRIAL
        if(args.Length==1 && args[0]=="--ci-r114-key-file-self-test")
            return CiR114KeyFileSmoke.Run();
#endif
        if (args.Length == 1 && args[0] == "--offline-self-test")
            return AlphaPreflight.SelfTest() &&
                EmbeddedWireGuardBridge.SelfTest() &&
                LocalWireGuardKeys.SelfTest() ? 0 : 1;
        if (args.Length == 1 && args[0] == "--service")
            return EmbeddedWireGuardBridge.RunWindowsService();
        if (args.Length > 0) return 2; // No headless privileged entrypoint.
        if (!OperatingSystem.IsWindows()) return 2;
        ApplicationConfiguration.Initialize();
        Application.Run(new AlphaForm());
        return 0;
    }
}

internal sealed class AlphaForm : Form
{
    private readonly Label _status = new() { Dock=DockStyle.Fill, AutoSize=false };
    private readonly Button _connect = new() { Text="选择配置并连接（实验）", Width=225, Height=42 };
    private readonly Button _disconnect = new() { Text="断开本次创建的隧道", Width=200, Height=42 };
    private readonly Button _report = new() { Text="导出脱敏测试报告", Width=185, Height=42 };
    private readonly Button _generate = new() { Text="生成本机测试密钥（离线）", Width=218, Height=42 };
    private bool _busy;
    // Never adopt/delete a tunnel service created by any earlier process or
    // by the official client; a crash requires attended manual recovery.
    private bool _ownedThisSession;
    private string _lastResult = "NOT_TESTED";
    private string _keygenResult = "NOT_TESTED";
    private string _observed = "NOT_TESTED";

    internal AlphaForm()
    {
        Text="Oracle Proxy · WireGuard 功能 Alpha（无防泄漏承诺）";
        Width=970; Height=460; MinimumSize=new Size(940,440);
        StartPosition=FormStartPosition.CenterScreen;
        Font=new Font("Microsoft YaHei UI",10);
        var panel=new TableLayoutPanel { Dock=DockStyle.Fill, Padding=new Padding(18),
            ColumnCount=1, RowCount=4 };
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute,62));
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute,118));
        panel.RowStyles.Add(new RowStyle(SizeType.Absolute,66));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent,100));
        Controls.Add(panel);
        panel.Controls.Add(new Label {
            Dock=DockStyle.Fill,
            Font=new Font("Microsoft YaHei UI",14,FontStyle.Bold),
            Text="WireGuard VPN 功能 Alpha · 未验收 / 不可直接替换 WireSock"
        },0,0);
        panel.Controls.Add(new Label {
            Dock=DockStyle.Fill, ForeColor=Color.Firebrick,
            Text="仅供可在本机键盘恢复的备用 Windows 测试电脑。\n"+
                 "不验证系统级断线防泄漏、UU 远控连续性或断电恢复。\n"+
                 "离线生成本机测试密钥不要求管理员，且不会启动 VPN。\n"+
                 "连接隧道才需要本地管理员并确认风险。\n"+
                 "本 Alpha 随包携带官方已验证 WireGuardNT DLL 和自编译隧道服务；不包含密钥或额外 WFP。路由/DNS 仍会影响整机网络。"
        },0,1);
        var row=new FlowLayoutPanel { Dock=DockStyle.Fill, AutoScroll=true };
        row.Controls.Add(_generate); row.Controls.Add(_connect);
        row.Controls.Add(_disconnect); row.Controls.Add(_report);
        panel.Controls.Add(row,0,2);
        _status.Text="尚未连接。所有实际网络行为均需显式确认。";
        panel.Controls.Add(_status,0,3);
        _connect.Click += async (_,_)=> await ConnectAsync();
        _disconnect.Click += async (_,_)=> await DisconnectAsync();
        _report.Click += (_,_)=> ExportReport();
        _generate.Click += (_,_)=> GenerateKeysOffline();
        FormClosing += (_,e)=> {
            if (_busy) { e.Cancel=true; return; }
            if (_ownedThisSession && EmbeddedWireGuardBridge.ReadServiceState()=="Running") {
                var result=MessageBox.Show(this,
                    "本次启动的实验隧道还在运行。建议先点「断开」。\n"+
                    "现在退出不会自动删除服务，可能需要本地管理员手动恢复。仍要退出吗？",
                    "实验隧道仍在运行",MessageBoxButtons.YesNo,MessageBoxIcon.Warning);
                if(result!=DialogResult.Yes)e.Cancel=true;
            }
        };
        RefreshUi();
    }

    private void RefreshUi()
    {
        _connect.Enabled=!_busy && !_ownedThisSession;
        _disconnect.Enabled=!_busy && _ownedThisSession;
        _report.Enabled=!_busy;
        _generate.Enabled=!_busy;
    }

    private void GenerateKeysOffline()
    {
        if (_busy) return;
        if(MessageBox.Show(this,
            "本操作仅在本机用安全随机数生成 WireGuard X25519 测试密钥对。\n"+
            "私钥以文本形式保存在你选择的本地目录中新建的受限权限子目录中；"+
            "不会复制到剪贴板，也不会自动写入现有 .conf、启动隧道或连接网络。\n"+
            "不要选择 OneDrive/网盘同步目录、共享目录或其他用户可访问的路径。\n"+
            "确认只在受你控制的离线本地目录保存测试密钥？",
            "R114 · 离线生成测试密钥",MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning)!=DialogResult.Yes) return;

        using var folder=new FolderBrowserDialog {
            Description="选择用于保存新密钥子目录的本地文件夹（勿选同步盘/网络共享）",
            UseDescriptionForTitle=true,ShowNewFolderButton=true
        };
        if(folder.ShowDialog(this)!=DialogResult.OK)return;
        _busy=true;RefreshUi();
        try
        {
            var output=LocalWireGuardKeys.Create(folder.SelectedPath);
            _keygenResult="LOCAL_KEYPAIR_CREATED_ACL_VERIFIED";
            _status.Text="离线密钥生成完成。私钥在新建的受限文件夹中；"+
                "公钥可用于今后的测试服务端。未修改网络或现有配置。";
            MessageBox.Show(this,
                "生成成功；没有连接 VPN。\n\n公钥（允许配置到测试服务器）：\n"+
                output.PublicKey+"\n\n本机存放目录：\n"+output.DirectoryPath+
                "\n\n请勿发送 *.privatekey 文件给他人或上传到 GitHub。",
                "R114 · 本机密钥生成完成",MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch
        {
            _keygenResult="LOCAL_KEYPAIR_FAILED_REQUIRES_LOCAL_INSPECTION";
            _status.Text="离线密钥生成失败，未请求任何网络操作；"+
                "请检查本地文件夹权限，并确认没有遗留的测试密钥文件。";
            MessageBox.Show(this,
                "无法安全保存本机密钥对。没有请求连接网络。\n"+
                "请检查所选目录是否为本机磁盘，是否包含链接或权限限制；"+
                "若有部分文件，先人工检查，不要随意删除其他文件。",
                "生成失败",MessageBoxButtons.OK,MessageBoxIcon.Warning);
        }
        finally { _busy=false;RefreshUi(); }
    }

    private async Task ConnectAsync()
    {
        if (_busy || _ownedThisSession) return;
        if (!AlphaPreflight.Administrator()) {
            MessageBox.Show(this,"必须在本机通过 Windows 标准「以管理员身份运行」启动。\n"+
                "不会自动提升权限或绕过安全设置。","无权限",MessageBoxButtons.OK,MessageBoxIcon.Warning);
            return;
        }
        using var pick=new OpenFileDialog {
            Filter="专用 WireGuard 配置 (OracleProxyAlphaTest.conf)|OracleProxyAlphaTest.conf",
            FileName=AlphaPreflight.FixedName+".conf",
            CheckFileExists=true, Multiselect=false, Title="仅选择专用、测试用途配置"
        };
        if(pick.ShowDialog(this)!=DialogResult.OK) return;
        string check=AlphaPreflight.CheckFile(pick.FileName);
        if(check!="CONFIG_SHAPE_OK_NOT_NETWORK_PROOF") {
            _lastResult=check;
            _status.Text="配置拒绝："+check;
            return;
        }
        if(EmbeddedWireGuardBridge.ReadServiceState()!="Absent") {
            _lastResult="PREEXISTING_SERVICE_REFUSED";
            _status.Text="专用测试服务已存在或状态不明；拒绝覆盖其他会话/安装。";
            return;
        }
        if(MessageBox.Show(this,
            "将通过已安装的内置 WireGuard 引擎 创建专用 Windows 隧道服务。\n"+
            "连接后可能改变整机路由、DNS 和防火墙；即便 Alpha 本身不添加 WFP，"+
            "官方组件也可能管理自己的系统策略。\n"+
            "此版本没有自动断线保护或可靠恢复，不适合依赖 UU 的远控电脑。\n"+
            "确认自己在本地、具备管理员恢复权限，且这是非关键测试电脑？",
            "确认有断网风险",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)
            return;
        _busy=true;RefreshUi();_status.Text="正在请求内置 WireGuard 引擎 创建专用隧道…";
        try {
            // Mark attempt owned before starting; an ambiguous timeout may
            // leave the exact service and must be explicitly handled.
            _ownedThisSession=true;
            var result=await Task.Run(()=>EmbeddedWireGuardBridge.Install(pick.FileName));
            _lastResult=result;
            _observed=EmbeddedWireGuardBridge.ReadServiceState();
            _status.Text=result=="OFFICIAL_WIREGUARD_COMMAND_OK" && _observed=="Running"
                ? "内置 WireGuard 引擎 服务已运行；真实跨网络握手/出口防泄漏尚未验证。"
                : "安装结果未能证明连接成功："+result+" / "+_observed+
                    "。可尝试断开本次创建的实验服务。";
        }
        catch {
            _lastResult="START_EXCEPTION_NOT_NETWORK_PROOF";
            _status.Text="连接出现异常；可能存在部分安装，尝试显式断开或本机管理员恢复。";
        }
        finally { _busy=false;RefreshUi(); }
    }

    private async Task DisconnectAsync()
    {
        if(_busy || !_ownedThisSession) return;
        if(!AlphaPreflight.Administrator()) {
            _status.Text="拒绝：本机管理员权限不足。"; return;
        }
        if(MessageBox.Show(this,"仅卸载本窗口会话创建的固定名 WireGuard 隧道服务。确认断开？",
            "实验断开",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes)
            return;
        _busy=true;RefreshUi();_status.Text="正在请求内置 WireGuard 引擎 停止专用服务…";
        try {
            string result=await Task.Run(EmbeddedWireGuardBridge.Uninstall);
            _lastResult=result;
            _observed=EmbeddedWireGuardBridge.ReadServiceState();
            if(result=="OFFICIAL_WIREGUARD_COMMAND_OK" && _observed=="Absent") {
                _ownedThisSession=false;
                _status.Text="专用服务已停止并移除（未验证 DNS/路由或其他软件全部恢复）。";
            }
            else _status.Text="断开结果存在不确定性："+result+" / "+_observed+
                "；请在本机使用内置 WireGuard 引擎 管理工具检查。";
        }
        catch {
            _lastResult="STOP_EXCEPTION_REQUIRES_LOCAL_RECOVERY";
            _status.Text="无法确认安全断开；请在本机使用内置 WireGuard 引擎 管理工具恢复。";
        }
        finally { _busy=false;RefreshUi(); }
    }

    private void ExportReport()
    {
        if(_busy)return;
        // Only categorical claims: no IPs, key, server, config content, path
        // or command output. Report is saved only by user action.
        var report=new {
            schema_version=2, report_kind="R114_EMBEDDED_WG_OFFLINE_KEYS_ALPHA_UNVERIFIED",
            observed_utc=DateTimeOffset.UtcNow.ToString("O"),
            admin_token_present=AlphaPreflight.Administrator(),
            official_wireguard_binary_trust=EmbeddedWireGuardBridge.TrustStatus(),
            dedicated_test_service_status=EmbeddedWireGuardBridge.ReadServiceState(),
            local_gui_started_this_service=_ownedThisSession,
            last_operation_result=_lastResult,
            local_offline_keygen_result=_keygenResult,
            two_host_wireguard_handshake="NOT_TESTED",
            all_device_ipv4_ipv6_udp_dns_wfp_fail_close="NOT_TESTED",
            automatic_disconnect_or_reboot_recovery="NOT_TESTED",
            uu_remote_compatibility="NOT_TESTED",
            signed_alpha_publisher=false, safe_to_replace_wiresock=false,
            ga_authorized=false, production_r83_unchanged=true
        };
        using var save=new SaveFileDialog { Filter="JSON 报告 (*.json)|*.json",
            FileName="OracleProxy-R114-AlphaReport.json",DefaultExt="json",
            AddExtension=true,OverwritePrompt=true };
        if(save.ShowDialog(this)!=DialogResult.OK)return;
        try {
            File.WriteAllText(save.FileName,JsonSerializer.Serialize(report,
                new JsonSerializerOptions{WriteIndented=true}),new UTF8Encoding(false));
            _status.Text="报告已本地保存；真实握手、防泄漏和 UU 仍为 NOT_TESTED。";
        }
        catch { _status.Text="报告保存失败。"; }
    }
}
