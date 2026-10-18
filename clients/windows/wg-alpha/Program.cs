using System.Text;
using System.Text.Json;
using System.Drawing;

namespace OracleProxy.WgAlpha;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--offline-self-test")
            return AlphaPreflight.SelfTest() && OfficialWireGuardBridge.SelfTest() ? 0 : 1;
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
    private bool _busy;
    // Never adopt/delete a tunnel service created by any earlier process or
    // by the official client; a crash requires attended manual recovery.
    private bool _ownedThisSession;
    private string _lastResult = "NOT_TESTED";
    private string _observed = "NOT_TESTED";

    internal AlphaForm()
    {
        Text="Oracle Proxy · WireGuard 功能 Alpha（无防泄漏承诺）";
        Width=800; Height=445; MinimumSize=new Size(690,400);
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
                 "必须单独安装官方 WireGuard Windows，并由用户以管理员身份启动。\n"+
                 "本 Alpha 不捆绑密钥/驱动，不启用额外 WFP。配置中的路由/DNS 仍会影响整机网络。"
        },0,1);
        var row=new FlowLayoutPanel { Dock=DockStyle.Fill, AutoScroll=true };
        row.Controls.Add(_connect); row.Controls.Add(_disconnect); row.Controls.Add(_report);
        panel.Controls.Add(row,0,2);
        _status.Text="尚未连接。所有实际网络行为均需显式确认。";
        panel.Controls.Add(_status,0,3);
        _connect.Click += async (_,_)=> await ConnectAsync();
        _disconnect.Click += async (_,_)=> await DisconnectAsync();
        _report.Click += (_,_)=> ExportReport();
        FormClosing += (_,e)=> {
            if (_busy) { e.Cancel=true; return; }
            if (_ownedThisSession && OfficialWireGuardBridge.ReadServiceState()=="Running") {
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
        if(OfficialWireGuardBridge.ReadServiceState()!="Absent") {
            _lastResult="PREEXISTING_SERVICE_REFUSED";
            _status.Text="专用测试服务已存在或状态不明；拒绝覆盖其他会话/安装。";
            return;
        }
        if(MessageBox.Show(this,
            "将通过已安装的官方 WireGuard 创建专用 Windows 隧道服务。\n"+
            "连接后可能改变整机路由、DNS 和防火墙；即便 Alpha 本身不添加 WFP，"+
            "官方组件也可能管理自己的系统策略。\n"+
            "此版本没有自动断线保护或可靠恢复，不适合依赖 UU 的远控电脑。\n"+
            "确认自己在本地、具备管理员恢复权限，且这是非关键测试电脑？",
            "确认有断网风险",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)
            return;
        _busy=true;RefreshUi();_status.Text="正在请求官方 WireGuard 创建专用隧道…";
        try {
            // Mark attempt owned before starting; an ambiguous timeout may
            // leave the exact service and must be explicitly handled.
            _ownedThisSession=true;
            var result=await Task.Run(()=>OfficialWireGuardBridge.Install(pick.FileName));
            _lastResult=result;
            _observed=OfficialWireGuardBridge.ReadServiceState();
            _status.Text=result=="OFFICIAL_WIREGUARD_COMMAND_OK" && _observed=="Running"
                ? "官方 WireGuard 服务已运行；真实跨网络握手/出口防泄漏尚未验证。"
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
        _busy=true;RefreshUi();_status.Text="正在请求官方 WireGuard 停止专用服务…";
        try {
            string result=await Task.Run(OfficialWireGuardBridge.Uninstall);
            _lastResult=result;
            _observed=OfficialWireGuardBridge.ReadServiceState();
            if(result=="OFFICIAL_WIREGUARD_COMMAND_OK" && _observed=="Absent") {
                _ownedThisSession=false;
                _status.Text="专用服务已停止并移除（未验证 DNS/路由或其他软件全部恢复）。";
            }
            else _status.Text="断开结果存在不确定性："+result+" / "+_observed+
                "；请在本机使用官方 WireGuard 管理工具检查。";
        }
        catch {
            _lastResult="STOP_EXCEPTION_REQUIRES_LOCAL_RECOVERY";
            _status.Text="无法确认安全断开；请在本机使用官方 WireGuard 管理工具恢复。";
        }
        finally { _busy=false;RefreshUi(); }
    }

    private void ExportReport()
    {
        if(_busy)return;
        // Only categorical claims: no IPs, key, server, config content, path
        // or command output. Report is saved only by user action.
        var report=new {
            schema_version=1, report_kind="R111_FUNCTIONAL_WG_ALPHA_UNVERIFIED",
            observed_utc=DateTimeOffset.UtcNow.ToString("O"),
            admin_token_present=AlphaPreflight.Administrator(),
            official_wireguard_binary_trust=OfficialWireGuardBridge.TrustStatus(),
            dedicated_test_service_status=OfficialWireGuardBridge.ReadServiceState(),
            local_gui_started_this_service=_ownedThisSession,
            last_operation_result=_lastResult,
            two_host_wireguard_handshake="NOT_TESTED",
            all_device_ipv4_ipv6_udp_dns_wfp_fail_close="NOT_TESTED",
            automatic_disconnect_or_reboot_recovery="NOT_TESTED",
            uu_remote_compatibility="NOT_TESTED",
            signed_alpha_publisher=false, safe_to_replace_wiresock=false,
            ga_authorized=false, production_r83_unchanged=true
        };
        using var save=new SaveFileDialog { Filter="JSON 报告 (*.json)|*.json",
            FileName="OracleProxy-R111-AlphaReport.json",DefaultExt="json",
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
