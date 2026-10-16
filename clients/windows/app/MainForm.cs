using System.Drawing;
using System.Windows.Forms;

namespace OracleProxy.Windows.Preview;

internal sealed class MainForm : Form
{
    private readonly Label _status;
    private readonly Label _details;
    private readonly Button _refresh;
    private readonly CancellationTokenSource _shutdown = new();

    internal MainForm()
    {
        Text = "Oracle Proxy · Windows 自研客户端 v0.2 测试版（只读）";
        Width = 740;
        Height = 560;
        MinimumSize = new Size(630, 500);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Microsoft YaHei UI", 10f);
        BackColor = Color.White;

        var root = new TableLayoutPanel {
            Dock = DockStyle.Fill, RowCount = 5, ColumnCount = 1,
            Padding = new Padding(20)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 62));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 105));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
        Controls.Add(root);

        root.Controls.Add(new Label {
            Text = "Oracle Proxy · 自研客户端 v0.2（只读测试）",
            Dock = DockStyle.Fill,
            Font = new Font("Microsoft YaHei UI", 15f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft
        }, 0, 0);

        _status = new Label {
            Text = "准备读取本机状态…",
            Dock = DockStyle.Fill, ForeColor = Color.DarkSlateBlue,
            TextAlign = ContentAlignment.MiddleLeft
        };
        root.Controls.Add(_status, 0, 1);

        _details = new Label {
            Dock = DockStyle.Fill,
            Text = "尚未读取系统数据。",
            BorderStyle = BorderStyle.FixedSingle,
            Padding = new Padding(16)
        };
        root.Controls.Add(_details, 0, 2);

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill };
        _refresh = new Button { Text = "刷新只读诊断", Width = 165, Height = 38 };
        var policyButton = new Button {
            Text = "查看安全策略模拟", Width = 195, Height = 38
        };
        _refresh.Click += async (_, _) => await RefreshDiagnosticsAsync();
        policyButton.Click += (_, _) => ShowPolicySimulation();
        buttons.Controls.Add(_refresh);
        buttons.Controls.Add(policyButton);
        var managerButton = new Button {
            Text = "查看后台服务", Width = 145, Height = 38
        };
        managerButton.Click += async (_, _) => await CheckManagerAsync();
        buttons.Controls.Add(managerButton);
        var connectCheck = new Button {
            Text = "连接安全检查", Width = 156, Height = 38
        };
        var disconnectCheck = new Button {
            Text = "断开安全检查", Width = 156, Height = 38
        };
        connectCheck.Click += async (_, _) =>
            await CheckSafeControlAsync("RequestConnect");
        disconnectCheck.Click += async (_, _) =>
            await CheckSafeControlAsync("RequestExplicitDisconnect");
        buttons.Controls.Add(connectCheck);
        buttons.Controls.Add(disconnectCheck);
#if ORACLE_DISPOSABLE_LAB
        if (LabAdminControlClient.OnDisposableRunner())
        {
            var labOn = new Button { Text = "CI实验连接", Width = 135, Height = 38 };
            var labOff = new Button { Text = "CI实验断开", Width = 135, Height = 38 };
            labOn.Click += async (_, _) => await ToggleCiLabAsync(true);
            labOff.Click += async (_, _) => await ToggleCiLabAsync(false);
            buttons.Controls.Add(labOn);
            buttons.Controls.Add(labOff);
        }
#endif
        root.Controls.Add(buttons, 0, 3);

        root.Controls.Add(new Label {
            Dock = DockStyle.Fill, ForeColor = Color.Firebrick,
            Text = "v0.2 只读测试版：不能连接 Oracle VPN，不能代理上网，没有断线防泄漏。\n" +
                   "无须管理员权限；不启动 PowerShell，不改 UU、WireSock、路由或防火墙。",
            TextAlign = ContentAlignment.MiddleLeft
        }, 0, 4);

        Shown += async (_, _) => await RefreshDiagnosticsAsync();
        FormClosed += (_, _) => _shutdown.Cancel();
    }

    private async Task RefreshDiagnosticsAsync()
    {
        _refresh.Enabled = false;
        _status.Text = "正在读取本机脱敏状态…";
        try
        {
            var d = await SanitizedDiagnostics.CollectAsync(_shutdown.Token);
            if (_shutdown.IsCancellationRequested) return;
            _details.Text =
                $"活动以太网/Wi-Fi 候选接口：{d.PhysicalAdapterCount} 个\n" +
                $"候选接口关联 IPv4 默认路由：{Flag(d.IPv4DefaultRoute)}\n" +
                $"候选接口关联 IPv6 默认路由：{Flag(d.IPv6DefaultRoute)}\n\n" +
                $"WireSock 驱动：{d.WireSockDriverState}\n" +
                $"WireSock 服务：{d.WireSockServiceState}\n" +
                $"WireGuard 管理服务：{d.WireGuardManagerState}\n" +
                $"UU 远程服务进程：{Flag(d.UuServerPresent)}\n\n" +
                $"采集时间（UTC）：{d.CollectedAtUtc}\n" +
                "VPN 连接状态：未知（尚未验证握手）\n" +
                "防泄漏保护：未知（尚未测试）";
            _status.Text = "只读诊断完成；没有连接或操作 VPN。";
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (_shutdown.IsCancellationRequested) return;
            _status.Text = "只读诊断暂不可用。";
            _details.Text = ex is InvalidOperationException
                ? ex.Message
                : "诊断异常；未修改任何网络设置。";
        }
        finally
        {
            if (!_shutdown.IsCancellationRequested && !IsDisposed)
                _refresh.Enabled = true;
        }
    }

    // Preview buttons exercise the real OS-token-verified SYSTEM request
    // gate; they must never start or stop VPN without verified WFP.
    private async Task CheckSafeControlAsync(string command)
    {
        try
        {
            bool deniedSafely = await ManagerControlClient.VerifySafetyDenialAsync(
                command, _shutdown.Token);
            if (_shutdown.IsCancellationRequested) return;
            MessageBox.Show(this, deniedSafely
                ? "后台服务已验证身份，并按安全策略拒绝执行。\\n" +
                  "当前尚无经验证的 WFP 断线防泄漏保护，不能连接或断开 VPN。"
                : "后台服务不可用，管理员授权不足或安全返回不符合协议。\\n" +
                  "没有执行任何 VPN 控制。",
                "VPN 安全控制尚未开放",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested) { }
        catch
        {
            if (!_shutdown.IsCancellationRequested)
                MessageBox.Show(this, "无法验证后台安全控制通道。\\n" +
                    "没有执行任何 VPN 操作。", "安全检查失败",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private async Task CheckManagerAsync()
    {
        try
        {
            var report = await ManagerStatusClient.ReadAsync(_shutdown.Token);
            if (_shutdown.IsCancellationRequested) return;
            MessageBox.Show(this,
                "已查询 Windows 后台服务的受限状态接口。\\n\\n" +
                "服务接口：操作系统身份校验、只读模式\\n" +
                "实际 VPN 握手：" + report.Connected + "\\n" +
                "断线防泄漏：" + report.LeakProtection + "\\n" +
                "允许修改 VPN：" + (report.MutationsAvailable ? "是" : "否") + "\\n\\n" +
                "此按钮不会启动或停止 WireGuard。",
                "实验后台服务状态", MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested) { }
        catch
        {
            if (!_shutdown.IsCancellationRequested)
                MessageBox.Show(this,
                    "后台实验服务未安装、不可访问或响应不符合安全协议。\\n" +
                    "本客户端未修改任何 VPN 或网络设置。",
                    "后台服务不可用", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

#if ORACLE_DISPOSABLE_LAB
    private async Task ToggleCiLabAsync(bool connect)
    {
        if (!LabAdminControlClient.OnDisposableRunner()) return;
        if (MessageBox.Show(this,
            "此按钮仅在 GitHub 一次性 Windows 测试虚拟机中控制两个临时实验隧道。\\n" +
            "不会连接 Oracle，也没有断线保护。确认执行？",
            "CI 实验环境确认", MessageBoxButtons.YesNo,
            MessageBoxIcon.Warning) != DialogResult.Yes) return;
        try
        {
            bool success;
            if (connect)
            {
                bool a = await LabAdminControlClient.SendAsync(
                    "StartLabPeerA", _shutdown.Token);
                bool b = a && await LabAdminControlClient.SendAsync(
                    "StartLabPeerB", _shutdown.Token);
                success = a && b;
                if (a && !b)
                    await LabAdminControlClient.SendAsync(
                        "StopLabPeerA", _shutdown.Token);
            }
            else
            {
                bool b = await LabAdminControlClient.SendAsync(
                    "StopLabPeerB", _shutdown.Token);
                bool a = await LabAdminControlClient.SendAsync(
                    "StopLabPeerA", _shutdown.Token);
                success = a && b;
            }
            if (!_shutdown.IsCancellationRequested)
                MessageBox.Show(this, success ?
                    "临时实验服务状态已更新。必须另行核实真实握手和路由。" :
                    "未获得后台服务的全部实验操作许可，可能需要独立回滚检查。",
                    "CI 实验服务", MessageBoxButtons.OK,
                    success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }
        catch
        {
            if (!_shutdown.IsCancellationRequested)
                MessageBox.Show(this, "实验服务命令失败；没有触碰生产 VPN。",
                    "CI 实验失败", MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
        }
    }

#endif
    private static string Flag(bool value) => value ? "存在" : "未发现";

    private void ShowPolicySimulation()
    {
        var input = new PolicyInput(
            VpnIntent.Enabled, TunnelStatus.Disconnected, false, false,
            ClientKind.Ordinary, EgressPath.Physical, false, false,
            IpFamily.IPv4, PacketKind.Tcp);
        var app = ProtectionPolicy.Evaluate(input);
        var uu = ProtectionPolicy.Evaluate(input with {
            Client = ClientKind.UuRemote, IdentityVerified = true
        });
        MessageBox.Show(this,
            "模拟场景：VPN 已开启，但隧道意外掉线。\n\n" +
            $"普通应用物理直连：{(app.Allowed ? "允许" : "拒绝")}\n" +
            $"已验证 UU 程序直连：{(uu.Allowed ? "允许" : "拒绝")}\n\n" +
            "此处只有数学规则判断，没有安装任何网络过滤规则。\n" +
            "这不是实际网络锁，无法阻止真实 IP 泄漏。",
            "离线策略模拟", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }
}
