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
        Text = "Oracle Proxy · Windows 客户端预览版";
        Width = 740;
        Height = 530;
        MinimumSize = new Size(630, 460);
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
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 60));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
        Controls.Add(root);

        root.Controls.Add(new Label {
            Text = "Oracle Proxy · 自研 Windows 客户端",
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
        root.Controls.Add(buttons, 0, 3);

        root.Controls.Add(new Label {
            Dock = DockStyle.Fill, ForeColor = Color.Firebrick,
            Text = "开发预览版：尚不能连接 VPN，也不提供断线防泄漏保护。\n" +
                   "不会修改 WireSock、UU、Windows 防火墙或 Oracle 服务器。",
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
                $"物理网络适配器：{d.PhysicalAdapterCount} 个\n" +
                $"IPv4 默认路由：{Flag(d.IPv4DefaultRoute)}\n" +
                $"IPv6 默认路由：{Flag(d.IPv6DefaultRoute)}\n\n" +
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
