using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace OracleProxy.AppSocks5.GUI.Experimental;

// R56: exclusively controls the opt-in R55 unprivileged SSH SOCKS5 helper.
// Does not connect/stop WireGuard, Windows services, WFP or system proxy.
internal sealed class MainForm : Form
{
    private readonly TextBox _host = new() { Width = 340 };
    private readonly TextBox _user = new() { Width = 340, Text = "ubuntu" };
    private readonly TextBox _port = new() { Width = 340, Text = "22" };
    private readonly TextBox _key = new() { Width = 340 };
    private readonly Label _status = new()
    {
        AutoSize = false, Dock = DockStyle.Fill,
        ForeColor = Color.MidnightBlue,
        Text = "未连接：不会自动启动代理。"
    };
    private readonly Button _connect = new() { Text = "连接应用级代理", Width = 165, Height = 40 };
    private readonly Button _disconnect = new() { Text = "断开代理", Width = 105, Height = 40, Enabled = false };
    private readonly Button _verify = new() { Text = "验证 SOCKS5 出口", Width = 145, Height = 40, Enabled = false };
    private readonly Button _addressDiagnostic = new() {
        Text = "Google 双栈诊断", Dock = DockStyle.Fill, Enabled = false
    };
    private readonly Label _probeStatus = new() {
        Dock = DockStyle.Fill, ForeColor = Color.DarkSlateBlue,
        Text = "普通 Edge 不会自动使用 SOCKS5；请通过下方验证按钮检查真实出口。"
    };
    private readonly Button _browse = new() { Text = "选择本地私钥…", Width = 130, Height = 34 };
    private readonly CancellationTokenSource _closing = new();
    private ChildProcessLease? _lease;
    private bool _busy;
    private bool _isClosing;
    private bool _resourcesDisposed;
    private bool _socksReady;
    private bool _verifying;
    private bool _diagnosing;
    private CancellationTokenSource? _verificationCancel;

    internal MainForm()
    {
        Text = "Oracle Proxy R58 · Windows 应用代理实验版（非 VPN）";
        Width = 690;
        Height = 548;
        MinimumSize = new Size(640, 520);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Microsoft YaHei UI", 9.5f);
        BackColor = Color.White;

        var layout = new TableLayoutPanel {
            Dock = DockStyle.Fill, Padding = new Padding(18),
            ColumnCount = 2, RowCount = 10
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 136));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 55));
        for (int row = 1; row <= 4; row++)
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
        Controls.Add(layout);

        var heading = new Label {
            Text = "Oracle Proxy · SOCKS5 SSH 应用级代理",
            Dock = DockStyle.Fill, Font = new Font(
                "Microsoft YaHei UI", 14, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft
        };
        layout.Controls.Add(heading, 0, 0);
        layout.SetColumnSpan(heading, 2);

        AddInput(layout, "Oracle SSH 主机", _host, 1);
        AddInput(layout, "SSH 用户", _user, 2);
        AddInput(layout, "SSH 端口", _port, 3);
        var keyPanel = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        _key.Width = 325;
        keyPanel.Controls.Add(_key);
        keyPanel.Controls.Add(_browse);
        layout.Controls.Add(new Label { Text = "本地 SSH 私钥", Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft }, 0, 4);
        layout.Controls.Add(keyPanel, 1, 4);
        _browse.Click += (_, _) => {
            using var dialog = new OpenFileDialog {
                Title = "仅在本机选择 SSH 私钥（不会上传）",
                CheckFileExists = true, Multiselect = false,
                Filter = "SSH 私钥文件 (*.key;*.pem)|*.key;*.pem|所有文件 (*.*)|*.*"
            };
            if (dialog.ShowDialog(this) == DialogResult.OK) _key.Text = dialog.FileName;
        };

        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill };
        buttons.Controls.Add(_connect);
        buttons.Controls.Add(_disconnect);
        buttons.Controls.Add(_verify);
        layout.Controls.Add(buttons, 1, 5);
        _connect.Click += async (_, _) => await ConnectAsync();
        _disconnect.Click += (_, _) => Disconnect();
        _verify.Click += async (_, _) => await VerifyExitAsync();
        _addressDiagnostic.Click += async (_, _) => await CompareAddressFamilyAsync();

        layout.Controls.Add(_status, 1, 6);
        layout.Controls.Add(_addressDiagnostic, 0, 7);
        layout.Controls.Add(_probeStatus, 1, 7);

        var notes = new Label {
            Dock = DockStyle.Fill, ForeColor = Color.DarkSlateGray,
            Text = "仅监听本机 127.0.0.1:10880。需在独立 Edge 测试窗口手动指定 SOCKS5。\n" +
                   "“已启动”只代表本地端口就绪，不保证 Oracle 出口或浏览器流量。 " +
                   "不会自动更改 Edge、Windows 系统代理、DNS、路由或 UU。\n" +
                   "断开会关闭本窗口拥有的代理与 SSH 子进程，其他软件不受控制。",
            AutoSize = false
        };
        layout.Controls.Add(notes, 0, 8);
        layout.SetColumnSpan(notes, 2);
        var safety = new Label {
            Dock = DockStyle.Fill, ForeColor = Color.Firebrick,
            Text = "实验性应用代理 ≠ WireGuard VPN；没有全设备 WFP 防泄漏。不要用于生产替换 WireSock。",
            TextAlign = ContentAlignment.MiddleLeft
        };
        layout.Controls.Add(safety, 0, 9);
        layout.SetColumnSpan(safety, 2);
    }

    private static void AddInput(TableLayoutPanel grid, string label, TextBox control, int row)
    {
        grid.Controls.Add(new Label { Text = label, Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft }, 0, row);
        grid.Controls.Add(control, 1, row);
    }

    private void Display(string message)
    {
        if (_isClosing || IsDisposed) return;
        _status.Text = message;
    }

    private void SetButtons()
    {
        if (_isClosing || IsDisposed) return;
        _connect.Enabled = !_busy && _lease is null;
        _disconnect.Enabled = _lease is not null;
        _verify.Enabled = !_verifying && !_diagnosing && _socksReady && !_isClosing &&
            _lease is not null && _lease.Running;
        _addressDiagnostic.Enabled = !_verifying && !_diagnosing && _socksReady &&
            !_isClosing && _lease is not null && _lease.Running;
        _host.Enabled = _user.Enabled = _port.Enabled = _key.Enabled =
            _browse.Enabled = _lease is null && !_busy;
    }

    private async Task ConnectAsync()
    {
        if (_busy || _lease is not null || _isClosing) return;
        _busy = true;
        SetButtons();
        if (!SshInput.TryParse(_host.Text.Trim(), _user.Text.Trim(),
            _port.Text.Trim(), _key.Text, out var options) || options is null)
        {
            Display("拒绝连接：请核对主机、用户名、端口、真实私钥文件以及已验证的 known_hosts。");
            _busy = false;
            SetButtons();
            return;
        }

        string helper = Path.Combine(AppContext.BaseDirectory,
            "OracleProxy.AppSocks5.Experimental.exe");
        if (!File.Exists(helper) ||
            (File.GetAttributes(helper) & FileAttributes.ReparsePoint) != 0)
        {
            Display("拒绝连接：缺少同目录 R55 实验代理程序，或文件是不可信的链接。");
            _busy = false;
            SetButtons();
            return;
        }

        ChildProcessLease? starting = null;
        try
        {
            var info = new ProcessStartInfo(helper) {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var argument in new[] {
                "--host", options.Host,
                "--user", options.User,
                "--identity", options.KeyPath,
                "--ssh-port", options.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)
            }) info.ArgumentList.Add(argument);

            var ready = new TaskCompletionSource<bool>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            starting = ChildProcessLease.Start(info);
            // Assign first, then read output; never trust stdout from a random
            // named process. The bundled child must own the job and exit with it.
            starting.Process.OutputDataReceived += (_, e) => {
                if (e.Data is "R55_LOCAL_SOCKS5_LISTENING: 127.0.0.1:10880")
                    ready.TrySetResult(true);
            };
            starting.Process.ErrorDataReceived += (_, _) => { }; // no path/key leakage
            starting.Process.BeginOutputReadLine();
            starting.Process.BeginErrorReadLine();
            _lease = starting;
            _busy = false;
            SetButtons();
            Display("正在建立 SSH 本地 SOCKS5 监听（尚未验证 Oracle 出口）…");

            Task exited = starting.Process.WaitForExitAsync(_closing.Token);
            Task expired = Task.Delay(TimeSpan.FromSeconds(16), _closing.Token);
            Task first = await Task.WhenAny(ready.Task, exited, expired);
            if (_isClosing || !ReferenceEquals(_lease, starting)) return;
            if (first != ready.Task || !starting.Running)
            {
                Display("连接未就绪或已退出。请检查 SSH 指纹信任、私钥或网络；不修改系统网络。");
                Disconnect(preserveMessage: true);
                return;
            }
            _socksReady = true;
            _probeStatus.Text = "点击「验证 SOCKS5 出口」独立验证两家 HTTPS 服务（不修改 Edge 或系统网络）。";
            Display("本地 SOCKS5 已启动：127.0.0.1:10880（真实 Oracle 出口须另行测试）");
            SetButtons();
            _ = MonitorExitAsync(starting);
        }
        catch (OperationCanceledException) when (_isClosing) { }
        catch
        {
            if (!_isClosing)
            {
                Display("连接被拒绝或发生异常。没有更改防火墙、路由、DNS 或系统代理。");
                Disconnect(preserveMessage: true);
            }
        }
        finally
        {
            _busy = false;
            SetButtons();
            if (starting is not null && !ReferenceEquals(_lease, starting))
                starting.Dispose();
        }
    }

    private async Task VerifyExitAsync()
    {
        if (_verifying || !_socksReady || _isClosing || _lease is null ||
            !_lease.Running) return;
        var owner = _lease;
        var token = CancellationTokenSource.CreateLinkedTokenSource(_closing.Token);
        _verificationCancel = token;
        _verifying = true;
        _probeStatus.Text = "只通过 127.0.0.1:10880 SOCKS5 核验两家 HTTPS 出口服务…";
        SetButtons();
        try
        {
            var result = await ExitIpProbe.VerifyAsync(
                _host.Text.Trim(), token.Token);
            if (!_isClosing && ReferenceEquals(_lease, owner))
                _probeStatus.Text = result.Summary;
        }
        catch (OperationCanceledException) { }
        catch
        {
            if (!_isClosing && ReferenceEquals(_lease, owner))
                _probeStatus.Text = "验证失败：SOCKS5 或 HTTPS 请求异常；未尝试直连回退。";
        }
        finally
        {
            if (ReferenceEquals(_verificationCancel, token))
                _verificationCancel = null;
            token.Dispose();
            _verifying = false;
            SetButtons();
        }
    }

    private async Task CompareAddressFamilyAsync()
    {
        if (_diagnosing || _verifying || !_socksReady || _isClosing ||
            _lease is null || !_lease.Running) return;
        if (!SshInput.TryParse(_host.Text.Trim(), _user.Text.Trim(),
            _port.Text.Trim(), _key.Text, out var options) || options is null)
        {
            _probeStatus.Text = "双栈诊断拒绝执行：SSH 身份、私钥或主机密钥配置无效。";
            return;
        }
        var owner = _lease;
        using var token = CancellationTokenSource.CreateLinkedTokenSource(_closing.Token);
        _verificationCancel = token;
        _diagnosing = true;
        _probeStatus.Text = "只读比较 Google 域名和 Oracle IPv4 的 SOCKS5 CONNECT（可能需要约一分钟）…";
        SetButtons();
        try
        {
            var result = await SocksAddressFamilyDiagnostic.CompareAsync(
                options, token.Token);
            if (!_isClosing && ReferenceEquals(_lease, owner))
                _probeStatus.Text = result.Summary;
        }
        catch (OperationCanceledException) { }
        catch
        {
            if (!_isClosing && ReferenceEquals(_lease, owner))
                _probeStatus.Text = "Google 双栈诊断失败；未更改 Oracle、DNS、系统代理或防火墙。";
        }
        finally
        {
            if (ReferenceEquals(_verificationCancel, token))
                _verificationCancel = null;
            _diagnosing = false;
            SetButtons();
        }
    }

    private async Task MonitorExitAsync(ChildProcessLease tracked)
    {
        try { await tracked.Process.WaitForExitAsync(_closing.Token); }
        catch (OperationCanceledException) { return; }
        catch (ObjectDisposedException) { return; }
        if (_isClosing || IsDisposed) return;
        try
        {
            if (!IsHandleCreated) return;
            BeginInvoke((Action)(() => {
                if (_isClosing || !ReferenceEquals(_lease, tracked)) return;
                Display("SSH 代理进程已退出；本地代理不再可用。");
                Disconnect(preserveMessage: true);
            }));
        }
        catch (InvalidOperationException) { }
    }

    private void Disconnect(bool preserveMessage = false)
    {
        ChildProcessLease? owned = _lease;
        _lease = null;
        _verificationCancel?.Cancel();
        _socksReady = false;
        if (!preserveMessage && !_isClosing)
            _probeStatus.Text = "代理已停止；普通 Edge 仍按原有网络设置连接。";
        if (owned is not null)
        {
            try { owned.Dispose(); }
            catch { /* Fail closed: ownership revoked; Windows job is the fallback. */ }
        }
        if (!preserveMessage)
            Display("已断开应用代理：本窗口启动的 R55 / SSH 进程已要求结束。");
        SetButtons();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        _isClosing = true;
        _closing.Cancel();
        Disconnect();
        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_resourcesDisposed)
        {
            _resourcesDisposed = true;
            _isClosing = true;
            _closing.Cancel();
            Disconnect();
            _closing.Dispose();
        }
        base.Dispose(disposing);
    }
}
