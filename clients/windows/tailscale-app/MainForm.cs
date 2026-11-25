using System.Diagnostics;

namespace OracleProxy.Tailscale;

internal sealed class MainForm : Form
{
    private static readonly Color Canvas = Color.FromArgb(232, 239, 245);
    private static readonly Color Surface = Color.FromArgb(248, 250, 253);
    private static readonly Color Ink = Color.FromArgb(29, 47, 66);
    private static readonly Color Muted = Color.FromArgb(66, 87, 108);
    private static readonly Color Accent = Color.FromArgb(52, 81, 111);
    private static readonly Color Alert = Color.FromArgb(148, 44, 38);
    private static readonly Color Connected = Color.FromArgb(19, 106, 80);

    private readonly AccountClient _account = new();
    private readonly TextBox _user = new() { PlaceholderText = "输入账号", AccessibleName = "账号", MaxLength = 64 };
    private readonly TextBox _password = new()
    {
        PlaceholderText = "输入密码", AccessibleName = "密码", UseSystemPasswordChar = true, MaxLength = 128,
    };
    private readonly Label _heading = new() { Text = "登录账号", AutoSize = true };
    private readonly Label _identity = new() { AutoSize = true, Visible = false, UseMnemonic = false };
    private readonly Label _status = new() { AutoSize = true, UseMnemonic = false, AccessibleName = "连接状态" };
    private readonly SmoothButton _login = new() { Text = "登录", Name = "account-login" };
    private readonly SmoothButton _connect = new() { Text = "连接", Enabled = false, Visible = false };
    private readonly TableLayoutPanel _fields = new() { AutoSize = true, Dock = DockStyle.Top, ColumnCount = 1 };
    private readonly string _stateRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Morandi", "ProxyTailscale");
    private readonly CancellationTokenSource _lifetime = new();
    private CancellationTokenSource? _connecting;
    private Task? _connectTask;
    private string? _session;
    private string? _state;
    private DaemonProcess? _daemon;
    private ExitProfile? _profile;
    private bool _connected;
    private Task? _disconnectTask;
    private bool _closing;
    private bool _closeApproved;

    internal MainForm()
    {
        Text = "Proxy";
        Font = new Font("Microsoft YaHei UI", 10);
        MinimumSize = new Size(400, 440);
        ClientSize = new Size(500, 418);
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        BackColor = Canvas;
        ForeColor = Ink;
        var scroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true };
        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1, Padding = new Padding(26, 22, 26, 22),
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var header = new FlowLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true, WrapContents = false, Margin = new Padding(0, 0, 0, 14),
        };
        header.Controls.Add(new Label
        {
            Text = "Proxy", Font = new Font("Segoe UI", 25, FontStyle.Bold), AutoSize = true, Margin = Padding.Empty,
        });
        header.Controls.Add(new Label
        {
            Text = "v" + typeof(MainForm).Assembly.GetName().Version?.ToString(3), ForeColor = Muted,
            Font = new Font("Segoe UI", 9), AutoSize = true, Margin = new Padding(12, 16, 0, 0),
        });
        layout.Controls.Add(header);
        var card = new SmoothSurface
        {
            AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Top,
            BackColor = Surface, Padding = new Padding(22, 18, 22, 20), Margin = Padding.Empty,
        };
        var content = new TableLayoutPanel
        {
            AutoSize = true, Dock = DockStyle.Top, ColumnCount = 1, Margin = Padding.Empty,
        };
        content.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        _heading.Font = new Font(Font.FontFamily, 16, FontStyle.Bold);
        _heading.Margin = new Padding(0, 0, 0, 10);
        _identity.ForeColor = Muted;
        _identity.Margin = new Padding(0, 0, 0, 12);
        content.Controls.Add(_heading);
        content.Controls.Add(_identity);
        _fields.Margin = Padding.Empty;
        _fields.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        AddField("账号", _user);
        AddField("密码", _password);
        content.Controls.Add(_fields);
        StyleAction(_login);
        StyleAction(_connect);
        content.Controls.Add(_login);
        content.Controls.Add(_connect);
        _status.Anchor = AnchorStyles.Left | AnchorStyles.Right;
        _status.Margin = new Padding(0, 12, 0, 0);
        content.SizeChanged += (_, _) =>
            _status.MaximumSize = new Size(Math.Max(1, content.ClientSize.Width), 0);
        content.Controls.Add(_status);
        card.Controls.Add(content);
        layout.Controls.Add(card);
        scroll.Controls.Add(layout);
        Controls.Add(scroll);
        AcceptButton = _login;
        _login.Click += async (_, _) => await Login();
        _connect.Click += async (_, _) =>
        {
            if (_connected || _connecting is not null)
            {
                _disconnectTask = Disconnect(keepCoordinator: true);
                await _disconnectTask;
            }
            else
            {
                _connectTask = Connect();
                await _connectTask;
            }
        };
        Shown += PrepareLogin;
        FormClosing += CloseRequested;
    }

    private void AddField(string label, TextBox input)
    {
        _fields.Controls.Add(new Label { Text = label, AutoSize = true, Margin = new Padding(0, 0, 0, 5) });
        _fields.Controls.Add(new SmoothInputFrame(input)
        {
            Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, 12),
        });
    }

    private static void StyleAction(SmoothButton button)
    {
        button.Dock = DockStyle.Top;
        button.Height = 42;
        button.Margin = Padding.Empty;
        button.Primary = true;
        button.BackColor = Accent;
        button.ForeColor = Color.White;
        button.FlatAppearance.MouseOverBackColor = Color.FromArgb(44, 71, 100);
        button.FlatAppearance.MouseDownBackColor = Color.FromArgb(36, 60, 85);
    }

    private void SetStatus(string message, Color? color = null)
    {
        _status.Text = message;
        _status.ForeColor = color ?? Muted;
        _status.Visible = message.Length != 0;
    }

    private void ShowSession(bool loggedIn)
    {
        _heading.Text = loggedIn ? "当前连接" : "登录账号";
        _identity.Visible = loggedIn;
        _fields.Visible = !loggedIn;
        _login.Visible = !loggedIn;
        _login.Enabled = !loggedIn;
        _connect.Visible = loggedIn;
        _connect.Enabled = loggedIn;
        AcceptButton = loggedIn ? _connect : _login;
    }

    private async void PrepareLogin(object? sender, EventArgs e)
    {
        try { await _account.PrepareLogin(_lifetime.Token); }
        catch (Exception error) when (error is IOException or HttpRequestException or OperationCanceledException) { }
    }

    private async Task Login()
    {
        string username = _user.Text.Trim().ToLowerInvariant();
        if (username.Length == 0 || _password.TextLength == 0)
        {
            SetStatus("请输入账号和密码。", Alert);
            (username.Length == 0 ? _user : _password).Focus();
            return;
        }
        _login.Enabled = false;
        SetStatus("正在连接账号服务…");
        try
        {
            _state = ClientConnection.StateFor(_stateRoot, username);
            string device;
            try { device = ClientConnection.Device(_state); }
            catch (IOException error) when (error.Message != "INVALID_PROXY_DEVICE_ID")
            {
                throw new IOException("DEVICE_FILE_UNAVAILABLE", error);
            }
            _session = await _account.Login(username, _password.Text, device, _lifetime.Token,
                () => { if (!_closing) SetStatus("正在尝试备用登录路径…"); });
            _password.Clear();
            _identity.Text = username;
            ShowSession(loggedIn: true);
            SetStatus("已断开 · 当前直连");
        }
        catch (Exception exception) when (!_closing)
        {
            SetStatus(Message(exception), Alert);
            _login.Enabled = true;
        }
        catch (Exception) when (_closing) { }
    }

    private async Task Connect()
    {
        if (_session is null || _state is null || _connecting is not null) return;
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        _connecting = attempt;
        _connect.Text = "取消连接";
        SetStatus("正在连接…");
        var elapsed = Stopwatch.StartNew();
        string phase = "ACCOUNT_PROFILE";
        try
        {
            var retained = _daemon;
            _daemon = null;
            (_daemon, _profile) = await ClientConnection.Open(_account, _session, _state, attempt.Token, stage =>
            {
                phase = stage;
                if (!_closing && !attempt.IsCancellationRequested)
                    SetStatus(PhaseStatus(stage));
            }, retained: retained, previous: _profile);
            _connected = true;
            SetStatus($"已连接 · {elapsed.ElapsedMilliseconds} ms", Connected);
        }
        catch (Exception failure)
        {
            try { await StopDaemon(); }
            catch (Exception cleanup) { failure = cleanup; }
            if (!_closing && !attempt.IsCancellationRequested)
            {
                SetStatus(ConnectFailure(failure, phase), Alert);
                if (failure.Message == "LOGIN_REQUIRED")
                {
                    _session = null;
                    ShowSession(loggedIn: false);
                }
            }
        }
        finally
        {
            _connecting = null;
            if (!_closing && !attempt.IsCancellationRequested)
            {
                _connect.Text = _connected ? "断开" : "连接";
                _connect.Enabled = _session is not null;
            }
        }
    }

    private async Task Disconnect(bool keepCoordinator)
    {
        _connect.Enabled = false;
        SetStatus("正在恢复直连…");
        try
        {
            if (_connecting is not null) await _connecting.CancelAsync();
            if (_connectTask is not null) await _connectTask;
            if (!keepCoordinator || !_connected || _daemon is null ||
                _profile is null || !await ClientConnection.TryRestoreDirect(_daemon, _profile, _lifetime.Token))
                await StopDaemon();
            _connected = false;
            SetStatus("已断开 · 当前直连");
            _connect.Text = "连接";
            _connect.Enabled = _session is not null && !_closing;
        }
        catch (Exception failure)
        {
            SetStatus(Message(failure), Alert);
            _connect.Text = "断开";
            _connect.Enabled = !_closing;
        }
    }

    private async Task StopDaemon()
    {
        if (_daemon is not { } daemon) return;
        _daemon = null;
        await daemon.DisposeAsync();
    }

    private async void CloseRequested(object? sender, FormClosingEventArgs e)
    {
        if (_closeApproved) return;
        e.Cancel = true;
        if (_closing) return;
        _closing = true;
        await _lifetime.CancelAsync();
        if (_disconnectTask is not null) await _disconnectTask;
        await Disconnect(keepCoordinator: false);
        _closeApproved = true;
        Close();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _account.Dispose();
            _lifetime.Dispose();
        }
        base.Dispose(disposing);
    }

    private static string PhaseStatus(string phase) => phase switch
    {
        "ACCOUNT_PROFILE" or "RETAINED_ACCOUNT_PROFILE" => "正在检查账号与设备授权…",
        "DAEMON_PROFILE" => "正在启动本机连接引擎…",
        "ENROLLMENT_START" or "COORDINATOR_NODE_KEY" => "正在联系 Tailscale 协调服务…",
        "ACCOUNT_CONFIRM" => "正在确认设备登记…",
        "SELECT_EXIT" or "RETAINED_SELECT_EXIT" => "正在设置代理出口…",
        "VERIFY_EXIT" => "正在验证 IPv4 和 IPv6 出口…",
        _ => "正在连接…",
    };

    private static string ConnectFailure(Exception error, string phase)
    {
        string message = Message(error);
        if (message != GenericFailure) return message;
        return phase switch
        {
            "ACCOUNT_PROFILE" or "RETAINED_ACCOUNT_PROFILE" => "无法获取连接授权，请重试。",
            "DAEMON_PROFILE" => "本机连接引擎启动失败，请重试。",
            "ENROLLMENT_START" or "COORDINATOR_NODE_KEY" => "未能与 Tailscale 协调服务建立连接。",
            "ACCOUNT_CONFIRM" => "服务器暂未确认设备登记，请重试。",
            "SELECT_EXIT" or "RETAINED_SELECT_EXIT" => "无法设置代理出口，请重试。",
            "VERIFY_EXIT" => "无法验证代理出口，请重试。",
            _ => GenericFailure,
        };
    }

    private const string GenericFailure = "暂时无法连接，请重试";

    private static string Message(Exception error) => error switch
    {
        UnauthorizedAccessException => "无法访问本机的 Proxy 设备文件。",
        IOException { Message: "INVALID_PROXY_DEVICE_ID" } => "本机设备文件格式异常，请联系管理员。",
        _ => MessageForCode(error.Message),
    };

    private static string MessageForCode(string code) => code switch
    {
        "DEVICE_FILE_UNAVAILABLE" => "无法读取或建立本机的 Proxy 设备文件。",
        "INVALID_CREDENTIALS" => "账号或密码有误。",
        "RATE_LIMITED" => "登录尝试过多，请等待一分钟后重试。",
        "ACCOUNT_DNS_FAILED" => "无法解析账号服务地址，请检查 DNS 或网络。",
        "ACCOUNT_CONNECT_FAILED" => "无法访问账号服务，请检查当前网络。",
        "ACCOUNT_PROXY_FAILED" => "Windows 系统代理无法连接账号服务。",
        "ACCOUNT_TLS_FAILED" => "无法验证账号服务的 HTTPS 连接，请检查系统日期和时间。",
        "ACCOUNT_TIMEOUT" => "提交账号请求超时，请重试。",
        "ACCOUNT_ROUTE_TIMEOUT" => "未能验证账号服务的登录路径，请检查网络。",
        "TAILSCALE_ENGINE_START_TIMEOUT" => "本机连接引擎启动超时。",
        "TAILSCALE_DAEMON_EXITED" => "本机连接引擎意外退出。",
        "TAILSCALE_COORDINATOR_TIMEOUT" => "已登录账号，但等待 Tailscale 协调服务超时。",
        "TAILSCALE_ENROLLMENT_TIMEOUT" => "设备已向协调服务登记，但服务器确认超时。",
        "TAILSCALE_DEVICE_ALREADY_REGISTERED" => "本机已有登记记录，请在后台核对设备状态。",
        "TAILSCALE_LOCAL_CONTROL_REJECTED" => "本机连接引擎拒绝了当前操作。",
        "ACCOUNT_HTTP_FAILED" => "账号 HTTPS 请求中断，请重试。",
        "ACCOUNT_SERVICE_UNAVAILABLE" or "TAILSCALE_SERVICE_UNAVAILABLE" or "CONTROL_UNAVAILABLE"
            => "账号服务暂不可用，请稍后重试。",
        "ACCOUNT_RESPONSE_INVALID" or "INVALID_REQUEST" => "账号服务响应异常，请稍后重试。",
        "TAILSCALE_ACCOUNT_NOT_ACTIVE" => "账号当前不可连接",
        "DEVICE_LIMIT_EXCEEDED" => "已达到设备上限",
        "LOGIN_REQUIRED" => "登录已过期",
        "EXIT_NOT_VERIFIED" => "暂时无法验证代理出口",
        _ => GenericFailure,
    };
}
