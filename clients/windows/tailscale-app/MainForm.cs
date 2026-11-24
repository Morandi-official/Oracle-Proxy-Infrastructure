using System.Diagnostics;

namespace OracleProxy.Tailscale;

internal sealed class MainForm : Form
{
    private readonly AccountClient _account = new();
    private readonly TextBox _user = new() { PlaceholderText = "账号", Dock = DockStyle.Top };
    private readonly TextBox _password = new() { PlaceholderText = "密码", UseSystemPasswordChar = true, Dock = DockStyle.Top };
    private readonly Label _status = new() { Text = "请登录", AutoSize = true, Padding = new Padding(0, 12, 0, 12) };
    private readonly Button _login = new() { Text = "登录", AutoSize = true };
    private readonly Button _connect = new() { Text = "连接", Enabled = false, AutoSize = true };
    private readonly Button _disconnect = new() { Text = "断开并恢复直连", Enabled = false, AutoSize = true };
    private readonly string _stateRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Morandi", "ProxyTailscale");
    private readonly CancellationTokenSource _lifetime = new();
    private CancellationTokenSource? _connecting;
    private Task? _connectTask;
    private string? _session;
    private string? _state;
    private DaemonProcess? _daemon;
    private bool _closing;
    private bool _closeApproved;

    internal MainForm()
    {
        Text = "Proxy";
        MinimumSize = new Size(420, 305);
        ClientSize = new Size(490, 310);
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, ColumnCount = 1, Padding = new Padding(22) };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = "Proxy", Font = new Font(Font.FontFamily, 22, FontStyle.Bold), AutoSize = true });
        layout.Controls.Add(_status);
        layout.Controls.Add(_user);
        layout.Controls.Add(_password);
        var actions = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Padding = new Padding(0, 8, 0, 0) };
        actions.Controls.AddRange([_login, _connect, _disconnect]);
        layout.Controls.Add(actions);
        Controls.Add(layout);
        AcceptButton = _login;
        _login.Click += async (_, _) => await Login();
        _connect.Click += async (_, _) =>
        {
            _connectTask = Connect();
            await _connectTask;
        };
        _disconnect.Click += async (_, _) => await Disconnect();
        FormClosing += CloseRequested;
    }

    private async Task Login()
    {
        _login.Enabled = false;
        _status.Text = "正在登录";
        try
        {
            string username = _user.Text.Trim();
            _state = ClientConnection.StateFor(_stateRoot, username);
            _session = await _account.Login(username, _password.Text, ClientConnection.Device(_state), _lifetime.Token);
            _password.Clear();
            _user.Hide();
            _password.Hide();
            _login.Hide();
            _connect.Enabled = true;
            AcceptButton = _connect;
            _status.Text = "已断开 · 当前直连";
        }
        catch (Exception exception) when (!_closing)
        {
            _status.Text = Message(exception);
            _login.Enabled = true;
        }
        catch (Exception) when (_closing) { }
    }

    private async Task Connect()
    {
        if (_session is null || _state is null || _connecting is not null || _daemon is not null) return;
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        _connecting = attempt;
        _connect.Enabled = false;
        _disconnect.Enabled = true;
        _status.Text = "正在连接";
        var elapsed = Stopwatch.StartNew();
        try
        {
            (_daemon, _) = await ClientConnection.Open(_account, _session, _state, attempt.Token);
            _status.Text = $"已连接 · {elapsed.ElapsedMilliseconds} ms";
        }
        catch (Exception failure)
        {
            try { await StopDaemon(); }
            catch (Exception cleanup) { failure = cleanup; }
            if (!_closing && !attempt.IsCancellationRequested)
            {
                _status.Text = Message(failure);
                if (failure.Message == "LOGIN_REQUIRED")
                {
                    _session = null;
                    _user.Show();
                    _password.Show();
                    _login.Show();
                    _login.Enabled = true;
                    AcceptButton = _login;
                }
            }
        }
        finally
        {
            _connecting = null;
            if (!_closing)
            {
                _connect.Enabled = _daemon is null && _session is not null;
                _disconnect.Enabled = _daemon is not null;
            }
        }
    }

    private async Task Disconnect()
    {
        _connect.Enabled = false;
        _disconnect.Enabled = false;
        _status.Text = "正在恢复直连";
        try
        {
            if (_connecting is not null) await _connecting.CancelAsync();
            if (_connectTask is not null) await _connectTask;
            await StopDaemon();
            _status.Text = "已断开 · 当前直连";
            _connect.Enabled = _session is not null && !_closing;
        }
        catch (Exception failure) { _status.Text = Message(failure); }
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
        await Disconnect();
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

    private static string Message(Exception error) => error.Message switch
    {
        "INVALID_CREDENTIALS" => "账号或密码有误",
        "TAILSCALE_ACCOUNT_NOT_ACTIVE" => "账号当前不可连接",
        "DEVICE_LIMIT_EXCEEDED" => "已达到设备上限",
        "LOGIN_REQUIRED" => "登录已过期",
        "EXIT_NOT_VERIFIED" => "暂时无法验证代理出口",
        _ => "暂时无法连接，请重试",
    };
}
