using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal sealed class MainForm : Form
{
    private readonly Label _mode=new(){Text="正在读取系统服务…",AutoSize=true,Font=new Font("Microsoft YaHei UI",23,FontStyle.Bold)};
    private readonly Label _detail=new(){Text="",AutoSize=true,MaximumSize=new Size(680,0)};
    private readonly Label _usage=new(){Text="用量未知",AutoSize=true};
    private readonly Label _expiry=new(){Text="到期日未知",AutoSize=true};
    private readonly Label _telemetry=new(){Text="延迟 — · UU —",AutoSize=true};
    private readonly ProgressBar _progress=new(){Minimum=0,Maximum=1000,Value=0,Width=650,Height=18};
    private readonly TextBox _username=new(){PlaceholderText="管理员分配的账号",Width=215,MaxLength=64};
    private readonly TextBox _password=new(){PlaceholderText="管理员分配的密码",Width=215,UseSystemPasswordChar=true,MaxLength=128};
    private readonly Button _login=new(){Text="登录",AutoSize=true};
    private readonly Button _connect=new(){Text="连接",Width=155,Height=48};
    private readonly Button _disconnect=new(){Text="断开并恢复直连",Width=180,Height=48};
    private readonly System.Windows.Forms.Timer _timer=new(){Interval=3000};
    private bool _busy;
    internal MainForm()
    {
        Text="Oracle Proxy";ClientSize=new Size(920,625);MinimumSize=new Size(850,650);BackColor=Color.FromArgb(243,246,251);Font=new Font("Microsoft YaHei UI",10);StartPosition=FormStartPosition.CenterScreen;
        var sidebar=new Panel{Dock=DockStyle.Left,Width=170,BackColor=Color.FromArgb(20,31,53)};
        sidebar.Controls.Add(new Label{Text="ORACLE\nPROXY\n\n连接与用量\n\nWireGuard\n\n设备与诊断",ForeColor=Color.White,AutoSize=true,Location=new Point(24,35),Font=new Font(Font.FontFamily,13,FontStyle.Bold)});Controls.Add(sidebar);
        var body=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(28,30,18,20)};
        foreach(var item in new Control[]{_mode,_detail,new Label{Height=12},_telemetry,new Label{Height=10},_usage,_progress,_expiry}){item.Margin=new Padding(0,0,0,14);body.Controls.Add(item);}
        var buttons=new FlowLayoutPanel{AutoSize=true,Width=660,Height=60};buttons.Controls.AddRange([_connect,_disconnect]);body.Controls.Add(buttons);
        var credentials=new FlowLayoutPanel{AutoSize=true,Width=660,Height=40};credentials.Controls.AddRange([_username,_password,_login]);body.Controls.Add(credentials);
        var tools=new FlowLayoutPanel{AutoSize=true,Width=660,Height=45};
        foreach(var (label,action) in new (string,Action)[]{("安装 / 升级服务",()=>Installer.Elevate(false)),("卸载",()=>{if(MessageBox.Show(this,"将停止 VPN 并恢复直连，再卸载系统服务。继续？","卸载",MessageBoxButtons.OKCancel)==DialogResult.OK)Installer.Elevate(true);})}){
            var b=new Button{Text=label,AutoSize=true};b.Click+=(_,_)=>{try{action();}catch{_detail.Text="操作未完成，请检查 UAC 提示或使用完整便携包。";}};tools.Controls.Add(b);}
        var refreshUu=new Button{Text="重新识别 UU",AutoSize=true};refreshUu.Click+=async(_,_)=>await Act("RefreshUu");tools.Controls.Add(refreshUu);
        var logout=new Button{Text="退出账号",AutoSize=true};logout.Click+=async(_,_)=>await Act("Logout");tools.Controls.Add(logout);body.Controls.Add(tools);
        body.Controls.Add(new Label{Text="本包为集成候选版。IPv6 当前阻断；UU 实机连续性与重启验收尚未完成。",AutoSize=true,MaximumSize=new Size(650,0),ForeColor=Color.DarkOrange});
        Controls.Add(body);body.BringToFront();
        _login.Click+=async(_,_)=>await Act("Login");_connect.Click+=async(_,_)=>await Act("Connect");_disconnect.Click+=async(_,_)=>await Act("Disconnect");
        _timer.Tick+=async(_,_)=>{if(!_busy)await Act("Status");};Shown+=async(_,_)=>{await Act("Status");_timer.Start();};FormClosed+=(_,_)=>_timer.Dispose();
    }
    private async Task Act(string command)
    {
        if(_busy)return;_busy=true;_connect.Enabled=_disconnect.Enabled=_login.Enabled=false;
        try{
            var state=await ControlPipe.Send(command,command=="Login"?_username.Text:null,command=="Login"?_password.Text:null);
            if(command=="Login")_password.Clear();
            string mode=state["mode"]?.GetValue<string>() ?? "unknown";bool guard=state["guard"]?.GetValue<bool>()==true;
            _mode.Text=mode switch{"connected"=>"已连接 Oracle","connecting"=>"正在连接","protected"=>guard?"已保护 · 等待连接":"保护尚未验证","disconnected"=>"已断开 · 当前直连","recovery"=>"需要恢复处理",_=>"状态未知"};
            _mode.ForeColor=mode=="connected"?Color.FromArgb(11,137,108):mode=="disconnected"?Color.FromArgb(55,70,96):Color.DarkOrange;
            _detail.Text=state["error"]?.GetValue<string>() is string error && error.Length>0?Message(error):guard?"防泄漏规则保持启用。意外中断时不会主动恢复普通应用直连。":"点击连接前，请先登录管理员分配的账号。";
            var account=state["account"]?.AsObject();
            if(account is not null){
                long used=account["used_bytes"]!.GetValue<long>();long? limit=account["limit_bytes"]?.GetValue<long>();
                _usage.Text=$"{account["username"]} · 本月已用 {Size(used)} / {(limit is null?"不限":Size(limit.Value))}";
                _progress.Value=limit is >0?(int)Math.Clamp((double)used/limit.Value*1000,0,1000):limit==0?1000:0;
                long? expires=account["expires_at"]?.GetValue<long>();
                _expiry.Text=$"到期：{(expires is null?"长期":DateTimeOffset.FromUnixTimeSeconds(expires.Value).ToLocalTime().ToString("yyyy-MM-dd HH:mm"))}   ·   设备 {account["device_count"]}/{account["device_limit"]}   ·   UTC 账期 {state["period"]}";
            }else{_usage.Text="登录后显示本月用量与限额";_progress.Value=0;_expiry.Text="账号由管理员创建，不开放自行注册。";}
            long? latency=state["latency_ms"]?.GetValue<long>();long? at=state["received_at"]?.GetValue<long>();
            _telemetry.Text=$"隧道 HTTP 延迟：{(latency is null?"—":latency+" ms")} · 已验证 UU 程序：{state["uu_verified_programs"]} · 用量更新时间：{(at is null?"—":DateTimeOffset.FromUnixTimeSeconds(at.Value).ToLocalTime().ToString("HH:mm:ss"))}";
        }catch{_mode.Text="系统服务不可用";_mode.ForeColor=Color.DarkOrange;_detail.Text="首次使用请点击“安装 / 升级服务”并完成 UAC。服务身份无法验证时不会发送账号密码。";}
        finally{_busy=false;_connect.Enabled=_disconnect.Enabled=_login.Enabled=true;}
    }
    private static string Size(long bytes)=>$"{bytes/(double)(1L<<30):0.00} GiB（{bytes:N0} B）";
    private static string Message(string code)=>code switch{
        "INVALID_CREDENTIALS"=>"账号或密码错误。", "DEVICE_LIMIT_REACHED"=>"设备数量已达上限，请联系管理员撤销旧设备。", "RATE_LIMITED"=>"登录尝试过于频繁，请稍后重试。",
        "UU_TRUST_NOT_VERIFIED"=>"发现 UU 安装记录，但程序签名或目录权限尚未通过核验。保持原有网络，请勿在远控机器强行连接。",
        "ACCOUNT_NOT_ACTIVE"=>"账号已停用、到期、超额，或服务器状态暂不可验证。", "RECOVERY_REQUIRED"=>"清理尚未通过验证，防泄漏保护保留。请使用本机恢复操作。",
        "LOGIN_REQUIRED"=>"请先登录账号。", "DISCONNECT_BEFORE_LOGIN"=>"更换登录前请先断开。", _=>$"操作尚未完成：{code}。"};
}
