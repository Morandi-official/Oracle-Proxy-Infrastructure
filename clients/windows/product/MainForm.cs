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
    private string _connectionReport="尚未读取系统服务。";
    private string _uuReport="请先在断开状态点击“重新识别 UU”。";
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
        foreach(var (label,action) in new (string,Action)[]{("安装 / 升级服务",()=>Installer.Elevate(false)),("卸载",()=>{if(MessageBox.Show(this,"将恢复直连并卸载系统服务、删除本机密钥。服务器仍保留设备记录与用量，请联系管理员撤销旧设备以释放名额。继续？","卸载",MessageBoxButtons.OKCancel)==DialogResult.OK)Installer.Elevate(true);})}){
            var b=new Button{Text=label,AutoSize=true};b.Click+=(_,_)=>{try{action();}catch{_detail.Text="操作未完成，请检查 UAC 提示或使用完整便携包。";}};tools.Controls.Add(b);}
        var refreshUu=new Button{Text="重新识别 UU",AutoSize=true};refreshUu.Click+=async(_,_)=>await Act("RefreshUu");tools.Controls.Add(refreshUu);
        var inspectConnection=new Button{Text="连接诊断",AutoSize=true};inspectConnection.Click+=(_,_)=>ShowReport("连接诊断",_connectionReport);tools.Controls.Add(inspectConnection);
        var inspectUu=new Button{Text="UU 检查详情",AutoSize=true};inspectUu.Click+=(_,_)=>ShowUuReport();tools.Controls.Add(inspectUu);
        foreach(bool restore in new[]{false,true}){
            var maintenance=new Button{Text=restore?"恢复 UU 权限（UAC）":"修复 UU 权限（UAC）",AutoSize=true};
            maintenance.Click+=(_,_)=>{try{Installer.ElevateUuPermissions(restore);}catch{_detail.Text="UU 权限维护未启动，请检查 UAC 提示。";}};tools.Controls.Add(maintenance);
        }
        var recover=new Button{Text="恢复直连（UAC）",AutoSize=true};recover.Click+=(_,_)=>{if(MessageBox.Show(this,"将停止本产品的隧道、关闭自动连接并恢复直连。已保存密钥保留；损坏的加密状态会保留备份。继续？","紧急恢复",MessageBoxButtons.OKCancel)==DialogResult.OK){try{Installer.ElevateRecovery();}catch{_detail.Text="恢复请求未完成。";}}};tools.Controls.Add(recover);
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
            var state=await ControlPipe.Send(command=="Status"?"Prepare":command,command=="Login"?_username.Text:null,command=="Login"?_password.Text:null);
            if(command=="Login")_password.Clear();
            Display(state);
        }catch{
            _mode.Text="系统服务不可用";_mode.ForeColor=Color.DarkOrange;_detail.Text="首次使用请点击“安装 / 升级服务”并完成 UAC。服务身份无法验证时不会发送账号密码。";
            try{string path=Path.Combine(Platform.Root,"diagnostics.json");if(new FileInfo(path).Length<=4096){var d=JsonNode.Parse(File.ReadAllText(path));_detail.Text+=$" 诊断：{d?["stage"]} / {d?["code"]}。";}}catch{}
        }
        finally{_busy=false;_connect.Enabled=_disconnect.Enabled=_login.Enabled=true;}
    }
    private void ShowUuReport()=>ShowReport("UU 自动识别详情",_uuReport);
    private void ShowReport(string title,string report)
    {
        using var dialog=new Form{Text=title,StartPosition=FormStartPosition.CenterParent,ClientSize=new Size(760,400),MinimizeBox=false,MaximizeBox=false};
        var text=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Both,WordWrap=false,Dock=DockStyle.Fill,Text=report};
        var copy=new Button{Text="复制诊断（不含账号密码或密钥）",Dock=DockStyle.Bottom,Height=40};copy.Click+=(_,_)=>Clipboard.SetText(report);
        dialog.Controls.Add(text);dialog.Controls.Add(copy);dialog.ShowDialog(this);
    }
    private static string UuReason(string code)=>code switch{
        "UU_EXECUTABLE_OWNER_UNTRUSTED"=>"程序文件由普通用户拥有，可被改变权限",
        "UU_EXECUTABLE_WRITABLE"=>"程序文件允许普通用户改写",
        "UU_DIRECTORY_OWNER_UNTRUSTED"=>"安装目录或父目录由普通用户拥有",
        "UU_DIRECTORY_WRITABLE"=>"安装目录或父目录允许普通用户修改",
        "UU_REPARSE_POINT"=>"安装路径含链接或重解析点",
        "UU_PUBLISHER_UNRECOGNIZED"=>"签名发布者未在网易允许名单中",
        "UU_SIGNATURE_NOT_VERIFIED"=>"Windows 未通过数字签名验证（可能涉及证书缓存）",
        "UU_SIGNATURE_UNREADABLE"=>"没有可读取的数字签名",
        "UU_DIRECTORY_UNREADABLE"=>"安装目录不可读取或超出扫描限制",
        _=>"尚未通过检查"};
    internal string UuReport=>_uuReport;
    internal string ConnectionReport=>_connectionReport;
    internal int UsageProgress=>_progress.Value;
    internal bool UsageFresh=>_progress.Enabled;
    internal void Display(JsonObject state)
    {
            _connectionReport="连接诊断（不含账号密码、令牌或密钥）\r\n";
            foreach(string key in new[]{"product_version","mode","error","intent","guard","transport","connection_stage","core_stage","core_pid","tun_permitted","server_handshake_at","peer_rx_bytes","peer_tx_bytes","uu_verified_programs","quick_ready","preparing","verified_at","connect_switch_ms"})_connectionReport+=$"{key}: {state[key]}\r\n";
            if(state["failure"] is JsonObject failure)foreach(string key in new[]{"stage","category","hresult","native_error","socket_error","http_error","http_status","core_stage","at"})_connectionReport+=$"failure.{key}: {failure[key]}\r\n";
            Text="Oracle Proxy · "+(state["product_version"]?.GetValue<string>() ?? "0.3.0-rc6");
            _uuReport="UU 自动发现与信任核验（只读）\r\n服务版本："+(state["product_version"]?.GetValue<string>() ?? "未知")+
                $"\r\n候选：{state["uu_candidates"]} · 通过：{state["uu_verified_programs"]} · 拒绝：{state["uu_rejected"]}\r\n";
            if(state["uu_diagnostics"] is JsonArray uuIssues && uuIssues.Count>0){
                foreach(var item in uuIssues)_uuReport+=$"\r\n{UuReason(item!["code"]!.GetValue<string>())}\r\n{item["code"]} {item["detail"]}\r\n{item["path"]}\r\n";
            }else _uuReport+="\r\n暂无拒绝详情；请在断开状态点击“重新识别 UU”。";
            string mode=state["mode"]?.GetValue<string>() ?? "unknown";bool guard=state["guard"]?.GetValue<bool>()==true;
            _mode.Text=mode switch{"connected"=>guard?(state["transport"]?.GetValue<string>() switch{"wireguard-https"=>"已连接 Oracle · HTTPS","wireguard-quic"=>"已连接 Oracle · QUIC",_=>"已连接 Oracle · UDP"}):"连接保护未验证","connecting"=>"正在连接","protected"=>guard?"已保护 · 等待连接":"保护尚未验证","disconnected"=>"已断开 · 当前直连","recovery"=>"需要恢复处理",_=>"状态未知"};
            _mode.ForeColor=mode=="connected"?Color.FromArgb(11,137,108):mode=="disconnected"?Color.FromArgb(55,70,96):Color.DarkOrange;
            string policy=state["account"]?["status"]?.GetValue<string>() ?? "";
            _detail.Text=state["error"]?.GetValue<string>() is string error && error.Length>0?Message(error):guard?(policy is "disabled" or "expired" or "quota" or "server_budget" or "unavailable"?$"账号状态：{PolicyName(policy)}。防泄漏保护保留。":"防泄漏规则保持启用。意外中断时不会主动恢复普通应用直连。"):"点击连接前，请先登录管理员分配的账号。";
            if(mode=="disconnected" && state["quick_ready"]?.GetValue<bool>()==true)_detail.Text="快速连接已就绪。当前普通应用仍直连；点击连接后启用防泄漏与 VPN。";
            else if(mode=="disconnected" && state["preparing"]?.GetValue<bool>()==true)_detail.Text="正在预备加密通道，当前普通应用仍直连。首次连接或网络变化可能需要等待。";
            var account=state["account"]?.AsObject();
            if(account is not null){
                long used=account["used_bytes"]!.GetValue<long>();long? limit=account["limit_bytes"]?.GetValue<long>();
                _usage.Text=$"{account["username"]} · 本月已用 {FormatBytes(used)} / {(limit is null?"不限":FormatBytes(limit.Value))}";
                _progress.Value=limit is >0?(int)Math.Clamp((double)used/limit.Value*1000,0,1000):limit==0?1000:0;
                long? expires=account["expires_at"]?.GetValue<long>();
                _expiry.Text=$"到期：{(expires is null?"长期":DateTimeOffset.FromUnixTimeSeconds(expires.Value).ToLocalTime().ToString("yyyy-MM-dd HH:mm"))}   ·   设备 {account["device_count"]}/{account["device_limit"]}   ·   UTC 账期 {state["period"]}";
            }else{_usage.Text="登录后显示本月用量与限额";_progress.Value=0;_expiry.Text="账号由管理员创建，不开放自行注册。";}
            long? latency=state["latency_ms"]?.GetValue<long>();long? at=state["observed_at"]?.GetValue<long>();
            bool fresh=at is long received && DateTimeOffset.UtcNow.ToUnixTimeSeconds()-received<=20;_progress.Enabled=fresh;
            if(!fresh && account is not null)_detail.Text+=" 用量未刷新，显示的是上次读取值。";
            _telemetry.Text=$"隧道 HTTP 延迟：{(latency is null?"—":latency+" ms")} · 已验证 UU 程序：{state["uu_verified_programs"]} · 用量更新时间：{(at is null?"—":DateTimeOffset.FromUnixTimeSeconds(at.Value).ToLocalTime().ToString("HH:mm:ss"))}";
    }
    private static string PolicyName(string status)=>status switch{"disabled"=>"已停用","expired"=>"已到期","quota"=>"配额已耗尽","server_budget"=>"服务器出站额度保护中",_=>"待核对"};
    private static string FormatBytes(long bytes)=>$"{bytes/(double)(1L<<30):0.00} GiB（{bytes:N0} B）";
    private static string Message(string code)=>code switch{
        "INVALID_CREDENTIALS"=>"账号或密码错误。", "DEVICE_LIMIT_REACHED"=>"设备数量已达上限，请联系管理员撤销旧设备。", "RATE_LIMITED"=>"登录尝试过于频繁，请稍后重试。",
        "UU_TRUST_NOT_VERIFIED"=>"发现 UU 安装记录，但程序签名或目录权限尚未通过核验。保持原有网络，请勿在远控机器强行连接。",
        "SERVICE_OPERATION_FAILED"=>"连接未完成，请点击“连接诊断”查看失败阶段和错误码。",
        "CORE_READY_TIMEOUT"=>"隧道核心启动超时，保护保持启用。请复制“连接诊断”。",
        "ORACLE_PROBE_TIMEOUT"=>"Oracle 出口验证超时，保护保持启用。请复制“连接诊断”。",
        "ORACLE_PROBE_HTTP_FAILED"=>"Oracle 出口请求失败，保护保持启用。请复制“连接诊断”。",
        "UU_MAINTENANCE_BUSY"=>"UU 权限维护进行中，请完成后再连接。",
        "ACCOUNT_NOT_ACTIVE"=>"账号已停用、到期、超额，或服务器状态暂不可验证。", "RECOVERY_REQUIRED"=>"清理尚未通过验证，防泄漏保护保留。请使用本机恢复操作。",
        "STATE_MISSING_RECOVERY_REQUIRED"=>"加密状态文件缺失，已保留原防泄漏策略。请在本机使用恢复操作。",
        "LOGIN_REQUIRED"=>"请先登录账号。", "DISCONNECT_BEFORE_LOGIN"=>"更换登录前请先断开。", _=>$"操作尚未完成：{code}。"};
}
