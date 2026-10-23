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
    private bool _busy,_renderingTransport,_connectionIntent;
    private readonly ComboBox _transportChoice=new(){DropDownStyle=ComboBoxStyle.DropDownList,Width=240};
    private readonly SemaphoreSlim _requests=new(1,1);
    private readonly Func<string,string?,string?,Task<JsonObject>> _send;
    private sealed class BufferedFlowPanel : FlowLayoutPanel
    {
        internal BufferedFlowPanel(){DoubleBuffered=true;ResizeRedraw=true;}
    }
    private string _connectionReport="尚未读取系统服务。";
    private string _uuReport="请先在断开状态点击“重新识别 UU”。";
    private readonly Label _protocol=MetricValue(),_exitIp=MetricValue(),_download=MetricValue(),_upload=MetricValue(),_latency=MetricValue(),_uu=MetricValue();
    private readonly Label _accountName=new(){AutoSize=true,Text="尚未登录"};
    private readonly Label _usageUpdated=new(){AutoSize=true,ForeColor=Color.FromArgb(100,113,134)};
    private readonly Button _logout=new(){Text="退出账号",AutoSize=true};
    private long? _sampleAt,_sampleRx,_sampleTx;
    private uint _samplePid;
    private static Label MetricValue()=>new(){Text="—",Dock=DockStyle.Fill,AutoEllipsis=true,Height=30,TextAlign=ContentAlignment.MiddleLeft,Font=new Font("Microsoft YaHei UI",13,FontStyle.Bold),Margin=new Padding(0)};
    private static TableLayoutPanel Stack(string name)=>new(){Name=name,Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,ColumnCount=1,Margin=new Padding(0),Padding=new Padding(0)};
    private static void Row(TableLayoutPanel panel,Control item){int row=panel.RowCount++;panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));item.Dock=DockStyle.Fill;panel.Controls.Add(item,0,row);}
    private static Control Metric(string title,Label value){var cell=Stack("metric"+title);cell.Margin=new Padding(0,0,18,12);Row(cell,new Label{Text=title,AutoSize=true,ForeColor=Color.FromArgb(100,113,134),Margin=new Padding(0,0,0,3)});Row(cell,value);return cell;}
    private static GroupBox Card(string name,string title,TableLayoutPanel content){var card=new GroupBox{Name=name,Text=title,Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Padding=new Padding(18,24,18,14),Margin=new Padding(0,0,0,16),BackColor=Color.White};card.Controls.Add(content);return card;}
    private static BufferedFlowPanel Actions()=>new(){AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Fill,WrapContents=true,Margin=new Padding(0,6,0,6),Padding=new Padding(0)};
    internal MainForm(Func<string,string?,string?,Task<JsonObject>>? send=null)
    {
        _send=send ?? ControlPipe.Send;DoubleBuffered=true;
        Text="Oracle Proxy";ClientSize=new Size(1120,860);MinimumSize=new Size(900,600);BackColor=Color.FromArgb(243,246,251);Font=new Font("Microsoft YaHei UI",10);StartPosition=FormStartPosition.CenterScreen;
        var shell=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Margin=new Padding(0)};
        shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,174));shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        shell.RowStyles.Add(new RowStyle(SizeType.Percent,100));Controls.Add(shell);
        var sidebar=new Panel{Dock=DockStyle.Fill,BackColor=Color.FromArgb(20,31,53),Margin=new Padding(0),Padding=new Padding(18,28,16,18)};
        var navigation=Stack("navigation");navigation.ForeColor=Color.White;
        Row(navigation,new Label{Text="ORACLE\nPROXY",AutoSize=true,Font=new Font(Font.FontFamily,17,FontStyle.Bold),Margin=new Padding(0,0,0,30)});
        sidebar.Controls.Add(navigation);shell.Controls.Add(sidebar,0,0);
        var viewport=new Panel{Name="viewport",Dock=DockStyle.Fill,AutoScroll=true,Margin=new Padding(0)};shell.Controls.Add(viewport,1,0);
        var body=Stack("sections");body.Padding=new Padding(24,20,24,16);viewport.Controls.Add(body);
        _mode.AutoSize=false;_mode.Height=48;_mode.Font=new Font(Font.FontFamily,21,FontStyle.Bold);_mode.AutoEllipsis=true;_mode.Margin=new Padding(0,0,0,6);
        _detail.AutoSize=false;_detail.MaximumSize=Size.Empty;_detail.Height=58;_detail.Margin=new Padding(0,0,0,12);
        var connection=Stack("connectionContent");Row(connection,_mode);Row(connection,_detail);
        var metrics=new TableLayoutPanel{Name="connectionMetrics",AutoSize=true,Dock=DockStyle.Fill,ColumnCount=3,RowCount=2,Margin=new Padding(0)};
        for(int i=0;i<3;i++)metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100f/3));
        var values=new[]{Metric("当前协议",_protocol),Metric("已验证出口 IP",_exitIp),Metric("隧道 HTTP 延迟",_latency),Metric("下载速率 · VPN",_download),Metric("上传速率 · VPN",_upload),Metric("UU 直连保护",_uu)};
        for(int i=0;i<values.Length;i++)metrics.Controls.Add(values[i],i%3,i/3);Row(connection,metrics);
        _transportChoice.Items.AddRange(["自动（UDP 优先）","WireGuard / UDP","QUIC / HTTP/3"]);_transportChoice.SelectedIndex=0;
        var selection=Actions();selection.Controls.Add(new Label{Text="首选连接方式",AutoSize=true,Margin=new Padding(0,8,16,0)});selection.Controls.Add(_transportChoice);Row(connection,selection);
        _transportChoice.SelectedIndexChanged+=async(_,_)=>{if(!_renderingTransport && _transportChoice.SelectedIndex>=0)await Act(_transportChoice.SelectedIndex switch{1=>"PreferUdp",2=>"PreferQuic",_=>"PreferAuto"});};
        var buttons=Actions();_connect.BackColor=Color.FromArgb(11,137,108);_connect.ForeColor=Color.White;_connect.FlatStyle=FlatStyle.Flat;_connect.FlatAppearance.BorderSize=0;_connect.UseVisualStyleBackColor=false;_connect.Margin=new Padding(0,0,10,0);_disconnect.Margin=new Padding(0);buttons.Controls.AddRange([_connect,_disconnect]);Row(connection,buttons);
        _telemetry.AutoSize=false;_telemetry.Height=28;_telemetry.AutoEllipsis=true;_telemetry.ForeColor=Color.FromArgb(100,113,134);_telemetry.Margin=new Padding(0,8,0,0);Row(connection,_telemetry);
        var connectionCard=Card("connectionSection","01   当前连接",connection);Row(body,connectionCard);
        var account=Stack("accountContent");_accountName.AutoSize=false;_accountName.Height=30;_accountName.AutoEllipsis=true;_accountName.Font=new Font(Font.FontFamily,11,FontStyle.Bold);_accountName.Margin=new Padding(0,0,0,12);Row(account,_accountName);
        _usage.AutoSize=false;_usage.Height=30;_usage.Margin=new Padding(0,0,0,4);Row(account,_usage);
        _progress.Dock=DockStyle.Fill;_progress.Height=14;_progress.Margin=new Padding(0,0,0,10);Row(account,_progress);
        _expiry.AutoSize=false;_expiry.Height=28;_expiry.AutoEllipsis=true;_expiry.Margin=new Padding(0,0,0,6);Row(account,_expiry);_usageUpdated.AutoSize=false;_usageUpdated.Height=28;_usageUpdated.AutoEllipsis=true;_usageUpdated.Margin=new Padding(0,0,0,14);Row(account,_usageUpdated);
        var credentials=new TableLayoutPanel{Name="credentials",Dock=DockStyle.Fill,AutoSize=true,ColumnCount=2,RowCount=2,Margin=new Padding(0)};
        credentials.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));credentials.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));
        credentials.Controls.Add(new Label{Text="登录账号",AutoSize=true,Margin=new Padding(0,0,12,6)},0,0);credentials.Controls.Add(new Label{Text="密码",AutoSize=true,Margin=new Padding(0,0,0,6)},1,0);
        _username.Dock=_password.Dock=DockStyle.Fill;_username.Margin=new Padding(0,0,12,0);_password.Margin=new Padding(0);credentials.Controls.Add(_username,0,1);credentials.Controls.Add(_password,1,1);Row(account,credentials);
        var accountActions=Actions();_login.MinimumSize=_logout.MinimumSize=new Size(100,36);_login.Margin=new Padding(0,0,10,0);_logout.Margin=new Padding(0);accountActions.Controls.AddRange([_login,_logout]);Row(account,accountActions);
        _logout.Click+=async(_,_)=>await Act("Logout");var accountCard=Card("accountSection","02   账号与用量",account);Row(body,accountCard);
        var tools=Stack("toolsContent");
        var diagnostics=Actions();
        Button Tool(string title,Action action){var button=new Button{Text=title,AutoSize=true,MinimumSize=new Size(112,36),Margin=new Padding(0,0,10,8)};button.Click+=(_,_)=>action();return button;}
        diagnostics.Controls.Add(Tool("连接诊断",()=>ShowReport("连接诊断",_connectionReport)));
        diagnostics.Controls.Add(Tool("UU 检查详情",ShowUuReport));
        diagnostics.Controls.Add(Tool("重新识别 UU",async()=>await Act("RefreshUu")));
        void Open(string url){try{System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url){UseShellExecute=true});}catch{_detail.Text="未能打开默认浏览器。";}}
        diagnostics.Controls.Add(Tool("打开出口检查",()=>Open("https://www.cloudflare.com/cdn-cgi/trace")));
        diagnostics.Controls.Add(Tool("打开管理后台",()=>Open("https://vpn-admin.morandi.dpdns.org/")));Row(tools,diagnostics);
        Row(tools,new Label{Text="系统服务与恢复",AutoSize=true,ForeColor=Color.FromArgb(100,113,134),Margin=new Padding(0,10,0,4)});
        var maintenance=Actions();
        maintenance.Controls.Add(Tool("安装 / 升级服务",()=>{try{Installer.Elevate(false);}catch{_detail.Text="操作未完成，请检查 UAC 提示或使用完整便携包。";}}));
        maintenance.Controls.Add(Tool("卸载",()=>{if(MessageBox.Show(this,"将恢复直连并卸载系统服务、删除本机密钥。服务器仍保留设备记录与用量，请联系管理员撤销旧设备以释放名额。继续？","卸载",MessageBoxButtons.OKCancel)==DialogResult.OK){try{Installer.Elevate(true);}catch{_detail.Text="卸载未完成，请检查 UAC 提示。";}}}));
        foreach(bool restore in new[]{false,true})maintenance.Controls.Add(Tool(restore?"恢复 UU 权限（UAC）":"修复 UU 权限（UAC）",()=>{try{Installer.ElevateUuPermissions(restore);}catch{_detail.Text="UU 权限维护未启动，请检查 UAC 提示。";}}));
        maintenance.Controls.Add(Tool("恢复直连（UAC）",()=>{if(MessageBox.Show(this,"将停止本产品的隧道、关闭自动连接并恢复直连。已保存密钥保留；损坏的加密状态会保留备份。继续？","紧急恢复",MessageBoxButtons.OKCancel)==DialogResult.OK){try{Installer.ElevateRecovery();}catch{_detail.Text="恢复请求未完成。";}}}));Row(tools,maintenance);
        Row(tools,new Label{Text="集成候选版 · IPv6 当前阻断；UU 实机故障及重启连续性仍待验收。",AutoSize=false,Height=44,ForeColor=Color.DarkOrange,Margin=new Padding(0,10,0,0)});
        var toolsCard=Card("toolsSection","03   诊断与测试",tools);Row(body,toolsCard);
        foreach(var (title,target) in new[]{("01  当前连接",connectionCard),("02  账号与用量",accountCard),("03  诊断与测试",toolsCard)}){
            var button=new Button{Text=title,Dock=DockStyle.Fill,Height=46,TextAlign=ContentAlignment.MiddleLeft,FlatStyle=FlatStyle.Flat,BackColor=Color.FromArgb(20,31,53),UseVisualStyleBackColor=false,ForeColor=Color.White,Margin=new Padding(0,0,0,8)};button.FlatAppearance.BorderSize=0;button.Click+=(_,_)=>viewport.ScrollControlIntoView(target);Row(navigation,button);
        }
        _login.Click+=async(_,_)=>await Act("Login");_connect.Click+=async(_,_)=>await Act("Connect");_disconnect.Click+=async(_,_)=>await Act("Disconnect");
        _timer.Tick+=async(_,_)=>{if(!_busy)await Act("Status");};Shown+=async(_,_)=>{await Act("Status");_timer.Start();};FormClosed+=(_,_)=>_timer.Dispose();
    }
    internal async Task Act(string command)
    {
        bool passive=command=="Status";
        if(passive){if(!_requests.Wait(0))return;}
        else{
            if(_busy)return;_busy=true;_connect.Enabled=_disconnect.Enabled=_login.Enabled=_logout.Enabled=_transportChoice.Enabled=false;
            // A click arriving during a read waits for that read instead of
            // disappearing. Passive reads never change button enabled state.
            await _requests.WaitAsync();
        }
        try{
            var state=await _send(command=="Status"?"Prepare":command,command=="Login"?_username.Text:null,command=="Login"?_password.Text:null);
            if(command=="Login")_password.Clear();
            Display(state);
        }catch{
            _mode.Text="系统服务不可用";_mode.ForeColor=Color.DarkOrange;_protocol.Text=_exitIp.Text=_latency.Text=_uu.Text="—";UpdateRates(new JsonObject(),false);_progress.Enabled=false;_usageUpdated.Text="用量更新暂不可用，显示上次读取值。";_detail.Text="首次使用请点击“安装 / 升级服务”并完成 UAC。服务身份无法验证时不会发送账号密码。";
            try{string path=Path.Combine(Platform.Root,"diagnostics.json");if(new FileInfo(path).Length<=4096){var d=JsonNode.Parse(File.ReadAllText(path));_detail.Text+=$" 诊断：{d?["stage"]} / {d?["code"]}。";}}catch{}
        }
        finally{_requests.Release();if(!passive){_busy=false;_connect.Enabled=_disconnect.Enabled=_login.Enabled=_logout.Enabled=true;_transportChoice.Enabled=!_connectionIntent;}}
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
    internal int PollInterval=>_timer.Interval;
    internal void Display(JsonObject state)
    {
            _connectionReport="连接诊断（不含账号密码、令牌或密钥）\r\n";
            foreach(string key in new[]{"product_version","mode","error","intent","guard","transport","connection_stage","core_stage","carrier_stage","transport_preference","quic_available","native_udp_selected_port","client_handshake_reply","core_pid","tun_permitted","server_handshake_at","peer_rx_bytes","peer_tx_bytes","uu_verified_programs","quick_ready","preparing","verified_at","connect_switch_ms","click_to_ready_ms"})_connectionReport+=$"{key}: {state[key]}\r\n";
            if(state["carrier_failures"] is JsonObject failures)foreach(string transport in new[]{"wireguard-udp","wireguard-quic","wireguard-https"})if(failures[transport] is JsonObject attempt)foreach(string key in new[]{"error","carrier_stage","probe_failures","elapsed_ms"})_connectionReport+=$"attempt.{transport}.{key}: {attempt[key]}\r\n";
            _connectionIntent=state["intent"]?.GetValue<bool>()==true;
            _renderingTransport=true;
            try{_transportChoice.SelectedIndex=state["transport_preference"]?.GetValue<string>() switch{"udp"=>1,"quic"=>2,_=>0};}finally{_renderingTransport=false;}
            _transportChoice.Enabled=!_connectionIntent && !_busy;
            if(state["native_udp_attempt"] is JsonObject native)foreach(string key in new[]{"endpoint_port","selected_port","socket_binding","server_handshake_at_observed","started_at","started_without_tun","probe_result","probe_failures","attempt_elapsed_ms"})_connectionReport+=$"native_udp.{key}: {native[key]}\r\n";
            if(state["switch_timings"] is JsonObject timings)foreach(string key in new[]{"uu_discovery_ms","state_saved_ms","guard_installed_ms","tun_active_ms","complete_ms"})_connectionReport+=$"switch.{key}: {timings[key]}\r\n";
            if(state["failure"] is JsonObject failure)foreach(string key in new[]{"stage","category","hresult","native_error","socket_error","http_error","http_status","core_stage","at"})_connectionReport+=$"failure.{key}: {failure[key]}\r\n";
            Text="Oracle Proxy · "+(state["product_version"]?.GetValue<string>() ?? "0.3.0-rc10");
            _uuReport="UU 自动发现与信任核验（只读）\r\n服务版本："+(state["product_version"]?.GetValue<string>() ?? "未知")+
                $"\r\n候选：{state["uu_candidates"]} · 通过：{state["uu_verified_programs"]} · 拒绝：{state["uu_rejected"]}\r\n";
            if(state["uu_diagnostics"] is JsonArray uuIssues && uuIssues.Count>0){
                foreach(var item in uuIssues)_uuReport+=$"\r\n{UuReason(item!["code"]!.GetValue<string>())}\r\n{item["code"]} {item["detail"]}\r\n{item["path"]}\r\n";
            }else _uuReport+="\r\n暂无拒绝详情；请在断开状态点击“重新识别 UU”。";
            string mode=state["mode"]?.GetValue<string>() ?? "unknown";bool guard=state["guard"]?.GetValue<bool>()==true;
            _timer.Interval=mode is "protected" or "connecting" || (state["preparing"]?.GetValue<bool>()==true && state["quick_ready"]?.GetValue<bool>()!=true)?250:mode=="connected"?1000:3000;
            _mode.Text=mode switch{"connected"=>guard?(state["transport"]?.GetValue<string>() switch{"wireguard-https"=>"已连接 Oracle · HTTPS","wireguard-quic"=>"已连接 Oracle · QUIC / HTTP/3",_=>"已连接 Oracle · UDP"}):"连接保护未验证","connecting"=>"正在连接","protected"=>guard?"已保护 · 等待连接":"保护尚未验证","disconnected"=>"已断开 · 当前直连","recovery"=>"需要恢复处理",_=>"状态未知"};
            _mode.ForeColor=mode=="connected"?Color.FromArgb(11,137,108):mode=="disconnected"?Color.FromArgb(55,70,96):Color.DarkOrange;
            string policy=state["account"]?["status"]?.GetValue<string>() ?? "";
            string detail=state["error"]?.GetValue<string>() is string error && error.Length>0?Message(error):guard?(policy is "disabled" or "expired" or "quota" or "server_budget" or "unavailable"?$"账号状态：{PolicyName(policy)}。防泄漏保护保留。":"防泄漏规则保持启用。意外中断时不会主动恢复普通应用直连。"):"点击连接前，请先登录管理员分配的账号。";
            if(mode=="disconnected" && state["quick_ready"]?.GetValue<bool>()==true)detail="快速连接已就绪（"+(state["transport"]?.GetValue<string>() switch{"wireguard-quic"=>"QUIC / HTTP/3","wireguard-https"=>"HTTPS 兜底通道",_=>"WireGuard UDP 主通道"})+"）。当前普通应用仍直连；点击连接后启用防泄漏与 VPN。";
            else if(mode=="disconnected" && state["preparing"]?.GetValue<bool>()==true)detail="正在预备加密通道，当前普通应用仍直连。首次连接或网络变化可能需要等待。";
            var account=state["account"]?.AsObject();
            if(account is not null){
                long used=account["used_bytes"]!.GetValue<long>();long? limit=account["limit_bytes"]?.GetValue<long>();
                _accountName.Text=$"{account["username"]}  ·  {(policy=="active"?"账号可用":PolicyName(policy))}";
                _usage.Text=$"本月已用 {FormatBytes(used)} / {(limit is null?"不限量":FormatBytes(limit.Value))}"+(limit is null?"":$"    ·    剩余 {FormatBytes(Math.Max(0,limit.Value-used))}");
                _progress.Value=limit is >0?(int)Math.Clamp((double)used/limit.Value*1000,0,1000):limit==0?1000:0;
                long? expires=account["expires_at"]?.GetValue<long>();
                _expiry.Text=$"到期：{(expires is null?"长期":DateTimeOffset.FromUnixTimeSeconds(expires.Value).ToLocalTime().ToString("yyyy-MM-dd HH:mm"))}   ·   已登记设备 {account["device_count"]} / {account["device_limit"]}   ·   UTC 账期 {state["period"]}";
            }else{_accountName.Text="尚未登录";_usage.Text="登录后显示本月用量与限额";_progress.Value=0;_expiry.Text="账号由管理员创建，不开放自行注册。";}
            long? latency=state["latency_ms"]?.GetValue<long>();long? at=state["observed_at"]?.GetValue<long>();
            bool fresh=at is long received && DateTimeOffset.UtcNow.ToUnixTimeSeconds()-received<=20;_progress.Enabled=fresh;
            if(!fresh && account is not null)detail+=" 用量未刷新，显示的是上次读取值。";
            // Set the final text once: intermediate short text used to resize
            // every AutoSize row twice on every 250 ms preparation poll.
            if(_detail.Text!=detail)_detail.Text=detail;
            _protocol.Text=mode=="connected"?state["transport"]?.GetValue<string>() switch{"wireguard-udp"=>"WireGuard / UDP","wireguard-quic"=>"QUIC / HTTP/3","wireguard-https"=>"HTTPS / TLS 兜底",_=>"—"}:"—";
            _exitIp.Text=mode=="connected"?state["verified_exit_ip"]?.GetValue<string>() ?? "待验证":"—";
            _latency.Text=mode=="connected" && latency is not null?$"{latency} ms":"—";
            _uu.Text=$"{state["uu_verified_programs"] ?? (JsonNode)0} 个程序已验证";
            UpdateRates(state,mode=="connected" && guard);
            _telemetry.Text=mode=="connected"?"流量速率来自本机 VPN 网卡；HTTP 延迟包含隧道与目标站点响应时间。":"协议及出口 IP 将在本次连接验证通过后显示。";
            _usageUpdated.Text=$"用量更新：{(at is null?"—":DateTimeOffset.FromUnixTimeSeconds(at.Value).ToLocalTime().ToString("HH:mm:ss"))}  ·  {(fresh?"服务器账单统计":"上次读取值，等待刷新")}";

    }
    internal string DownloadRate=>_download.Text;
    internal string UploadRate=>_upload.Text;
    private void UpdateRates(JsonObject state,bool connected)
    {
        var sample=state["traffic"] as JsonObject;
        long? at=sample?["sample_ms"]?.GetValue<long>(),rx=sample?["rx_bytes"]?.GetValue<long>(),tx=sample?["tx_bytes"]?.GetValue<long>();
        uint pid=state["core_pid"]?.GetValue<uint>() ?? 0;
        if(!connected || at is null || rx is null || tx is null || rx<0 || tx<0){_sampleAt=_sampleRx=_sampleTx=null;_samplePid=0;_download.Text=_upload.Text="—";return;}
        if(pid==_samplePid && _sampleAt is long before && at>before && at-before<=10000 && _sampleRx is long oldRx && _sampleTx is long oldTx && rx>=oldRx && tx>=oldTx){
            _download.Text=FormatRate((rx.Value-oldRx)*1000d/(at.Value-before));_upload.Text=FormatRate((tx.Value-oldTx)*1000d/(at.Value-before));
        }else if(pid!=_samplePid || _sampleAt is null || at<_sampleAt || rx<_sampleRx || tx<_sampleTx || at-_sampleAt>10000)_download.Text=_upload.Text="采样中…";
        _sampleAt=at;_sampleRx=rx;_sampleTx=tx;_samplePid=pid;
    }
    private static string FormatRate(double bytes)=>bytes>=1024*1024?$"{bytes/(1024*1024):0.0} MiB/s":bytes>=1024?$"{bytes/1024:0.0} KiB/s":$"{bytes:0} B/s";
    private static string PolicyName(string status)=>status switch{"disabled"=>"已停用","expired"=>"已到期","quota"=>"配额已耗尽","server_budget"=>"服务器出站额度保护中",_=>"待核对"};
    private static string FormatBytes(long bytes)=>bytes>=(1L<<40)?$"{bytes/(double)(1L<<40):0.00} TiB":bytes>=(1L<<30)?$"{bytes/(double)(1L<<30):0.00} GiB":bytes>=(1L<<20)?$"{bytes/(double)(1L<<20):0.00} MiB":bytes>=1024?$"{bytes/1024d:0.0} KiB":$"{bytes:N0} B";
    private static string Message(string code)=>code switch{
        "QUIC_NOT_AVAILABLE"=>"服务器暂未提供 QUIC / HTTP/3，请使用自动模式。", "DISCONNECT_BEFORE_TRANSPORT_CHANGE"=>"请先断开，再选择连接方式。",
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
