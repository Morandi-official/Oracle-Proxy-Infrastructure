using System.Text;
using System.Text.Json.Nodes;
namespace OracleProxy.Product;

internal sealed partial class MainForm
{
    private readonly Button _udpStart=new(){Name="udp-six-start",Text="一键诊断六个 UDP 入口",Height=40,Margin=new Padding(0,0,10,8)};
    private readonly Button _udpCancel=new(){Name="udp-six-cancel",Text="取消 UDP 诊断",Height=40,Margin=new Padding(0,0,10,8),Enabled=false};
    private readonly Button _udpCopy=new(){Name="udp-six-copy",Text="复制 UDP 诊断报告",Height=40,Margin=new Padding(0,0,10,8),Enabled=false};
    private readonly Label _udpHeading=new(){Name="udp-six-heading",AutoSize=true,Visible=false,Margin=new Padding(0,8,0,6),ForeColor=Muted};
    private readonly DataGridView _udpGrid=new(){Name="udp-six-results",Height=206,Visible=false,ReadOnly=true,
        AllowUserToAddRows=false,AllowUserToDeleteRows=false,AllowUserToResizeRows=false,RowHeadersVisible=false,
        AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,BackgroundColor=Color.White,BorderStyle=BorderStyle.None,
        SelectionMode=DataGridViewSelectionMode.FullRowSelect,MultiSelect=false,ScrollBars=ScrollBars.Horizontal,
        ColumnHeadersHeightSizeMode=DataGridViewColumnHeadersHeightSizeMode.DisableResizing,ColumnHeadersHeight=30};
    private bool _udpDiagnosing,_udpAvailable;
    private string _udpReport="尚未运行 UDP 诊断。";
    private static readonly Dictionary<string,string> UdpResults=new(){
        ["PASSED"]="出口已验证",["LOCAL_WRITE_ERROR"]="本机发送错误",["NO_INITIATION_SENT"]="未发出握手请求",
        ["SERVER_OBSERVATION_UNAVAILABLE"]="服务器观察不可用",["RETURN_OR_LOCAL_RECEIVE_PATH"]="回程或本机接收异常",
        ["REPLY_WITHOUT_VERIFIED_EGRESS"]="收到响应，出口未验证",["INSUFFICIENT_OBSERVATION"]="观察不完整，暂不能定位",
        ["FORWARD_PATH_NOT_OBSERVED"]="服务器未观察到请求",["SERVER_RESPONSE_NOT_OBSERVED"]="服务器未观察到响应"};
    private void BuildUdpDiagnostics(TableLayoutPanel content,TableLayoutPanel actions,Action<TableLayoutPanel,Button> add)
    {
        add(actions,_udpStart);add(actions,_udpCancel);add(actions,_udpCopy);
        _udpStart.Click+=async(_,_)=>await Act("StartUdpDiagnostics");
        _udpCancel.Click+=async(_,_)=>await Act("CancelUdpDiagnostics");
        _udpCopy.Click+=(_,_)=>{try{Clipboard.SetText(_udpReport);_detail.Text="UDP 诊断报告已复制，不含密码、令牌或密钥。";}catch{ShowReport("UDP 诊断报告",_udpReport);}};
        _help.SetToolTip(_udpStart,"保持已断开，逐个验证六个 UDP 入口并关联服务器记录。约 1—3 分钟，可取消。不会切换为其他传输协议。");
        foreach(var (name,title,weight) in new[]{("address","入口",180f),("port","端口",65f),("client","本机握手 发 / 收",130f),("server","服务端握手 收 / 发",145f),("result","结果",235f)})
            _udpGrid.Columns.Add(new DataGridViewTextBoxColumn{Name=name,HeaderText=title,FillWeight=weight,SortMode=DataGridViewColumnSortMode.NotSortable});
        _udpGrid.RowTemplate.Height=28;
        foreach(var target in UdpDiagnosticTarget.All)_udpGrid.Rows.Add(target.Address,target.Port,"—","—","待测试");
        Row(content,_udpHeading);Row(content,_udpGrid);
    }
    private static string UdpText(JsonNode? node)=>node is JsonValue value && value.TryGetValue<string>(out var text)?text:"";
    private static bool UdpFlag(JsonNode? node)=>node is JsonValue value && value.TryGetValue<bool>(out bool flag) && flag;
    private static long? UdpNumber(JsonNode? node)
    {
        if(node is not JsonValue value)return null;
        if(value.TryGetValue<long>(out long n) && n>=0)return n;
        if(value.TryGetValue<int>(out int i) && i>=0)return i;
        if(value.TryGetValue<uint>(out uint u))return u;
        return null;
    }
    private void DisplayUdpDiagnostics(JsonObject state)
    {
        _udpAvailable=UdpFlag(state["udp_diagnostics_available"]);
        if(state["udp_diagnostic"] is not JsonObject report){_udpDiagnosing=false;_udpHeading.Visible=_udpGrid.Visible=false;_udpCopy.Enabled=false;_udpReport="尚未运行 UDP 诊断。";return;}
        _udpDiagnosing=UdpFlag(report["running"]);
        string phase=UdpText(report["phase"]);
        string title=phase switch{"starting"=>"准备诊断","running"=>"逐个验证 UDP 入口","stopping"=>"正在停止诊断并整理记录","complete"=>"UDP 诊断完成，当前仍保持断开","cancelled"=>"UDP 诊断已取消","failed"=>"UDP 诊断未完成",_=>"UDP 诊断记录"};
        _udpHeading.Text=title;_udpHeading.Visible=_udpGrid.Visible=true;
        var text=new StringBuilder("UDP 六入口诊断（不含账号密码、令牌或密钥）\r\n");
        text.AppendLine(title);
        string reason=UdpText(report["error"]) switch{"DIAGNOSTIC_BUSY"=>"服务器已有诊断任务，请稍后重试。","DIAGNOSTIC_RATE_LIMITED"=>"诊断请求过于频繁，请稍后重试。","DIAGNOSTIC_EXPIRED_OR_RESTARTED"=>"服务器采集已到期或服务已重启，本轮观察不完整。","DIAGNOSTIC_ACCOUNT_NOT_ACTIVE"=>"账号状态当前不允许诊断。","LOGIN_REQUIRED"=>"登录已过期，请重新登录。","CONTROL_SERVICE_UNAVAILABLE"=>"服务器配对服务暂不可用。","DIAGNOSTIC_API_TIMEOUT"=>"服务端诊断接口请求超时，本轮未完成；这不是主动取消，也不表示所有 UDP 入口不可用。","DIAGNOSTIC_DEADLINE"=>"诊断达到总时限，本轮观察不完整。",_=>""};
        if(reason.Length>0)text.AppendLine(reason);
        string failureStage=UdpText(report["failure_stage"]) switch{
            "server_start"=>"服务端开始采集","server_begin"=>"服务端开始入口测试","server_sample"=>"服务端汇总入口记录",
            "local_core_start"=>"本机启动诊断核心","egress_probe"=>"出口验证","local_core_stop"=>"本机停止诊断核心",_=>""};
        if(failureStage.Length>0)text.AppendLine("停止位置："+failureStage);
        if(UdpNumber(report["elapsed_ms"]) is long elapsed && elapsed<=300000)text.AppendLine($"本轮耗时：{elapsed / 1000.0:F1} 秒");
        if(Guid.TryParseExact(UdpText(report["diagnostic_id"]),"D",out var identity))text.AppendLine("诊断编号："+identity);
        if(UdpNumber(report["started_at"]) is long at && at<=4102444800)text.AppendLine("开始时间："+DateTimeOffset.FromUnixTimeSeconds(at).ToOffset(TimeSpan.FromHours(8)).ToString("yyyy-MM-dd HH:mm:ss zzz"));
        text.AppendLine(UdpFlag(report["ipv6_requested"])?"出口验证包含 IPv4 与 IPv6。":"本轮仅验证已提供的 IPv4 出口。");
        text.AppendLine("客户端收包层：UDP 套接字；物理网卡层未采集。计数不能确定具体中间网络节点。\r\n");
        text.AppendLine("服务端报文头计数用于配对，不等同于认证成功；内核握手与出口验证分别记录。\r\n");
        if(report["trials"] is JsonArray trials)for(int i=0;i<6 && i<trials.Count;i++){
            var target=UdpDiagnosticTarget.All[i];var trial=trials[i];
            if(UdpText(trial?["address"])!=target.Address || UdpNumber(trial?["port"])!=target.Port)continue;
            string pending=UdpText(trial?["phase"]);
            string result=UdpResults.TryGetValue(UdpText(trial?["verdict"]),out var known)?known:
                UdpFlag(trial?["client"]?["egress_verified"])?"客户端出口已验证":pending switch{"pending"=>"待测试","running"=>"正在测试","failed"=>"出口未验证，等待服务器记录",_=>"等待汇总"};
            var counters=trial?["client"]?["counters"];var captured=trial?["server"]?["capture"];
            string local=$"{UdpNumber(counters?["tx_initiations"])?.ToString()??"—"} / {UdpNumber(counters?["rx_responses"])?.ToString()??"—"}";
            string remote=$"{UdpNumber(captured?["rx_initiations"])?.ToString()??"—"} / {UdpNumber(captured?["tx_responses"])?.ToString()??"—"}";
            _udpGrid.Rows[i].SetValues(target.Address,target.Port,local,remote,result);
            text.AppendLine($"{target.Address}:{target.Port} · {result}");
            text.AppendLine($"  本机握手 发/收：{local}；服务端握手 收/发：{remote}");
            if(UdpNumber(trial?["client"]?["elapsed_ms"]) is long trialElapsed && trialElapsed<=180000)text.AppendLine($"  本机探测耗时：{trialElapsed} ms");
            foreach(string key in new[]{"read_errors","write_errors","last_read_error","last_write_error"})if(UdpNumber(counters?[key]) is long n)text.AppendLine($"  client.{key}: {n}");
            text.AppendLine($"  服务器观察完整：{UdpFlag(captured?["complete_observation"])}；内核握手更新：{UdpFlag(trial?["server"]?["kernel_handshake_advanced"])}");
            text.AppendLine();
        }
        if(phase is "failed")text.AppendLine("诊断流程未完成，请保留本报告；这不等同于六个端口全部不可用。");
        if(!_udpDiagnosing && !UdpFlag(report["server_capture_closed"]))text.AppendLine("服务器结束确认不可用，采集任务有自动到期限制。");
        _udpReport=text.ToString();_udpCopy.Enabled=true;
        _udpStart.Enabled=_udpAvailable && _lastMode=="disconnected" && !_udpDiagnosing && !_connectionIntent && _authenticated && _deviceRegistered && !_busy && !_closing;
        _udpCancel.Enabled=_udpDiagnosing && !_busy && !_closing;
        if(_udpDiagnosing)_timer.Interval=1000;
    }
}
