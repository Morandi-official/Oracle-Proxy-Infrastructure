using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal sealed class MainForm : Form
{
    private async Task ShowGitHubReport()
    {
        if(_githubChecking)return;_githubChecking=true;
        try{string report=await GitHubDiagnostics.Run();if(!IsDisposed && !_closing)ShowReport("GitHub 连通性",report);}
        finally{_githubChecking=false;}
    }
    private readonly Label _mode=new(){Text="正在读取系统服务…",AutoSize=true,Font=new Font("Microsoft YaHei UI",23,FontStyle.Bold)};
    private readonly Label _detail=new(){Text="",AutoSize=true,MaximumSize=new Size(680,0)};
    private readonly Label _usage=new(){Text="用量未知",AutoSize=true};
    private readonly Label _expiry=new(){Text="到期日未知",AutoSize=true};
    private readonly Label _telemetry=new(){Text="延迟 — · UU —",AutoSize=true};
    private readonly ProgressBar _progress=new(){Minimum=0,Maximum=1000,Value=0,Width=650,Height=18};
    private readonly TextBox _username=new(){PlaceholderText="管理员分配的账号",Width=215,MaxLength=64};
    private readonly TextBox _password=new(){PlaceholderText="管理员分配的密码",Width=215,UseSystemPasswordChar=true,MaxLength=128};
    private readonly Button _login=new(){Text="登录",AutoSize=true};
    private readonly Button _connect=new(){Text="连接",Width=155,Height=48,Enabled=false};
    private readonly Button _disconnect=new(){Text="断开并恢复直连",Width=180,Height=48};
    private readonly System.Windows.Forms.Timer _timer=new(){Interval=3000};
    private bool _githubChecking;
    private bool _native8443Available,_native8443Selected;
    private bool _deviceRegistered,_canConnect,_canRegister,_registrationShown;
    private string _deviceIdentity="",_deviceListSignature="";
    private readonly TextBox _deviceName=new(){Name="device-name",MaxLength=80,Dock=DockStyle.Fill};
    private readonly Label _deviceIdentityLabel=new(){AutoSize=false,Height=28,AutoEllipsis=true};
    private readonly Label _registrationNote=new(){AutoSize=false,Height=48};
    private readonly CheckBox _deviceConfirmation=new(){Name="device-confirm",Text="这是我的设备，我确认将它登记到当前账号。",AutoSize=false,Height=44,Dock=DockStyle.Fill};
    private readonly Button _registerDevice=new(){Name="register-device",Text="确认并登记此设备",Width=190,Height=38,Enabled=false};
    private readonly ListBox _knownDevices=new(){Name="my-devices",Dock=DockStyle.Fill,Height=90,HorizontalScrollbar=true};
    private readonly TableLayoutPanel _registrationGroup;
    private readonly TableLayoutPanel _deviceDetails;
    private readonly TableLayoutPanel _credentials;
    private readonly BufferedFlowPanel _maintenance;
    private readonly Button _deviceToggle=new(){Name="device-details-toggle",Text="展开设备详情",AutoSize=true};
    private readonly Button _credentialsToggle=new(){Text="切换账号",AutoSize=true};
    private readonly Button _maintenanceToggle=new(){Name="maintenance-toggle",Text="展开系统维护",AutoSize=true};
    private readonly Button _emergencyRecovery=new(){Name="emergency-recovery",Text="恢复直连（UAC）",AutoSize=true};
    private readonly ToolTip _help=new(){ShowAlways=true,InitialDelay=350,ReshowDelay=100,AutoPopDelay=18000};
    private bool _deviceExpanded,_credentialsExpanded,_hasAccount;
    private bool _deviceDetailsShown=true,_deviceToggleShown=true;
    private static readonly Color Ink=Color.FromArgb(32,47,68),Muted=Color.FromArgb(100,116,139),Accent=Color.FromArgb(10,132,108),Border=Color.FromArgb(222,229,238);

    private readonly Button _native8443Test;
    private bool _busy,_renderingTransport,_connectionIntent,_closing,_allowClose;
    private readonly ComboBox _transportChoice=new(){DropDownStyle=ComboBoxStyle.DropDownList,Width=240};
    private readonly SemaphoreSlim _requests=new(1,1);
    private readonly CancellationTokenSource _lifetime=new();
    private CancellationTokenSource _requestEpoch=new();
    private readonly TimeSpan _requestTimeout,_quitTimeout,_statusTimeout;
    private readonly Func<string,string?,string?,Task<JsonObject>> _send;
    private readonly bool _realService;
    private bool _needsReconcile,_startupPrepared,_uuMaintaining,_statusReadSucceeded;
    private string _lastMode="unknown";
    private sealed class BufferedFlowPanel : FlowLayoutPanel
    {
        internal BufferedFlowPanel(){DoubleBuffered=true;ResizeRedraw=true;}
        public override Size GetPreferredSize(Size proposedSize)
        {
            // TableLayoutPanel asks AutoSize children for their height before
            // docking them. Bound that measurement to the actual row width so
            // wrapped buttons contribute every row to the card's height.
            int available=Parent is null?ClientSize.Width:Parent.ClientSize.Width-Parent.Padding.Horizontal-Margin.Horizontal;
            int width=proposedSize.Width>0?proposedSize.Width:available;
            if(available>0)width=width>0?Math.Min(width,available):available;
            width=Math.Max(1,width);
            var preferred=base.GetPreferredSize(new Size(width,0));
            return new Size(width,preferred.Height);
        }
    }
    private string _connectionReport="尚未读取系统服务。";
    private string _uuReport="请先在断开状态点击“重新识别 UU”。";
    private readonly Label _protocol=MetricValue(),_exitIp=MetricValue(),_download=MetricValue(),_upload=MetricValue(),_latency=MetricValue(),_uu=MetricValue();
    private readonly Label _accountName=new(){AutoSize=true,Text="尚未登录"};
    private readonly Label _usageUpdated=new(){AutoSize=true,ForeColor=Color.FromArgb(100,113,134)};
    private readonly Button _logout=new(){Text="退出账号",AutoSize=true,Visible=false};
    private long? _sampleAt,_sampleRx,_sampleTx;
    private uint _samplePid;
    private static Label MetricValue()=>new(){Text="—",Dock=DockStyle.Fill,AutoEllipsis=true,Height=30,TextAlign=ContentAlignment.MiddleLeft,Font=new Font("Microsoft YaHei UI",13,FontStyle.Bold),Margin=new Padding(0)};
    private static TableLayoutPanel Stack(string name){var panel=new TableLayoutPanel{Name=name,Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,ColumnCount=1,Margin=new Padding(0),Padding=new Padding(0)};panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));return panel;}
    private static void Row(TableLayoutPanel panel,Control item){int row=panel.RowCount++;panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));item.Dock=DockStyle.Fill;panel.Controls.Add(item,0,row);}
    private static Control Metric(string title,Label value){var cell=Stack("metric"+title);cell.Margin=new Padding(0,0,18,12);Row(cell,new Label{Text=title,AutoSize=true,ForeColor=Color.FromArgb(100,113,134),Margin=new Padding(0,0,0,3)});Row(cell,value);return cell;}
    private sealed class SectionCard:GroupBox
    {
        internal SectionCard(){DoubleBuffered=true;ResizeRedraw=true;SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer,true);}
        public override Rectangle DisplayRectangle=>new(Padding.Left,Padding.Top,Math.Max(0,ClientSize.Width-Padding.Horizontal),Math.Max(0,ClientSize.Height-Padding.Vertical));
        public override Size GetPreferredSize(Size proposedSize)
        {
            int width=proposedSize.Width>Padding.Horizontal?proposedSize.Width:Width;
            width=Math.Max(Padding.Horizontal+1,width);
            int height=Controls.Count==0?0:Controls[0].GetPreferredSize(new Size(width-Padding.Horizontal,0)).Height;
            return new Size(width,height+Padding.Vertical);
        }
        protected override void OnPaint(PaintEventArgs e){
            e.Graphics.Clear(Parent?.BackColor ?? BackColor);e.Graphics.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            float radius=12f*DeviceDpi/96f;var area=new RectangleF(0.5f,0.5f,Width-1f,Height-1f);
            using var path=new System.Drawing.Drawing2D.GraphicsPath();float diameter=radius*2;
            path.AddArc(area.Left,area.Top,diameter,diameter,180,90);path.AddArc(area.Right-diameter,area.Top,diameter,diameter,270,90);path.AddArc(area.Right-diameter,area.Bottom-diameter,diameter,diameter,0,90);path.AddArc(area.Left,area.Bottom-diameter,diameter,diameter,90,90);path.CloseFigure();
            using var fill=new SolidBrush(BackColor);e.Graphics.FillPath(fill,path);using var pen=new Pen(Border);e.Graphics.DrawPath(pen,path);
            using var heading=new Font(Font.FontFamily,10,FontStyle.Bold);
            TextRenderer.DrawText(e.Graphics,Text,heading,new Rectangle(Padding.Left,10*DeviceDpi/96,Width-Padding.Horizontal,24*DeviceDpi/96),Muted,TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        }
    }
    private static GroupBox Card(string name,string title,TableLayoutPanel content){var card=new SectionCard{Name=name,Text=title,Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Padding=new Padding(20,44,20,18),Margin=new Padding(0,0,0,16),BackColor=Color.White};card.Controls.Add(content);return card;}
    private static void StyleButton(Button button,bool primary=false){
        button.FlatStyle=FlatStyle.Flat;button.FlatAppearance.BorderColor=primary?Accent:Border;button.FlatAppearance.BorderSize=primary?0:1;
        button.BackColor=primary?Accent:Color.White;button.ForeColor=primary?Color.White:Ink;button.UseVisualStyleBackColor=false;button.Cursor=Cursors.Hand;
        button.FlatAppearance.MouseOverBackColor=primary?Color.FromArgb(8,112,92):Color.FromArgb(239,244,249);button.FlatAppearance.MouseDownBackColor=primary?Color.FromArgb(7,97,80):Color.FromArgb(226,234,243);
        button.MinimumSize=new Size(Math.Max(button.MinimumSize.Width,92),36);button.Padding=new Padding(10,3,10,3);button.AccessibleName=button.Text;
    }
    private void RegistrationDisclosure(){
        bool expanded=!_deviceRegistered || _deviceExpanded;
        // Visible includes parent visibility. A hidden/minimized test window can
        // report false even when this child's own visible bit is already true;
        // repeat assignments would otherwise relayout every ancestor per poll.
        if(_deviceDetailsShown!=expanded){_deviceDetailsShown=expanded;_deviceDetails.Visible=expanded;}
        if(_deviceToggleShown!=_deviceRegistered){_deviceToggleShown=_deviceRegistered;_deviceToggle.Visible=_deviceRegistered;}
        string caption=expanded?"收起设备详情":"展开设备详情";
        if(_deviceToggle.Text!=caption)_deviceToggle.Text=caption;
    }
    private static BufferedFlowPanel Actions()=>new(){AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Fill,WrapContents=true,Margin=new Padding(0,6,0,6),Padding=new Padding(0)};
    internal MainForm(Func<string,string?,string?,Task<JsonObject>>? send=null,TimeSpan? requestTimeout=null,TimeSpan? quitTimeout=null)
    {
        _send=send ?? ControlPipe.Send;_realService=send is null;DoubleBuffered=true;
        _requestTimeout=requestTimeout??TimeSpan.FromSeconds(30);_quitTimeout=quitTimeout??TimeSpan.FromSeconds(15);
        if(_requestTimeout<=TimeSpan.Zero || _requestTimeout>TimeSpan.FromMinutes(1) || _quitTimeout<=TimeSpan.Zero || _quitTimeout>TimeSpan.FromMinutes(1))throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        _statusTimeout=TimeSpan.FromMilliseconds(Math.Min(_requestTimeout.TotalMilliseconds,6000));
        Text="Oracle Proxy";AutoScaleMode=AutoScaleMode.Dpi;ClientSize=new Size(1080,820);MinimumSize=new Size(720,520);BackColor=Color.FromArgb(244,247,251);ForeColor=Ink;Font=new Font("Microsoft YaHei UI",10);StartPosition=FormStartPosition.CenterScreen;
        var shell=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Margin=new Padding(0)};
        shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,166));shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        shell.RowStyles.Add(new RowStyle(SizeType.Percent,100));Controls.Add(shell);
        var sidebar=new Panel{Dock=DockStyle.Fill,BackColor=Color.FromArgb(20,31,53),Margin=new Padding(0),Padding=new Padding(18,28,16,18)};
        var navigation=Stack("navigation");navigation.ForeColor=Color.White;
        Row(navigation,new Label{Text="ORACLE\nPROXY",AutoSize=true,Font=new Font(Font.FontFamily,17,FontStyle.Bold),Margin=new Padding(0,0,0,30)});
        sidebar.Controls.Add(navigation);shell.Controls.Add(sidebar,0,0);
        var workspace=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,Margin=new Padding(0)};
        workspace.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));workspace.RowStyles.Add(new RowStyle(SizeType.Percent,100));workspace.RowStyles.Add(new RowStyle(SizeType.AutoSize));shell.Controls.Add(workspace,1,0);
        var viewport=new Panel{Name="viewport",Dock=DockStyle.Fill,AutoScroll=true,Margin=new Padding(0)};workspace.Controls.Add(viewport,0,0);
        var body=Stack("sections");body.Padding=new Padding(22,20,22,16);viewport.Controls.Add(body);
        void FitBody(){
            int width=Math.Max(1,viewport.ClientSize.Width-(viewport.VerticalScroll.Visible?SystemInformation.VerticalScrollBarWidth:0));
            if(body.MaximumSize.Width!=width)body.MaximumSize=new Size(width,0);
            if(body.Width!=width)body.Width=width;
        }
        viewport.SizeChanged+=(_,_)=>FitBody();body.SizeChanged+=(_,_)=>FitBody();
        _mode.AutoSize=false;_mode.Height=44;_mode.Font=new Font(Font.FontFamily,20,FontStyle.Bold);_mode.AutoEllipsis=true;_mode.Margin=new Padding(0,0,0,6);
        _detail.AutoSize=true;_detail.MinimumSize=new Size(0,45);_detail.ForeColor=Muted;_detail.Margin=new Padding(0,0,0,12);
        _detail.SizeChanged+=(_,_)=>{int width=Math.Max(1,_detail.Parent?.ClientSize.Width??1);if(_detail.MaximumSize.Width!=width)_detail.MaximumSize=new Size(width,0);};
        var connection=Stack("connectionContent");Row(connection,_mode);Row(connection,_detail);
        var metrics=new TableLayoutPanel{Name="connectionMetrics",AutoSize=true,Dock=DockStyle.Fill,ColumnCount=3,RowCount=2,Margin=new Padding(0)};
        for(int i=0;i<3;i++)metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100f/3));
        _exitIp.Height=46;_exitIp.Font=new Font(Font.FontFamily,10,FontStyle.Bold);_protocol.Font=new Font(Font.FontFamily,11,FontStyle.Bold);
        var values=new[]{Metric("当前协议",_protocol),Metric("已验证出口 IP",_exitIp),Metric("隧道 HTTP 延迟",_latency),Metric("下载速率 · VPN",_download),Metric("上传速率 · VPN",_upload),Metric("UU 直连保护",_uu)};
        for(int i=0;i<values.Length;i++)metrics.Controls.Add(values[i],i%3,i/3);Row(connection,metrics);
        _transportChoice.Items.AddRange(["自动（UDP 优先）","WireGuard / UDP","QUIC / HTTP/3"]);_transportChoice.SelectedIndex=0;
        var selection=Actions();selection.Controls.Add(new Label{Text="首选连接方式",AutoSize=true,Margin=new Padding(0,8,16,0)});selection.Controls.Add(_transportChoice);Row(connection,selection);
        _transportChoice.SelectionChangeCommitted+=async(_,_)=>{if(!_renderingTransport && _transportChoice.SelectedIndex>=0)await Act(TransportPolicy.ClientSelection(_transportChoice.SelectedIndex,_native8443Available));};
        var buttons=Actions();_connect.BackColor=Color.FromArgb(11,137,108);_connect.ForeColor=Color.White;_connect.FlatStyle=FlatStyle.Flat;_connect.FlatAppearance.BorderSize=0;_connect.UseVisualStyleBackColor=false;_connect.Margin=new Padding(0,0,10,0);_disconnect.Margin=new Padding(0);buttons.Controls.AddRange([_connect,_disconnect]);Row(connection,buttons);
        _help.SetToolTip(_connect,"连接使用所选首选通道；必要时自动切换备用通道。防泄漏启用后，普通应用流量经 Oracle 出口。");
        _help.SetToolTip(_disconnect,"停止本次 VPN 连接并恢复普通应用直连。保留系统服务和已登记设备，便于下次连接。");
        _help.SetToolTip(_transportChoice,"UDP 为主通道，QUIC 为备用；受限网络下自动使用 HTTPS 兜底。连接期间先断开再切换。");
        Row(connection,new Label{Text="关闭窗口会安全断开并退出。",AutoSize=true,ForeColor=Color.FromArgb(100,113,134),Margin=new Padding(0,8,0,0)});
        _telemetry.AutoSize=false;_telemetry.Height=28;_telemetry.AutoEllipsis=true;_telemetry.ForeColor=Color.FromArgb(100,113,134);_telemetry.Margin=new Padding(0,8,0,0);Row(connection,_telemetry);
        var connectionCard=Card("connectionSection","01   当前连接",connection);Row(body,connectionCard);
        var account=Stack("accountContent");_accountName.AutoSize=false;_accountName.Height=30;_accountName.AutoEllipsis=true;_accountName.Font=new Font(Font.FontFamily,11,FontStyle.Bold);_accountName.Margin=new Padding(0,0,0,12);Row(account,_accountName);
        _usage.AutoSize=false;_usage.Height=30;_usage.Margin=new Padding(0,0,0,4);Row(account,_usage);
        _progress.Dock=DockStyle.Fill;_progress.Height=14;_progress.Margin=new Padding(0,0,0,10);Row(account,_progress);
        _expiry.AutoSize=false;_expiry.Height=28;_expiry.AutoEllipsis=true;_expiry.Margin=new Padding(0,0,0,6);Row(account,_expiry);_usageUpdated.AutoSize=false;_usageUpdated.Height=28;_usageUpdated.AutoEllipsis=true;_usageUpdated.Margin=new Padding(0,0,0,14);Row(account,_usageUpdated);
        _registrationGroup=Stack("deviceRegistration");
        var deviceHeader=new TableLayoutPanel{Name="deviceSummary",Dock=DockStyle.Fill,AutoSize=true,ColumnCount=2,RowCount=1,Margin=new Padding(0,6,0,8)};
        deviceHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));deviceHeader.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        _deviceIdentityLabel.Dock=DockStyle.Fill;_deviceIdentityLabel.TextAlign=ContentAlignment.MiddleLeft;_deviceIdentityLabel.Margin=new Padding(0,0,10,0);
        _deviceToggle.Margin=new Padding(0);deviceHeader.Controls.Add(_deviceIdentityLabel,0,0);deviceHeader.Controls.Add(_deviceToggle,1,0);Row(_registrationGroup,deviceHeader);
        _deviceDetails=Stack("deviceDetails");
        Row(_deviceDetails,new Label{Text="确认这台设备属于你后登记；重复登录不会重复占用名额。",AutoSize=false,Height=36,ForeColor=Muted});
        Row(_deviceDetails,new Label{Text="设备名称（可改成便于辨认的名字）",AutoSize=true});
        Row(_deviceDetails,_deviceName);Row(_deviceDetails,_deviceConfirmation);
        var registrationActions=Actions();registrationActions.Controls.Add(_registerDevice);Row(_deviceDetails,registrationActions);
        Row(_deviceDetails,_registrationNote);Row(_deviceDetails,new Label{Text="此账号已登记的设备",AutoSize=true,ForeColor=Muted});Row(_deviceDetails,_knownDevices);Row(_registrationGroup,_deviceDetails);
        _deviceToggle.Click+=(_,_)=>{_deviceExpanded=!_deviceExpanded;RegistrationDisclosure();};
        Row(account,_registrationGroup);_registrationGroup.Visible=false;
        _deviceName.TextChanged+=(_,_)=>UpdateRegistrationActions();_deviceConfirmation.CheckedChanged+=(_,_)=>UpdateRegistrationActions();
        _registerDevice.Click+=async(_,_)=>{if(_deviceConfirmation.Checked)await Act("ConfirmDevice");};
        _credentials=new TableLayoutPanel{Name="credentials",Dock=DockStyle.Fill,AutoSize=true,ColumnCount=2,RowCount=2,Margin=new Padding(0)};
        _credentials.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));_credentials.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,50));
        _credentials.Controls.Add(new Label{Text="登录账号",AutoSize=true,Margin=new Padding(0,0,12,6)},0,0);_credentials.Controls.Add(new Label{Text="密码",AutoSize=true,Margin=new Padding(0,0,0,6)},1,0);
        _username.Dock=_password.Dock=DockStyle.Fill;_username.Margin=new Padding(0,0,12,0);_password.Margin=new Padding(0);_credentials.Controls.Add(_username,0,1);_credentials.Controls.Add(_password,1,1);Row(account,_credentials);
        var accountActions=Actions();_login.MinimumSize=_logout.MinimumSize=new Size(100,36);_login.Margin=new Padding(0,0,10,0);_logout.Margin=new Padding(0);accountActions.Controls.AddRange([_login,_credentialsToggle,_logout]);Row(account,accountActions);
        _credentialsToggle.Margin=new Padding(0,0,10,0);_credentialsToggle.Visible=false;
        _credentialsToggle.Click+=(_,_)=>{_credentialsExpanded=!_credentialsExpanded;_credentials.Visible=_credentialsExpanded;_login.Visible=_credentialsExpanded;_credentialsToggle.Text=_credentialsExpanded?"取消切换":"切换账号";if(_credentialsExpanded)_username.Focus();};
        _password.KeyDown+=async(_,e)=>{if(e.KeyCode==Keys.Enter && _login.Enabled){e.SuppressKeyPress=true;await Act("Login");}};
        _logout.Click+=async(_,_)=>await Act("Logout");var accountCard=Card("accountSection","02   账号、用量与设备",account);Row(body,accountCard);
        var tools=Stack("toolsContent");
        var diagnostics=Actions();
        Button Tool(string title,Action action){var button=new Button{Text=title,AutoSize=true,MinimumSize=new Size(112,36),Margin=new Padding(0,0,10,8)};button.Click+=(_,_)=>action();return button;}
        diagnostics.Controls.Add(Tool("连接诊断",()=>ShowReport("连接诊断",_connectionReport)));
        diagnostics.Controls.Add(Tool("GitHub 连通性",async()=>await ShowGitHubReport()));
        diagnostics.Controls.Add(Tool("UU 检查详情",ShowUuReport));
        diagnostics.Controls.Add(Tool("重新识别 UU",async()=>await Act("RefreshUu")));
        _native8443Test=Tool("原生 UDP 8443 测试",async()=>await Act("PreferUdp8443"));diagnostics.Controls.Add(_native8443Test);
        void Open(string url){try{System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url){UseShellExecute=true});}catch{_detail.Text="未能打开默认浏览器。";}}
        diagnostics.Controls.Add(Tool("打开出口检查",()=>Open("https://www.cloudflare.com/cdn-cgi/trace")));
        diagnostics.Controls.Add(Tool("打开管理后台",()=>Open("https://vpn-admin.morandi.dpdns.org/")));Row(tools,diagnostics);
        _maintenance=Actions();_maintenance.Name="system-maintenance";_maintenance.Visible=false;
        _maintenanceToggle.Margin=new Padding(0,0,10,6);Row(tools,_maintenanceToggle);
        _maintenanceToggle.Click+=(_,_)=>{_maintenance.Visible=!_maintenance.Visible;_maintenanceToggle.Text=_maintenance.Visible?"收起系统维护":"展开系统维护";};
        _maintenance.Controls.Add(Tool("安装 / 升级服务",()=>{try{Installer.Elevate(false);}catch{_detail.Text="操作未完成，请检查 UAC 提示或使用完整便携包。";}}));
        _maintenance.Controls.Add(Tool("卸载",()=>{if(MessageBox.Show(this,"将恢复直连并卸载系统服务、删除本机密钥。服务器仍保留设备记录与用量，请联系管理员撤销旧设备以释放名额。继续？","卸载",MessageBoxButtons.OKCancel)==DialogResult.OK){try{Installer.Elevate(true);}catch{_detail.Text="卸载未完成，请检查 UAC 提示。";}}}));
        foreach(bool restore in new[]{false,true})_maintenance.Controls.Add(Tool(restore?"恢复 UU 权限（UAC）":"修复 UU 并重新识别（UAC）",async()=>await MaintainUu(restore)));
        Row(tools,_maintenance);
        Row(tools,new Label{Text="候选版 · 安装与维护操作需要 Windows 管理员授权。",AutoSize=false,Height=30,ForeColor=Muted,Margin=new Padding(0,10,0,0)});
        var toolsCard=Card("toolsSection","03   诊断与测试",tools);Row(body,toolsCard);
        // Recovery must remain reachable when a service command is stalled,
        // cards are collapsed, or the smaller viewport has scrolled elsewhere.
        var safety=Actions();safety.Name="safety-actions";safety.BackColor=Color.White;safety.Margin=new Padding(0);safety.Padding=new Padding(22,8,22,8);
        _emergencyRecovery.Margin=new Padding(0,0,12,0);safety.Controls.Add(_emergencyRecovery);
        safety.Controls.Add(new Label{Text="操作无响应时可在本机恢复直连。",AutoSize=true,ForeColor=Muted,Margin=new Padding(0,8,0,0)});workspace.Controls.Add(safety,0,1);
        _emergencyRecovery.Click+=(_,_)=>{
            if(MessageBox.Show(this,"将停止本产品的隧道、关闭自动连接并恢复直连。已保存密钥保留；损坏的加密状态会保留备份。继续？","紧急恢复",MessageBoxButtons.OKCancel)!=DialogResult.OK)return;
            CancelRequests();_needsReconcile=true;RefreshActions();
            try{Installer.ElevateRecovery();_detail.Text="恢复请求已提交；等待系统服务确认结果。";}
            catch{_detail.Text="恢复请求未完成，请检查 UAC 提示。现有连接结果仍待确认。";}
        };
        foreach(var (title,target) in new[]{("01  当前连接",connectionCard),("02  账号与设备",accountCard),("03  诊断与测试",toolsCard)}){
            var button=new Button{Text=title,Dock=DockStyle.Fill,Height=46,TextAlign=ContentAlignment.MiddleLeft,FlatStyle=FlatStyle.Flat,BackColor=Color.FromArgb(20,31,53),UseVisualStyleBackColor=false,ForeColor=Color.White,Margin=new Padding(0,0,0,8)};button.FlatAppearance.BorderSize=0;button.Click+=(_,_)=>viewport.ScrollControlIntoView(target);Row(navigation,button);
        }
        _login.Click+=async(_,_)=>await Act("Login");_connect.Click+=async(_,_)=>await Act("Connect");_disconnect.Click+=async(_,_)=>await Act("Disconnect");
        _timer.Tick+=async(_,_)=>{if(!_busy && !_closing)await Act("Status");};
        Shown+=async(_,_)=>{
            await Act("Status");
            if(!IsDisposed && !_closing && _statusReadSucceeded && !_needsReconcile && !_startupPrepared && _deviceRegistered && !_connectionIntent && _lastMode=="disconnected"){
                _startupPrepared=true;await Act("Prepare");
            }
            if(!IsDisposed && !_closing)_timer.Start();
        };
        IEnumerable<Control> Descendants(Control root){foreach(Control child in root.Controls){yield return child;foreach(var nested in Descendants(child))yield return nested;}}
        foreach(var button in Descendants(body).OfType<Button>())StyleButton(button,button==_connect);StyleButton(_emergencyRecovery);
        foreach(var input in Descendants(body).OfType<TextBox>()){input.BorderStyle=BorderStyle.FixedSingle;input.AccessibleName=input==_username?"登录账号":input==_password?"密码":"设备名称";}
        _help.SetToolTip(_telemetry,"速率按本机 VPN 网卡字节增量统计；HTTP 延迟包含 Oracle 隧道与检测站点响应时间，不能等同于游戏延迟。");
        foreach(var value in new[]{_download,_upload})_help.SetToolTip(value,"本机 VPN 网卡的实时速率。1 MiB/s 约为 8.39 Mbps；测速网站通常使用 Mbps。");
        _help.SetToolTip(_emergencyRecovery,"独立于当前请求的本机恢复入口。需要 Windows 管理员授权；恢复完成前不会把网络状态当作已断开。");
        FitBody();
        FormClosing+=async(_,e)=>{
            // Only a deliberate user close changes connection intent. Windows
            // shutdown, forced termination and GUI crashes retain fail-close.
            if(e.CloseReason==CloseReason.UserClosing && !_allowClose){e.Cancel=true;await QuitClient();}
        };
    }
    protected override void Dispose(bool disposing){if(disposing){_lifetime.Cancel();_requestEpoch.Cancel();_timer.Dispose();_help.Dispose();}base.Dispose(disposing);}
    private void CancelRequests(){var previous=_requestEpoch;_requestEpoch=new CancellationTokenSource();previous.Cancel();previous.Dispose();}
    private void RefreshActions()
    {
        if(IsDisposed)return;
        bool available=!_busy && !_closing && !_needsReconcile && !_uuMaintaining;
        _connect.Enabled=available && _canConnect;_disconnect.Enabled=_login.Enabled=_logout.Enabled=available;
        _transportChoice.Enabled=available && !_connectionIntent;_native8443Test.Enabled=available && !_connectionIntent && _native8443Available;
        UpdateRegistrationActions();
    }
    private async Task<JsonObject> SendRequest(string command,string? username,string? password,CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();
        Task<JsonObject> pending=_realService?ControlPipe.Send(command,username,password,cancel):_send(command,username,password);
        try{return await pending.WaitAsync(cancel);}
        catch{
            // A cancelled wait cannot undo a command already admitted by the
            // service. Never render its late response or silently retry it.
            _=pending.ContinueWith(t=>{_ = t.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
            throw;
        }
    }
    internal async Task<bool> QuitClient()
    {
        if(_closing || IsDisposed)return false;
        _closing=true;_timer.Stop();CancelRequests();RefreshActions();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);deadline.CancelAfter(_quitTimeout);
        bool acquired=false,sentQuit=false;
        try{
            await _requests.WaitAsync(deadline.Token);acquired=true;
            if(_realService && ControlPipe.ServiceAbsent()){_allowClose=true;Close();return true;}
            if(_needsReconcile){
                // The service processes the pipe serially. Its fresh Status
                // response is a barrier after the earlier uncertain command.
                var reconciled=await SendRequest("Status",null,null,deadline.Token);
                Display(reconciled);if(reconciled["ok"]?.GetValue<bool>()!=true)throw new IOException("PREVIOUS_OPERATION_NOT_CONFIRMED");
                _needsReconcile=false;
            }
            sentQuit=true;var state=await SendRequest("Quit",null,null,deadline.Token);
            Display(state);
            if(state["ok"]?.GetValue<bool>()!=true || state["intent"]?.GetValue<bool>()!=false || state["core_pid"]?.GetValue<uint>()!=0 || state["mode"]?.GetValue<string>()!="disconnected")throw new IOException("SAFE_EXIT_NOT_VERIFIED");
            _allowClose=true;Close();return true;
        }catch{
            if(sentQuit)_needsReconcile=true;
            if(!IsDisposed)_detail.Text="退出结果未确认，窗口保持打开。请稍后重试；底部“恢复直连（UAC）”始终可用。";
            return false;
        }finally{
            if(acquired)_requests.Release();
            if(!_allowClose && !IsDisposed){_closing=false;RefreshActions();_timer.Start();}
        }
    }
    internal async Task Act(string command)
    {
        if(_closing || IsDisposed)return;
        bool passive=command=="Status";
        if(passive)_statusReadSucceeded=false;
        if(!passive && (_busy || _needsReconcile || _uuMaintaining))return;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token,_requestEpoch.Token);deadline.CancelAfter(passive?_statusTimeout:_requestTimeout);
        bool acquired=false,sentMutation=false;
        if(!passive){_busy=true;RefreshActions();}
        try{
            if(passive){if(!_requests.Wait(0))return;acquired=true;}
            else{await _requests.WaitAsync(deadline.Token);acquired=true;}
            // A fresh/default UI must not silently restart the legacy 51820/443
            // plan. Resolve the advertised native port before the user's Connect.
            // Keep an already prepared8443 core warm, and never change an active
            // connection's policy from a status poll.
            if(command=="Connect" && _deviceRegistered && !_connectionIntent && _native8443Available && !_native8443Selected && (_transportChoice.SelectedIndex is 0 or 1)){
                sentMutation=true;var selected=await SendRequest(TransportPolicy.ClientSelection(_transportChoice.SelectedIndex,true),null,null,deadline.Token);
                Display(selected);if(selected["ok"]?.GetValue<bool>()!=true)return;
            }
            sentMutation=!passive;var state=await SendRequest(command,command=="Login"?_username.Text:command=="ConfirmDevice"?_deviceName.Text:null,command=="Login"?_password.Text:command=="ConfirmDevice" && _deviceConfirmation.Checked?"confirmed":null,deadline.Token);
            if(command=="Login")_password.Clear();
            if(passive && state["ok"]?.GetValue<bool>()==true){_needsReconcile=false;_statusReadSucceeded=true;}
            Display(state);
            if(command=="Login" && state["ok"]?.GetValue<bool>()==true && state["account"] is JsonObject){_credentialsExpanded=false;_credentials.Visible=false;_login.Visible=false;_credentialsToggle.Text="切换账号";}
            if(command=="Login" && !_deviceRegistered && state["account"] is JsonObject)_deviceName.Focus();
        }catch(OperationCanceledException){
            if(sentMutation)_needsReconcile=true;
            if(!IsDisposed && !_closing){
                _mode.Text=_needsReconcile?"操作结果待确认":"系统服务响应超时";_mode.ForeColor=Color.DarkOrange;
                _detail.Text=_needsReconcile?"等待已结束，服务可能仍在处理。确认状态后才能继续操作；底部可使用“恢复直连（UAC）”。":"暂未读到系统服务状态，稍后会重试。现有连接与保护不会因此更改。";
            }
        }catch{
            if(sentMutation)_needsReconcile=true;
            if(!IsDisposed && !_closing){
                _maintenance.Visible=true;_maintenanceToggle.Text="收起系统维护";_mode.Text="系统服务暂不可用";_mode.ForeColor=Color.DarkOrange;_protocol.Text=_exitIp.Text=_latency.Text=_uu.Text="—";UpdateRates(new JsonObject(),false);_progress.Enabled=false;_usageUpdated.Text="用量更新暂不可用，显示上次读取值。";
                _detail.Text=_needsReconcile?"上次操作结果尚未确认。请等待状态刷新；必要时使用底部“恢复直连（UAC）”。":"无法读取系统服务。首次使用请安装服务；已安装时可查看连接诊断或使用底部恢复入口。";
                try{string path=Path.Combine(Platform.Root,"diagnostics.json");if(new FileInfo(path).Length<=4096){var d=JsonNode.Parse(File.ReadAllText(path));_detail.Text+=$" 诊断：{d?["stage"]} / {d?["code"]}。";}}catch{}
            }
        }
        finally{if(acquired)_requests.Release();if(!passive)_busy=false;if(!IsDisposed && !_closing)RefreshActions();}
    }
    private async Task MaintainUu(bool restore)
    {
        if(_uuMaintaining || _closing || _busy || _needsReconcile)return;
        if(_connectionIntent){_detail.Text="请先断开 VPN，再进行 UU 权限维护。";return;}
        _uuMaintaining=true;RefreshActions();
        try{
            int result=await Installer.ElevateUuPermissionsAsync(restore,_lifetime.Token);
            if(IsDisposed)return;
            if(result==0){
                _uuMaintaining=false;await Act("RefreshUu");await Act("Status");
                if(!IsDisposed && !_needsReconcile && _uuReport.Contains("UU_DIRECTORY_WRITABLE",StringComparison.Ordinal))_detail.Text="部分 UU 目录仍可写，请查看“UU 检查详情”中的具体路径。";
            }else _detail.Text=result==4?"已取消 UU 权限维护，未自动重试。":"UU 权限维护未完成，请查看维护窗口中的提示。";
        }catch(IOException error)when(error.Message=="UU_MAINTENANCE_RESULT_PENDING"){
            if(!IsDisposed)_detail.Text="UU 权限维护可能仍在进行，尚未确认结果。请等待维护窗口结束后重新识别；未自动重试。";
        }catch(OperationCanceledException){ }
        catch{if(!IsDisposed)_detail.Text="UU 权限维护未启动，请检查 UAC 提示。";}
        finally{_uuMaintaining=false;if(!IsDisposed)RefreshActions();}
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
            foreach(string key in new[]{"product_version","mode","error","intent","guard","transport","connection_stage","core_stage","carrier_stage","transport_preference","transport_address","ipv6_policy","verified_exit_ipv6","quic_available","native_udp_8443_available","native_udp_port_preference","native_udp_selected_port","client_handshake_reply","core_pid","tun_permitted","server_handshake_at","peer_rx_bytes","peer_tx_bytes","uu_verified_programs","quick_ready","preparing","verified_at","connect_switch_ms","click_to_ready_ms"})_connectionReport+=$"{key}: {state[key]}\r\n";
            if(state["carrier_failures"] is JsonObject failures)foreach(string transport in new[]{"wireguard-udp","wireguard-quic","wireguard-https"})if(failures[transport] is JsonObject attempt)foreach(string key in new[]{"error","carrier_stage","probe_failures","core_uptime_ms","failed_at","core_pid"})_connectionReport+=$"attempt.{transport}.{key}: {attempt[key]}\r\n";
            _connectionIntent=state["intent"]?.GetValue<bool>()==true;
            _native8443Available=state["native_udp_8443_available"]?.GetValue<bool>()==true;
            _native8443Selected=state["native_udp_port_preference"]?.GetValue<int>()==8443;
            _native8443Test.Enabled=!_connectionIntent && !_busy && !_closing && !_needsReconcile && !_uuMaintaining && _native8443Available;
            _renderingTransport=true;
            try{_transportChoice.SelectedIndex=state["transport_preference"]?.GetValue<string>() switch{"udp"=>1,"quic"=>2,_=>0};}finally{_renderingTransport=false;}
            _transportChoice.Enabled=!_connectionIntent && !_busy && !_closing && !_needsReconcile && !_uuMaintaining;
            if(state["native_udp_attempt"] is JsonObject native)foreach(string key in new[]{"endpoint_port","preferred_port","selected_port","socket_binding","server_handshake_at_observed","started_at","started_without_tun","probe_result","probe_failures","core_age_ms","verified_after_start_ms","inner_mtu"})_connectionReport+=$"native_udp.{key}: {native[key]}\r\n";
            if(state["native_udp_attempt"]?["ports"] is JsonObject ports)foreach(string port in new[]{"51820","443","8443"})if(ports[port] is JsonObject counters)foreach(string key in new[]{"tx_initiations","rx_responses","rx_cookies","rx_invalid","rx_obsolete","read_errors","write_errors","last_read_error","last_write_error","rcvbuf_before","sndbuf_before","rcvbuf_after","sndbuf_after","socket_buffer_error"})_connectionReport+=$"native_udp.{port}.{key}: {counters[key]}\r\n";
            if(state["switch_timings"] is JsonObject timings)foreach(string key in new[]{"uu_discovery_ms","uu_signature_verifications","state_saved_ms","guard_installed_ms","tun_active_ms","complete_ms"})_connectionReport+=$"switch.{key}: {timings[key]}\r\n";
            if(state["failure"] is JsonObject failure)foreach(string key in new[]{"stage","category","hresult","native_error","socket_error","http_error","http_status","core_stage","at"})_connectionReport+=$"failure.{key}: {failure[key]}\r\n";
            Text="Oracle Proxy · "+(state["product_version"]?.GetValue<string>() ?? "0.3.0-rc18");
            _uuReport="UU 自动发现与信任核验（只读）\r\n服务版本："+(state["product_version"]?.GetValue<string>() ?? "未知")+
                $"\r\n候选：{state["uu_candidates"]} · 通过：{state["uu_verified_programs"]} · 拒绝：{state["uu_rejected"]}\r\n";
            if(state["uu_diagnostics"] is JsonArray uuIssues && uuIssues.Count>0){
                foreach(var item in uuIssues)_uuReport+=$"\r\n{UuReason(item!["code"]!.GetValue<string>())}\r\n{item["code"]} {item["detail"]}\r\n{item["path"]}\r\n";
            }else _uuReport+="\r\n暂无拒绝详情；请在断开状态点击“重新识别 UU”。";
            string mode=state["mode"]?.GetValue<string>() ?? "unknown";bool guard=state["guard"]?.GetValue<bool>()==true;
            _lastMode=mode;
            _timer.Interval=mode is "protected" or "connecting" || (state["preparing"]?.GetValue<bool>()==true && state["quick_ready"]?.GetValue<bool>()!=true)?250:mode=="connected"?1000:3000;
            _mode.Text=mode switch{"connected"=>guard?(state["transport"]?.GetValue<string>() switch{"wireguard-https"=>"已连接 Oracle · HTTPS","wireguard-quic"=>"已连接 Oracle · QUIC / HTTP/3",_=>"已连接 Oracle · UDP"}):"连接保护未验证","connecting"=>"正在连接","protected"=>guard?"已保护 · 等待连接":"保护尚未验证","disconnected"=>"已断开 · 当前直连","recovery"=>"需要恢复处理",_=>"状态未知"};
            _mode.ForeColor=mode=="connected"?Color.FromArgb(11,137,108):mode=="disconnected"?Color.FromArgb(55,70,96):Color.DarkOrange;
            string policy=state["account"]?["status"]?.GetValue<string>() ?? "";
            string detail=state["error"]?.GetValue<string>() is string error && error.Length>0?Message(error):guard?(policy is "disabled" or "expired" or "quota" or "server_budget" or "unavailable"?$"账号状态：{PolicyName(policy)}。防泄漏保护保留。":"连接受保护；意外中断时将阻止普通应用绕过 VPN。"):"点击连接前，请先登录管理员分配的账号。";
            if(state["error"]?.GetValue<string>()=="UU_TRUST_NOT_VERIFIED"){
                _maintenance.Visible=true;_maintenanceToggle.Text="收起系统维护";
                var writable=(state["uu_diagnostics"] as JsonArray)?.FirstOrDefault(item=>item?["code"]?.GetValue<string>() is "UU_DIRECTORY_WRITABLE" or "UU_EXECUTABLE_WRITABLE");
                detail=writable is not null?"UU 路径允许普通用户修改："+writable["path"]+"。请在“03 诊断与测试”点击“修复 UU 并重新识别（UAC）”。":"UU 信任核验未通过，请查看“UU 检查详情”；目录权限问题可使用“修复 UU 并重新识别（UAC）”。";
            }
            if(mode=="disconnected" && state["quick_ready"]?.GetValue<bool>()==true)detail="快速连接已就绪（"+(state["transport"]?.GetValue<string>() switch{"wireguard-quic"=>"QUIC / HTTP/3","wireguard-https"=>"HTTPS 兜底通道",_=>"WireGuard UDP 主通道"})+"）。当前普通应用仍直连；点击连接后启用防泄漏与 VPN。";
            else if(mode=="disconnected" && state["preparing"]?.GetValue<bool>()==true)detail="正在预备加密通道，当前普通应用仍直连。首次连接或网络变化可能需要等待。";
            var account=state["account"]?.AsObject();
            bool hasAccount=account is not null;
            if(_hasAccount!=hasAccount){
                _hasAccount=hasAccount;_credentialsExpanded=false;_credentials.Visible=!hasAccount;_login.Visible=!hasAccount;_credentialsToggle.Visible=hasAccount;_credentialsToggle.Text="切换账号";_logout.Visible=hasAccount;
            }
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
            
            UpdateRegistration(state);
            if(account is not null && !_deviceRegistered && mode=="disconnected"){
                _mode.Text="已登录 · 请确认本机设备";
                detail="请在账号与设备区核对本机名称和识别码，确认归属并登记后再连接。";
            }
            if(_detail.Text!=detail)_detail.Text=detail;
            string protocolText=mode=="connected"?state["transport"]?.GetValue<string>() switch{"wireguard-udp"=>"WireGuard / UDP","wireguard-quic"=>"QUIC / HTTP/3","wireguard-https"=>"HTTPS / TLS 兜底",_=>"—"}:"—";
            string exit4=state["verified_exit_ip"]?.GetValue<string>() ?? "待验证",exit6=state["verified_exit_ipv6"]?.GetValue<string>() ?? "";
            _exitIp.Text=mode=="connected"?exit4+(exit6.Length>0?"\n"+exit6:""):"—";
            string exitHelp=mode=="connected"?"IPv4："+exit4+(exit6.Length>0?"\nIPv6："+exit6:""):"连接验证通过后显示 Oracle 出口。";
            if(_help.GetToolTip(_exitIp)!=exitHelp)_help.SetToolTip(_exitIp,exitHelp);
            if(mode=="connected" && state["transport"]?.GetValue<string>()=="wireguard-udp" && state["native_udp_selected_port"] is JsonValue selectedPort && selectedPort.TryGetValue<int>(out int selectedUdpPort))protocolText+=" · "+selectedUdpPort;
            if(_protocol.Text!=protocolText)_protocol.Text=protocolText;
            _latency.Text=mode=="connected" && latency is not null?$"{latency} ms":"—";
            _uu.Text=$"{state["uu_verified_programs"] ?? (JsonNode)0} 个程序已验证";
            UpdateRates(state,mode=="connected" && guard);
            _telemetry.Text=mode=="connected"?(state["verified_exit_ipv6"] is not null?"双栈出口已验证 · ":"")+"防泄漏保护已启用":"连接通过验证后显示协议、出口与实时速率。";
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
    private void UpdateRegistrationActions(){
        _registerDevice.Enabled=!_busy && !_closing && !_needsReconcile && !_uuMaintaining && !_connectionIntent && _canRegister && _deviceConfirmation.Checked && _deviceName.Text.Trim().Length is >0 and <=80 && !_deviceName.Text.Any(char.IsControl);
    }
    private void UpdateRegistration(JsonObject state){
        var account=state["account"] as JsonObject;var registration=state["registration"] as JsonObject;
        bool showRegistration=account is not null;
        if(_registrationShown!=showRegistration){_registrationShown=showRegistration;_registrationGroup.Visible=showRegistration;}
        _deviceRegistered=state["device_registered"]?.GetValue<bool>()==true && registration?["status"]?.GetValue<string>()=="registered";
        string id=registration?["device_id"]?.GetValue<string>() ?? "";
        string identity=(account?["username"]?.GetValue<string>() ?? "")+"|"+id;
        string name=registration?["device_name"]?.GetValue<string>() ?? Environment.MachineName;
        if(identity!=_deviceIdentity){_deviceIdentity=identity;_deviceExpanded=false;_deviceName.Text=name;_deviceConfirmation.Checked=false;}
        else if(_deviceRegistered && !_deviceName.Focused && _deviceName.Text!=name)_deviceName.Text=name;
        _deviceIdentityLabel.Text="本机识别码："+(id.Length==0?"等待系统服务读取":id)+(_deviceRegistered?"  ·  已确认登记":"  ·  尚未确认");
        long at=state["observed_at"]?.GetValue<long>() ?? 0;bool fresh=at>0 && Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-at)<=20;
        bool active=account?["status"]?.GetValue<string>()=="active" && fresh;
        bool requiresSlot=registration?["requires_slot"]?.GetValue<bool>()!=false;
        int count=account?["device_count"]?.GetValue<int>() ?? 0,limit=account?["device_limit"]?.GetValue<int>() ?? 0;
        _canConnect=_deviceRegistered && active;_connect.Enabled=!_busy && !_closing && !_needsReconcile && !_uuMaintaining && _canConnect;
        _canRegister=registration is not null && !_deviceRegistered && active && (!requiresSlot || count<limit);
        _deviceName.ReadOnly=_deviceRegistered;_deviceConfirmation.Enabled=!_deviceRegistered && !_connectionIntent && active && registration is not null;
        long? confirmed=registration?["confirmed_at"]?.GetValue<long>();
        string note=registration is null?"请先安装 / 升级系统服务，以读取设备登记信息。":_deviceRegistered?"已登记："+name+(confirmed is null?"":"  ·  "+DateTimeOffset.FromUnixTimeSeconds(confirmed.Value).ToLocalTime().ToString("yyyy-MM-dd HH:mm")):_connectionIntent?"请先断开，再确认本机设备。":!active?"账号不可用或状态待刷新，暂不能登记。":requiresSlot && count>=limit?$"设备名额已满（{count}/{limit}），请联系管理员撤销旧设备。":"确认后仅登记当前设备；管理员可查看归属、确认时间与使用状态。";
        if(_registrationNote.Text!=note)_registrationNote.Text=note;
        var devices=state["devices"] as JsonArray;string signature=devices?.ToJsonString() ?? "";
        if(signature!=_deviceListSignature){
            _deviceListSignature=signature;_knownDevices.BeginUpdate();_knownDevices.Items.Clear();
            if(devices is not null)foreach(var device in devices)_knownDevices.Items.Add((device?["current"]?.GetValue<bool>()==true?"[本机] ":"")+(device?["name"]?.GetValue<string>() ?? "未命名")+"  ·  "+device?["id"]+(device?["revoked"]?.GetValue<bool>()==true?"  ·  已撤销":""));
            if(_knownDevices.Items.Count==0)_knownDevices.Items.Add("尚无已登记设备。");_knownDevices.EndUpdate();
        }
        RegistrationDisclosure();
        UpdateRegistrationActions();
    }
    private static string FormatRate(double bytes)=>bytes>=1024*1024?$"{bytes/(1024*1024):0.0} MiB/s":bytes>=1024?$"{bytes/1024:0.0} KiB/s":$"{bytes:0} B/s";
    private static string PolicyName(string status)=>status switch{"disabled"=>"已停用","expired"=>"已到期","quota"=>"配额已耗尽","server_budget"=>"服务器出站额度保护中",_=>"待核对"};
    private static string FormatBytes(long bytes)=>bytes>=(1L<<40)?$"{bytes/(double)(1L<<40):0.00} TiB":bytes>=(1L<<30)?$"{bytes/(double)(1L<<30):0.00} GiB":bytes>=(1L<<20)?$"{bytes/(double)(1L<<20):0.00} MiB":bytes>=1024?$"{bytes/1024d:0.0} KiB":$"{bytes:N0} B";
    private static string Message(string code)=>code switch{
        "DEVICE_CONFIRMATION_REQUIRED"=>"请先核对本机名称和识别码，勾选归属并登记此设备。",
        "DISCONNECT_BEFORE_ENROLLMENT"=>"请先断开 VPN，再确认本机设备。",
        "CLIENT_UPDATE_REQUIRED"=>"请升级客户端并在账号与设备区完成设备确认。",

        "QUIC_NOT_AVAILABLE"=>"服务器暂未提供 QUIC / HTTP/3，请使用自动模式。", "DISCONNECT_BEFORE_TRANSPORT_CHANGE"=>"请先断开，再选择连接方式。",
        "INVALID_CREDENTIALS"=>"账号或密码错误。", "DEVICE_LIMIT_REACHED"=>"设备数量已达上限，请联系管理员撤销旧设备。", "RATE_LIMITED"=>"登录尝试过于频繁，请稍后重试。",
        "UU_TRUST_NOT_VERIFIED"=>"UU 信任核验未通过，请查看“UU 检查详情”；目录权限问题可使用“修复 UU 并重新识别（UAC）”。",
        "SERVICE_OPERATION_FAILED"=>"连接未完成，请点击“连接诊断”查看失败阶段和错误码。",
        "CORE_READY_TIMEOUT"=>"隧道核心启动超时，保护保持启用。请复制“连接诊断”。",
        "ORACLE_PROBE_TIMEOUT"=>"Oracle 出口验证超时，保护保持启用。请复制“连接诊断”。",
        "ORACLE_PROBE_HTTP_FAILED"=>"Oracle 出口请求失败，保护保持启用。请复制“连接诊断”。",
        "UU_MAINTENANCE_BUSY"=>"UU 权限维护进行中，请完成后再连接。",
        "ACCOUNT_NOT_ACTIVE"=>"账号已停用、到期、超额，或服务器状态暂不可验证。", "RECOVERY_REQUIRED"=>"清理尚未通过验证，防泄漏保护保留。请使用本机恢复操作。",
        "STATE_MISSING_RECOVERY_REQUIRED"=>"加密状态文件缺失，已保留原防泄漏策略。请在本机使用恢复操作。",
        "LOGIN_REQUIRED"=>"请先登录账号。", "DISCONNECT_BEFORE_LOGIN"=>"更换登录前请先断开。", _=>$"操作尚未完成：{code}。"};
}
