using System.Text.Json.Nodes;
namespace OracleProxy.Product;
internal sealed partial class MainForm : Form
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
    private bool _backendIdle;
    private readonly System.Windows.Forms.Timer _timer=new(){Interval=3000};
    private bool _githubChecking;
    private bool _native8443Available;
    private bool _deviceRegistered,_canConnect,_canRegister,_registrationShown;
    private string _deviceIdentity="",_deviceListSignature="";
    private readonly TextBox _deviceName=new(){Name="device-name",MaxLength=80,Dock=DockStyle.Fill};
    private readonly Label _deviceIdentityLabel=new(){AutoSize=false,Height=28,AutoEllipsis=true};
    private readonly Label _registrationNote=new(){AutoSize=false,Height=48};
    private readonly CheckBox _deviceConfirmation=new(){Name="device-confirm",Text="这是我的设备，我确认将它登记到当前账号。",AutoSize=false,Height=44,Dock=DockStyle.Fill};
    private readonly Button _registerDevice=new(){Name="register-device",Text="确认并登记此设备",Width=190,Height=38,Enabled=false};
    private sealed record ListedDevice(string Id,string Name,bool Current){public override string ToString()=>(Current?"[本机] ":"")+Name+"  ·  "+Id;}
    private readonly Button _deleteDevice=new(){Name="delete-device",Text="删除选中设备",Enabled=false,AutoSize=true};
    private string? _deleteDeviceId;
    private string _admissionListSignature="";
    private readonly TableLayoutPanel _admissionDevicesPanel=Stack("admission-devices");
    private readonly ListBox _admissionDevices=new(){Name="admission-device-list",Height=110,Dock=DockStyle.Fill};
    private readonly Button _admissionDelete=new(){Name="admission-delete-device",Enabled=false,Text="删除选中旧设备并登记本机",Height=42};
    private readonly ListBox _knownDevices=new(){Name="my-devices",Dock=DockStyle.Fill,Height=90,HorizontalScrollbar=true};
    private readonly TableLayoutPanel _registrationGroup;
    private readonly TableLayoutPanel _deviceDetails;
    private readonly TableLayoutPanel _credentials;
    private readonly TableLayoutPanel _maintenance;
    private readonly Button _deviceToggle=new(){Name="device-details-toggle",Text="展开设备详情",AutoSize=true};
    private readonly Button _maintenanceToggle=new(){Name="maintenance-toggle",Text="展开系统维护",AutoSize=true};
    private readonly Button _emergencyRecovery=new(){Name="emergency-recovery",Text="恢复直连（UAC）",AutoSize=true};
    private readonly ToolTip _help=new(){ShowAlways=true,InitialDelay=350,ReshowDelay=100,AutoPopDelay=18000};
    private bool _deviceExpanded,_hasAccount,_authenticated,_dashboardShown,_toolsExpanded,_provisioning,_serviceReady;
    private readonly Button _bootstrapRetry=new(){Name="bootstrap-retry",Text="重试初始化",Height=38,Visible=false};
    private readonly TableLayoutPanel _shell,_toolsContent;
    private readonly Panel _loginGate;
    private readonly Panel _startupGate;
    private bool _initialViewResolved;
    private readonly Label _version=new(){Name="app-version",Text="v"+DeviceRegistration.Version.Split('+')[0],ForeColor=Color.Gray,AutoEllipsis=true,Font=new Font("Microsoft YaHei UI",9)};
    private readonly Label _loginFeedback=new(){Name="login-feedback",Text="登录后即可管理连接与设备。"};
    private readonly CheckBox _rememberLogin=new(){Name="remember-login",Text="记住登录（最多 30 天）",Checked=true,AutoSize=true};
    private readonly Button _diagnosticsToggle=new(){Name="diagnostics-toggle",Text="展开诊断与测试",Height=38,AutoSize=false};
    private static readonly Color Canvas=Color.FromArgb(232,239,245);
    private bool _deviceDetailsShown=true,_deviceToggleShown=true;
    private static readonly Color Ink=Color.FromArgb(38,55,73),Muted=Color.FromArgb(79,101,123),Accent=Color.FromArgb(86,116,145),Border=Color.FromArgb(194,209,222);

    private readonly Button _native8443Test;
    private bool _busy,_renderingTransport,_connectionIntent,_closing,_allowClose;
    private readonly ComboBox _udpPortChoice=new(){Name="udp-port-choice",DropDownStyle=ComboBoxStyle.DropDownList,Width=180};
    private sealed record UdpPortChoice(int Port,string Caption){public override string ToString()=>Caption;}
    private bool _renderingPort;
    private string _portListSignature="";
    private readonly ComboBox _transportChoice=new(){Name="transport-choice",DropDownStyle=ComboBoxStyle.DropDownList,Width=190};
    private readonly SemaphoreSlim _requests=new(1,1);
    private readonly CancellationTokenSource _lifetime=new();
    private CancellationTokenSource _requestEpoch=new();
    private readonly TimeSpan _requestTimeout,_quitTimeout,_statusTimeout;
    private readonly Func<string,string?,string?,Task<JsonObject>> _send;
    private readonly bool _realService;
    private bool _needsReconcile,_startupPrepared,_uuMaintaining,_statusReadSucceeded,_recovering;
    private readonly Func<CancellationToken,Task<int>> _recover;
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
    private DateTimeOffset _snapshotAt;
    private string _uuReport="请先在断开状态点击“重新识别 UU”。";
    private readonly Label _protocol=MetricValue(),_exitIp=MetricValue(),_download=MetricValue(),_upload=MetricValue(),_latency=MetricValue(),_uu=MetricValue();
    private readonly Label _accountName=new(){AutoSize=true,Text="尚未登录"};
    private readonly Label _usageUpdated=new(){AutoSize=true,ForeColor=Color.FromArgb(100,113,134)};
    private readonly Button _logout=new(){Text="退出登录",AutoSize=true,Visible=false};
    private long? _sampleAt,_sampleRx,_sampleTx;
    private uint _samplePid;
    private static Label MetricValue()=>new(){Text="—",Dock=DockStyle.Fill,AutoEllipsis=true,Height=30,TextAlign=ContentAlignment.MiddleLeft,Font=new Font("Microsoft YaHei UI",13,FontStyle.Bold),Margin=new Padding(0)};
    private static TableLayoutPanel Stack(string name){var panel=new TableLayoutPanel{Name=name,Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,ColumnCount=1,Margin=new Padding(0),Padding=new Padding(0)};panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));return panel;}
    private static void Row(TableLayoutPanel panel,Control item){int row=panel.RowCount++;panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));item.Dock=DockStyle.Fill;
        if(item is Label label && !label.AutoSize)label.MinimumSize=new Size(0,Math.Max(label.Height,TextRenderer.MeasureText("中文Ag",label.Font).Height+8));
        panel.Controls.Add(item,0,row);}
    private static Control Metric(string title,Label value){
        var cell=new Panel{Name="metric"+title,Dock=DockStyle.Fill,Margin=new Padding(0,0,14,8)};
        value.Dock=DockStyle.Fill;value.AutoSize=false;cell.Controls.Add(value);
        var caption=new Label{Text=title,Dock=DockStyle.Top,Height=22,ForeColor=Muted,Margin=new Padding(0)};value.Tag=caption;cell.Controls.Add(caption);
        return cell;
    }
    private static TableLayoutPanel ButtonGrid(string name){
        var grid=new TableLayoutPanel{Name=name,ColumnCount=4,RowCount=0,AutoSize=false,Height=0,Dock=DockStyle.Top,Margin=new Padding(0,8,0,0)};
        for(int i=0;i<3;i++)grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,1));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,0));
        // TableLayoutPanel expands its last column with unused pixels, even for
        // Absolute sizes. Give the 0-2 remainder pixels their own empty column.
        grid.SizeChanged+=(_,_)=>{int available=Math.Max(3,grid.ClientSize.Width-grid.Padding.Horizontal),width=available/3;for(int i=0;i<4;i++){int target=i==3?available-width*3:width;if(grid.ColumnStyles[i].Width!=target)grid.ColumnStyles[i].Width=target;}};
        return grid;
    }
    private void SetToolsExpanded(bool expanded){if(_toolsExpanded==expanded)return;_toolsExpanded=expanded;_toolsContent.Visible=expanded;_diagnosticsToggle.Text=expanded?"收起诊断与测试":"展开诊断与测试";}

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
            TextRenderer.DrawText(e.Graphics,Text,heading,new Rectangle(Padding.Left,12*DeviceDpi/96,Width-Padding.Horizontal,32*DeviceDpi/96),Muted,TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        }
    }
    private static GroupBox Card(string name,string title,TableLayoutPanel content){var card=new SectionCard{Name=name,Text=title,Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Padding=new Padding(20,46,20,14),Margin=new Padding(0,0,0,12),BackColor=Color.FromArgb(248,250,253)};card.Controls.Add(content);return card;}
    private static void StyleButton(Button button,bool primary=false){
        button.FlatStyle=FlatStyle.Flat;button.FlatAppearance.BorderColor=primary?Accent:Border;button.FlatAppearance.BorderSize=primary?0:1;
        button.BackColor=primary?Accent:Color.White;button.ForeColor=primary?Color.White:Ink;button.UseVisualStyleBackColor=false;button.Cursor=Cursors.Hand;
        button.FlatAppearance.MouseOverBackColor=primary?Color.FromArgb(68,98,128):Color.FromArgb(221,231,240);button.FlatAppearance.MouseDownBackColor=primary?Color.FromArgb(55,82,110):Color.FromArgb(207,222,235);
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
    internal MainForm(Func<string,string?,string?,Task<JsonObject>>? send=null,TimeSpan? requestTimeout=null,TimeSpan? quitTimeout=null,Func<CancellationToken,Task<int>>? recover=null)
    {
        _recover=recover ?? Installer.ElevateRecoveryAsync;
        _send=send ?? ControlPipe.Send;_realService=send is null;_serviceReady=!_realService;DoubleBuffered=true;
        _requestTimeout=requestTimeout??TimeSpan.FromSeconds(45);_quitTimeout=quitTimeout??TimeSpan.FromSeconds(45);
        if(_requestTimeout<=TimeSpan.Zero || _requestTimeout>TimeSpan.FromMinutes(1) || _quitTimeout<=TimeSpan.Zero || _quitTimeout>TimeSpan.FromMinutes(1))throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        _statusTimeout=TimeSpan.FromMilliseconds(Math.Min(_requestTimeout.TotalMilliseconds,6000));
        Text="Proxy";AutoScaleMode=AutoScaleMode.Dpi;ClientSize=new Size(1220,820);MinimumSize=new Size(760,540);BackColor=Canvas;ForeColor=Ink;Font=new Font("Microsoft YaHei UI",10);StartPosition=FormStartPosition.CenterScreen;
        var root=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=3,Margin=new Padding(0),Padding=new Padding(0)};
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));root.RowStyles.Add(new RowStyle(SizeType.Absolute,58));root.RowStyles.Add(new RowStyle(SizeType.Percent,100));root.RowStyles.Add(new RowStyle(SizeType.AutoSize));Controls.Add(root);
        var heading=new TableLayoutPanel{Name="app-header",Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Padding=new Padding(26,12,26,10),Margin=new Padding(0),BackColor=Canvas};
        heading.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));heading.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        heading.Controls.Add(new Label{Text="Proxy",AutoSize=true,ForeColor=Color.Black,Font=new Font(Font.FontFamily,21,FontStyle.Bold),Margin=new Padding(0,0,16,0)},0,0);
        _version.Dock=DockStyle.Fill;_version.TextAlign=ContentAlignment.MiddleLeft;heading.Controls.Add(_version,1,0);root.Controls.Add(heading,0,0);
        var content=new Panel{Dock=DockStyle.Fill,Margin=new Padding(0)};root.Controls.Add(content,0,1);
        _shell=new TableLayoutPanel{Name="dashboard",Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,Visible=false,Margin=new Padding(0)};
        _shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));_shell.RowStyles.Add(new RowStyle(SizeType.Absolute,44));_shell.RowStyles.Add(new RowStyle(SizeType.Percent,100));content.Controls.Add(_shell);
        var navigation=Actions();navigation.Name="navigation";navigation.BackColor=Canvas;navigation.Padding=new Padding(22,0,22,0);navigation.Margin=new Padding(0);_shell.Controls.Add(navigation,0,0);
        var viewport=new Panel{Name="viewport",Dock=DockStyle.Fill,AutoScroll=true,Margin=new Padding(0)};_shell.Controls.Add(viewport,0,1);
        var body=Stack("sections");body.Padding=new Padding(18,4,18,12);viewport.Controls.Add(body);
        var summary=new TableLayoutPanel{Name="summary-grid",AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=2,RowCount=1,Margin=Padding.Empty};
        summary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,56));summary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,44));summary.RowStyles.Add(new RowStyle(SizeType.AutoSize));Row(body,summary);

        _mode.AutoSize=false;_mode.Height=44;_mode.Font=new Font(Font.FontFamily,18,FontStyle.Bold);_mode.AutoEllipsis=true;_mode.Margin=new Padding(0,0,0,8);
        _detail.AutoSize=false;_detail.Height=34;_detail.MinimumSize=Size.Empty;_detail.MaximumSize=Size.Empty;_detail.AutoEllipsis=true;_detail.ForeColor=Muted;_detail.Margin=new Padding(0,0,0,6);
        var connection=Stack("connectionContent");Row(connection,_mode);Row(connection,_detail);
        var metrics=new TableLayoutPanel{Name="connectionMetrics",AutoSize=false,Height=156,Dock=DockStyle.Fill,ColumnCount=3,RowCount=2,Margin=new Padding(0,0,0,8)};
        for(int i=0;i<3;i++)metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100f/3));for(int i=0;i<2;i++)metrics.RowStyles.Add(new RowStyle(SizeType.Percent,50));
        _exitIp.Font=new Font(Font.FontFamily,10,FontStyle.Bold);_protocol.Font=new Font(Font.FontFamily,9.5f,FontStyle.Bold);
        var values=new[]{Metric("当前协议",_protocol),Metric("已验证出口 IP",_exitIp),Metric("隧道 HTTP 延迟",_latency),Metric("下载速率 · VPN",_download),Metric("上传速率 · VPN",_upload),Metric("UU 直连保护",_uu)};
        for(int i=0;i<values.Length;i++)metrics.Controls.Add(values[i],i%3,i/3);Row(connection,metrics);
        _transportChoice.Items.AddRange(["WireGuard / UDP","QUIC / HTTP/3"]);_transportChoice.SelectedIndex=0;
        var selection=Actions();selection.Controls.Add(new Label{Text="连接方式",AutoSize=true,Margin=new Padding(0,8,16,0)});selection.Controls.Add(_transportChoice);Row(connection,selection);
        selection.Controls.Add(new Label{Text="UDP 端口",AutoSize=true,Margin=new Padding(0,8,16,0)});selection.Controls.Add(_udpPortChoice);
        _udpPortChoice.Items.AddRange([new UdpPortChoice(0,"优选可用端口"),new UdpPortChoice(443,"443"),new UdpPortChoice(8443,"8443"),new UdpPortChoice(51820,"51820")]);_udpPortChoice.SelectedIndex=0;
        _udpPortChoice.SelectionChangeCommitted+=async(_,_)=>{if(!_renderingPort)await Act((_udpPortChoice.SelectedItem as UdpPortChoice)?.Port switch{443=>"PreferUdp443",8443=>"PreferUdp8443",51820=>"PreferUdp51820",_=>"PreferUdpAdaptive"});};
        _transportChoice.SelectionChangeCommitted+=async(_,_)=>{if(!_renderingTransport && _transportChoice.SelectedIndex>=0)await Act(TransportPolicy.ClientSelection(_transportChoice.SelectedIndex,_native8443Available));};
        var buttons=Actions();_connect.Margin=new Padding(0,0,10,0);_disconnect.Margin=new Padding(0);buttons.Controls.AddRange([_connect,_disconnect]);Row(connection,buttons);
        _help.SetToolTip(_connect,"使用所选通道连接；必要时自动尝试备用通道。连接通过验证后，普通应用流量经加密隧道发送。");
        _help.SetToolTip(_disconnect,"安全断开 VPN 并恢复普通应用直连，保留已登记设备。");
        _help.SetToolTip(_transportChoice,"UDP 优先，QUIC 与 HTTPS 作为备用。连接期间请先断开再切换。");
        _telemetry.AutoSize=false;_telemetry.Height=28;_telemetry.AutoEllipsis=true;_telemetry.ForeColor=Muted;_telemetry.Margin=new Padding(0,8,0,0);Row(connection,_telemetry);
        var connectionCard=Card("connectionSection","当前连接",connection);summary.Controls.Add(connectionCard,0,0);connectionCard.Margin=new Padding(0,0,10,12);
        var account=Stack("accountContent");_accountName.AutoSize=false;_accountName.Height=30;_accountName.AutoEllipsis=true;_accountName.Font=new Font(Font.FontFamily,11,FontStyle.Bold);_accountName.Margin=new Padding(0,0,0,10);Row(account,_accountName);
        _usage.AutoSize=false;_usage.Height=48;_usage.Margin=new Padding(0,0,0,4);Row(account,_usage);
        _progress.Dock=DockStyle.Fill;_progress.Height=20;_progress.Margin=new Padding(0,0,0,10);Row(account,_progress);
        _expiry.AutoSize=false;_expiry.Height=48;_expiry.AutoEllipsis=true;_expiry.Margin=new Padding(0,0,0,4);Row(account,_expiry);_usageUpdated.AutoSize=false;_usageUpdated.Height=28;_usageUpdated.AutoEllipsis=true;_usageUpdated.Margin=new Padding(0,0,0,10);Row(account,_usageUpdated);
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
        Row(_deviceDetails,_registrationNote);Row(_deviceDetails,new Label{Text="此账号已登记的设备",AutoSize=true,ForeColor=Muted});Row(_deviceDetails,_knownDevices);
        var deviceActions=Actions();deviceActions.Controls.Add(_deleteDevice);Row(_deviceDetails,deviceActions);
        _knownDevices.SelectedIndexChanged+=(_,_)=>RefreshActions();
        _deleteDevice.Click+=async(_,_)=>{
            if(_knownDevices.SelectedItem is not ListedDevice selected)return;
            string note=selected.Current?"删除本机登记将断开连接并退出登录。":"删除后该设备将无法继续使用代理。";
            if(MessageBox.Show(this,$"删除设备“{selected.Name}”？\n{note}","删除设备",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;
            _deleteDeviceId=selected.Id;try{await Act("DeleteDevice");}finally{_deleteDeviceId=null;}
        };
        Row(_registrationGroup,_deviceDetails);
        _deviceToggle.Click+=(_,_)=>{_deviceExpanded=!_deviceExpanded;RegistrationDisclosure();};
        Row(account,_registrationGroup);_registrationGroup.Visible=false;
        _deviceName.TextChanged+=(_,_)=>UpdateRegistrationActions();_deviceConfirmation.CheckedChanged+=(_,_)=>UpdateRegistrationActions();
        _registerDevice.Click+=async(_,_)=>{if(_deviceConfirmation.Checked)await Act("ConfirmDevice");};
        var accountActions=Actions();accountActions.Controls.Add(_logout);Row(account,accountActions);
        _logout.Click+=async(_,_)=>await Act("Logout");
        var accountCard=Card("accountSection","账号与设备",account);summary.Controls.Add(accountCard,1,0);
        void FitBody(){int width=Math.Max(1,viewport.ClientSize.Width-SystemInformation.VerticalScrollBarWidth);if(body.MaximumSize.Width!=width)body.MaximumSize=new Size(width,0);if(body.Width!=width)body.Width=width;
            bool wide=width>=1040*DeviceDpi/96;
            if(summary.ColumnCount!=(wide?2:1)){summary.SuspendLayout();summary.Controls.Clear();summary.ColumnCount=wide?2:1;summary.RowCount=wide?1:2;summary.ColumnStyles.Clear();summary.RowStyles.Clear();summary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,wide?56:100));if(wide)summary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,44));summary.RowStyles.Add(new RowStyle(SizeType.AutoSize));if(!wide)summary.RowStyles.Add(new RowStyle(SizeType.AutoSize));summary.Controls.Add(connectionCard,0,0);summary.Controls.Add(accountCard,wide?1:0,wide?0:1);connectionCard.Margin=new Padding(0,0,wide?10:0,12);summary.ResumeLayout(true);}
        }
        
        var tools=Stack("toolsContainer");_diagnosticsToggle.Dock=DockStyle.Fill;Row(tools,_diagnosticsToggle);_toolsContent=Stack("toolsContent");_toolsContent.Visible=false;Row(tools,_toolsContent);
        _diagnosticsToggle.Click+=(_,_)=>SetToolsExpanded(!_toolsExpanded);
        var diagnostics=ButtonGrid("diagnostic-actions");
        Button Tool(string title,Action action){var button=new Button{Text=title,AutoSize=false,Height=40,Margin=new Padding(0,0,10,8)};button.Click+=(_,_)=>action();return button;}
        void Add(TableLayoutPanel grid,Button button){int index=grid.Controls.Count;int row=index/3;if(row>=grid.RowCount){grid.RowCount=row+1;grid.RowStyles.Add(new RowStyle(SizeType.Absolute,48));grid.Height=grid.RowCount*48;}button.Dock=DockStyle.Fill;grid.Controls.Add(button,index%3,row);}
        Add(diagnostics,Tool("连接诊断",()=>ShowReport("连接诊断",ConnectionReport)));
        Add(diagnostics,Tool("GitHub 连通性",async()=>await ShowGitHubReport()));Add(diagnostics,Tool("UU 检查详情",ShowUuReport));
        Add(diagnostics,Tool("重新识别 UU",async()=>await Act("RefreshUu")));
        _native8443Test=Tool("原生 UDP 8443 测试",async()=>await Act("PreferUdp8443"));Add(diagnostics,_native8443Test);
        void Open(string url){try{System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url){UseShellExecute=true});}catch{_detail.Text="未能打开默认浏览器。";}}
        Add(diagnostics,Tool("打开出口检查",()=>Open("https://www.cloudflare.com/cdn-cgi/trace")));
        Row(_toolsContent,diagnostics);
        BuildUdpDiagnostics(_toolsContent,diagnostics,Add);
        _maintenance=ButtonGrid("system-maintenance");_maintenance.Visible=false;
        Row(_toolsContent,_maintenanceToggle);_maintenanceToggle.Click+=(_,_)=>{_maintenance.Visible=!_maintenance.Visible;_maintenanceToggle.Text=_maintenance.Visible?"收起系统维护":"展开系统维护";};
        void Install(){try{Installer.Elevate(false);}catch{_loginFeedback.Text=_detail.Text="安装未完成，请检查 UAC 提示或使用完整软件包。";}}
        Add(_maintenance,Tool("安装 / 升级服务",Install));
        Add(_maintenance,Tool("卸载服务",()=>{if(MessageBox.Show(this,"将恢复直连并卸载系统服务、删除本机密钥。设备登记与用量仍保留，可在其他已登录客户端或后台删除旧设备释放名额。继续？","卸载",MessageBoxButtons.OKCancel)==DialogResult.OK){try{Installer.Elevate(true);}catch{_detail.Text="卸载未完成，请检查 UAC 提示。";}}}));
        foreach(bool restore in new[]{false,true}){var button=Tool(restore?"恢复 UU 权限":"修复 UU 权限",async()=>await MaintainUu(restore));_help.SetToolTip(button,"需要管理员授权。修复后自动重新识别；恢复使用原权限备份。");Add(_maintenance,button);}Row(_toolsContent,_maintenance);
        var toolsCard=Card("toolsSection","诊断与测试",tools);Row(body,toolsCard);
        foreach(var (title,target) in new[]{("当前连接",connectionCard),("账号与设备",accountCard),("诊断与测试",toolsCard)}){
            var button=new Button{Text=title,AutoSize=false,Width=148,Height=36,TextAlign=ContentAlignment.MiddleCenter,FlatStyle=FlatStyle.Flat,BackColor=Canvas,UseVisualStyleBackColor=false,ForeColor=Ink,Margin=new Padding(0,0,10,0)};button.FlatAppearance.BorderSize=0;button.Click+=(_,_)=>{if(target==toolsCard)SetToolsExpanded(true);viewport.ScrollControlIntoView(target);};navigation.Controls.Add(button);
        }
        // The login screen is the initial view. Only an authenticated service
        // response with an account can reveal the dashboard.
        _loginGate=new Panel{Name="login-gate",Dock=DockStyle.Fill,AutoScroll=true,Margin=new Padding(0),BackColor=Canvas,Visible=false};content.Controls.Add(_loginGate);_loginGate.BringToFront();
        var loginContent=Stack("loginContent");
        Row(loginContent,new Label{Text="登录账号",AutoSize=true,Font=new Font(Font.FontFamily,18,FontStyle.Bold),Margin=new Padding(0,0,0,10)});
        Row(loginContent,new Label{Text="使用管理员提供的账号和密码，登录时自动登记本机设备。",AutoSize=true,ForeColor=Muted,Margin=new Padding(0,0,0,18)});
        _credentials=Stack("credentials");_username.Dock=_password.Dock=DockStyle.Fill;_username.Height=_password.Height=36;_username.Margin=_password.Margin=new Padding(0,0,0,12);
        Row(_credentials,new Label{Text="账号",AutoSize=true,Margin=new Padding(0,0,0,4)});Row(_credentials,_username);Row(_credentials,new Label{Text="密码",AutoSize=true,Margin=new Padding(0,0,0,4)});Row(_credentials,_password);Row(loginContent,_credentials);
        _rememberLogin.Margin=new Padding(0,0,0,12);Row(loginContent,_rememberLogin);_help.SetToolTip(_rememberLogin,"最多保留 30 天的加密登录令牌，不保存明文密码；退出账号后立即清除。");
        _login.AutoSize=false;_login.Height=44;_login.Margin=new Padding(0,0,0,12);Row(loginContent,_login);
        _loginFeedback.AutoSize=false;_loginFeedback.Height=44;_loginFeedback.AutoEllipsis=true;_loginFeedback.ForeColor=Muted;Row(loginContent,_loginFeedback);
        Row(_admissionDevicesPanel,new Label{Text="设备名额已满，请先删除不再使用的设备。",AutoSize=true,ForeColor=Muted});
        Row(_admissionDevicesPanel,_admissionDevices);Row(_admissionDevicesPanel,_admissionDelete);_admissionDevicesPanel.Visible=false;Row(loginContent,_admissionDevicesPanel);
        _admissionDevices.SelectedIndexChanged+=(_,_)=>RefreshActions();
        _admissionDelete.Click+=async(_,_)=>{
            if(_admissionDevices.SelectedItem is not ListedDevice selected)return;
            if(MessageBox.Show(this,$"删除旧设备“{selected.Name}”并登记本机？","释放设备名额",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;
            _deleteDeviceId=selected.Id;try{await Act("DeleteDevice");}finally{_deleteDeviceId=null;}
        };
        Row(loginContent,_bootstrapRetry);_bootstrapRetry.Click+=async(_,_)=>{if(await ProvisionService())await StartReadyClient();};
        var loginCard=Card("login-card","",loginContent);loginCard.Dock=DockStyle.None;loginCard.AutoSize=true;loginCard.Padding=new Padding(28,24,28,24);_loginGate.Controls.Add(loginCard);
        void FitLogin(){int width=Math.Min(470,Math.Max(1,_loginGate.ClientSize.Width-40));loginCard.Width=width;loginCard.MaximumSize=new Size(width,0);loginCard.Left=Math.Max(0,(_loginGate.ClientSize.Width-width)/2);loginCard.Top=Math.Max(12,(_loginGate.ClientSize.Height-loginCard.Height)/2);}
        _loginGate.SizeChanged+=(_,_)=>FitLogin();loginCard.SizeChanged+=(_,_)=>FitLogin();
        _startupGate=new Panel{Name="startup-gate",Dock=DockStyle.Fill,BackColor=Canvas};
        _startupGate.Controls.Add(new Label{Name="startup-message",Text="正在准备安全连接…",Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleCenter,ForeColor=Muted});content.Controls.Add(_startupGate);_startupGate.BringToFront();
        var safety=Actions();safety.Name="safety-actions";safety.BackColor=Canvas;safety.Margin=new Padding(0);safety.Padding=new Padding(22,8,22,10);
        _emergencyRecovery.Margin=new Padding(0,0,12,0);safety.Controls.Add(_emergencyRecovery);safety.Controls.Add(new Label{Text="连接异常时，可在本机恢复直连。",AutoSize=true,ForeColor=Muted,Margin=new Padding(0,8,0,0)});root.Controls.Add(safety,0,2);
        _emergencyRecovery.Click+=async(_,_)=>{
            if(_recovering || MessageBox.Show(this,"将停止隧道、关闭自动连接并恢复直连。已保存密钥保留；损坏的加密状态会保留备份。继续？","恢复直连",MessageBoxButtons.OKCancel)!=DialogResult.OK)return;
            await RecoverDirect();
        };
        _login.Click+=async(_,_)=>await Act(_rememberLogin.Checked?"LoginRemembered":"Login");_connect.Click+=async(_,_)=>await Act("Connect");_disconnect.Click+=async(_,_)=>await Act("Disconnect");
        _password.KeyDown+=async(_,e)=>{if(e.KeyCode==Keys.Enter && _login.Enabled){e.SuppressKeyPress=true;await Act(_rememberLogin.Checked?"LoginRemembered":"Login");}};
        _timer.Tick+=async(_,_)=>{if(!_busy && !_closing)await Act("Status");};
        Shown+=async(_,_)=>{if(_realService){if(await ProvisionService())await StartReadyClient();}else{await Act("Status");await StartReadyClient();}};
        IEnumerable<Control> Descendants(Control parent){foreach(Control child in parent.Controls){yield return child;foreach(var nested in Descendants(child))yield return nested;}}
        foreach(var button in Descendants(body).Concat(Descendants(_loginGate)).OfType<Button>())StyleButton(button,button==_connect || button==_login);StyleButton(_emergencyRecovery);
        foreach(var input in new[]{_username,_password,_deviceName}){input.BorderStyle=BorderStyle.FixedSingle;input.AccessibleName=input==_username?"登录账号":input==_password?"密码":"设备名称";}
        _help.SetToolTip(_telemetry,"速率按本机 VPN 网卡字节增量统计；HTTP 延迟包含隧道及检测站点响应时间，与游戏延迟不同。");
        foreach(var value in new[]{_download,_upload})_help.SetToolTip(value,"本机 VPN 网卡实时速率，统一使用十进制 MB/s、KB/s、B/s。1 MB/s = 8 Mbps。");
        _help.SetToolTip(_emergencyRecovery,"独立的本机恢复入口，需要管理员授权；恢复完成前不会把网络状态当作已断开。");
        AcceptButton=null;viewport.SizeChanged+=(_,_)=>FitBody();FitBody();FitLogin();
        var area=Screen.FromControl(this).WorkingArea;Size=new Size(Math.Min(Width,area.Width),Math.Min(Height,area.Height));
        FormClosing+=async(_,e)=>{if(e.CloseReason==CloseReason.UserClosing && !_allowClose){e.Cancel=true;await QuitClient();}};
    }

    private void RevealView(bool? dashboard)
    {
        if(dashboard.HasValue && _initialViewResolved && _dashboardShown==dashboard.Value)return;
        if(!dashboard.HasValue && !_initialViewResolved && _startupGate.Visible)return;
        // Hold painting across the whole transition, including native child
        // HWNDs. This changes no network state and never awaits while frozen.
        Bitmap? previous=dashboard.HasValue && _initialViewResolved && IsHandleCreated && Visible?ViewBitmap(_dashboardShown?(Control)_shell:_loginGate):null;
        _viewBlend?.Dispose();_viewBlend=null;
        bool redraw=IsHandleCreated && Visible;
        if(redraw)SendMessage(Handle,0x000B,IntPtr.Zero,IntPtr.Zero);
        SuspendLayout();_shell.SuspendLayout();_loginGate.SuspendLayout();
        try{
            _dashboardShown=dashboard==true;_initialViewResolved=dashboard.HasValue;
            _shell.Visible=dashboard==true;_loginGate.Visible=dashboard==false;_startupGate.Visible=!dashboard.HasValue;
            (dashboard==true?(Control)_shell:dashboard==false?_loginGate:_startupGate).BringToFront();
            AcceptButton=dashboard==true?_connect:dashboard==false?_login:null;
        }finally{
            _loginGate.ResumeLayout(true);_shell.ResumeLayout(true);ResumeLayout(true);
            if(redraw){SendMessage(Handle,0x000B,new IntPtr(1),IntPtr.Zero);}
            if(dashboard.HasValue)BlendView(previous,dashboard.Value?(Control)_shell:_loginGate);else previous?.Dispose();
            Invalidate(true);
        }
    }
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr window,uint message,IntPtr wParam,IntPtr lParam);
    private async Task StartReadyClient()
    {
        if(!IsDisposed && !_closing && _authenticated && _statusReadSucceeded && !_needsReconcile && !_startupPrepared && _deviceRegistered && !_connectionIntent && !_udpDiagnosing && _lastMode=="disconnected"){
            _startupPrepared=true;await Act("Prepare");
        }
        if(!IsDisposed && !_closing && _serviceReady)_timer.Start();
    }
    private async Task<bool> ProvisionService()
    {
        if(_provisioning || _closing || IsDisposed)return false;
        _provisioning=true;_serviceReady=false;_timer.Stop();_bootstrapRetry.Visible=false;_loginFeedback.Text="正在准备系统服务，请完成可能出现的 Windows 授权。";RefreshActions();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);deadline.CancelAfter(TimeSpan.FromMinutes(3));
        try{
            string version=typeof(MainForm).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).OfType<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion;
            async Task<JsonObject> Read(CancellationToken cancel){using var limit=CancellationTokenSource.CreateLinkedTokenSource(cancel);limit.CancelAfter(TimeSpan.FromSeconds(8));try{return await ControlPipe.Send("Status",null,null,limit.Token);}catch(OperationCanceledException)when(!cancel.IsCancellationRequested){throw new IOException("SERVICE_STATUS_TIMEOUT");}}
            var state=await ServiceBootstrap.Ensure(version,Read,Installer.ElevateInstallAsync,deadline.Token);
            if(IsDisposed || _closing)return false;
            await ControlPipe.Send("AttachClient",null,null,deadline.Token);
            _backendIdle=false;_serviceReady=true;_statusReadSucceeded=true;_needsReconcile=false;Display(state);return true;
        }catch(Exception error){
            if(!IsDisposed && !_closing){
                _loginFeedback.Text=error.Message=="SERVICE_SETUP_CANCELLED"?"已取消初始化。完成系统服务准备后才可登录。":error is OperationCanceledException?"初始化结果尚未确认，请等待安装窗口结束后重试。":"系统服务尚未准备完成，请重试初始化。";
                _bootstrapRetry.Visible=true;RevealView(false);
            }
            return false;
        }finally{_provisioning=false;if(!IsDisposed){if(!_serviceReady)_bootstrapRetry.Visible=true;RefreshActions();}}
    }
    protected override void Dispose(bool disposing){if(disposing){_viewBlend?.Dispose();_lifetime.Cancel();_requestEpoch.Cancel();_timer.Dispose();_help.Dispose();}base.Dispose(disposing);}
    private void CancelRequests(){var previous=_requestEpoch;_requestEpoch=new CancellationTokenSource();previous.Cancel();previous.Dispose();}
    private void RefreshActions()
    {
        if(IsDisposed)return;
        bool available=_serviceReady && !_provisioning && !_busy && !_closing && !_needsReconcile && !_uuMaintaining && !_recovering;
        _connect.Enabled=available && !_udpDiagnosing && _authenticated && _canConnect;_disconnect.Enabled=_login.Enabled=_logout.Enabled=available;
        _transportChoice.Enabled=available && !_connectionIntent && !_udpDiagnosing;_udpPortChoice.Enabled=_transportChoice.Enabled && _transportChoice.SelectedIndex==0;_native8443Test.Enabled=available && !_connectionIntent && !_udpDiagnosing && _native8443Available;
        _udpStart.Enabled=available && _udpAvailable && _lastMode=="disconnected" && !_udpDiagnosing && !_connectionIntent && _authenticated && _deviceRegistered;_udpCancel.Enabled=available && _udpDiagnosing;_maintenance.Enabled=available && !_udpDiagnosing;
        _deleteDevice.Enabled=available && _hasAccount && !_udpDiagnosing && _knownDevices.SelectedItem is ListedDevice;
        _admissionDelete.Enabled=available && _hasAccount && !_deviceRegistered && _admissionDevices.SelectedItem is ListedDevice;
        UpdateRegistrationActions();
    }
    private async Task<JsonObject> SendRequest(string command,string? username,string? password,CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();
        async Task<JsonObject> Real(){
            while(true){try{
                    if(command!="Status"){
                        await ControlPipe.Send("AttachClient",null,null,cancel);
                        _backendIdle=false;_timer.Start();
                    }
                    return await ControlPipe.Send(command,username,password,cancel);
                }
                catch(IOException error)when(error.Message=="SERVICE_BUSY"){await Task.Delay(200,cancel);}}
        }
        Task<JsonObject> pending=_realService?Real():_send(command,username,password);
        try{return await pending.WaitAsync(cancel);}
        catch{
            // A cancelled wait cannot undo a command already admitted by the
            // service. Never render its late response or silently retry it.
            _=pending.ContinueWith(t=>{_ = t.Exception;},CancellationToken.None,TaskContinuationOptions.OnlyOnFaulted|TaskContinuationOptions.ExecuteSynchronously,TaskScheduler.Default);
            throw;
        }
    }
    internal async Task RecoverDirect()
    {
        if(_recovering || _closing || IsDisposed)return;
        _recovering=true;CancelRequests();_needsReconcile=true;RefreshActions();_emergencyRecovery.Enabled=false;
        string result="恢复结果尚未确认，请查看连接诊断。";
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);deadline.CancelAfter(TimeSpan.FromMinutes(2));
        try{
            _loginFeedback.Text=_detail.Text="正在等待管理员授权及本机恢复，请稍候…";
            int code=await _recover(deadline.Token);
            result=code==4?"已取消管理员授权，正在重新读取服务状态。":code==0?"恢复程序已完成，正在核对直连状态。":"恢复未完成，正在重新读取服务诊断；保护状态以服务确认为准。";
        }catch(OperationCanceledException){result="恢复等待已结束，后台恢复可能仍在执行；请先查看诊断，不要重复提交。";}
        catch{result="恢复程序未完成，正在重新读取服务诊断。";}
        finally{
            _recovering=false;
            if(!IsDisposed){
                _emergencyRecovery.Enabled=true;
                await Act("Status");
                if(!IsDisposed){_loginFeedback.Text=_detail.Text=result+" "+_detail.Text;RefreshActions();}
            }
        }
    }
    internal async Task<bool> QuitClient()
    {
        if(_closing || IsDisposed)return false;
        if(_recovering){_detail.Text="正在恢复直连，请等待本次恢复结果后再关闭。";return false;}
        _closing=true;_timer.Stop();CancelRequests();RefreshActions();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);deadline.CancelAfter(_quitTimeout);
        bool acquired=false,sentQuit=false;
        try{
            await _requests.WaitAsync(deadline.Token);acquired=true;
            if(_backendIdle || _realService && ControlPipe.ServiceAbsent()){_allowClose=true;Close();return true;}
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
            if(!IsDisposed)_loginFeedback.Text=_detail.Text="退出结果未确认，窗口保持打开。请稍后重试；底部“恢复直连（UAC）”始终可用。";
            return false;
        }finally{
            if(acquired)_requests.Release();
            if(!_allowClose && !IsDisposed){_closing=false;RefreshActions();_timer.Start();}
        }
    }
    internal async Task Act(string command)
    {
        if(_closing || IsDisposed || _recovering)return;
        bool passive=command=="Status";
        if(passive && _backendIdle)return;
        if(passive)_statusReadSucceeded=false;
        if(!passive && (!_serviceReady || _provisioning || _busy || _needsReconcile || _uuMaintaining))return;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token,_requestEpoch.Token);deadline.CancelAfter(passive?_statusTimeout:_requestTimeout);
        bool acquired=false,sentMutation=false;
        if(!passive){_busy=true;if(command is "Login" or "LoginRemembered")_loginFeedback.Text="正在验证账号并登记设备…";RefreshActions();}
        try{
            if(passive){if(!_requests.Wait(0))return;acquired=true;}
            else{await _requests.WaitAsync(deadline.Token);acquired=true;}
            // Ordinary Connect preserves the service's adaptive port plan.
            // A diagnostic pin is set only by its explicit diagnostic button.
            if(command is "Login" or "LoginRemembered" && _connectionIntent){
                sentMutation=true;var off=await SendRequest("Disconnect",null,null,deadline.Token);Display(off);
                if(off["ok"]?.GetValue<bool>()!=true || off["intent"]?.GetValue<bool>()!=false)throw new IOException("SAFE_OFF_NOT_VERIFIED");
            }
            sentMutation=!passive;var state=await SendRequest(command,command is "Login" or "LoginRemembered"?_username.Text:command=="ConfirmDevice"?_deviceName.Text:command=="DeleteDevice"?_deleteDeviceId:null,command is "Login" or "LoginRemembered"?_password.Text:command=="ConfirmDevice" && _deviceConfirmation.Checked?"confirmed":null,deadline.Token);
            if(command is "Login" or "LoginRemembered")_password.Clear();
            if(passive && state["ok"]?.GetValue<bool>()==true){_needsReconcile=false;_statusReadSucceeded=true;}
            Display(state);
            if(state["shutdown_after_response"]?.GetValue<bool>()==true && state["ok"]?.GetValue<bool>()==true){_backendIdle=true;_timer.Stop();}
            if(command=="Logout" && state["ok"]?.GetValue<bool>()==true){_username.Clear();_password.Clear();_startupPrepared=false;}
            if(command is "Login" or "LoginRemembered" && !_deviceRegistered && state["account"] is JsonObject)_deviceName.Focus();
        }catch(OperationCanceledException){
            if(sentMutation)_needsReconcile=true;
            if(!IsDisposed && !_closing){
                _mode.Text=_needsReconcile?"操作结果待确认":"系统服务响应超时";_mode.ForeColor=Color.DarkOrange;
                _detail.Text=_needsReconcile?"等待已结束，服务可能仍在处理。确认状态后才能继续操作；底部可使用“恢复直连（UAC）”。":"暂未读到系统服务状态，稍后会重试。现有连接与保护不会因此更改。";
                _loginFeedback.Text=_detail.Text;
            }
        }catch{
            if(sentMutation)_needsReconcile=true;
            if(!IsDisposed && !_closing){
                _maintenance.Visible=true;_maintenanceToggle.Text="收起系统维护";_mode.Text="系统服务暂不可用";_mode.ForeColor=Color.DarkOrange;_protocol.Text=_exitIp.Text=_latency.Text=_uu.Text="—";UpdateRates(new JsonObject(),false);_progress.Enabled=false;_usageUpdated.Text="用量更新暂不可用，显示上次读取值。";
                _detail.Text=_needsReconcile?"上次操作结果尚未确认。请等待状态刷新；必要时使用底部“恢复直连（UAC）”。":"无法读取系统服务。首次使用请安装服务；已安装时可查看连接诊断或使用底部恢复入口。";
                try{string path=Path.Combine(Platform.Root,"diagnostics.json");if(new FileInfo(path).Length<=4096){var d=JsonNode.Parse(File.ReadAllText(path));_detail.Text+=$" 诊断：{d?["stage"]} / {d?["code"]}。";}}catch{}
                _loginFeedback.Text=_detail.Text;
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
    internal string ConnectionReport=>_connectionReport+"\r\nui_snapshot_age_seconds: "+(_snapshotAt==default?"unavailable":Math.Max(0,(long)(DateTimeOffset.UtcNow-_snapshotAt).TotalSeconds).ToString())+"\r\n"+CompatibilityDiagnostics.Read();
    internal int UsageProgress=>_progress.Value;
    internal bool UsageFresh=>_progress.Enabled;
    internal int PollInterval=>_timer.Interval;
    internal void Display(JsonObject state)
    {
            _snapshotAt=DateTimeOffset.UtcNow;_connectionReport="连接诊断（不含账号密码、令牌或密钥）\r\n";
            foreach(string key in new[]{"product_version","mode","error","intent","guard","transport","connection_stage","core_stage","carrier_stage","transport_preference","transport_address","transport_private_address","transport_port","ipv6_policy","verified_exit_ipv6","quic_available","native_udp_8443_available","native_udp_adaptive","native_udp_port_preference","native_udp_selected_port","client_handshake_reply","core_pid","tun_permitted","tun_route_mask","server_handshake_at","peer_rx_bytes","peer_tx_bytes","uu_verified_programs","quick_ready","preparing","verified_at","connect_switch_ms","click_to_ready_ms"})_connectionReport+=$"{key}: {state[key]}\r\n";
            if(state["carrier_failures"] is JsonObject failures)foreach(string transport in new[]{"wireguard-udp","wireguard-quic","wireguard-https"})if(failures[transport] is JsonObject attempt)foreach(string key in new[]{"error","transport_address","started_at","carrier_stage","probe_failures","core_uptime_ms","failed_at","core_pid"})_connectionReport+=$"attempt.{transport}.{key}: {attempt[key]}\r\n";
            _connectionIntent=state["intent"]?.GetValue<bool>()==true;
            _native8443Available=state["native_udp_8443_available"]?.GetValue<bool>()==true;
            _native8443Test.Enabled=!_connectionIntent && !_busy && !_closing && !_needsReconcile && !_uuMaintaining && _native8443Available;
            _renderingTransport=true;
            try{_transportChoice.SelectedIndex=state["transport_preference"]?.GetValue<string>()=="quic"?1:0;}finally{_renderingTransport=false;}
            _renderingPort=true;try{
                int[] availablePorts=(state["native_udp_ports"] as JsonArray)?.Select(p=>p?.GetValue<int>()??0).Where(p=>p is 443 or 8443 or 51820).Distinct().ToArray()??[];
                string portSignature=string.Join(",",availablePorts);
                if(portSignature!=_portListSignature){_portListSignature=portSignature;_udpPortChoice.Items.Clear();_udpPortChoice.Items.Add(new UdpPortChoice(0,"优选可用端口"));foreach(int p in new[]{443,8443,51820}.Where(availablePorts.Contains))_udpPortChoice.Items.Add(new UdpPortChoice(p,p.ToString()));}
                int preferred=state["native_udp_port_preference"]?.GetValue<int>()??0;
                _udpPortChoice.SelectedIndex=Math.Max(0,_udpPortChoice.Items.Cast<UdpPortChoice>().ToList().FindIndex(p=>p.Port==preferred));
            }finally{_renderingPort=false;}
            _udpPortChoice.Enabled=!_connectionIntent && !_busy && !_udpDiagnosing && _transportChoice.SelectedIndex==0;
            _transportChoice.Enabled=!_connectionIntent && !_busy && !_closing && !_needsReconcile && !_uuMaintaining && !_recovering;
            if(state["native_udp_attempt"] is JsonObject native)foreach(string key in new[]{"transport_address","port_order","endpoint_port","preferred_port","selected_port","socket_binding","server_handshake_at_observed","started_at","started_without_tun","probe_result","probe_failures","core_age_ms","verified_after_start_ms","inner_mtu"})_connectionReport+=$"native_udp.{key}: {native[key]}\r\n";
            if(state["native_udp_attempt"]?["ports"] is JsonObject ports)foreach(string port in new[]{"51820","443","8443"})if(ports[port] is JsonObject counters)foreach(string key in new[]{"tx_initiations","rx_responses","rx_cookies","rx_invalid","rx_obsolete","read_errors","write_errors","last_read_error","last_write_error","rcvbuf_before","sndbuf_before","rcvbuf_after","sndbuf_after","socket_buffer_error"})_connectionReport+=$"native_udp.{port}.{key}: {counters[key]}\r\n";
            if(state["switch_timings"] is JsonObject timings)foreach(string key in new[]{"uu_discovery_ms","uu_signature_verifications","state_saved_ms","guard_installed_ms","tun_active_ms","complete_ms"})_connectionReport+=$"switch.{key}: {timings[key]}\r\n";
            if(state["failure"] is JsonObject failure)foreach(string key in new[]{"stage","category","hresult","native_error","socket_error","http_error","http_status","core_stage","at"})_connectionReport+=$"failure.{key}: {failure[key]}\r\n";
            string entry=state["transport_address"]?.GetValue<string>()??"";
            string local=state["transport_private_address"]?.GetValue<string>()??"";
            int? ingressPort=state["transport_port"]?.GetValue<int>();
            string suffix=ingressPort is int ingressPortValue?":"+ingressPortValue:"";

            string productVersion=state["product_version"]?.GetValue<string>() ?? DeviceRegistration.Version;
            _version.Text="v"+productVersion.Split('+')[0];
            if(_help.GetToolTip(_version)!=productVersion)_help.SetToolTip(_version,productVersion);
            _connectionReport=_connectionReport.Replace("ORACLE_EGRESS_","EGRESS_",StringComparison.Ordinal).Replace("ORACLE_","EGRESS_",StringComparison.Ordinal).Replace("oracle_egress_","egress_",StringComparison.Ordinal).Replace("oracle_","egress_",StringComparison.Ordinal);
            _uuReport="UU 自动发现与信任核验（只读）\r\n服务版本："+(state["product_version"]?.GetValue<string>() ?? "未知")+
                $"\r\n候选：{state["uu_candidates"]} · 通过：{state["uu_verified_programs"]} · 拒绝：{state["uu_rejected"]}\r\n";
            if(state["uu_diagnostics"] is JsonArray uuIssues && uuIssues.Count>0){
                foreach(var item in uuIssues)_uuReport+=$"\r\n{UuReason(item!["code"]!.GetValue<string>())}\r\n{item["code"]} {item["detail"]}\r\n{item["path"]}\r\n";
            }else _uuReport+="\r\n暂无拒绝详情；请在断开状态点击“重新识别 UU”。";
            string mode=state["mode"]?.GetValue<string>() ?? "unknown";bool guard=state["guard"]?.GetValue<bool>()==true;
            _lastMode=mode;
            DisplayUdpDiagnostics(state);
            _timer.Interval=_udpDiagnosing?1000:mode is "protected" or "connecting" || (state["preparing"]?.GetValue<bool>()==true && state["quick_ready"]?.GetValue<bool>()!=true)?250:mode=="connected"?1000:3000;
            _mode.Text=mode switch{"connected"=>guard?(state["transport"]?.GetValue<string>() switch{"wireguard-https"=>"已连接 · HTTPS","wireguard-quic"=>"已连接 · QUIC / HTTP/3",_=>"已连接 · UDP"}):"连接保护未验证","connecting"=>"正在连接","protected"=>guard?"已保护 · 等待连接":"保护尚未验证","disconnected"=>"已断开 · 当前直连","recovery"=>"需要恢复处理",_=>"状态未知"};
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
            var account=state["login_authenticated"]?.GetValue<bool>()==true?state["account"]?.AsObject():null;
            bool hasAccount=account is not null;
            if(_hasAccount!=hasAccount){
                _hasAccount=hasAccount;_credentials.Visible=!LoginAdmission.DashboardReady(state);_login.Visible=!LoginAdmission.DashboardReady(state);_logout.Visible=hasAccount;
            }
            _authenticated=LoginAdmission.DashboardReady(state);
            if(_dashboardShown && !_authenticated){_username.Clear();_password.Clear();}
            // Reveal only after every label and child layout below is ready.
            if(!_authenticated){
                string code=state["error"]?.GetValue<string>() ?? "";
                string feedback=code.Length>0?Message(code):_connectionIntent?"当前连接仍受保护，登录前会先安全断开。":"登录后即可管理连接与设备。";
                if(_loginFeedback.Text!=feedback)_loginFeedback.Text=feedback;
            }
            if(account is not null){
                long used=account["used_bytes"]!.GetValue<long>();long? limit=account["limit_bytes"]?.GetValue<long>();
                _accountName.Text=$"{account["username"]}  ·  {(policy=="active"?"账号可用":PolicyName(policy))}";
                _usage.Text=$"本月已用 {FormatBytes(used)} / {(limit is null?"不限量":FormatBytes(limit.Value))}"+(limit is null?"":$"\n剩余 {FormatBytes(Math.Max(0,limit.Value-used))}");
                _progress.Value=limit is >0?(int)Math.Clamp((double)used/limit.Value*1000,0,1000):limit==0?1000:0;
                long? expires=account["expires_at"]?.GetValue<long>();
                _expiry.Text=$"到期：{(expires is null?"长期":DateTimeOffset.FromUnixTimeSeconds(expires.Value).ToLocalTime().ToString("yyyy-MM-dd HH:mm"))}\n已登记设备 {account["device_count"]} / {account["device_limit"]}   ·   UTC 账期 {state["period"]}";
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
            if(_detail.Text!=detail)_detail.Text=detail;if(_help.GetToolTip(_detail)!=detail)_help.SetToolTip(_detail,detail);
            string protocolText=mode=="connected"?state["transport"]?.GetValue<string>() switch{"wireguard-udp"=>"WireGuard / UDP","wireguard-quic"=>"QUIC / HTTP/3","wireguard-https"=>"HTTPS / TLS 兜底",_=>"—"}:"—";
            string exit4=state["verified_exit_ip"]?.GetValue<string>() ?? "待验证",exit6=state["verified_exit_ipv6"]?.GetValue<string>() ?? "";
            _exitIp.Text=mode=="connected"?exit4+(exit6.Length>0?"\n"+exit6:""):"—";
            string exitHelp=mode=="connected"?"IPv4："+exit4+(exit6.Length>0?"\nIPv6："+exit6:""):"连接验证通过后显示出口。";
            if(_help.GetToolTip(_exitIp)!=exitHelp)_help.SetToolTip(_exitIp,exitHelp);
            if(mode=="connected" && state["transport"]?.GetValue<string>()=="wireguard-udp" && state["native_udp_selected_port"] is JsonValue selectedPort && selectedPort.TryGetValue<int>(out int selectedUdpPort))protocolText+=" · "+selectedUdpPort;
            string entryText=entry.Length>0?$"公网 {entry}{suffix}\n内网 {(local.Length>0?local+suffix:"—")}":"—";
            if(_protocol.Tag is Label protocolCaption)protocolCaption.Text=mode=="connected"?protocolText:"连接入口 · 公网 / 内网";
            if(_protocol.Text!=entryText)_protocol.Text=entryText;
            _help.SetToolTip(_protocol,protocolText+"\n"+entryText);
            _latency.Text=mode=="connected" && latency is not null?$"{latency} ms":"—";
            _uu.Text=$"{state["uu_verified_programs"] ?? (JsonNode)0} 个程序已验证";
            UpdateRates(state,mode=="connected" && guard);
            _telemetry.Text=mode=="connected"?(state["verified_exit_ipv6"] is not null?"双栈出口已验证 · ":"")+"防泄漏保护已启用":"连接通过验证后显示协议、出口与实时速率。";
            _usageUpdated.Text=$"用量更新：{(at is null?"—":DateTimeOffset.FromUnixTimeSeconds(at.Value).ToLocalTime().ToString("HH:mm:ss"))}  ·  {(fresh?"服务器账单统计":"上次读取值，等待刷新")}";
            // A valid remembered token can precede the background account
            // refresh after service restart. This is not a signed-out state.
            bool restoring=state["login_authenticated"]?.GetValue<bool>()==true && account is null;
            _startupGate.Controls[0].Text=restoring?"正在恢复已保存的登录…":"正在准备安全连接…";
            if(restoring)_timer.Interval=1000;
            RevealView(restoring?null:_authenticated);

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
        _canConnect=_authenticated && _deviceRegistered && active;_connect.Enabled=!_busy && !_closing && !_needsReconcile && !_uuMaintaining && _canConnect;
        _canRegister=registration is not null && !_deviceRegistered && active && (!requiresSlot || count<limit);
        _deviceName.ReadOnly=_deviceRegistered;_deviceConfirmation.Enabled=!_deviceRegistered && !_connectionIntent && active && registration is not null;
        long? confirmed=registration?["confirmed_at"]?.GetValue<long>();
        string note=registration is null?"请先安装 / 升级系统服务，以读取设备登记信息。":_deviceRegistered?"已登记："+name+(confirmed is null?"":"  ·  "+DateTimeOffset.FromUnixTimeSeconds(confirmed.Value).ToLocalTime().ToString("yyyy-MM-dd HH:mm")):_connectionIntent?"请先断开，再确认本机设备。":!active?"账号不可用或状态待刷新，暂不能登记。":requiresSlot && count>=limit?$"设备名额已满（{count}/{limit}），请展开设备详情删除旧设备。":"确认后仅登记当前设备；管理员可查看归属、确认时间与使用状态。";
        if(_registrationNote.Text!=note)_registrationNote.Text=note;
        var devices=state["devices"] as JsonArray;string signature=devices?.ToJsonString() ?? "";
        if(signature!=_deviceListSignature){
            _deviceListSignature=signature;_knownDevices.BeginUpdate();_knownDevices.Items.Clear();
            if(devices is not null)foreach(var device in devices.Where(d=>d?["revoked"]?.GetValue<bool>()!=true)){
                string listedId=device?["id"]?.GetValue<string>()??"";
                if(listedId.Length==12)_knownDevices.Items.Add(new ListedDevice(listedId,device?["name"]?.GetValue<string>()??"未命名",device?["current"]?.GetValue<bool>()==true));
            }

            if(_knownDevices.Items.Count==0)_knownDevices.Items.Add("尚无已登记设备。");_knownDevices.EndUpdate();
        }
        _admissionDevicesPanel.Visible=account is not null && !_deviceRegistered;
        if(_admissionDevicesPanel.Visible && _admissionListSignature!=signature){_admissionListSignature=signature;_admissionDevices.BeginUpdate();_admissionDevices.Items.Clear();foreach(var item in _knownDevices.Items.OfType<ListedDevice>().Where(d=>!d.Current))_admissionDevices.Items.Add(item);_admissionDevices.EndUpdate();}
        RegistrationDisclosure();
        UpdateRegistrationActions();
    }
    private static string FormatRate(double bytes)=>bytes>=1_000_000?$"{bytes/1_000_000:0.0} MB/s":bytes>=1000?$"{bytes/1000:0.0} KB/s":$"{bytes:0} B/s";
    private static string PolicyName(string status)=>status switch{"disabled"=>"已停用","expired"=>"已到期","quota"=>"配额已耗尽","server_budget"=>"服务器出站额度保护中",_=>"待核对"};
    private static string FormatBytes(long bytes)=>bytes>=1_000_000_000_000L?$"{bytes/1_000_000_000_000d:0.00} TB":bytes>=1_000_000_000?$"{bytes/1_000_000_000d:0.00} GB":bytes>=1_000_000?$"{bytes/1_000_000d:0.00} MB":bytes>=1000?$"{bytes/1000d:0.0} KB":$"{bytes:N0} B";
    private static string Message(string code)=>code switch{
        "DISCONNECT_BEFORE_UDP_DIAGNOSTIC"=>"请先断开并恢复直连，再运行 UDP 诊断。",
        "DIAGNOSTIC_BUSY"=>"UDP 诊断正在运行，可先取消诊断。",
        "DIAGNOSTIC_RATE_LIMITED"=>"诊断请求过于频繁，请稍后重试。",
        "UDP_DIAGNOSTIC_NOT_AVAILABLE"=>"服务器尚未提供 UDP 配对诊断，请稍后刷新状态。",
        "DEVICE_CONFIRMATION_REQUIRED"=>"设备登记尚未完成，请重新登录；登记成功后才能进入连接页面。",
        "DEVICE_REVOKED"=>"此设备身份已撤销，请重新登录以检查名额并登记。",
        "DISCONNECT_BEFORE_ENROLLMENT"=>"请先断开 VPN，再确认本机设备。",
        "CLIENT_UPDATE_REQUIRED"=>"请升级客户端并在账号与设备区完成设备确认。",

        "QUIC_NOT_AVAILABLE"=>"服务器暂未提供 QUIC / HTTP/3，请选择 UDP。", "DISCONNECT_BEFORE_TRANSPORT_CHANGE"=>"请先断开，再选择连接方式。",
        "INVALID_CREDENTIALS"=>"账号或密码错误。", "DEVICE_LIMIT_REACHED"=>"设备名额已满，请在下方删除旧设备后登记本机。", "RATE_LIMITED"=>"登录尝试过于频繁，请稍后重试。",
        "UU_TRUST_NOT_VERIFIED"=>"UU 信任核验未通过，请查看“UU 检查详情”；目录权限问题可使用“修复 UU 并重新识别（UAC）”。",
        "SERVICE_OPERATION_FAILED"=>"连接未完成，请点击“连接诊断”查看失败阶段和错误码。",
        "CORE_READY_TIMEOUT"=>"隧道核心启动超时，保护保持启用。请复制“连接诊断”。",
        "ORACLE_PROBE_TIMEOUT"=>"出口验证超时，保护保持启用。请复制“连接诊断”。",
        "ORACLE_PROBE_HTTP_FAILED"=>"出口请求失败，保护保持启用。请复制“连接诊断”。",
        "UU_MAINTENANCE_BUSY"=>"UU 权限维护进行中，请完成后再连接。",
        "TUN_ROUTE_NOT_ACTIVE"=>"Windows 尚未将普通应用流量送入 VPN，连接未生效。请查看连接诊断；防泄漏保护保持开启。",
        "ACCOUNT_NOT_ACTIVE"=>"账号已停用、到期、超额，或服务器状态暂不可验证。", "RECOVERY_REQUIRED"=>"清理尚未通过验证，防泄漏保护保留。请使用本机恢复操作。",
        "STATE_MISSING_RECOVERY_REQUIRED"=>"加密状态文件缺失，已保留原防泄漏策略。请在本机使用恢复操作。",
        "LOGIN_SESSION_EXPIRED"=>"登录已过期，请重新登录。",
        "LOGIN_REQUIRED"=>"请先登录账号。", "DISCONNECT_BEFORE_LOGIN"=>"更换登录前请先断开。", _=>$"操作尚未完成：{code}。"};
}
