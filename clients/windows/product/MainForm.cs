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
    private readonly Label _mode=new(){Name="connection-status",Text="正在读取系统服务…",AutoSize=true,Font=ClientAppearance.CreateFont(23,FontStyle.Bold)};
    private readonly Label _detail=new(){Name="connection-detail",Text="",AutoSize=true,MaximumSize=new Size(680,0)};
    private readonly Label _usage=new WrappingLabel{Name="cycle-usage",Text="等待同步用量"};
    private readonly Label _cycle=new WrappingLabel{Name="cycle-interval",ForeColor=ClientAppearance.SecondaryText};
    private readonly Label _expiry=new WrappingLabel{Name="account-expiry",Text="到期日未知"};
    private readonly Label _telemetry=new(){Text="延迟 — · UU —",AutoSize=true};
    private readonly SmoothProgressBar _progress=new(){Minimum=0,Maximum=1000,Value=0,Width=650,Height=18};
    private readonly TextBox _username=new(){PlaceholderText="管理员分配的账号",Width=215,MaxLength=64};
    private readonly TextBox _password=new(){PlaceholderText="管理员分配的密码",Width=215,UseSystemPasswordChar=true,MaxLength=128};
    private readonly SmoothButton _login=new(){Name="login",Text="登录",AutoSize=true};
    private readonly SmoothButton _connectionAction=new(){Name="connect",Text="连接",Width=180,Height=48,Enabled=false};
    private string _lastUiCommand="";
    private long? _lastUiQueueMs,_lastUiAttachMs,_lastUiResponseMs,_lastUiCompleteMs;
    private bool _backendIdle,_sessionAttached,_recoveryProvedDirect;
    private string _startupReport="尚未读取初始化结果。";
    private readonly System.Windows.Forms.Timer _timer=new(){Interval=3000};
    private bool _githubChecking;
    private bool _native8443Available;
    private bool _deviceRegistered,_canConnect,_canRegister,_registrationShown,_admissionShown;
    private string _deviceIdentity="";
    private ListedDevice[]? _deviceRows;
    private readonly TextBox _deviceName=new(){Name="device-name",MaxLength=80,Dock=DockStyle.Fill};
    private readonly Label _deviceIdentityLabel=new WrappingLabel{Name="current-device"};
    private readonly Label _registrationNote=new WrappingLabel{Name="device-registration-note",Margin=new Padding(0,2,0,8)};
    private readonly SmoothCheckBox _deviceConfirmation=new(){Name="device-confirm",Text="这是我的设备，我确认将它登记到当前账号。",AutoSize=false,Height=44,Dock=DockStyle.Fill};
    private readonly SmoothButton _registerDevice=new(){Name="register-device",Text="确认并登记此设备",Width=190,Height=38,Enabled=false};
    private sealed record ListedDevice(string Id,string Name,bool Current){public override string ToString()=>(Current?"[本机] ":"")+Name+"  ·  "+Id;}
    private readonly SmoothButton _deleteDevice=new(){Name="delete-device",Text="删除选中设备",Enabled=false,AutoSize=true};
    private string? _deleteDeviceId;
    private readonly TableLayoutPanel _admissionDevicesPanel=Stack("admission-devices");
    private readonly ListBox _admissionDevices=new(){Name="admission-device-list",Height=110,Dock=DockStyle.Fill};
    private readonly SmoothButton _admissionDelete=new(){Name="admission-delete-device",Enabled=false,Text="删除选中旧设备并登记本机",Height=42};
    private readonly ListBox _knownDevices=new(){Name="my-devices",Dock=DockStyle.Fill,Height=90,HorizontalScrollbar=true};
    private readonly TableLayoutPanel _registrationGroup=Stack("deviceRegistration");
    private readonly TableLayoutPanel _credentials;
    private readonly TableLayoutPanel _maintenance;
    private readonly SmoothButton _maintenanceToggle=new(){Name="maintenance-toggle",Text="展开系统维护",AutoSize=true};
    private readonly SmoothButton _emergencyRecovery=new(){Name="emergency-recovery",Text="恢复直连（UAC）",AutoSize=true};
    private readonly ToolTip _help=new(){ShowAlways=true,InitialDelay=350,ReshowDelay=100,AutoPopDelay=18000};
    private bool _hasAccount,_authenticated,_dashboardShown,_toolsExpanded,_provisioning,_serviceReady;
    private readonly SmoothButton _bootstrapRetry=new(){Name="bootstrap-retry",Text="重试初始化",Height=38,Visible=false};
    private readonly TableLayoutPanel _shell,_toolsContent,_connectionContent,_accountContent;
    private readonly Panel _loginGate;
    private readonly Panel _startupGate;
    private readonly StableViewport _viewport;
    private bool _initialViewResolved;
    private readonly Label _version=new(){Name="app-version",Text="v"+DeviceRegistration.Version.Split('+')[0],ForeColor=ClientAppearance.SecondaryText,AutoEllipsis=true,Font=ClientAppearance.CreateFont(9)};
    private readonly Label _loginFeedback=new(){Name="login-feedback",Text="登录后即可管理连接与设备。"};
    private readonly SmoothCheckBox _rememberLogin=new(){Name="remember-login",Text="记住登录（最多 30 天）",Checked=true,AutoSize=true};
    private readonly SmoothButton _diagnosticsToggle=new(){Name="diagnostics-toggle",Text="展开诊断与测试",Height=38,AutoSize=false};
    private static readonly Color Canvas=ClientAppearance.Canvas;
    private static readonly Color Ink=ClientAppearance.Ink,Muted=ClientAppearance.SecondaryText,Accent=ClientAppearance.Accent,Border=ClientAppearance.Border;

    private bool _busy,_connectionIntent,_closing,_allowClose;
    private readonly SmoothComboBox _udpPortChoice=new(){Name="udp-port-choice",DropDownStyle=ComboBoxStyle.DropDownList,Width=180};
    private sealed record UdpPortChoice(int Port,string Caption){public override string ToString()=>Caption;}
    private bool _renderingPort;
    private string _portListSignature="";
    private readonly SemaphoreSlim _requests=new(1,1);
    private readonly CancellationTokenSource _lifetime=new();
    private CancellationTokenSource _requestEpoch=new();
    private readonly TimeSpan _requestTimeout,_loginTimeout,_quitTimeout,_statusTimeout;
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
    private JsonObject? _diagnosticSnapshot;
    private DateTimeOffset _snapshotAt;
    private string _uuReport="请先在断开状态点击“重新识别 UU”。";
    private readonly Label _protocol=MetricValue(),_exitIp=MetricValue(),_download=MetricValue("download-rate"),_upload=MetricValue("upload-rate"),_latency=MetricValue(),_uu=MetricValue();
    private readonly Label _accountName=new(){AutoSize=true,Text="尚未登录"};
    private readonly Label _usageUpdated=new WrappingLabel{Name="usage-updated",ForeColor=Muted};
    private readonly SmoothButton _logout=new(){Text="退出登录",AutoSize=true,Visible=false};
    private long? _sampleAt,_sampleRx,_sampleTx;
    private uint _samplePid;
    private static Label MetricValue(string name="")=>new(){Name=name,Text="—",Dock=DockStyle.Fill,AutoEllipsis=true,Height=30,TextAlign=ContentAlignment.MiddleLeft,Font=ClientAppearance.CreateFont(13,FontStyle.Bold),Margin=new Padding(0)};
    private static TableLayoutPanel Stack(string name){var panel=new TableLayoutPanel{Name=name,Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,ColumnCount=1,Margin=new Padding(0),Padding=new Padding(0)};panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));return panel;}
    private static void Row(TableLayoutPanel panel,Control item){int row=panel.RowCount++;panel.RowStyles.Add(new RowStyle(SizeType.AutoSize));if(item is TextBox or ListBox)item=new SmoothInputFrame(item);item.Dock=DockStyle.Fill;
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
        private readonly SmoothOutline _outline=new();
        protected override void Dispose(bool disposing){if(disposing)_outline.Dispose();base.Dispose(disposing);}
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
            var path=_outline.Get(Size,DeviceDpi,0.75f,14);
            using var fill=new SolidBrush(BackColor);e.Graphics.FillPath(fill,path);using var pen=new Pen(Border);e.Graphics.DrawPath(pen,path);
            using var heading=new Font(Font.FontFamily,10,FontStyle.Bold);
            TextRenderer.DrawText(e.Graphics,Text,heading,new Rectangle(Padding.Left,12*DeviceDpi/96,Width-Padding.Horizontal,32*DeviceDpi/96),Muted,TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        }
    }
    private static GroupBox Card(string name,string title,TableLayoutPanel content){var card=new SectionCard{Name=name,Text=title,Dock=DockStyle.Top,AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Padding=new Padding(20,46,20,14),Margin=new Padding(0,0,0,12),BackColor=ClientAppearance.Surface};card.Controls.Add(content);return card;}
    private static void StyleButton(Button button,bool primary=false){
        if(button is SmoothButton smooth)smooth.Primary=primary;
        button.FlatStyle=FlatStyle.Flat;button.FlatAppearance.BorderColor=primary?Accent:ClientAppearance.ControlBorder;button.FlatAppearance.BorderSize=primary?0:1;
        button.BackColor=primary?Accent:ClientAppearance.Surface;button.ForeColor=primary?ClientAppearance.AccentText:Ink;button.UseVisualStyleBackColor=false;button.Cursor=Cursors.Hand;
        button.FlatAppearance.MouseOverBackColor=primary?ClientAppearance.PrimaryHover:ClientAppearance.Hover;button.FlatAppearance.MouseDownBackColor=primary?ClientAppearance.PrimaryPressed:ClientAppearance.Pressed;
        button.MinimumSize=new Size(Math.Max(button.MinimumSize.Width,92),36);button.Padding=new Padding(10,3,10,3);button.AccessibleName=button.Text;
        if(button.Name is "delete-device" or "admission-delete-device" || button.Text=="卸载服务")button.ForeColor=ClientAppearance.Destructive;
    }
    private static BufferedFlowPanel Actions()=>new(){AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Fill,WrapContents=true,Margin=new Padding(0,6,0,6),Padding=new Padding(0)};
    internal MainForm(Func<string,string?,string?,Task<JsonObject>>? send=null,TimeSpan? requestTimeout=null,TimeSpan? quitTimeout=null,Func<CancellationToken,Task<int>>? recover=null)
    {
        _recover=recover ?? Installer.ElevateRecoveryAsync;
        _send=send ?? ControlPipe.Send;_realService=send is null;_serviceReady=!_realService;DoubleBuffered=true;
        _requestTimeout=requestTimeout??TimeSpan.FromSeconds(45);_quitTimeout=quitTimeout??TimeSpan.FromSeconds(45);
        _loginTimeout=requestTimeout??TimeSpan.FromSeconds(55);
        if(_requestTimeout<=TimeSpan.Zero || _requestTimeout>TimeSpan.FromMinutes(1) || _quitTimeout<=TimeSpan.Zero || _quitTimeout>TimeSpan.FromMinutes(1))throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        _statusTimeout=TimeSpan.FromMilliseconds(Math.Min(_requestTimeout.TotalMilliseconds,6000));
        Text="Proxy";AutoScaleMode=AutoScaleMode.Dpi;ClientSize=new Size(1220,820);MinimumSize=new Size(760,540);BackColor=Canvas;ForeColor=Ink;Font=ClientAppearance.CreateFont(10);StartPosition=FormStartPosition.CenterScreen;
        var root=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=3,Margin=new Padding(0),Padding=new Padding(0)};
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));root.RowStyles.Add(new RowStyle(SizeType.Absolute,58));root.RowStyles.Add(new RowStyle(SizeType.Percent,100));root.RowStyles.Add(new RowStyle(SizeType.AutoSize));Controls.Add(root);
        var heading=new TableLayoutPanel{Name="app-header",Dock=DockStyle.Fill,ColumnCount=2,RowCount=1,Padding=new Padding(26,12,26,10),Margin=new Padding(0),BackColor=Canvas};
        heading.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));heading.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
        heading.Controls.Add(new Label{Text="Proxy",AutoSize=true,ForeColor=Ink,Font=new Font(Font.FontFamily,21,FontStyle.Bold),Margin=new Padding(0,0,16,0)},0,0);
        _version.Dock=DockStyle.Fill;_version.TextAlign=ContentAlignment.MiddleLeft;heading.Controls.Add(_version,1,0);root.Controls.Add(heading,0,0);
        var content=new Panel{Dock=DockStyle.Fill,Margin=new Padding(0)};root.Controls.Add(content,0,1);
        _shell=new TableLayoutPanel{Name="dashboard",Dock=DockStyle.Fill,ColumnCount=1,RowCount=2,Visible=false,Margin=new Padding(0)};
        _shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));_shell.RowStyles.Add(new RowStyle(SizeType.Absolute,44));_shell.RowStyles.Add(new RowStyle(SizeType.Percent,100));content.Controls.Add(_shell);
        var navigation=new TableLayoutPanel{Name="navigation",Dock=DockStyle.Fill,ColumnCount=4,RowCount=1,BackColor=Canvas,Padding=new Padding(22,0,22,4),Margin=Padding.Empty};
        for(int column=0;column<4;column++)navigation.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,25));
        navigation.RowStyles.Add(new RowStyle(SizeType.Percent,100));_shell.Controls.Add(navigation,0,0);
        var viewport=_viewport=new StableViewport{Name="viewport",Dock=DockStyle.Fill,AutoScroll=true,Margin=new Padding(0)};_shell.Controls.Add(viewport,0,1);
        var body=Stack("sections");body.Padding=new Padding(18,4,18,12);viewport.Controls.Add(body);
        var summary=new TableLayoutPanel{Name="summary-grid",AutoSize=true,AutoSizeMode=AutoSizeMode.GrowAndShrink,Dock=DockStyle.Top,ColumnCount=2,RowCount=1,Margin=Padding.Empty};
        summary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,56));summary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,44));summary.RowStyles.Add(new RowStyle(SizeType.AutoSize));Row(body,summary);

        _mode.AutoSize=false;_mode.Height=44;_mode.Font=new Font(Font.FontFamily,18,FontStyle.Bold);_mode.AutoEllipsis=false;_mode.Margin=new Padding(0,0,0,8);
        _detail.AutoSize=false;_detail.Height=62;_detail.MinimumSize=Size.Empty;_detail.MaximumSize=Size.Empty;_detail.AutoEllipsis=false;_detail.ForeColor=Muted;_detail.Margin=new Padding(0,0,0,6);
        var connection=_connectionContent=Stack("connectionContent");Row(connection,_mode);Row(connection,_detail);
        var metrics=new TableLayoutPanel{Name="connectionMetrics",AutoSize=false,Height=156,Dock=DockStyle.Fill,ColumnCount=3,RowCount=2,Margin=new Padding(0,0,0,8)};
        for(int i=0;i<3;i++)metrics.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100f/3));for(int i=0;i<2;i++)metrics.RowStyles.Add(new RowStyle(SizeType.Percent,50));
        _exitIp.Font=new Font(Font.FontFamily,10,FontStyle.Bold);_protocol.Font=new Font(Font.FontFamily,9.5f,FontStyle.Bold);
        var values=new[]{Metric("当前协议",_protocol),Metric("出口 IP",_exitIp),Metric("HTTP 延迟",_latency),Metric("实时下载",_download),Metric("实时上传",_upload),Metric("UU 直连保护",_uu)};
        for(int i=0;i<values.Length;i++)metrics.Controls.Add(values[i],i%3,i/3);Row(connection,metrics);
        var selection=Actions();selection.Controls.Add(new Label{Text="连接方式",AutoSize=true,Margin=new Padding(0,8,16,0)});selection.Controls.Add(new Label{Text="WireGuard / UDP",AutoSize=true,Margin=new Padding(0,8,0,0)});Row(connection,selection);
        selection.Controls.Add(new Label{Text="UDP 端口",AutoSize=true,Margin=new Padding(0,8,16,0)});selection.Controls.Add(_udpPortChoice);
        _udpPortChoice.Items.AddRange([new UdpPortChoice(0,"优选可用端口"),new UdpPortChoice(443,"443"),new UdpPortChoice(8443,"8443"),new UdpPortChoice(51820,"51820")]);_udpPortChoice.SelectedIndex=0;
        _udpPortChoice.SelectionChangeCommitted+=async(_,_)=>{if(!_renderingPort)await Act((_udpPortChoice.SelectedItem as UdpPortChoice)?.Port switch{443=>"PreferUdp443",8443=>"PreferUdp8443",51820=>"PreferUdp51820",_=>"PreferUdpAdaptive"});};
        var buttons=Actions();_connectionAction.Margin=Padding.Empty;buttons.Controls.Add(_connectionAction);
        var directApplications=new SmoothButton{Name="direct-applications",Text="应用直连",Width=138,Height=48,Margin=new Padding(10,0,0,0)};
        directApplications.Click+=(_,_)=>ShowDirectApplications();buttons.Controls.Add(directApplications);Row(connection,buttons);
        _telemetry.AutoSize=false;_telemetry.Height=28;_telemetry.AutoEllipsis=true;_telemetry.ForeColor=Muted;_telemetry.Margin=new Padding(0,8,0,0);Row(connection,_telemetry);
        var connectionCard=Card("connectionSection","当前连接",connection);summary.Controls.Add(connectionCard,0,0);connectionCard.Margin=new Padding(0,0,10,12);
        var account=_accountContent=Stack("accountContent");_accountName.AutoSize=false;_accountName.Height=30;_accountName.AutoEllipsis=true;_accountName.Font=new Font(Font.FontFamily,11,FontStyle.Bold);_accountName.Margin=new Padding(0,0,0,10);Row(account,_accountName);
        _usage.Margin=new Padding(0,0,0,4);Row(account,_usage);
        _progress.Dock=DockStyle.Fill;_progress.Height=20;_progress.Margin=new Padding(0,0,0,10);Row(account,_progress);
        _cycle.Margin=new Padding(0,0,0,4);Row(account,_cycle);
        _expiry.Margin=new Padding(0,0,0,4);Row(account,_expiry);
        _usageUpdated.Margin=new Padding(0,0,0,10);Row(account,_usageUpdated);
        var devices=Stack("devicesContent");
        Row(devices,_deviceIdentityLabel);
        Row(devices,new Label{Text="已登记设备",AutoSize=true,ForeColor=Muted,Margin=new Padding(0,10,0,4)});
        Row(devices,_knownDevices);
        var deviceActions=Actions();deviceActions.Controls.Add(_deleteDevice);Row(devices,deviceActions);
        _knownDevices.SelectedIndexChanged+=(_,_)=>RefreshActions();
        _deleteDevice.Click+=async(_,_)=>{
            if(_knownDevices.SelectedItem is not ListedDevice selected)return;
            string note=selected.Current?"删除本机登记将断开连接并退出登录。":"删除后该设备将无法继续使用代理。";
            if(MessageBox.Show(this,$"删除设备“{selected.Name}”？\n{note}","删除设备",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;
            _deleteDeviceId=selected.Id;try{await Act("DeleteDevice");}finally{_deleteDeviceId=null;}
        };
        var devicesCard=Card("device-management-section","设备管理",devices);Row(body,devicesCard);
        var accountActions=Actions();accountActions.Controls.Add(_logout);Row(account,accountActions);
        _logout.Click+=async(_,_)=>await Act("Logout");
        var accountCard=Card("accountSection","账号用量",account);summary.Controls.Add(accountCard,1,0);
        void FitBody(){int width=Math.Max(1,viewport.ClientSize.Width-SystemInformation.VerticalScrollBarWidth);if(body.MaximumSize.Width!=width)body.MaximumSize=new Size(width,0);if(body.Width!=width)body.Width=width;
            bool wide=width>=1180*DeviceDpi/96;
            if(summary.ColumnCount!=(wide?2:1)){summary.SuspendLayout();summary.Controls.Clear();summary.ColumnCount=wide?2:1;summary.RowCount=wide?1:2;summary.ColumnStyles.Clear();summary.RowStyles.Clear();summary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,wide?56:100));if(wide)summary.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,44));summary.RowStyles.Add(new RowStyle(SizeType.AutoSize));if(!wide)summary.RowStyles.Add(new RowStyle(SizeType.AutoSize));summary.Controls.Add(connectionCard,0,0);summary.Controls.Add(accountCard,wide?1:0,wide?0:1);connectionCard.Margin=new Padding(0,0,wide?10:0,12);summary.ResumeLayout(true);}
        }
        
        var tools=Stack("toolsContainer");_diagnosticsToggle.Dock=DockStyle.Fill;Row(tools,_diagnosticsToggle);_toolsContent=Stack("toolsContent");_toolsContent.Visible=false;Row(tools,_toolsContent);
        _diagnosticsToggle.Click+=(_,_)=>SetToolsExpanded(!_toolsExpanded);
        var diagnostics=ButtonGrid("diagnostic-actions");
        SmoothButton Tool(string title,Action action){var button=new SmoothButton{Text=title,AutoSize=false,Height=40,Margin=new Padding(0,0,10,8)};button.Click+=(_,_)=>action();return button;}
        void Add(TableLayoutPanel grid,Button button){int index=grid.Controls.Count;int row=index/3;if(row>=grid.RowCount){grid.RowCount=row+1;grid.RowStyles.Add(new RowStyle(SizeType.Absolute,48));grid.Height=grid.RowCount*48;}button.Dock=DockStyle.Fill;grid.Controls.Add(button,index%3,row);}
        var connectionDiagnostics=Tool("连接诊断",()=>ShowReport("连接诊断",ConnectionReport));connectionDiagnostics.Name="connection-diagnostics";Add(diagnostics,connectionDiagnostics);
        Add(diagnostics,Tool("GitHub 连通性",async()=>await ShowGitHubReport()));Add(diagnostics,Tool("UU 检查详情",ShowUuReport));
        Row(_toolsContent,diagnostics);
        BuildUdpDiagnostics(_toolsContent,diagnostics,Add);
        _maintenance=ButtonGrid("system-maintenance");_maintenance.Visible=false;
        Row(_toolsContent,_maintenanceToggle);_maintenanceToggle.Click+=(_,_)=>{_maintenance.Visible=!_maintenance.Visible;_maintenanceToggle.Text=_maintenance.Visible?"收起系统维护":"展开系统维护";};
        void Install(){try{Installer.Elevate(false);}catch{_loginFeedback.Text=_detail.Text="安装未完成，请检查 UAC 提示或使用完整软件包。";}}
        Add(_maintenance,Tool("安装 / 升级服务",Install));
        Add(_maintenance,Tool("卸载服务",()=>{if(MessageBox.Show(this,"将恢复直连并卸载系统服务、删除本机密钥。设备登记与用量仍保留，可在其他已登录客户端或后台删除旧设备释放名额。继续？","卸载",MessageBoxButtons.OKCancel)==DialogResult.OK){try{Installer.Elevate(true);}catch{_detail.Text="卸载未完成，请检查 UAC 提示。";}}}));
        foreach(bool restore in new[]{false,true}){var button=Tool(restore?"恢复 UU 权限":"修复 UU 权限",async()=>await MaintainUu(restore));_help.SetToolTip(button,"需要管理员授权。修复后自动重新识别；恢复使用原权限备份。");Add(_maintenance,button);}Row(_toolsContent,_maintenance);
        var toolsCard=Card("toolsSection","诊断与测试",tools);Row(body,toolsCard);
        foreach(var (name,title,target) in new[]{("navigate-connection","当前连接",connectionCard),("navigate-usage","账号用量",accountCard),("navigate-devices","设备管理",devicesCard),("navigate-tools","诊断与测试",toolsCard)}){
            var button=new SmoothButton{Name=name,Text=title,AutoSize=false,Dock=DockStyle.Fill,TextAlign=ContentAlignment.MiddleCenter,FlatStyle=FlatStyle.Flat,BackColor=Canvas,UseVisualStyleBackColor=false,ForeColor=Ink,Margin=new Padding(4,0,4,0)};button.FlatAppearance.BorderSize=0;button.Click+=(_,_)=>{if(target==toolsCard)SetToolsExpanded(true);viewport.ScrollControlIntoView(target);};navigation.Controls.Add(button);
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
        _loginFeedback.AutoSize=true;_loginFeedback.AutoEllipsis=false;_loginFeedback.ForeColor=Muted;Row(loginContent,_loginFeedback);
        Row(_registrationGroup,_registrationNote);
        Row(_registrationGroup,new Label{Text="本机设备名称",AutoSize=true});
        Row(_registrationGroup,_deviceName);Row(_registrationGroup,_deviceConfirmation);
        var registrationActions=Actions();registrationActions.Controls.Add(_registerDevice);Row(_registrationGroup,registrationActions);
        _deviceName.TextChanged+=(_,_)=>UpdateRegistrationActions();_deviceConfirmation.CheckedChanged+=(_,_)=>UpdateRegistrationActions();
        _registerDevice.Click+=async(_,_)=>{if(_deviceConfirmation.Checked)await Act("ConfirmDevice");};
        _registrationGroup.Visible=false;Row(loginContent,_registrationGroup);
        Row(_admissionDevicesPanel,new Label{Text="设备名额已满，请先删除不再使用的设备。",AutoSize=true,ForeColor=Muted});
        Row(_admissionDevicesPanel,_admissionDevices);Row(_admissionDevicesPanel,_admissionDelete);_admissionDevicesPanel.Visible=false;Row(loginContent,_admissionDevicesPanel);
        _admissionDevices.SelectedIndexChanged+=(_,_)=>RefreshActions();
        _admissionDelete.Click+=async(_,_)=>{
            if(_admissionDevices.SelectedItem is not ListedDevice selected)return;
            if(MessageBox.Show(this,$"删除旧设备“{selected.Name}”并登记本机？","释放设备名额",MessageBoxButtons.OKCancel,MessageBoxIcon.Question)!=DialogResult.OK)return;
            _deleteDeviceId=selected.Id;try{await Act("DeleteDevice");}finally{_deleteDeviceId=null;}
        };
        var copyStartup=new SmoothButton{Name="copy-startup-diagnostics",Text="复制登录诊断",Height=36};
        Row(loginContent,copyStartup);copyStartup.Click+=(_,_)=>Clipboard.SetText(LoginDiagnostics());
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
        _login.Click+=async(_,_)=>await Act(_rememberLogin.Checked?"LoginRemembered":"Login");_connectionAction.Click+=async(_,_)=>await Act(DisconnectAction?"Disconnect":"Connect");
        _password.KeyDown+=async(_,e)=>{if(e.KeyCode==Keys.Enter && _login.Enabled){e.SuppressKeyPress=true;await Act(_rememberLogin.Checked?"LoginRemembered":"Login");}};
        _timer.Tick+=async(_,_)=>{
            if(_busy || _closing || _recovering)return;
            await Act("Status");
            if(!_startupPrepared && _canConnect)await StartReadyClient();
        };
        Shown+=async(_,_)=>{if(_realService){if(await ProvisionService())await StartReadyClient();}else{await Act("Status");await StartReadyClient();}};
        IEnumerable<Control> Descendants(Control parent){foreach(Control child in parent.Controls){yield return child;foreach(var nested in Descendants(child))yield return nested;}}
        foreach(var button in Descendants(_shell).Concat(Descendants(_loginGate)).OfType<Button>())StyleButton(button,button==_connectionAction || button==_login);StyleButton(_emergencyRecovery);
        foreach(var input in new[]{_username,_password,_deviceName}){input.BorderStyle=BorderStyle.None;input.AccessibleName=input==_username?"登录账号":input==_password?"密码":"设备名称";}
        _help.SetToolTip(_telemetry,"速率按本机 VPN 网卡字节增量统计；HTTP 延迟包含隧道及检测站点响应时间，与游戏延迟不同。");
        foreach(var value in new[]{_download,_upload})_help.SetToolTip(value,"按本机 VPN 网卡字节变化约每秒更新。1 MB/s = 8 Mbps。");
        _help.SetToolTip(_emergencyRecovery,"独立的本机恢复入口，需要管理员授权；恢复完成前不会把网络状态当作已断开。");
        AcceptButton=null;viewport.SizeChanged+=(_,_)=>FitBody();FitBody();FitLogin();
        var area=Screen.FromControl(this).WorkingArea;Size=new Size(Math.Min(Width,area.Width),Math.Min(Height,area.Height));
        FormClosing+=async(_,e)=>{if((e.CloseReason is CloseReason.UserClosing or CloseReason.TaskManagerClosing) && !_allowClose){e.Cancel=true;await QuitClient();}};
    }

    private void RevealView(bool? dashboard)
    {
        if(dashboard.HasValue && _initialViewResolved && _dashboardShown==dashboard.Value)return;
        if(!dashboard.HasValue && !_initialViewResolved && _startupGate.Visible)return;
        // Hold painting across the whole transition, including native child
        // HWNDs. This changes no network state and never awaits while frozen.
        Bitmap? previous=ClientAppearance.AnimateTransitions && dashboard.HasValue && _initialViewResolved && IsHandleCreated && Visible?ViewBitmap(_dashboardShown?(Control)_shell:_loginGate):null;
        _viewBlend?.Dispose();_viewBlend=null;
        bool redraw=IsHandleCreated && Visible;
        if(redraw)SendMessage(Handle,0x000B,IntPtr.Zero,IntPtr.Zero);
        SuspendLayout();_shell.SuspendLayout();_loginGate.SuspendLayout();
        try{
            _dashboardShown=dashboard==true;_initialViewResolved=dashboard.HasValue;
            _shell.Visible=dashboard==true;_loginGate.Visible=dashboard==false;_startupGate.Visible=!dashboard.HasValue;
            (dashboard==true?(Control)_shell:dashboard==false?_loginGate:_startupGate).BringToFront();
            AcceptButton=dashboard==true?_connectionAction:dashboard==false?_login:null;
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
        if(!IsDisposed && ActionsAvailable && _canConnect && _statusReadSucceeded && !_startupPrepared
            && !_connectionIntent && !_udpDiagnosing && _lastMode=="disconnected"){
            _startupPrepared=true;await Act("Prepare");
        }
        if(!IsDisposed && !_closing && _serviceReady)_timer.Start();
    }
    private static string ClientVersion=>typeof(MainForm).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute),false).OfType<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion;
    private async Task AttachReadyService(CancellationToken cancel)
    {
        // Only the authenticated current controller may enable login. Attach
        // returns a fresh snapshot; never display the pre-attachment read.
        var state=await ControlPipe.Send("AttachClient",null,null,cancel);
        if(!ServiceBootstrap.Current(state,ClientVersion))throw new IOException("SERVICE_ATTACHMENT_NOT_VERIFIED");
        if(IsDisposed || _closing)return;
        _sessionAttached=true;_backendIdle=false;_recoveryProvedDirect=false;_serviceReady=true;_statusReadSucceeded=true;_needsReconcile=false;
        _bootstrapRetry.Visible=false;_startupReport="初始化已完成。版本："+ClientVersion;Display(state);
    }
    private string StartupFailure(Exception error)
    {
        string code=error.Message;
        if(code.Length>80 || !code.All(c=>c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_'))code=error is OperationCanceledException?"SETUP_RESULT_PENDING":"SETUP_FAILED";
        string installed="";
        try{
            string path=Path.Combine(Platform.Root,"diagnostics.json");
            if(new FileInfo(path).Length<=4096){
                var value=JsonNode.Parse(File.ReadAllText(path))?["code"]?.GetValue<string>();
                if(value is {Length:>0 and <=80} && value.All(c=>c is >= 'A' and <= 'Z' or >= '0' and <= '9' or '_'))installed="；后台记录："+value;
            }
        }catch{}
        _startupReport="版本："+ClientVersion+"\r\n初始化："+code+installed;
        return code switch{
            "CLIENT_PACKAGE_INCOMPLETE"=>"客户端文件不完整或版本不一致。请完整解压便携包，保留 runtime 文件夹，再重试初始化。\r\n诊断：CLIENT_PACKAGE_INCOMPLETE",
            "SERVICE_SETUP_CANCELLED"=>"已取消初始化。可以重试或关闭窗口。",
            "SETUP_RESULT_PENDING"=>"初始化尚未结束。可以关闭此窗口，后台维护将继续；结束后重新打开。",
            _=>"系统服务尚未准备完成。可重试、复制登录诊断或关闭窗口。"
        };
    }
    private async Task<bool> ProvisionService()
    {
        if(_provisioning || _closing || IsDisposed)return false;
        _provisioning=true;_serviceReady=false;_timer.Stop();_bootstrapRetry.Visible=false;_loginFeedback.Text="正在准备系统服务，请完成可能出现的 Windows 授权。";RefreshActions();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);deadline.CancelAfter(TimeSpan.FromMinutes(3));
        try{
            string version=ClientVersion;
            async Task<JsonObject> Read(CancellationToken cancel){using var limit=CancellationTokenSource.CreateLinkedTokenSource(cancel);limit.CancelAfter(TimeSpan.FromSeconds(8));try{return await ControlPipe.Send("Status",null,null,limit.Token);}catch(OperationCanceledException)when(!cancel.IsCancellationRequested){throw new IOException("SERVICE_STATUS_TIMEOUT");}}
            var state=await ServiceBootstrap.Ensure(version,Read,Installer.ElevateInstallAsync,deadline.Token);
            if(IsDisposed || _closing)return false;
            await AttachReadyService(deadline.Token);return !IsDisposed && !_closing;
        }catch(Exception error){
            if(!IsDisposed && !_closing){
                _loginFeedback.Text=StartupFailure(error);
                _bootstrapRetry.Visible=true;RevealView(false);
            }
            return false;
        }finally{_provisioning=false;if(!IsDisposed){if(!_serviceReady)_bootstrapRetry.Visible=true;RefreshActions();}}
    }
    protected override void Dispose(bool disposing){if(disposing){_viewBlend?.Dispose();_lifetime.Cancel();_requestEpoch.Cancel();_timer.Dispose();_help.Dispose();}base.Dispose(disposing);}
    private void CancelRequests(){var previous=_requestEpoch;_requestEpoch=new CancellationTokenSource();previous.Cancel();previous.Dispose();}
    private bool ActionsAvailable => _serviceReady && !_provisioning && !_busy && !_closing && !_needsReconcile && !_uuMaintaining && !_recovering;
    private bool DisconnectAction => _connectionIntent || _lastMode is "connected" or "connecting" or "protected" or "recovery";
    private void UpdateConnectionAction()
    {
        bool disconnect=DisconnectAction;
        string name=disconnect?"disconnect":"connect";
        if(_connectionAction.Name!=name)_connectionAction.Name=name;
        string text=disconnect?"断开并恢复直连":"连接";
        if(_connectionAction.Text!=text)_connectionAction.Text=text;
        string help=disconnect?"安全断开 VPN 并恢复普通应用直连，保留已登记设备。":"连接后验证代理出口，自动选择可用的 UDP 端口。";
        if(_help.GetToolTip(_connectionAction)!=help)_help.SetToolTip(_connectionAction,help);
        _connectionAction.Enabled=ActionsAvailable && (disconnect || (_lastMode=="disconnected" && !_udpDiagnosing && _canConnect));
    }
    private void RefreshActions()
    {
        if(IsDisposed)return;
        _emergencyRecovery.Enabled=!_provisioning && !_recovering;
        bool available=ActionsAvailable;
        UpdateConnectionAction();_login.Enabled=_logout.Enabled=available;
        _udpPortChoice.Enabled=available && !_connectionIntent && !_udpDiagnosing;
        UpdateUdpAction();_maintenance.Enabled=available && !_udpDiagnosing;
        _deleteDevice.Enabled=available && _hasAccount && !_udpDiagnosing && _knownDevices.SelectedItem is ListedDevice;
        _admissionDelete.Enabled=available && _hasAccount && !_deviceRegistered && _admissionDevices.SelectedItem is ListedDevice;
        UpdateRegistrationActions();
        _updateDirectApplicationDialog?.Invoke();
    }
    private async Task<JsonObject> SendRequest(string command,string? username,string? password,CancellationToken cancel)
    {
        cancel.ThrowIfCancellationRequested();
        async Task<JsonObject> Real(){
            while(true){try{
                    if(command is not ("Status" or "Connect" or "Prepare" or "Disconnect" or "Quit" or "AddDirectApplication" or "RemoveDirectApplication")){
                        var attached=await ControlPipe.Send("AttachClient",null,null,cancel);
                        if(!ServiceBootstrap.Current(attached,ClientVersion))throw new IOException("SERVICE_ATTACHMENT_NOT_VERIFIED");
                        _sessionAttached=true;_recoveryProvedDirect=false;
                        _backendIdle=false;if(!_closing)_timer.Start();
                    }
                    if(command is "Connect" or "Prepare" or "Disconnect" or "Quit"){
                        // The service verifies the live window's identity and version
                        // in the same transaction as the requested operation.
                        string attachedCommand=command switch{"Connect"=>"AttachConnect","Disconnect"=>"AttachDisconnect","Prepare"=>"AttachPrepare",_=>"AttachQuit"};
                        if(command is "Connect" or "Disconnect")_lastUiAttachMs=0;
                        var state=await Task.Run(()=>ControlPipe.Send(attachedCommand,null,null,cancel),cancel);
                        if(!ServiceBootstrap.MatchesService(state,ClientVersion))throw new IOException("SERVICE_ATTACHMENT_NOT_VERIFIED");
                        if(command!="Quit"){
                            _sessionAttached=true;_recoveryProvedDirect=false;_backendIdle=false;
                            if(!_closing)_timer.Start();
                        }
                        return state;
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
        if(_recovering || _provisioning || _closing || IsDisposed)return;
        _recovering=true;CancelRequests();_needsReconcile=true;RefreshActions();_emergencyRecovery.Enabled=false;
        string result="恢复结果尚未确认，请查看连接诊断。";
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);deadline.CancelAfter(TimeSpan.FromMinutes(2));
        try{
            try{
                _loginFeedback.Text=_detail.Text="正在等待管理员授权及本机恢复，请稍候…";
                int code=await _recover(deadline.Token);
                _recoveryProvedDirect=code==0;
                result=code==4?"已取消管理员授权，正在重新读取服务状态。":code==0?"恢复程序已完成，正在核对直连状态。":"恢复未完成，正在重新读取服务诊断；保护状态以服务确认为准。";
            }catch(OperationCanceledException){result="恢复等待已结束，后台恢复可能仍在执行；请先查看诊断，不要重复提交。";}
            catch(Exception error){result=StartupFailure(error);}
            if(IsDisposed)return;
            _backendIdle=false;
            if(_realService){
                using var verify=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);verify.CancelAfter(TimeSpan.FromSeconds(12));
                try{
                    var current=await ControlPipe.Send("Status",null,null,verify.Token);
                    if(!ServiceBootstrap.Current(current,ClientVersion))throw new IOException("SERVICE_VERSION_NOT_VERIFIED");
                    await AttachReadyService(verify.Token);if(!IsDisposed)_timer.Start();
                }
                catch(Exception error){if(!IsDisposed){_serviceReady=false;_bootstrapRetry.Visible=true;result+="\r\n"+StartupFailure(error);RevealView(false);}}
            }else{_timer.Start();await Act("Status");}
            if(!IsDisposed)_loginFeedback.Text=_detail.Text=result;
        }finally{
            _recovering=false;if(!IsDisposed)RefreshActions();
        }
    }
    internal async Task<bool> QuitClient()
    {
        if(_closing || IsDisposed)return false;
        // An uninitialized window has never attached or admitted a network
        // command. Closing its UI does not alter/claim the prior network state.
        // Elevated maintenance is independent and must finish its transaction.
        if(_recovering){_detail.Text="正在恢复直连，请等待本次恢复结果后再关闭。";return false;}
        if(_realService && !_sessionAttached || _recoveryProvedDirect){
            _closing=true;_allowClose=true;_timer.Stop();Close();return true;
        }
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
            // A second authenticated window can own the existing connection.
            // This acknowledgment is issued only after this window detached.
            if(state["ok"]?.GetValue<bool>()==true && state["window_detached"]?.GetValue<bool>()==true
                && state["shutdown_after_response"]?.GetValue<bool>()!=true){
                _allowClose=true;Close();return true;
            }
            Display(state);
            if(state["ok"]?.GetValue<bool>()!=true || state["intent"]?.GetValue<bool>()!=false || state["core_pid"]?.GetValue<uint>()!=0
                || state["mode"]?.GetValue<string>()!="disconnected" || (_realService
                    ?state["adapter_parked"]?.GetValue<bool>()!=false:state["adapter_parked"]?.GetValue<bool>()==true)
                || state["guard"]?.GetValue<bool>()==true || state["tun_permitted"]?.GetValue<bool>()==true)throw new IOException("SAFE_EXIT_NOT_VERIFIED");
            if(_realService){
                if(state["shutdown_after_response"]?.GetValue<bool>()!=true)throw new IOException("SERVICE_SHUTDOWN_NOT_ACKNOWLEDGED");
                await ControlPipe.WaitStopped(deadline.Token);
            }
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
    internal async Task<JsonObject?> Act(string command,string? applicationPath=null)
    {
        bool passive=command=="Status",login=command is "Login" or "LoginRemembered";
        if(_closing || IsDisposed || _recovering && !passive)return null;
        if(passive && _backendIdle)return null;
        if(passive)_statusReadSucceeded=false;
        if(!passive && (!_serviceReady || _provisioning || _busy || _needsReconcile || _uuMaintaining))return null;
        JsonObject? response=null;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token,_requestEpoch.Token);deadline.CancelAfter(passive?_statusTimeout:login?_loginTimeout:_requestTimeout);
        bool acquired=false,sentMutation=false,awaitingResponse=true;
        bool toggle=command is "Connect" or "Disconnect";var operationTimer=System.Diagnostics.Stopwatch.StartNew();
        using var focusScroll=toggle?_viewport.HoldFocusScroll():null;
        if(toggle){_lastUiCommand=command;_lastUiQueueMs=_lastUiAttachMs=_lastUiResponseMs=_lastUiCompleteMs=null;}
        if(!passive){
            _busy=true;
            if(login)_loginFeedback.Text="正在验证账号并登记设备…";
            void ShowPendingFeedback()
            {
                if(toggle){
                    _mode.Text=command=="Connect"?"正在连接…":"正在断开…";
                    _detail.Text=command=="Connect"?"正在启用加密连接并核验出口。":"正在停止隧道并核验直连恢复。";
                }
                RefreshActions();
            }
            // Start the requested service transition before the pending-status
            // layout. Both final labels are populated from the audited response.
            if(toggle && IsHandleCreated)BeginInvoke((Action)(()=>{
                if(!IsDisposed && !_closing && awaitingResponse)ShowPendingFeedback();
            }));
            else ShowPendingFeedback();
        }
        try{
            if(passive){if(!_requests.Wait(0))return null;acquired=true;}
            else{await _requests.WaitAsync(deadline.Token);acquired=true;}
            if(toggle)_lastUiQueueMs=operationTimer.ElapsedMilliseconds;
            // Ordinary Connect preserves the service's adaptive port plan.
            // A diagnostic pin is set only by its explicit diagnostic button.
            if(login && _connectionIntent){
                sentMutation=true;var off=await SendRequest("Disconnect",null,null,deadline.Token);Display(off);
                if(off["ok"]?.GetValue<bool>()!=true || off["intent"]?.GetValue<bool>()!=false)throw new IOException("SAFE_OFF_NOT_VERIFIED");
            }
            string? argument=command switch{"Login" or "LoginRemembered"=>_username.Text,"ConfirmDevice"=>_deviceName.Text,"DeleteDevice"=>_deleteDeviceId,_=>applicationPath};
            sentMutation=!passive;var state=await SendRequest(command,argument,login?_password.Text:command=="ConfirmDevice" && _deviceConfirmation.Checked?"confirmed":null,deadline.Token);
            awaitingResponse=false;
            if(toggle)_lastUiResponseMs=operationTimer.ElapsedMilliseconds;
            if(login)_password.Clear();
            if(passive && state["ok"]?.GetValue<bool>()==true){_needsReconcile=false;_statusReadSucceeded=true;}
            Display(state);
            response=state;
            if(state["shutdown_after_response"]?.GetValue<bool>()==true && state["ok"]?.GetValue<bool>()==true){
                _backendIdle=true;_timer.Stop();
                // Keep the window responsive but do not admit a reconnect into
                // the previous service's acknowledged shutdown transition.
                if(_realService){try{await ControlPipe.WaitStopped(deadline.Token);}catch{_backendIdle=false;if(!_closing)_timer.Start();throw;}}
            }
            if(command=="Logout" && state["ok"]?.GetValue<bool>()==true){_username.Clear();_password.Clear();_startupPrepared=false;}
            if(login && !_deviceRegistered && state["account"] is JsonObject)_deviceName.Focus();
        }catch(OperationCanceledException){
            if(sentMutation)_needsReconcile=true;
            if(!IsDisposed && !_closing){
                _mode.Text=_needsReconcile?"操作结果待确认":"系统服务响应超时";_mode.ForeColor=ClientAppearance.Warning;
                _detail.Text=_needsReconcile?"等待已结束，服务可能仍在处理。确认状态后才能继续操作；底部可使用“恢复直连（UAC）”。":"暂未读到系统服务状态，稍后会重试。现有连接与保护不会因此更改。";
                _loginFeedback.Text=_detail.Text;
            }
        }catch{
            if(sentMutation)_needsReconcile=true;
            if(!IsDisposed && !_closing){
                _maintenance.Visible=true;_maintenanceToggle.Text="收起系统维护";_mode.Text="系统服务暂不可用";_mode.ForeColor=ClientAppearance.Warning;_protocol.Text=_exitIp.Text=_latency.Text=_uu.Text="—";UpdateRates(new JsonObject(),false);_progress.Enabled=false;_usageUpdated.Text="用量更新暂不可用，显示上次读取值。";
                _detail.Text=_needsReconcile?"上次操作结果尚未确认。请等待状态刷新；必要时使用底部“恢复直连（UAC）”。":"无法读取系统服务。首次使用请安装服务；已安装时可查看连接诊断或使用底部恢复入口。";
                try{string path=Path.Combine(Platform.Root,"diagnostics.json");if(new FileInfo(path).Length<=4096){var d=JsonNode.Parse(File.ReadAllText(path));_detail.Text+=$" 诊断：{d?["stage"]} / {d?["code"]}。";}}catch{}
                _loginFeedback.Text=_detail.Text;
            }
        }
        finally{awaitingResponse=false;if(toggle)_lastUiCompleteMs=operationTimer.ElapsedMilliseconds;if(acquired)_requests.Release();if(!passive)_busy=false;if(!IsDisposed && !_closing)RefreshActions();}
        if(login || command is "ConfirmDevice" or "DeleteDevice")await StartReadyClient();
        return response;
    }
    private async Task MaintainUu(bool restore)
    {
        if(_uuMaintaining || _closing || _busy || _needsReconcile)return;
        if(DisconnectAction){_detail.Text="请先断开 VPN，再进行 UU 权限维护。";return;}
        _uuMaintaining=true;RefreshActions();
        try{
            int result=await Installer.ElevateUuPermissionsAsync(restore,_lifetime.Token);
            if(IsDisposed)return;
            if(result==0){
                _uuMaintaining=false;await Act("RefreshUu");
            }else _detail.Text=result==4?"已取消 UU 权限维护，未自动重试。":"UU 权限维护未完成，请查看维护窗口中的提示。";
        }catch(IOException error)when(error.Message=="UU_MAINTENANCE_RESULT_PENDING"){
            if(!IsDisposed)_detail.Text="UU 权限维护可能仍在进行，尚未确认结果。请等待维护窗口结束后重新识别；未自动重试。";
        }catch(OperationCanceledException){ }
        catch{if(!IsDisposed)_detail.Text="UU 权限维护未启动，请检查 UAC 提示。";}
        finally{_uuMaintaining=false;if(!IsDisposed)RefreshActions();}
    }
    private void ShowUuReport()=>ShowReport("UU 自动识别详情",_uuReport,async()=>{
        await Act("RefreshUu");
        if(!IsDisposed && !_closing)ShowUuReport();
    });
    private void ShowReport(string title,string report,Func<Task>? refresh=null)
    {
        using var dialog=new Form{Text=title,StartPosition=FormStartPosition.CenterParent,ClientSize=new Size(760,400),MinimizeBox=false,MaximizeBox=false};
        var text=new TextBox{Name="diagnostic-report",Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Both,WordWrap=false,Dock=DockStyle.Fill,Text=report};
        var copy=new SmoothButton{Text="复制诊断（不含账号密码或密钥）",Dock=DockStyle.Bottom,Height=40};copy.Click+=(_,_)=>Clipboard.SetText(report);
        StyleButton(copy,true);dialog.Padding=new Padding(12);dialog.BackColor=Canvas;dialog.Controls.Add(new SmoothInputFrame(text){Dock=DockStyle.Fill});dialog.Controls.Add(copy);
        if(refresh is not null){
            var rescan=new SmoothButton{Text="重新识别 UU",Dock=DockStyle.Bottom,Height=40,
                Enabled=!DisconnectAction && !_busy && !_needsReconcile && !_udpDiagnosing && _serviceReady && !_uuMaintaining};
            StyleButton(rescan);
            rescan.Click+=(_,_)=>{dialog.DialogResult=DialogResult.Retry;};
            dialog.Controls.Add(rescan);
        }
        if(dialog.ShowDialog(this)==DialogResult.Retry && refresh is not null)
            BeginInvoke((Action)(async()=>await refresh()));
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
    private string LoginDiagnostics()
    {
        var report = new System.Text.StringBuilder(_startupReport);
        if (_diagnosticSnapshot is JsonObject state) {
            report.Append("\r\n登录状态：" + state["error"]);
            if (state["failure"] is JsonObject failure)
                foreach (string key in new[] { "stage", "category", "account_phase", "socket_error", "http_error", "http_status", "at" })
                    report.Append($"\r\n{key}: {failure[key]}");
        }
        return report.ToString();
    }

    private static string BuildConnectionReport(JsonObject? state)
    {
        if(state is null)return "尚未读取系统服务。";
        var report=new System.Text.StringBuilder("连接诊断（不含账号密码、令牌或密钥）\r\n");
            foreach(string key in new[]{"product_version","egress_probe_protocol","mode","error","intent","guard","transport","connection_stage","core_stage","carrier_stage","transport_address","transport_private_address","transport_port","ipv6_policy","verified_exit_ipv6","native_udp_8443_available","native_udp_adaptive","native_udp_port_preference","native_udp_selected_port","client_handshake_reply","core_pid","adapter_parked","tun_permitted","tun_route_mask","server_handshake_at","peer_rx_bytes","peer_tx_bytes","uu_verified_programs","uu_discovery_verified","uu_candidates","uu_rejected","quick_ready","preparing","verified_at","connect_switch_ms","click_to_ready_ms"})report.Append($"{key}: {state[key]}\r\n");

            if(state["native_udp_attempt"] is JsonObject native)foreach(string key in new[]{"transport_address","port_order","endpoint_port","preferred_port","selected_port","socket_binding","server_handshake_at_observed","started_at","started_without_tun","probe_result","probe_failures","core_age_ms","verified_after_start_ms","inner_mtu"})report.Append($"native_udp.{key}: {native[key]}\r\n");
            if(state["native_udp_attempt"]?["ports"] is JsonObject ports)foreach(string port in new[]{"51820","443","8443"})if(ports[port] is JsonObject counters)foreach(string key in new[]{"tx_initiations","rx_responses","rx_cookies","rx_invalid","rx_obsolete","read_errors","write_errors","last_read_error","last_write_error","rcvbuf_before","sndbuf_before","rcvbuf_after","sndbuf_after","socket_buffer_error"})report.Append($"native_udp.{port}.{key}: {counters[key]}\r\n");
            if(state["switch_timings"] is JsonObject timings)foreach(string key in new[]{"uu_discovery_ms","uu_signature_verifications","state_saved_ms","guard_installed_ms","protection_joined_ms","tun_active_ms","initial_probe_ms","complete_ms"})report.Append($"switch.{key}: {timings[key]}\r\n");
            if(state["core_start_timings"] is JsonObject coreTimings)foreach(string key in new[]{"bundle_ms","process_ms","private_probe_ready_ms","adapter_ready_ms","receipt_ms","adapter_create_ms","adapter_audit_ms","empty_audited"})report.Append($"core.{key}: {coreTimings[key]}\r\n");
            if(state["control_timings"] is JsonObject controlTimings)foreach(string key in new[]{"service_ready_ms","attested_pipe_ms","response_ms"})report.Append($"control.{key}: {controlTimings[key]}\r\n");
            if(state["disconnect_timings"] is JsonObject offTimings)foreach(string key in new[]{"core_stopped_ms","tunnel_audited_ms","state_saved_ms","complete_ms"})report.Append($"disconnect.{key}: {offTimings[key]}\r\n");
            if(state["failure"] is JsonObject failure)foreach(string key in new[]{"stage","category","account_phase","hresult","native_error","socket_error","http_error","http_status","core_stage","at"})report.Append($"failure.{key}: {failure[key]}\r\n");
        return report.ToString().Replace("ORACLE_EGRESS_","EGRESS_",StringComparison.Ordinal).Replace("ORACLE_","EGRESS_",StringComparison.Ordinal).Replace("oracle_egress_","egress_",StringComparison.Ordinal).Replace("oracle_","egress_",StringComparison.Ordinal);
    }
    internal string UuReport=>_uuReport;
    internal string ConnectionReport=>BuildConnectionReport(_diagnosticSnapshot)+"\r\nui_snapshot_age_seconds: "+(_snapshotAt==default?"unavailable":Math.Max(0,(long)(DateTimeOffset.UtcNow-_snapshotAt).TotalSeconds).ToString())+"\r\n"+CompatibilityDiagnostics.Read()+$"\r\nui_last_command: {_lastUiCommand}\r\nui_queue_ms: {_lastUiQueueMs}\r\nui_attach_ms: {_lastUiAttachMs}\r\nui_response_ms: {_lastUiResponseMs}\r\nui_complete_ms: {_lastUiCompleteMs}";
    internal int UsageProgress=>_progress.Value;
    internal bool UsageFresh=>_progress.Enabled;
    internal int PollInterval=>_timer.Interval;
    internal void Display(JsonObject state)
    {
        SuspendLayout();_shell.SuspendLayout();_loginGate.SuspendLayout();
        // Suspend the direct layout owners as well as their outer view. A
        // parent suspension alone does not batch its nested grid mutations.
        _connectionContent.SuspendLayout();_accountContent.SuspendLayout();_registrationGroup.SuspendLayout();
        try{DisplaySnapshot(state);}
        finally{
            _registrationGroup.ResumeLayout(true);_accountContent.ResumeLayout(true);_connectionContent.ResumeLayout(true);
            _loginGate.ResumeLayout(true);_shell.ResumeLayout(true);ResumeLayout(true);
        }
    }
    private void DisplaySnapshot(JsonObject state)
    {
            _snapshotAt=DateTimeOffset.UtcNow;_diagnosticSnapshot=(JsonObject)state.DeepClone();
            _connectionIntent=state["intent"]?.GetValue<bool>()==true;
            _native8443Available=state["native_udp_8443_available"]?.GetValue<bool>()==true;

            _renderingPort=true;try{
                int[] availablePorts=(state["native_udp_ports"] as JsonArray)?.Select(p=>p?.GetValue<int>()??0).Where(p=>p is 443 or 8443 or 51820).Distinct().ToArray()??[];
                string portSignature=string.Join(",",availablePorts);
                if(portSignature!=_portListSignature){_portListSignature=portSignature;_udpPortChoice.Items.Clear();_udpPortChoice.Items.Add(new UdpPortChoice(0,"优选可用端口"));foreach(int p in new[]{443,8443,51820}.Where(availablePorts.Contains))_udpPortChoice.Items.Add(new UdpPortChoice(p,p.ToString()));}
                int preferred=state["native_udp_port_preference"]?.GetValue<int>()??0;
                _udpPortChoice.SelectedIndex=Math.Max(0,_udpPortChoice.Items.Cast<UdpPortChoice>().ToList().FindIndex(p=>p.Port==preferred));
            }finally{_renderingPort=false;}
            _udpPortChoice.Enabled=!_connectionIntent && !_busy && !_udpDiagnosing;

            string entry=state["transport_address"]?.GetValue<string>()??"";
            string local=state["transport_private_address"]?.GetValue<string>()??"";
            int? ingressPort=state["transport_port"]?.GetValue<int>();
            string suffix=ingressPort is int ingressPortValue?":"+ingressPortValue:"";

            string productVersion=state["product_version"]?.GetValue<string>() ?? DeviceRegistration.Version;
            _version.Text="v"+productVersion.Split('+')[0];
            if(_help.GetToolTip(_version)!=productVersion)_help.SetToolTip(_version,productVersion);
            _uuReport="UU 自动发现与信任核验（只读）\r\n服务版本："+(state["product_version"]?.GetValue<string>() ?? "未知")+
                $"\r\n候选：{state["uu_candidates"]} · 本次通过：{state["uu_discovery_verified"] ?? state["uu_verified_programs"]} · 拒绝：{state["uu_rejected"]}\r\n";
            int uuVerified=state["uu_discovery_verified"]?.GetValue<int>() ?? state["uu_verified_programs"]?.GetValue<int>() ?? 0;
            bool uuDetected=state["uu_candidates"]?.GetValue<int>()>0;
            bool uuNeedsTunnel=uuDetected && uuVerified==0;
            if(uuNeedsTunnel)
                _uuReport+="\r\n未自动验证的 UU 程序默认走 VPN。断开后可修复权限，或在“应用直连”添加 UU 的 EXE。";
            if(state["uu_diagnostics"] is JsonArray uuIssues && uuIssues.Count>0){
                foreach(var item in uuIssues)_uuReport+=$"\r\n{UuReason(item!["code"]!.GetValue<string>())}\r\n{item["code"]} {item["detail"]}\r\n{item["path"]}\r\n";
            }else _uuReport+="\r\n暂无拒绝详情；请在断开状态点击“重新识别 UU”。";
            string mode=state["mode"]?.GetValue<string>() ?? "unknown";bool guard=state["guard"]?.GetValue<bool>()==true;
            // A parked empty adapter is compatible with direct access. A live
            // connection intent, guard or tunnel permission still calls for recovery.
            if(mode=="disconnected" && (_connectionIntent || guard || state["tun_permitted"]?.GetValue<bool>()==true))mode="recovery";
            _lastMode=mode;
            DisplayUdpDiagnostics(state);
            _timer.Interval=_udpDiagnosing?1000:mode is "protected" or "connecting"?100:(state["preparing"]?.GetValue<bool>()==true && state["quick_ready"]?.GetValue<bool>()!=true)?250:mode=="connected"?1000:3000;
            _mode.Text=mode switch{"connected"=>guard?"已连接 · UDP":"连接保护未验证","connecting"=>"正在连接","protected"=>guard?"已保护 · 等待连接":"保护尚未验证","disconnected"=>"已断开 · 当前直连","recovery"=>"需要恢复处理",_=>"状态未知"};
            _mode.ForeColor=mode=="connected"?ClientAppearance.Positive:mode=="disconnected"?Ink:ClientAppearance.Warning;
            string policy=state["account"]?["status"]?.GetValue<string>() ?? "";
            string detail=state["error"]?.GetValue<string>() is string error && error.Length>0?Message(error):guard?(policy is "disabled" or "expired" or "quota" or "server_budget" or "unavailable"?$"账号状态：{PolicyName(policy)}。防泄漏保护保留。":"连接受保护；中断时保持阻断，防止流量绕过 VPN。"):
                LoginAdmission.DashboardReady(state)?"当前为直连。点击“连接”启动 VPN。":"请使用管理员提供的账号和密码登录。";
            if(state["error"]?.GetValue<string>()=="UU_TRUST_NOT_VERIFIED"){
                _maintenance.Visible=true;_maintenanceToggle.Text="收起系统维护";
                var writable=(state["uu_diagnostics"] as JsonArray)?.FirstOrDefault(item=>item?["code"]?.GetValue<string>() is "UU_DIRECTORY_WRITABLE" or "UU_EXECUTABLE_WRITABLE");
                detail=writable is not null?"UU 安装目录允许普通用户修改。请展开系统维护，选择“修复 UU 权限”；完整路径见 UU 检查详情。":"UU 信任核验未通过，请查看 UU 检查详情。目录权限问题可使用“修复 UU 权限”。";
            }
            if(mode=="disconnected" && (state["adapter_parked"]?.GetValue<bool>()==true || state["quick_ready"]?.GetValue<bool>()==true))detail="当前为直连。点击“连接”后将验证代理出口。";
            else if(mode=="disconnected" && state["preparing"]?.GetValue<bool>()==true)detail="正在准备连接，当前仍为直连。首次连接或网络变化可能需要等待。";
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
                long remaining=account["remaining_bytes"]?.GetValue<long>() ?? (limit is long cap?cap-used:0);
                _accountName.Text=$"{account["username"]}  ·  {(policy=="active"?"账号可用":PolicyName(policy))}";
                _usage.Text=$"本周期已用 {FormatBytes(used)} / {(limit is null?"不限量":FormatBytes(limit.Value))}"+(limit is null?"":$"\n剩余 {FormatBytes(Math.Max(0,remaining))}");
                _progress.Value=limit is >0?(int)Math.Clamp((double)used/limit.Value*1000,0,1000):limit==0?1000:0;
                long? expires=account["expires_at"]?.GetValue<long>();
                _expiry.Text=$"账号到期  {(expires is null?"长期":LocalDateTime(expires.Value))}";
                var cycle=account["cycle"] as JsonObject;
                long? start=cycle?["start_at"]?.GetValue<long>(),end=cycle?["end_at"]?.GetValue<long>();
                _cycle.Text=start is long from && end is long to && from<to?$"周期（本地时间）  {LocalDateTime(from)} 至 {LocalDateTime(to)}":"周期时间待同步";
            }else{_accountName.Text="尚未登录";_usage.Text="登录后显示用量与限额";_progress.Value=0;_cycle.Text="";_expiry.Text="";}
            long? latency=state["latency_ms"]?.GetValue<long>();long? at=state["observed_at"]?.GetValue<long>();
            bool fresh=at is long received && DateTimeOffset.UtcNow.ToUnixTimeSeconds()-received<=20;_progress.Enabled=fresh;
            if(!fresh && account is not null)detail+=" 用量未刷新，显示的是上次读取值。";
            // Set the final text once: intermediate short text used to resize
            // every AutoSize row twice on every 250 ms preparation poll.
            
            UpdateRegistration(state);
            if(account is not null && !_deviceRegistered && mode=="disconnected"){
                _mode.Text="已登录 · 请确认本机设备";
                detail="请先登记本机，再连接 VPN。";
            }
            if(_detail.Text!=detail)_detail.Text=detail;if(_help.GetToolTip(_detail)!=detail)_help.SetToolTip(_detail,detail);
            string protocolText=mode=="connected"?"WireGuard / UDP":"—";
            string exit4=state["verified_exit_ip"]?.GetValue<string>() ?? "待验证",exit6=state["verified_exit_ipv6"]?.GetValue<string>() ?? "";
            _exitIp.Text=mode=="connected"?exit4+(exit6.Length>0?"\n"+exit6:""):"—";
            string exitHelp=mode=="connected"?"IPv4："+exit4+(exit6.Length>0?"\nIPv6："+exit6:""):"连接验证通过后显示出口。";
            if(_help.GetToolTip(_exitIp)!=exitHelp)_help.SetToolTip(_exitIp,exitHelp);
            if(mode=="connected" && state["transport"]?.GetValue<string>()=="wireguard-udp" && state["native_udp_selected_port"] is JsonValue selectedPort && selectedPort.TryGetValue<int>(out int selectedUdpPort))protocolText+=" · "+selectedUdpPort;
            string entryText=entry.Length>0?$"公网 {entry}{suffix}\n内网 {(local.Length>0?local+suffix:"—")}":"—";
            if(_protocol.Tag is Label protocolCaption)protocolCaption.Text=mode=="connected"?protocolText:"连接入口";
            if(_protocol.Text!=entryText)_protocol.Text=entryText;
            string protocolHelp=protocolText+"\n"+entryText;
            if(_help.GetToolTip(_protocol)!=protocolHelp)_help.SetToolTip(_protocol,protocolHelp);
            _latency.Text=mode=="connected" && latency is not null?$"{latency} ms":"—";
            _uu.Text=state["error"]?.GetValue<string>()=="UU_TRUST_NOT_VERIFIED"
                ?"信任核验未通过"
                :uuNeedsTunnel?"已识别 · 走 VPN":uuVerified>0?$"{uuVerified} 个程序已验证":state["uu_candidates"] is null?"待识别":"未发现 UU";
            string uuHelp=uuNeedsTunnel?"UU 暂无直连权限。连接后使用 VPN，可在断开时修复权限。":"仅通过信任核验的 UU 程序可以直连。";
            if(_help.GetToolTip(_uu)!=uuHelp)_help.SetToolTip(_uu,uuHelp);
            UpdateRates(state,mode=="connected" && guard);
            _telemetry.Text=mode=="connected"?(state["verified_exit_ipv6"] is not null?"双栈出口已验证 · ":"")+"防泄漏保护已启用":"连接通过验证后显示协议、出口与实时速率。";
            bool estimated=account?["cycle"]?["usage_estimated"]?.GetValue<bool>()==true;
            _usageUpdated.Text=$"用量同步  {(at is null?"—":DateTimeOffset.FromUnixTimeSeconds(at.Value).ToLocalTime().ToString("HH:mm:ss"))}  ·  {(fresh?(estimated?"服务器估算":"服务器统计"):"等待刷新")}";
            // A valid remembered token can precede the background account
            // refresh after service restart. This is not a signed-out state.
            bool restoring=state["login_authenticated"]?.GetValue<bool>()==true && account is null;
            _startupGate.Controls[0].Text=restoring?"正在恢复已保存的登录…":"正在准备安全连接…";
            bool awaitingFirstRefresh=restoring && string.IsNullOrEmpty(state["error"]?.GetValue<string>());
            // Poll local IPC promptly while the first authenticated account
            // response is pending. Retain the slower recovery poll on failure.
            if(restoring)_timer.Interval=awaitingFirstRefresh?100:1000;
            UpdateUdpAction();
            RevealView(awaitingFirstRefresh?null:_authenticated);

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
        _registerDevice.Enabled=ActionsAvailable && !_connectionIntent && _canRegister && _deviceConfirmation.Checked && _deviceName.Text.Trim().Length is >0 and <=80 && !_deviceName.Text.Any(char.IsControl);
    }
    private void UpdateRegistration(JsonObject state){
        var account=state["account"] as JsonObject;var registration=state["registration"] as JsonObject;
        _deviceRegistered=state["device_registered"]?.GetValue<bool>()==true && registration?["status"]?.GetValue<string>()=="registered";
        string id=registration?["device_id"]?.GetValue<string>() ?? "";
        string identity=(account?["username"]?.GetValue<string>() ?? "")+"|"+id;
        string name=registration?["device_name"]?.GetValue<string>() ?? Environment.MachineName;
        if(identity!=_deviceIdentity){_startupPrepared=false;_deviceIdentity=identity;_deviceName.Text=name;_deviceConfirmation.Checked=false;}
        long at=state["observed_at"]?.GetValue<long>() ?? 0;bool fresh=at>0 && Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-at)<=20;
        bool active=account?["status"]?.GetValue<string>()=="active" && fresh;
        bool requiresSlot=registration?["requires_slot"]?.GetValue<bool>()!=false;
        int count=account?["device_count"]?.GetValue<int>() ?? 0,limit=account?["device_limit"]?.GetValue<int>() ?? 0;
        bool pending=account is not null && !_deviceRegistered && registration is not null;
        bool full=requiresSlot && count>=limit;
        bool showRegistration=pending && !full;
        bool showAdmission=pending && full;
        if(_registrationShown!=showRegistration){_registrationShown=showRegistration;_registrationGroup.Visible=showRegistration;}
        if(_admissionShown!=showAdmission){_admissionShown=showAdmission;_admissionDevicesPanel.Visible=showAdmission;}
        string deviceInfo=$"本机已登记  ·  {name}  ·  {id}\n设备名额  {count} / {limit}";
        if(_deviceIdentityLabel.Text!=deviceInfo)_deviceIdentityLabel.Text=deviceInfo;
        _canConnect=_authenticated && _deviceRegistered && active;UpdateConnectionAction();
        _canRegister=showRegistration && active;
        _deviceConfirmation.Enabled=_canRegister && !_connectionIntent;
        string note=_connectionIntent?"请先断开，再登记本机。":!active?"账号不可用或状态待刷新，暂不能登记。":$"本机尚未登记  ·  {id}";
        if(_registrationNote.Text!=note)_registrationNote.Text=note;
        var rows=(state["devices"] as JsonArray)?.OfType<JsonObject>()
            .Where(device=>device["revoked"]?.GetValue<bool>()!=true)
            .Select(device=>new ListedDevice(device["id"]?.GetValue<string>()??"",device["name"]?.GetValue<string>()??"未命名",device["current"]?.GetValue<bool>()==true))
            .Where(device=>device.Id.Length==12 && device.Id.All(Uri.IsHexDigit)).ToArray()??[];
        if(_deviceRows is null || !_deviceRows.SequenceEqual(rows)){
            _deviceRows=rows;
            SyncDevices(_knownDevices,rows);
            SyncDevices(_admissionDevices,rows.Where(device=>!device.Current));
        }
        UpdateRegistrationActions();
    }
    private static void SyncDevices(ListBox list,IEnumerable<ListedDevice> rows){
        string? selected=(list.SelectedItem as ListedDevice)?.Id;
        list.BeginUpdate();
        try{
            list.Items.Clear();
            foreach(var device in rows){
                int index=list.Items.Add(device);
                if(device.Id==selected)list.SelectedIndex=index;
            }
            if(list.Items.Count==0)list.Items.Add("尚无已登记设备。");
        }finally{list.EndUpdate();}
    }
    private static string FormatRate(double bytes)=>$"{bytes/1_000_000:0.000} MB/s";
    private static string LocalDateTime(long seconds)=>DateTimeOffset.FromUnixTimeSeconds(seconds).ToLocalTime().ToString("yyyy-MM-dd HH:mm");
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

        "DISCONNECT_BEFORE_TRANSPORT_CHANGE"=>"请先断开，再选择 UDP 端口。",
        "INVALID_CREDENTIALS"=>"账号或密码错误。", "DEVICE_LIMIT_REACHED"=>"设备名额已满，请在下方删除旧设备后登记本机。", "RATE_LIMITED"=>"登录尝试过于频繁，请稍后重试。",
        "UU_TRUST_NOT_VERIFIED"=>"UU 信任核验未通过，请查看“UU 检查详情”；目录权限问题可使用“修复 UU 权限”。",
        "SERVICE_OPERATION_FAILED"=>"连接未完成，请点击“连接诊断”查看失败阶段和错误码。",
        "CORE_READY_TIMEOUT"=>"隧道核心启动超时，保护保持启用。请复制“连接诊断”。",
        "ORACLE_PROBE_TIMEOUT"=>"出口验证超时，保护保持启用。请复制“连接诊断”。",
        "ORACLE_PROBE_HTTP_FAILED"=>"出口请求失败，保护保持启用。请复制“连接诊断”。",
        "UU_MAINTENANCE_BUSY"=>"UU 权限维护进行中，请完成后再连接。",
        "UU_REPAIR_DISCONNECT_REQUIRED"=>"请在 VPN 安全断开、网络诊断结束后重试 UU 维护。",
        "DIRECT_APPS_DISCONNECT_REQUIRED"=>"请在本机 VPN 断开、网络诊断结束后编辑应用直连名单。",
        "DIRECT_APP_LOCAL_EXE_REQUIRED"=>"请选择本机固定磁盘上的 EXE 文件。链接和区分大小写的目录无法使用。",
        "DIRECT_APP_FILE_UNAVAILABLE"=>"无法读取或锁定所选 EXE。请确认文件仍在原处，且更新程序已结束。",
        "DIRECT_APPS_LIMIT_REACHED"=>$"已达到 {DirectApplicationLease.Limit} 个应用的上限，请先移除一项。",
        "TUN_ROUTE_NOT_ACTIVE"=>"Windows 尚未将普通应用流量送入 VPN，连接未生效。请查看连接诊断；防泄漏保护保持开启。",
        "ACCOUNT_NOT_ACTIVE"=>"账号已停用、到期、超额，或服务器状态暂不可验证。", "RECOVERY_REQUIRED"=>"清理尚未通过验证，防泄漏保护保留。请使用本机恢复操作。",
        "STATE_MISSING_RECOVERY_REQUIRED"=>"加密状态文件缺失，已保留原防泄漏策略。请在本机使用恢复操作。",
        "LOGIN_SESSION_EXPIRED"=>"登录已过期，请重新登录。",
        "ACCOUNT_API_UNREACHABLE"=>"暂时无法连接账号服务。可重试登录，有效的已保存会话会自动重试。",
        "LOGIN_REQUIRED"=>"请先登录账号。", "DISCONNECT_BEFORE_LOGIN"=>"更换登录前请先断开。", _=>$"操作尚未完成：{code}。"};
}
