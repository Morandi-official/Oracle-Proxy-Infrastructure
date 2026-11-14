using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
namespace OracleProxy.Product;

// Static, cached GDI+ outlines: two tangent-matched cubics per corner. The
// curvature tapers to zero at the straight edges; no animation or bitmap cache.
internal sealed class SmoothOutline : IDisposable
{
    private GraphicsPath? _path;
    private (Size Size,int Dpi,float Inset,float Radius) _key;
    internal GraphicsPath Get(Size size,int dpi,float inset=0.75f,float radius=12)
    {
        var key=(size,dpi,inset,radius);
        if(_path is not null && _key==key)return _path;
        _path?.Dispose();_key=key;
        return _path=Create(new RectangleF(inset,inset,Math.Max(1,size.Width-2*inset),Math.Max(1,size.Height-2*inset)),radius*dpi/96f);
    }
    internal static GraphicsPath Create(RectangleF b,float radius)
    {
        var path=new GraphicsPath();float r=Math.Min(radius,Math.Min(b.Width,b.Height)/2),x=b.Left,y=b.Top,w=b.Width,h=b.Height;
        path.StartFigure();path.AddLine(x+r,y,x+w-r,y);
        path.AddBezier(x+w-r,y,x+w-.67f*r,y,x+w-.4f*r,y,x+w-.2f*r,y+.2f*r);
        path.AddBezier(x+w-.2f*r,y+.2f*r,x+w,y+.4f*r,x+w,y+.67f*r,x+w,y+r);
        path.AddLine(x+w,y+r,x+w,y+h-r);
        path.AddBezier(x+w,y+h-r,x+w,y+h-.67f*r,x+w,y+h-.4f*r,x+w-.2f*r,y+h-.2f*r);
        path.AddBezier(x+w-.2f*r,y+h-.2f*r,x+w-.4f*r,y+h,x+w-.67f*r,y+h,x+w-r,y+h);
        path.AddLine(x+w-r,y+h,x+r,y+h);
        path.AddBezier(x+r,y+h,x+.67f*r,y+h,x+.4f*r,y+h,x+.2f*r,y+h-.2f*r);
        path.AddBezier(x+.2f*r,y+h-.2f*r,x,y+h-.4f*r,x,y+h-.67f*r,x,y+h-r);
        path.AddLine(x,y+h-r,x,y+r);
        path.AddBezier(x,y+r,x,y+.67f*r,x,y+.4f*r,x+.2f*r,y+.2f*r);
        path.AddBezier(x+.2f*r,y+.2f*r,x+.4f*r,y,x+.67f*r,y,x+r,y);path.CloseFigure();return path;
    }
    public void Dispose(){_path?.Dispose();_path=null;}
}

internal sealed class SmoothButton : Button
{
    private readonly SmoothOutline _outline=new(),_focus=new();
    private bool _hover,_pressed;
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    internal bool Primary {get;set;}
    internal SmoothButton(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw,true);}
    protected override void OnMouseEnter(EventArgs e){_hover=true;base.OnMouseEnter(e);Invalidate();}
    protected override void OnMouseLeave(EventArgs e){_hover=false;_pressed=false;base.OnMouseLeave(e);Invalidate();}
    protected override void OnMouseDown(MouseEventArgs e){_pressed=e.Button==MouseButtons.Left;base.OnMouseDown(e);Invalidate();}
    protected override void OnMouseUp(MouseEventArgs e){_pressed=false;base.OnMouseUp(e);Invalidate();}
    protected override void OnKeyDown(KeyEventArgs e){if(e.KeyCode==Keys.Space)_pressed=true;base.OnKeyDown(e);Invalidate();}
    protected override void OnKeyUp(KeyEventArgs e){_pressed=false;base.OnKeyUp(e);Invalidate();}
    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(Parent?.BackColor??SystemColors.Control);e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
        Color fill=!Enabled?Color.FromArgb(224,231,237):_pressed?FlatAppearance.MouseDownBackColor:_hover?FlatAppearance.MouseOverBackColor:BackColor;
        using(var brush=new SolidBrush(fill))e.Graphics.FillPath(brush,_outline.Get(Size,DeviceDpi));
        using(var pen=new Pen(Primary&&Enabled?fill:Color.FromArgb(181,198,213)))e.Graphics.DrawPath(pen,_outline.Get(Size,DeviceDpi));
        if(Focused&&ShowFocusCues){using var pen=new Pen(Color.FromArgb(53,86,119),1.5f);e.Graphics.DrawPath(pen,_focus.Get(Size,DeviceDpi,3,8));}
        TextRenderer.DrawText(e.Graphics,Text,Font,Rectangle.Inflate(ClientRectangle,-8,-3),Enabled?ForeColor:Color.FromArgb(108,122,136),TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis|TextFormatFlags.SingleLine);
    }
    protected override void Dispose(bool disposing){if(disposing){_outline.Dispose();_focus.Dispose();}base.Dispose(disposing);}
}

// Keep native text editing, password masking, IME, selection and accessibility.
internal sealed class SmoothInputFrame : Panel
{
    private readonly SmoothOutline _outline=new();
    private readonly Control _input;
    internal SmoothInputFrame(Control input)
    {
        _input=input;Name=input.Name+"-frame";Margin=input.Margin;Height=input.Height+16;MinimumSize=new Size(0,36);BackColor=Color.White;
        SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw,true);
        if(input is TextBox text)text.BorderStyle=BorderStyle.None;
        if(input is ListBox list)list.BorderStyle=BorderStyle.None;
        input.Dock=DockStyle.None;input.Margin=Padding.Empty;Controls.Add(input);
        input.Enter+=(_,_)=>Invalidate();input.Leave+=(_,_)=>Invalidate();input.EnabledChanged+=(_,_)=>Invalidate();
        Click+=(_,_)=>input.Focus();
    }
    protected override void OnLayout(LayoutEventArgs e){base.OnLayout(e);int pad=10*DeviceDpi/96;int height=_input is TextBox text&&!text.Multiline?text.PreferredHeight:Math.Max(1,ClientSize.Height-2*pad/2);_input.SetBounds(pad,Math.Max(4,(ClientSize.Height-height)/2),Math.Max(1,ClientSize.Width-2*pad),height);}
    protected override void OnPaintBackground(PaintEventArgs e)=>e.Graphics.Clear(Parent?.BackColor??SystemColors.Control);
    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;using var brush=new SolidBrush(_input.BackColor);e.Graphics.FillPath(brush,_outline.Get(Size,DeviceDpi));
        using var pen=new Pen(ContainsFocus?Color.FromArgb(86,116,145):Color.FromArgb(194,209,222),ContainsFocus?1.5f:1f);e.Graphics.DrawPath(pen,_outline.Get(Size,DeviceDpi));
    }
    protected override void Dispose(bool disposing){if(disposing)_outline.Dispose();base.Dispose(disposing);}
}

internal sealed class SmoothCheckBox : CheckBox
{
    internal SmoothCheckBox(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer,true);}
    public override Size GetPreferredSize(Size proposedSize){var size=base.GetPreferredSize(proposedSize);return new Size(size.Width+8*DeviceDpi/96,size.Height+2*DeviceDpi/96);}
    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(Parent?.BackColor??BackColor);e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
        float side=17*DeviceDpi/96f;var box=new RectangleF(1,(Height-side)/2,side,side);using var path=SmoothOutline.Create(box,5*DeviceDpi/96f);
        using(var brush=new SolidBrush(Checked?Color.FromArgb(86,116,145):Color.White))e.Graphics.FillPath(brush,path);
        using(var pen=new Pen(Focused&&ShowFocusCues?Color.FromArgb(53,86,119):Color.FromArgb(159,180,199),1.4f))e.Graphics.DrawPath(pen,path);
        if(Checked){using var pen=new Pen(Color.White,2*DeviceDpi/96f){StartCap=LineCap.Round,EndCap=LineCap.Round,LineJoin=LineJoin.Round};e.Graphics.DrawLines(pen,[new PointF(box.X+side*.23f,box.Y+side*.52f),new PointF(box.X+side*.44f,box.Y+side*.72f),new PointF(box.X+side*.8f,box.Y+side*.3f)]);}
        TextRenderer.DrawText(e.Graphics,Text,Font,new Rectangle((int)side+8,0,Math.Max(1,Width-(int)side-8),Height),Enabled?ForeColor:SystemColors.GrayText,TextFormatFlags.Left|TextFormatFlags.VerticalCenter|TextFormatFlags.WordBreak);
    }
}

internal sealed class SmoothProgressBar : Control
{
    private readonly SmoothOutline _outline=new();private int _maximum=1000,_minimum,_value;
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    internal int Minimum{get=>_minimum;set{_minimum=value;Invalidate();}}
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    internal int Maximum{get=>_maximum;set{_maximum=value;Invalidate();}}
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    internal int Value{get=>_value;set{int v=Math.Clamp(value,_minimum,_maximum);if(v!=_value){_value=v;Invalidate();}}}
    internal SmoothProgressBar(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw,true);AccessibleRole=AccessibleRole.ProgressBar;TabStop=false;}
    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(Parent?.BackColor??BackColor);e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;var shape=_outline.Get(Size,DeviceDpi,0.75f,6);
        using(var brush=new SolidBrush(Color.FromArgb(221,231,240)))e.Graphics.FillPath(brush,shape);
        float width=(Width-2)*(_value-_minimum)/(float)Math.Max(1,_maximum-_minimum);
        if(width>0){var saved=e.Graphics.Save();e.Graphics.SetClip(shape);using var brush=new SolidBrush(Enabled?Color.FromArgb(86,116,145):Color.FromArgb(151,169,185));e.Graphics.FillRectangle(brush,1,1,width,Height-2);e.Graphics.Restore(saved);}
    }
    protected override AccessibleObject CreateAccessibilityInstance()=>new ProgressAccessible(this);
    private sealed class ProgressAccessible(SmoothProgressBar owner) : ControlAccessibleObject(owner)
    {
        public override string? Value {get=>$"{owner.Value} / {owner.Maximum}";set{}}
    }
    protected override void Dispose(bool disposing){if(disposing)_outline.Dispose();base.Dispose(disposing);}
}

// Native ComboBox behavior and popup, with a static rounded face and rounded
// popup clipping. No replacement focus/selection logic or render-loop timer.
internal sealed class SmoothComboBox : ComboBox
{
    private readonly SmoothOutline _outline=new();
    internal SmoothComboBox(){DrawMode=DrawMode.OwnerDrawFixed;FlatStyle=FlatStyle.Flat;}
    protected override void OnFontChanged(EventArgs e){base.OnFontChanged(e);ItemHeight=Math.Max(24,Font.Height+10);}
    protected override void OnDrawItem(DrawItemEventArgs e)
    {
        if(e.Index<0)return;
        e.DrawBackground();bool selected=(e.State&DrawItemState.Selected)!=0;
        e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;var b=Rectangle.Inflate(e.Bounds,-2,-1);using var path=SmoothOutline.Create(b,6*DeviceDpi/96f);
        using(var brush=new SolidBrush(selected?Color.FromArgb(221,231,240):Color.White))e.Graphics.FillPath(brush,path);
        TextRenderer.DrawText(e.Graphics,GetItemText(Items[e.Index]),Font,Rectangle.Inflate(b,-7,0),ForeColor,TextFormatFlags.VerticalCenter|TextFormatFlags.Left|TextFormatFlags.EndEllipsis);
    }
    protected override void OnDropDown(EventArgs e)
    {
        base.OnDropDown(e);var info=new ComboInfo{Size=Marshal.SizeOf<ComboInfo>()};
        if(GetComboBoxInfo(Handle,ref info)&&info.List!=IntPtr.Zero&&GetWindowRect(info.List,out var r)){
            using var shape=SmoothOutline.Create(new RectangleF(0,0,r.Right-r.Left,r.Bottom-r.Top),9*DeviceDpi/96f);
            using var graphics=Graphics.FromHwnd(info.List);var region=new Region(shape);try{var hrgn=region.GetHrgn(graphics);if(SetWindowRgn(info.List,hrgn,true)==0)DeleteObject(hrgn);}finally{region.Dispose();}
        }
    }
    private void PaintFace(Graphics g)
    {
        g.Clear(Parent?.BackColor??BackColor);g.SmoothingMode=SmoothingMode.AntiAlias;var shape=_outline.Get(Size,DeviceDpi);
        using(var brush=new SolidBrush(Enabled?Color.White:Color.FromArgb(233,238,243)))g.FillPath(brush,shape);
        using(var pen=new Pen(Focused?Color.FromArgb(86,116,145):Color.FromArgb(194,209,222),Focused?1.5f:1f))g.DrawPath(pen,shape);
        int arrow=25*DeviceDpi/96;TextRenderer.DrawText(g,Text,Font,new Rectangle(10*DeviceDpi/96,0,Math.Max(1,Width-arrow-12*DeviceDpi/96),Height),Enabled?ForeColor:SystemColors.GrayText,TextFormatFlags.VerticalCenter|TextFormatFlags.Left|TextFormatFlags.EndEllipsis|TextFormatFlags.SingleLine);
        float x=Width-arrow/2f,y=Height/2f;using var stroke=new Pen(Enabled?ForeColor:SystemColors.GrayText,1.6f*DeviceDpi/96){StartCap=LineCap.Round,EndCap=LineCap.Round,LineJoin=LineJoin.Round};g.DrawLines(stroke,[new PointF(x-4,y-2),new PointF(x,y+2),new PointF(x+4,y-2)]);
    }
    protected override void WndProc(ref Message m)
    {
        if(m.Msg==0x000F){var dc=BeginPaint(Handle,out var paint);try{if(dc!=IntPtr.Zero){using var g=Graphics.FromHdc(dc);PaintFace(g);}}finally{EndPaint(Handle,ref paint);}m.Result=IntPtr.Zero;return;}
        if(m.Msg==0x0318&&m.WParam!=IntPtr.Zero){using var g=Graphics.FromHdc(m.WParam);PaintFace(g);m.Result=IntPtr.Zero;return;}
        base.WndProc(ref m);
    }
    protected override void Dispose(bool disposing){if(disposing)_outline.Dispose();base.Dispose(disposing);}
    [StructLayout(LayoutKind.Sequential)]private struct NativeRect{public int Left,Top,Right,Bottom;}
    [StructLayout(LayoutKind.Sequential)]private struct ComboInfo{public int Size;public NativeRect ItemRect,ButtonRect;public int State;public IntPtr Combo,Item,List;}
    [StructLayout(LayoutKind.Sequential)]private struct PaintInfo{public IntPtr Dc;public int Erase;public NativeRect Rect;public int Restore,Update;public long R1,R2,R3,R4;}
    [DllImport("user32.dll")]private static extern bool GetComboBoxInfo(IntPtr hwnd,ref ComboInfo info);
    [DllImport("user32.dll")]private static extern bool GetWindowRect(IntPtr hwnd,out NativeRect rect);
    [DllImport("user32.dll")]private static extern int SetWindowRgn(IntPtr hwnd,IntPtr region,bool redraw);
    [DllImport("gdi32.dll")]private static extern bool DeleteObject(IntPtr obj);
    [DllImport("user32.dll")]private static extern IntPtr BeginPaint(IntPtr hwnd,out PaintInfo info);
    [DllImport("user32.dll")]private static extern bool EndPaint(IntPtr hwnd,ref PaintInfo info);
}

internal sealed class StableViewport : Panel
{
    private int _holds;
    internal IDisposable HoldFocusScroll(){_holds++;return new Hold(this);}
    protected override Point ScrollToControl(Control activeControl)=>_holds>0?DisplayRectangle.Location:base.ScrollToControl(activeControl);
    private sealed class Hold(StableViewport owner) : IDisposable
    {
        private StableViewport? _owner=owner;
        public void Dispose(){if(_owner is{} owner){_owner=null;owner._holds--;}}
    }
}
