using System.Drawing.Drawing2D;
namespace OracleProxy.Tailscale;

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

internal sealed class SmoothSurface : Panel
{
    private readonly SmoothOutline _outline = new();

    internal SmoothSurface() => SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
        ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        e.Graphics.Clear(Parent?.BackColor ?? SystemColors.Control);
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var path = _outline.Get(Size, DeviceDpi, radius: 18);
        using var brush = new SolidBrush(BackColor);
        using var pen = new Pen(Color.FromArgb(194, 209, 222));
        e.Graphics.FillPath(brush, path);
        e.Graphics.DrawPath(pen, path);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _outline.Dispose();
        base.Dispose(disposing);
    }
}
