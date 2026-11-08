using System.Drawing.Imaging;
namespace OracleProxy.Product;
internal sealed partial class MainForm
{
    private sealed class ViewBlend : Control
    {
        private readonly Bitmap _before,_after;
        private readonly System.Windows.Forms.Timer _frames=new(){Interval=15};
        private readonly long _started=System.Diagnostics.Stopwatch.GetTimestamp();
        internal ViewBlend(Bitmap before,Bitmap after){_before=before;_after=after;Dock=DockStyle.Fill;DoubleBuffered=true;SetStyle(ControlStyles.AllPaintingInWmPaint|ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer,true);_frames.Tick+=(_,_)=>{if(System.Diagnostics.Stopwatch.GetElapsedTime(_started).TotalMilliseconds>=135){_frames.Stop();Dispose();}else Invalidate();};}
        internal void Start()=>_frames.Start();
        protected override void OnPaint(PaintEventArgs e){
            e.Graphics.DrawImage(_after,ClientRectangle);float alpha=(float)Math.Clamp(1-System.Diagnostics.Stopwatch.GetElapsedTime(_started).TotalMilliseconds/135,0,1);
            using var attributes=new ImageAttributes();attributes.SetColorMatrix(new ColorMatrix{Matrix33=alpha});
            e.Graphics.DrawImage(_before,ClientRectangle,0,0,_before.Width,_before.Height,GraphicsUnit.Pixel,attributes);
        }
        protected override void Dispose(bool disposing){if(disposing){_frames.Dispose();_before.Dispose();_after.Dispose();}base.Dispose(disposing);}
    }
    private ViewBlend? _viewBlend;
    private static Bitmap? ViewBitmap(Control control)
    {
        if(!control.Visible || control.Width<1 || control.Height<1)return null;
        var value=new Bitmap(control.Width,control.Height);
        try{control.DrawToBitmap(value,new Rectangle(Point.Empty,value.Size));return value;}catch(ArgumentException){value.Dispose();return null;}
    }
    private void BlendView(Bitmap? before,Control target)
    {
        if(before is null)return;
        var after=ViewBitmap(target);if(after is null){before.Dispose();return;}
        _viewBlend?.Dispose();_viewBlend=new ViewBlend(before,after);target.Parent!.Controls.Add(_viewBlend);_viewBlend.BringToFront();_viewBlend.Start();
    }
}
