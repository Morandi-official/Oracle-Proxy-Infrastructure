using System.Text;
namespace OracleProxy.Product;
// One bounded UTF-8 line per pipe connection. Read available chunks instead
// of issuing a kernel read for each byte in the full status/diagnostic object.
internal static class ControlFrame
{
    internal static async Task<string> Read(Stream stream,int maximum,CancellationToken token)
    {
        if(maximum<0 || maximum>65536)throw new ArgumentOutOfRangeException(nameof(maximum));
        byte[] data=new byte[maximum+1];int count=0;
        while(count<data.Length){
            int read=await stream.ReadAsync(data.AsMemory(count,Math.Min(4096,data.Length-count)),token).ConfigureAwait(false);
            if(read==0)throw new IOException("INCOMPLETE_FRAME");
            int newline=data.AsSpan(count,read).IndexOf((byte)10);
            if(newline>=0){
                if(newline!=read-1)throw new IOException("INVALID_FRAME");
                return new UTF8Encoding(false,true).GetString(data,0,count+newline);
            }
            count+=read;
        }
        throw new IOException("FRAME_TOO_LARGE");
    }
}
