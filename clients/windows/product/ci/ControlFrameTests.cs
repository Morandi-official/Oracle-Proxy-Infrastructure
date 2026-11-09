using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using OracleProxy.Product;

internal static class ControlFrameTests
{
    private static async Task Expect(byte[] input,int maximum,string expected)
    {
        using var stream=new MemoryStream(input);
        try{await ControlFrame.Read(stream,maximum,CancellationToken.None);throw new Exception("BAD_FRAME_ACCEPTED");}
        catch(IOException error)when(error.Message==expected){}
    }
    private static async Task<long> Exchange(bool legacy,string payload)
    {
        string name="Proxy-frame-perf-"+Guid.NewGuid().ToString("N");
        using var server=new NamedPipeServerStream(name,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous);
        using var client=new NamedPipeClientStream(".",name,PipeDirection.InOut,PipeOptions.Asynchronous);
        using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await Task.WhenAll(server.WaitForConnectionAsync(deadline.Token),client.ConnectAsync(deadline.Token));
        async Task<string> OldRead(){byte[] buffer=new byte[65537];int count=0;while(count<buffer.Length){int n=await client.ReadAsync(buffer.AsMemory(count,1),deadline.Token);if(n==0)throw new IOException();if(buffer[count]==10)return new UTF8Encoding(false,true).GetString(buffer,0,count);count++;}throw new IOException();}
        var timer=Stopwatch.StartNew();
        Task<string> read=legacy?OldRead():ControlFrame.Read(client,65536,deadline.Token);
        await server.WriteAsync(Encoding.UTF8.GetBytes(payload+"\n"),deadline.Token);
        string actual=await read;
        if(actual!=payload)throw new Exception("FRAME_CONTENT_CHANGED");
        return timer.ElapsedMilliseconds;
    }
    private static async Task<int> Main()
    {
        foreach(bool fail in new[]{false,true}){
            int finalized=0;
            try{await ControlResponse.Deliver(()=>fail?Task.FromException(new IOException("DISCONNECTED_PIPE")):Task.CompletedTask,()=>finalized++);}
            catch(IOException error)when(fail && error.Message=="DISCONNECTED_PIPE"){}
            if(finalized!=1)throw new Exception("COMMITTED_OFF_MUST_FINALIZE_AFTER_REPLY_FAILURE");
        }
        Console.WriteLine("COMMITTED_OFF_FINALIZES_AFTER_REPLY_WRITE_OR_DISCONNECT=PASS");
        await Expect(Encoding.UTF8.GetBytes("abc"),32,"INCOMPLETE_FRAME");
        await Expect(Encoding.UTF8.GetBytes("abc\nsecond\n"),32,"INVALID_FRAME");
        await Expect(Encoding.UTF8.GetBytes("abcde\n"),4,"FRAME_TOO_LARGE");
        try{await ControlFrame.Read(new MemoryStream(new byte[]{255,10}),32,CancellationToken.None);throw new Exception("INVALID_UTF8_ACCEPTED");}
        catch(DecoderFallbackException){}
        using(var edge=new MemoryStream(Encoding.UTF8.GetBytes("abcd\n")))
            if(await ControlFrame.Read(edge,4,CancellationToken.None)!="abcd")throw new Exception("MAXIMUM_FRAME_REFUSED");
        using(var cancel=new CancellationTokenSource()){
            cancel.Cancel();try{await ControlFrame.Read(new MemoryStream(new byte[]{10}),32,cancel.Token);throw new Exception("CANCELLED_FRAME_READ");}catch(OperationCanceledException){}
        }
        foreach(int length in new[]{8192,49152}){
            string payload="状态"+new string('x',length-6);
            long old=await Exchange(true,payload),fast=await Exchange(false,payload);
            Console.WriteLine($"REAL_NAMED_PIPE_FRAME bytes={length} legacy_ms={old} chunked_ms={fast}");
            if(fast>=1000)throw new Exception("LOCAL_PIPE_FRAME_EXCEEDS_ONE_SECOND");
        }
        Console.WriteLine("BOUNDED_REAL_PIPE_UTF8_MAXIMUM_CANCELLATION_AND_SINGLE_FRAME=PASS");return 0;
    }
}
