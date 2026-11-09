namespace OracleProxy.Product;
// A single pending notification; timeout still drives lifetime/network checks.
internal sealed class RuntimeWake : IDisposable
{
    private readonly SemaphoreSlim _signal=new(0,1);
    internal void Pulse()
    {
        try{if(_signal.CurrentCount==0)_signal.Release();}
        catch(SemaphoreFullException){} // Concurrent completions coalesce.
        catch(ObjectDisposedException){} // A retired generation may finish late.
    }
    internal Task<bool> Wait(int milliseconds,CancellationToken cancel)=>_signal.WaitAsync(milliseconds,cancel);
    public void Dispose()=>_signal.Dispose();
}
