namespace OracleProxy.Product;
internal static class ServiceThreads
{
    // Process redirected stdout/stderr use synchronous Windows FileStream
    // handles, whose ReadAsync occupies a worker. Reserve headroom for those
    // readers, blocking WFP work and the control/proof continuations even on
    // two-core machines. Never lower a larger runtime/user minimum, alter the
    // maximum, or retain a process when the product is switched Off.
    internal static void Prepare()
    {
        ThreadPool.GetMinThreads(out int workers,out int completion);
        if(workers<8)ThreadPool.SetMinThreads(8,completion);
    }
    internal static int Minimum {get{ThreadPool.GetMinThreads(out int workers,out _);return workers;}}
}
