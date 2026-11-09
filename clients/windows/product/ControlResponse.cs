namespace OracleProxy.Product;
// A committed safe Off remains committed if its caller closes the pipe before
// the final write completes. Transport failure cannot leave an idle backend.
internal static class ControlResponse
{
    internal static async Task Deliver(Func<Task> write,Action finalized)
    {
        try{await write().ConfigureAwait(false);}
        finally{finalized();}
    }
}
