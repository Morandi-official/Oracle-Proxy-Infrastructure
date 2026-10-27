using System.Text.Json.Nodes;
namespace OracleProxy.Product;

// A silent initial handshake may have lost both the first initiation and its
// five-second retry before the first HTTP timeout is visible. Allow just that
// cold UDP case one bounded retry window; verified links and other carriers
// retain their existing budgets. This never authorizes traffic or changes WFP.
internal static class CarrierFallbackPolicy
{
    internal static bool ShouldFallback(TunnelTransport transport,bool generationVerified,bool replyReceived,
        JsonObject? evidence,int probeFailures,long elapsedMs,bool probePending)
    {
        if(probeFailures<2 || elapsedMs<0)return false;
        bool cold=SilentColdRetry(transport,generationVerified,replyReceived,evidence);
        long budget=transport==TunnelTransport.WireGuardUdp?(cold?12000:8000):6000;
        // Only the silent cold retry has a hard deadline across a pending HTTP
        // request. A genuine WG reply keeps the existing progress-aware probe.
        return elapsedMs>=budget && (!probePending || cold);
    }

    internal static bool SilentColdRetry(TunnelTransport transport,bool generationVerified,bool replyReceived,JsonObject? evidence)
    {
        if(transport!=TunnelTransport.WireGuardUdp || generationVerified || replyReceived || evidence is null)return false;
        try{
            ulong sent=0;
            foreach(var port in evidence){
                if(port.Key is not ("51820" or "443" or "8443") || port.Value is not JsonObject counters)return false;
                foreach(var item in counters){
                    if(!Unsigned(item.Value,out ulong value))return false;
                    switch(item.Key){
                    case "tx_initiations":
                        if(value>1_000_000)return false;sent+=value;break;
                    case "read_errors":case "write_errors":case "last_read_error":case "last_write_error":case "socket_buffer_error":
                        if(value!=0)return false;break;
                    case "rx_responses":
                        if(value!=0)return false;break;
                    case "rx_cookies":case "rx_invalid":case "rx_obsolete":
                        if(value>1_000_000)return false;break;
                    case "rcvbuf_before":case "sndbuf_before":case "rcvbuf_after":case "sndbuf_after":
                        if(value>64*1024*1024)return false;break;
                    default:return false;
                    }
                }
            }
            return sent>=2;
        }catch(Exception error)when(error is ArgumentException or InvalidOperationException or System.Text.Json.JsonException){return false;}
    }
    private static bool Unsigned(JsonNode? node,out ulong value)
    {
        value=0;if(node is not JsonValue number)return false;
        if(number.TryGetValue<ulong>(out value))return true;
        if(number.TryGetValue<uint>(out uint unsigned)){value=unsigned;return true;}
        if(number.TryGetValue<long>(out long signed) && signed>=0){value=(ulong)signed;return true;}
        if(number.TryGetValue<int>(out int integer) && integer>=0){value=(ulong)integer;return true;}
        return false;
    }
}
