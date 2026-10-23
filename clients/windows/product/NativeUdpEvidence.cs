using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
namespace OracleProxy.Product;
// Accept only the private core's fixed numeric/error event vocabulary. Never
// export raw stderr, endpoints, handshake contents, usernames or credentials.
internal sealed class NativeUdpEvidence
{
    private readonly object _gate=new();
    private readonly JsonObject _ports=new();
    private static readonly Regex Event=new(@"\ANATIVE_UDP_(51820|443)_(SEND_INIT|RECV_REPLY|RECV_COOKIE|RECV_INVALID|RECV_OBSOLETE|READ_ERROR_[0-9]{1,10}|WRITE_ERROR_[0-9]{1,10})\z",RegexOptions.CultureInvariant);
    internal void Clear(){lock(_gate)_ports.Clear();}
    internal bool Record(string? line)
    {
        if(line is null || line.Length>80)return false;
        var match=Event.Match(line);if(!match.Success)return false;
        string port=match.Groups[1].Value,kind=match.Groups[2].Value;
        uint? code=null;
        if(kind.StartsWith("READ_ERROR_",StringComparison.Ordinal) || kind.StartsWith("WRITE_ERROR_",StringComparison.Ordinal)){
            if(!uint.TryParse(kind[(kind.LastIndexOf('_')+1)..],out uint value))return false;code=value;
        }
        string field=kind switch{"SEND_INIT"=>"tx_initiations","RECV_REPLY"=>"rx_responses","RECV_COOKIE"=>"rx_cookies","RECV_INVALID"=>"rx_invalid","RECV_OBSOLETE"=>"rx_obsolete",_=>kind.StartsWith("READ_",StringComparison.Ordinal)?"read_errors":"write_errors"};
        lock(_gate){
            if(_ports[port] is not JsonObject counters){counters=new JsonObject();_ports[port]=counters;}
            counters[field]=Math.Min(1000000,(counters[field]?.GetValue<int>()??0)+1);
            if(code is not null)counters[field=="read_errors"?"last_read_error":"last_write_error"]=code.Value;
        }
        return true;
    }
    internal JsonObject Snapshot(){lock(_gate)return (JsonObject)_ports.DeepClone();}
}
