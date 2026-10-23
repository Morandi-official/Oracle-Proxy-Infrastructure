using System.ComponentModel;
using System.Net.Http;
using System.Net.Sockets;
using System.Text.Json.Nodes;

namespace OracleProxy.Product;
internal static class ConnectionFailure
{
    // Never serialize exception messages, URLs, headers, response bodies,
    // configurations or stack traces. Inner exceptions contribute enums only.
    internal static JsonObject Capture(string stage,Exception error,string coreStage)
    {
        string? socket=null,http=null;int? native=null,status=null;
        Exception? item=error;
        for(int depth=0;item is not null && depth<8;depth++,item=item.InnerException){
            if(item is SocketException network && Enum.IsDefined(network.SocketErrorCode))socket=network.SocketErrorCode.ToString();
            if(item is HttpRequestException request){if(Enum.IsDefined(request.HttpRequestError))http=request.HttpRequestError.ToString();if(request.StatusCode is { } code && (int)code is >=100 and <=599)status=(int)code;}
            if(item is Win32Exception windows && windows.NativeErrorCode is >=0 and <=65535)native=windows.NativeErrorCode;
        }
        return new(){["stage"]=stage,["category"]=error switch{TimeoutException=>"TIMEOUT",OperationCanceledException=>"CANCELLED",HttpRequestException=>"HTTP",SocketException=>"SOCKET",Win32Exception=>"WINDOWS",IOException=>"IO",UnauthorizedAccessException=>"ACCESS",_=>"OTHER"},
            ["hresult"]="0x"+unchecked((uint)error.HResult).ToString("X8"),["native_error"]=native,["socket_error"]=socket,["http_error"]=http,["http_status"]=status,["core_stage"]=coreStage,["at"]=DateTimeOffset.UtcNow.ToUnixTimeSeconds()};
    }
}
