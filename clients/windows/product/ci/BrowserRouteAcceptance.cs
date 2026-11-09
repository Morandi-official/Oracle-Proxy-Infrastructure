using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json.Nodes;
internal static class BrowserRouteAcceptance
{
    private static async Task<JsonObject> Cdp(ClientWebSocket ws,int id,string method,JsonObject args)
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(35));
        await ws.SendAsync(Encoding.UTF8.GetBytes(new JsonObject{["id"]=id,["method"]=method,["params"]=args}.ToJsonString()).AsMemory(),WebSocketMessageType.Text,true,timeout.Token);
        byte[] buffer=new byte[1024*1024];int count=0;
        while(true){var part=await ws.ReceiveAsync(buffer.AsMemory(count),timeout.Token);count+=part.Count;
            if(count==buffer.Length || part.MessageType==WebSocketMessageType.Close)throw new IOException("BROWSER_FRAME_INVALID");
            if(!part.EndOfMessage)continue;
            var value=JsonNode.Parse(buffer.AsSpan(0,count))!.AsObject();count=0;
            if(value["id"]?.GetValue<int>()!=id)continue;
            if(value["error"] is not null || value["result"]?["exceptionDetails"] is not null)throw new IOException("BROWSER_CDP_FAILED");
            return value["result"]!.AsObject();
        }
    }
    internal static async Task Run(HashSet<string> exits,string ipv6)
    {
        if(System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem)throw new IOException("BROWSER_MUST_BE_ORDINARY_USER");
        string edge=new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}.Select(p=>Path.Combine(p,"Microsoft","Edge","Application","msedge.exe")).First(File.Exists);
        string profile=Path.Combine(Path.GetTempPath(),"proxy-browser-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(profile);
        var start=new ProcessStartInfo(edge){UseShellExecute=false,CreateNoWindow=true};
        foreach(string arg in new[]{"--headless=new","--no-proxy-server","--disable-extensions","--no-first-run","--disable-background-networking","--disable-component-update","--remote-debugging-port=0","--user-data-dir="+profile,"about:blank"})start.ArgumentList.Add(arg);
        using var browser=Process.Start(start)??throw new IOException("BROWSER_START_FAILED");
        try{
            string portFile=Path.Combine(profile,"DevToolsActivePort");int port=0;
            for(int i=0;i<150;i++){try{if(File.Exists(portFile)&&int.TryParse(File.ReadLines(portFile).FirstOrDefault(),out port)&&port>1024)break;}catch(IOException){}await Task.Delay(100);}
            if(port<=1024)throw new IOException("BROWSER_DEBUG_NOT_READY");
            using var http=new HttpClient(new HttpClientHandler{UseProxy=false}){Timeout=TimeSpan.FromSeconds(5)};
            var pages=JsonNode.Parse(await http.GetStringAsync($"http://127.0.0.1:{port}/json/list"))!.AsArray();
            var uri=new Uri(pages.OfType<JsonObject>().First(x=>x["type"]?.GetValue<string>()=="page")["webSocketDebuggerUrl"]!.GetValue<string>());
            if(!uri.IsLoopback || uri.Port!=port)throw new IOException("BROWSER_DEBUG_IDENTITY_INVALID");
            using var ws=new ClientWebSocket();await ws.ConnectAsync(uri,CancellationToken.None);int id=1;
            foreach(string url in new[]{"https://www.ipcece.com/ip/","https://browserleaks.com/webrtc","https://vpn-admin.morandi.dpdns.org/privacy-check/"}){
                var nav=await Cdp(ws,id++,"Page.navigate",new(){["url"]=url});
                string error=nav["errorText"]?.GetValue<string>()??"";
                if(error.Length>0){Console.WriteLine("BROWSER_HOST="+new Uri(url).Host+" ERROR="+(error.StartsWith("net::ERR_")?error:"navigation_failed"));throw new IOException("BROWSER_NAVIGATION_FAILED");}
                bool ready=false;
                for(int n=0;n<80;n++){
                    var page=await Cdp(ws,id++,"Runtime.evaluate",new(){["expression"]="JSON.stringify({url:location.href,ready:document.readyState})",["returnByValue"]=true});
                    var state=JsonNode.Parse(page["result"]!["value"]!.GetValue<string>())!;
                    string actual=state["url"]!.GetValue<string>();
                    if(actual.StartsWith("chrome-error:") || actual.StartsWith("edge-error:"))throw new IOException("BROWSER_ERROR_DOCUMENT");
                    if(Uri.TryCreate(actual,UriKind.Absolute,out var actualUri)&&actualUri.Host==new Uri(url).Host&&state["ready"]?.GetValue<string>()=="complete"){ready=true;break;}
                    await Task.Delay(250);
                }
                if(!ready)throw new IOException("BROWSER_DOCUMENT_NOT_READY");
                Console.WriteLine("BROWSER_DOCUMENT_HOST="+new Uri(url).Host+" LOADED=PASS");
            }
            // Actual ICE gathering in ordinary Edge, no camera/microphone grant.
            var ice=await Cdp(ws,id++,"Runtime.evaluate",new(){["awaitPromise"]=true,["returnByValue"]=true,["expression"]="""
                new Promise(resolve=>{const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.cloudflare.com:3478'},{urls:'stun:stun.l.google.com:19302'}]});const ips=[];let done=false;function finish(){if(done)return;done=true;pc.close();resolve(ips);}pc.onicecandidate=e=>{if(!e.candidate){finish();return;}if(e.candidate.type==='srflx'&&e.candidate.address)ips.push(e.candidate.address);};pc.createDataChannel('probe');pc.createOffer().then(o=>pc.setLocalDescription(o)).catch(finish);setTimeout(finish,12000);})
                """});
            var addresses=ice["result"]!["value"]!.AsArray().Select(x=>x!.GetValue<string>()).Distinct().ToArray();
            bool all=addresses.All(x=>exits.Contains(x)||IPAddress.TryParse(x,out var ip)&&ip.Equals(IPAddress.Parse(ipv6)));
            Console.WriteLine("BROWSER_WEBRTC_PUBLIC_CANDIDATE_COUNT="+addresses.Length);
            if(!all)throw new IOException("BROWSER_WEBRTC_UNEXPECTED_PUBLIC_EXIT");
            Console.WriteLine("BROWSER_WEBRTC="+(addresses.Length>0?"VPN_PUBLIC_EXIT_VERIFIED":"INCONCLUSIVE_NO_PUBLIC_CANDIDATES"));
        }finally{
            if(!browser.HasExited){browser.Kill(true);await browser.WaitForExitAsync();}
            try{Directory.Delete(profile,true);}catch(IOException){}catch(UnauthorizedAccessException){}
        }
    }
}
