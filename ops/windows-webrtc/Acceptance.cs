using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json.Nodes;
using OracleProxy.Product;
internal static class Acceptance
{
 static void Check(bool ok,string code){if(!ok)throw new IOException(code);Console.WriteLine(code+"=PASS");}
 static async Task<JsonObject> Send(string command,string? name=null,string? value=null){var state=await ControlPipe.Send(command,name,value);if(state["ok"]?.GetValue<bool>()!=true)throw new IOException("FIXED_CLIENT_OPERATION_FAILED");return state;}
 static async Task<JsonObject> Cdp(ClientWebSocket ws,string expression,int id){
  using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
  var frame=new JsonObject{["id"]=id,["method"]="Runtime.evaluate",["params"]=new JsonObject{["expression"]=expression,["awaitPromise"]=true,["returnByValue"]=true}};
  await ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(frame.ToJsonString())),WebSocketMessageType.Text,true,deadline.Token);
  byte[] buffer=new byte[65536];
  while(true){int size=0;WebSocketReceiveResult response;do{if(size==buffer.Length)throw new IOException("CDP_FRAME_TOO_LARGE");response=await ws.ReceiveAsync(new ArraySegment<byte>(buffer,size,buffer.Length-size),deadline.Token);size+=response.Count;if(response.MessageType==WebSocketMessageType.Close)throw new IOException("CDP_CLOSED");}while(!response.EndOfMessage);
   var value=JsonNode.Parse(buffer.AsSpan(0,size))!.AsObject();if(value["id"]?.GetValue<int>()!=id)continue;
   if(value["error"] is not null || value["result"]?["exceptionDetails"] is not null)throw new IOException("BROWSER_EVALUATION_FAILED");
   return value["result"]!["result"]!["value"]!.AsObject();
  }
 }
 static async Task Browser(){
  Check(!System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem,"BROWSER_NOT_RUNNING_AS_SYSTEM");
  string edge=new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}.Select(p=>Path.Combine(p,"Microsoft","Edge","Application","msedge.exe")).FirstOrDefault(File.Exists)??throw new IOException("EDGE_NOT_INSTALLED");
  string profile=Path.Combine(Path.GetTempPath(),"oracle-webrtc-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(profile);
  var start=new ProcessStartInfo(edge){UseShellExecute=false,CreateNoWindow=true};
  foreach(string arg in new[]{"--headless=new","--no-first-run","--no-default-browser-check","--disable-background-networking","--disable-component-update","--disable-default-apps","--disable-sync","--remote-debugging-port=0","--user-data-dir="+profile,"https://vpn-admin.morandi.dpdns.org/privacy-check/"})start.ArgumentList.Add(arg);
  using var process=Process.Start(start)??throw new IOException("EDGE_START_FAILED");
  try{
   string portFile=Path.Combine(profile,"DevToolsActivePort");var wait=Stopwatch.StartNew();while(!File.Exists(portFile)&&wait.ElapsedMilliseconds<15000)await Task.Delay(100);
   int port=int.Parse(File.ReadLines(portFile).First());Check(port is >1024 and <=65535,"EPHEMERAL_BROWSER_DEBUG_PORT");
   using var http=new HttpClient(new HttpClientHandler{UseProxy=false}){Timeout=TimeSpan.FromSeconds(3)};
   JsonObject? target=null;while(wait.ElapsedMilliseconds<20000){var targets=JsonNode.Parse(await http.GetStringAsync($"http://127.0.0.1:{port}/json/list"))!.AsArray();target=targets.OfType<JsonObject>().FirstOrDefault(t=>t["type"]?.GetValue<string>()=="page" && t["url"]?.GetValue<string>()=="https://vpn-admin.morandi.dpdns.org/privacy-check/");if(target is not null)break;await Task.Delay(100);}
   if(target is null)throw new IOException("PRIVACY_PAGE_NOT_LOADED");
   var uri=new Uri(target["webSocketDebuggerUrl"]!.GetValue<string>());Check(uri.IsLoopback && uri.Port==port,"BROWSER_DEBUG_ENDPOINT_IS_OWN_LOOPBACK");
   using var ws=new ClientWebSocket();using var connectDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));await ws.ConnectAsync(uri,connectDeadline.Token);
   var result=await Cdp(ws,"(async()=>{for(let i=0;i<100&&(!document.getElementById('start')||typeof window.OraclePrivacyResult==='undefined');i++)await new Promise(r=>setTimeout(r,100));document.getElementById('start').click();for(let i=0;i<150&&!window.OraclePrivacyResult;i++)await new Promise(r=>setTimeout(r,100));return window.OraclePrivacyResult || {error:'DEADLINE'};})()",1);
   Check(result["oracle_verified"]?.GetValue<bool>()==true && result["unexpected_public"]?.GetValue<bool>()==false && result["public_ips"]!.AsArray().Any(p=>p?.GetValue<string>()=="152.67.156.100"),"REAL_EDGE_RTCPEERCONNECTION_STUN_PUBLIC_CANDIDATE_IS_ORACLE");
   Console.WriteLine("BROWSER_LOCAL_ICE_LITERAL_EXPOSED="+(result["local_exposed"]?.GetValue<bool>()==true));
  }finally{try{if(!process.HasExited)process.Kill(true);process.WaitForExit(5000);}catch{}try{Directory.Delete(profile,true);}catch{}}
 }
 static async Task CheckPhysical(uint index){
  var ip=(await Dns.GetHostAddressesAsync("stun.cloudflare.com")).First(a=>a.AddressFamily==AddressFamily.InterNetwork);
  bool blocked=false;using var socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
  socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder((int)index));
  try{await socket.ConnectAsync(new IPEndPoint(ip,3478));byte[] request=new byte[20];request[1]=1;request[4]=0x21;request[5]=0x12;request[6]=0xa4;request[7]=0x42;System.Security.Cryptography.RandomNumberGenerator.Fill(request.AsSpan(8));await socket.SendAsync(request,SocketFlags.None);}
  catch(SocketException error)when(error.SocketErrorCode==SocketError.AccessDenied){blocked=true;}
  Check(blocked,"PHYSICAL_BOUND_UDP_STUN_DENIED_BY_WFP");
 }
 static async Task<int> Main(){
  if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("GITHUB_REF")!="refs/heads/main")return 3;
  long initial=0;
  uint physical=(uint)NetworkInterface.GetAllNetworkInterfaces().First(n=>n.OperationalStatus==OperationalStatus.Up && n.GetIPProperties().GatewayAddresses.Any(g=>g.Address.AddressFamily==AddressFamily.InterNetwork)).GetIPProperties().GetIPv4Properties().Index;
  try{
   var login=await Send("Login",Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_USERNAME"),Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD"));
   Environment.SetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_USERNAME",null);Environment.SetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD",null);
   if(login["device_registered"]?.GetValue<bool>()!=true)login=await Send("ConfirmDevice","Cloud WebRTC acceptance","confirmed");
   initial=(login["peer_rx_bytes"]?.GetValue<long>()??0)+(login["peer_tx_bytes"]?.GetValue<long>()??0);
   await Send("PreferUdp8443");await Send("Connect");var timer=Stopwatch.StartNew();JsonObject state;
   do{await Task.Delay(250);state=await Send("Status");}while(state["mode"]?.GetValue<string>()!="connected"&&timer.ElapsedMilliseconds<30000);
   Check(state["mode"]?.GetValue<string>()=="connected" && state["transport"]?.GetValue<string>()=="wireguard-udp" && state["guard"]?.GetValue<bool>()==true,"PINNED_RC18_NATIVE_UDP_GUARD_CONNECTED");
   await CheckPhysical(physical);await Browser();
   await Send("Quit");state=await Send("Status");long used=(state["peer_rx_bytes"]?.GetValue<long>()??-1)+(state["peer_tx_bytes"]?.GetValue<long>()??-1)-initial;
   Check(used>=0 && used<=16*1024*1024 && state["intent"]?.GetValue<bool>()==false && state["core_pid"]?.GetValue<uint>()==0,"WEBRTC_ACCEPTANCE_BOUNDED_USAGE_AND_CORE_STOPPED");
   await Send("Logout");return 0;
  }catch(Exception error){Console.WriteLine("WEBRTC_ACCEPTANCE=FAILED_NO_RAW_BROWSER_OR_ACCOUNT_LOGS");if(System.Text.RegularExpressions.Regex.IsMatch(error.Message,"^[A-Z0-9_]{1,100}$"))Console.WriteLine("FAILED_CHECK="+error.Message);Console.WriteLine("FAILURE_CATEGORY="+error.GetType().Name);return 1;}
 }
}
