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
 static async Task<JsonObject> Send(string command,string? name=null,string? value=null){var state=await ControlPipe.Send(command,name,value);if(state["ok"]?.GetValue<bool>()!=true){Console.WriteLine("FAILED_OPERATION="+command);foreach(string field in new[]{"error","mode","connection_stage"}){string text=state[field]?.ToString()??"";if(System.Text.RegularExpressions.Regex.IsMatch(text,"^[A-Za-z0-9_-]{1,100}$"))Console.WriteLine("SERVICE_"+field.ToUpperInvariant()+"="+text);}foreach(string field in new[]{"device_count","device_limit"})if(state["account"]?[field] is JsonValue n && n.TryGetValue<int>(out var count))Console.WriteLine("ACCOUNT_"+field.ToUpperInvariant()+"="+count);throw new IOException("FIXED_CLIENT_OPERATION_FAILED");}return state;}
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
 sealed class PacketCounter:IDisposable {
  readonly string description,name;readonly string[] filters={"OPRtcA"+Guid.NewGuid().ToString("N")[..8],"OPRtcB"+Guid.NewGuid().ToString("N")[..8]};bool started;
  static string Run(params string[] arguments){var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"pktmon.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};foreach(var arg in arguments)start.ArgumentList.Add(arg);using var child=Process.Start(start)??throw new IOException("COUNTER_START_FAILED");var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();if(!child.WaitForExit(10000)){child.Kill(true);throw new IOException("COUNTER_DEADLINE");}string output=stdout.GetAwaiter().GetResult();_ = stderr.GetAwaiter().GetResult();if(child.ExitCode!=0 || output.Length>512*1024)throw new IOException("COUNTER_COMMAND_FAILED");return output;}
  public PacketCounter(string adapterName,string adapterDescription){name=adapterName;description=adapterDescription;if(Run("status").Trim()!="Packet Monitor is not running." || !System.Text.RegularExpressions.Regex.IsMatch(Run("filter","list"),@"\A\s*Packet Filters:\s*None\s*\z"))throw new IOException("PREEXISTING_COUNTER_REFUSED");try{Run("filter","add",filters[0],"-t","UDP","-p","3478");Run("filter","add",filters[1],"-t","UDP","-p","19302");Run("start","--capture","--counters-only","--comp","all");started=true;}catch{Dispose();throw;}}
  static IEnumerable<JsonObject> Objects(JsonNode? node){if(node is JsonObject obj){yield return obj;foreach(var pair in obj)foreach(var child in Objects(pair.Value))yield return child;}else if(node is JsonArray array)foreach(var item in array)foreach(var child in Objects(item))yield return child;}
  public long Packets(){var root=JsonNode.Parse(Run("counters","--json"));var components=Objects(root).Where(o=>o["Counters"] is JsonArray && o.Any(p=>p.Value is JsonValue v && v.TryGetValue<string>(out var text) && (string.Equals(text,description,StringComparison.OrdinalIgnoreCase)||string.Equals(text,name,StringComparison.OrdinalIgnoreCase)))).ToArray();if(components.Length==0)throw new IOException("PHYSICAL_COUNTER_COMPONENT_NOT_FOUND");long total=0;int found=0;foreach(var component in components)foreach(var counter in component["Counters"]!.AsArray())if(counter?["Type"]?.GetValue<string>()=="Flows"){total+=counter["Outbound"]?["Packets"]?.GetValue<long>()??throw new IOException("PHYSICAL_COUNTER_SCHEMA_CHANGED");found++;}if(found==0)throw new IOException("PHYSICAL_FLOW_COUNTER_NOT_FOUND");return total;}
  public void Dispose(){if(started){Run("stop");started=false;}if(Run("status").Trim()!="Packet Monitor is not running.")throw new IOException("ACTIVE_COUNTER_CLEANUP_REFUSED");string list=Run("filter","list");if(System.Text.RegularExpressions.Regex.IsMatch(list,@"\A\s*Packet Filters:\s*None\s*\z"))return;var rows=System.Text.RegularExpressions.Regex.Matches(list,@"(?m)^\s*\d+\s+(\S+)\s+.+$").Select(m=>m.Groups[1].Value).ToArray();if(rows.Length==0 || rows.Any(n=>!filters.Contains(n)) || rows.Distinct().Count()!=rows.Length)throw new IOException("FOREIGN_COUNTER_FILTER_REFUSED");Run("filter","remove");}
 }
 static async Task ProbePhysical(uint index){
  var ip=(await Dns.GetHostAddressesAsync("stun.cloudflare.com")).First(a=>a.AddressFamily==AddressFamily.InterNetwork);
  using var socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder((int)index));
  try{await socket.ConnectAsync(new IPEndPoint(ip,3478));byte[] request=new byte[20];request[1]=1;request[4]=0x21;request[5]=0x12;request[6]=0xa4;request[7]=0x42;System.Security.Cryptography.RandomNumberGenerator.Fill(request.AsSpan(8));await socket.SendAsync(request,SocketFlags.None);}
  catch(SocketException error)when(error.SocketErrorCode==SocketError.AccessDenied){} // Absence of this error is not proof of wire delivery.
 }
 static async Task<int> Main(){
  if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("GITHUB_REF")!="refs/heads/main")return 3;
  long initial=0;
  var adapter=NetworkInterface.GetAllNetworkInterfaces().First(n=>n.OperationalStatus==OperationalStatus.Up && n.GetIPProperties().GatewayAddresses.Any(g=>g.Address.AddressFamily==AddressFamily.InterNetwork));uint physical=(uint)adapter.GetIPProperties().GetIPv4Properties().Index;
  try{
   using var capture=new PacketCounter(adapter.Name,adapter.Description);await ProbePhysical(physical);await Task.Delay(500);long before=capture.Packets();Check(before>0,"BASELINE_RAW_STUN_PHYSICAL_COUNTER_POSITIVE");
   var login=await Send("Login",Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_USERNAME"),Environment.GetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD"));
   Environment.SetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_USERNAME",null);Environment.SetEnvironmentVariable("ORACLE_CLIENT_ACCEPTANCE_PASSWORD",null);
   if(login["device_registered"]?.GetValue<bool>()!=true)login=await Send("ConfirmDevice","Cloud WebRTC acceptance","confirmed");
   initial=(login["peer_rx_bytes"]?.GetValue<long>()??0)+(login["peer_tx_bytes"]?.GetValue<long>()??0);
   var descriptorClock=Stopwatch.StartNew();JsonObject descriptor;
   do{descriptor=await Send("Status");if(descriptor["device_registered"]?.GetValue<bool>()==true && descriptor["native_udp_8443_available"]?.GetValue<bool>()==true)break;await Task.Delay(250);}while(descriptorClock.ElapsedMilliseconds<12000);
   Check(descriptor["device_registered"]?.GetValue<bool>()==true && descriptor["native_udp_8443_available"]?.GetValue<bool>()==true,"CONFIRMED_NATIVE_DESCRIPTOR_READY_BEFORE_SELECTION");
   Console.WriteLine("DESCRIPTOR_REFRESH_WAIT_MS="+descriptorClock.ElapsedMilliseconds);
   await Send("PreferUdp8443");await Send("Connect");var timer=Stopwatch.StartNew();JsonObject state;
   do{await Task.Delay(250);state=await Send("Status");}while(state["mode"]?.GetValue<string>()!="connected"&&timer.ElapsedMilliseconds<30000);
   Check(state["mode"]?.GetValue<string>()=="connected" && state["transport"]?.GetValue<string>()=="wireguard-udp" && state["guard"]?.GetValue<bool>()==true,"PINNED_RC18_NATIVE_UDP_GUARD_CONNECTED");
   long connected=capture.Packets();await ProbePhysical(physical);await Browser();await Task.Delay(500);Check(capture.Packets()==connected,"REAL_RAW_STUN_HAS_ZERO_PHYSICAL_EGRESS_WITH_VPN");
   await Send("Quit");state=await Send("Status");long used=(state["peer_rx_bytes"]?.GetValue<long>()??-1)+(state["peer_tx_bytes"]?.GetValue<long>()??-1)-initial;
   Check(used>=0 && used<=16*1024*1024 && state["intent"]?.GetValue<bool>()==false && state["core_pid"]?.GetValue<uint>()==0,"WEBRTC_ACCEPTANCE_BOUNDED_USAGE_AND_CORE_STOPPED");
   await Send("Logout");return 0;
  }catch(Exception error){Console.WriteLine("WEBRTC_ACCEPTANCE=FAILED_NO_RAW_BROWSER_OR_ACCOUNT_LOGS");if(System.Text.RegularExpressions.Regex.IsMatch(error.Message,"^[A-Z0-9_]{1,100}$"))Console.WriteLine("FAILED_CHECK="+error.Message);Console.WriteLine("FAILURE_CATEGORY="+error.GetType().Name);return 1;}
 }
}
