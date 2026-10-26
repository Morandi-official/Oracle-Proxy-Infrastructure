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
 static async Task<JsonObject> CdpCommand(ClientWebSocket ws,string method,JsonObject parameters,int id){
  using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
  var frame=new JsonObject{["id"]=id,["method"]=method,["params"]=parameters};
  await ws.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(frame.ToJsonString())),WebSocketMessageType.Text,true,deadline.Token);
  byte[] buffer=new byte[65536];
  while(true){int size=0;WebSocketReceiveResult response;do{if(size==buffer.Length)throw new IOException("CDP_FRAME_TOO_LARGE");response=await ws.ReceiveAsync(new ArraySegment<byte>(buffer,size,buffer.Length-size),deadline.Token);size+=response.Count;if(response.MessageType==WebSocketMessageType.Close)throw new IOException("CDP_CLOSED");}while(!response.EndOfMessage);
   var value=JsonNode.Parse(buffer.AsSpan(0,size))!.AsObject();if(value["id"]?.GetValue<int>()!=id)continue;
   if(value["error"] is not null || value["result"]?["exceptionDetails"] is not null){if(value["error"]?["code"] is JsonValue code && code.TryGetValue<int>(out var number))Console.WriteLine("BROWSER_CDP_ERROR_CODE="+number);string category=value["result"]?["exceptionDetails"]?["exception"]?["className"]?.ToString()??"";if(System.Text.RegularExpressions.Regex.IsMatch(category,"^[A-Za-z]{1,40}$"))Console.WriteLine("BROWSER_JS_ERROR_CATEGORY="+category);throw new IOException("BROWSER_EVALUATION_FAILED");}
   return value["result"]!.AsObject();
  }
 }
 static async Task<JsonObject> Cdp(ClientWebSocket ws,string expression,int id){
  var result=await CdpCommand(ws,"Runtime.evaluate",new JsonObject{["expression"]=expression,["awaitPromise"]=true,["returnByValue"]=true},id);
  return result["result"]!["value"]!.AsObject();
 }
 static readonly JsonArray Results=new();
 static IPAddress[] PhysicalAddresses=[];
 static IPAddress? StunV6;
 const string Origin="https://vpn-admin.morandi.dpdns.org";
 static async Task Browser(bool checkStun=true,string permission="prompt"){

  Check(!System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem,"BROWSER_NOT_RUNNING_AS_SYSTEM");
  string edge=new[]{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}.Select(p=>Path.Combine(p,"Microsoft","Edge","Application","msedge.exe")).FirstOrDefault(File.Exists)??throw new IOException("EDGE_NOT_INSTALLED");
  string profile=Path.Combine(Path.GetTempPath(),"oracle-webrtc-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(profile);
  var start=new ProcessStartInfo(edge){UseShellExecute=false,CreateNoWindow=true};
  foreach(string arg in new[]{"--headless=new","--use-fake-device-for-media-stream","--no-proxy-server","--disable-extensions","--no-first-run","--no-default-browser-check","--disable-background-networking","--disable-component-update","--disable-default-apps","--disable-sync","--remote-debugging-port=0","--user-data-dir="+profile,"https://vpn-admin.morandi.dpdns.org/privacy-check/"})start.ArgumentList.Add(arg);
  using var process=Process.Start(start)??throw new IOException("EDGE_START_FAILED");
  try{
   string portFile=Path.Combine(profile,"DevToolsActivePort");var wait=Stopwatch.StartNew();while(!File.Exists(portFile)&&wait.ElapsedMilliseconds<15000)await Task.Delay(100);
   int port=int.Parse(File.ReadLines(portFile).First());Check(port is >1024 and <=65535,"EPHEMERAL_BROWSER_DEBUG_PORT");
   using var http=new HttpClient(new HttpClientHandler{UseProxy=false}){Timeout=TimeSpan.FromSeconds(3)};
   JsonObject? target=null;while(wait.ElapsedMilliseconds<20000){var targets=JsonNode.Parse(await http.GetStringAsync($"http://127.0.0.1:{port}/json/list"))!.AsArray();target=targets.OfType<JsonObject>().FirstOrDefault(t=>t["type"]?.GetValue<string>()=="page" && t["url"]?.GetValue<string>()=="https://vpn-admin.morandi.dpdns.org/privacy-check/");if(target is not null)break;await Task.Delay(100);}
   if(target is null)throw new IOException("PRIVACY_PAGE_NOT_LOADED");
   var uri=new Uri(target["webSocketDebuggerUrl"]!.GetValue<string>());Check(uri.IsLoopback && uri.Port==port,"BROWSER_DEBUG_ENDPOINT_IS_OWN_LOOPBACK");
   using var ws=new ClientWebSocket();using var connectDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(10));await ws.ConnectAsync(uri,connectDeadline.Token);
   bool ready=false;int call=1;var pageClock=Stopwatch.StartNew();while(pageClock.ElapsedMilliseconds<15000){try{var status=await Cdp(ws,"({ready:location.href==='https://vpn-admin.morandi.dpdns.org/privacy-check/' && document.readyState==='complete' && typeof window.OraclePrivacyResult!=='undefined' && !!document.getElementById('start')})",call++);if(status["ready"]?.GetValue<bool>()==true){ready=true;break;}}catch(IOException error)when(error.Message=="BROWSER_EVALUATION_FAILED"){}await Task.Delay(150);}
   Check(ready,"PUBLIC_EDGE_PRIVACY_DOCUMENT_AND_SCRIPT_READY");if(!checkStun)return;
   bool capture=permission is "granted" or "revoked";
   if(capture){
    await CdpCommand(ws,"Browser.grantPermissions",new JsonObject{["origin"]=Origin,["permissions"]=new JsonArray("audioCapture","videoCapture")},call++);
    var media=await Cdp(ws,"(async()=>{window.testMedia=await navigator.mediaDevices.getUserMedia({audio:true,video:true});return {active:window.testMedia.active,audio:window.testMedia.getAudioTracks().length,video:window.testMedia.getVideoTracks().length};})()",call++);
    Check(media["active"]?.GetValue<bool>()==true && media["audio"]?.GetValue<int>()==1 && media["video"]?.GetValue<int>()==1,"REAL_EDGE_FAKE_MEDIA_CAPTURE_PERMISSION_EXERCISED_"+permission);
   }
   if(permission is "denied" or "revoked"){
    if(permission=="revoked")await Cdp(ws,"(()=>{window.testMedia.getTracks().forEach(track=>track.stop());return {stopped:!window.testMedia.active};})()",call++);
    foreach(string name in new[]{"camera","microphone"})await CdpCommand(ws,"Browser.setPermission",new JsonObject{["origin"]=Origin,["permission"]=new JsonObject{["name"]=name},["setting"]="denied"},call++);
   }
   var states=await Cdp(ws,"(async()=>({camera:(await navigator.permissions.query({name:'camera'})).state,microphone:(await navigator.permissions.query({name:'microphone'})).state}))()",call++);
   string expected=permission=="prompt"?"prompt":permission=="granted"?"granted":"denied";
   Check(states["camera"]?.GetValue<string>()==expected && states["microphone"]?.GetValue<string>()==expected,"REAL_EDGE_PERMISSION_STATE_"+permission);
   foreach(bool ipv6 in new[]{false,true}){
    if(ipv6 && StunV6 is null)throw new IOException("PUBLIC_STUN_IPV6_DNS_REQUIRED");
    string urls=ipv6?System.Text.Json.JsonSerializer.Serialize(new[]{"stun:["+StunV6+"]:3478"}):"['stun:stun.cloudflare.com:3478','stun:stun.l.google.com:19302']";
    string expression="(async()=>{const pc=new RTCPeerConnection({iceServers:[{urls:"+urls+"}],iceCandidatePoolSize:0});const rows=[];pc.createDataChannel('privacy');try{await new Promise(async(resolve,reject)=>{const timer=setTimeout(resolve,12000);pc.onicecandidate=e=>{if(e.candidate){rows.push({type:e.candidate.type,address:e.candidate.address,related:e.candidate.relatedAddress});}else{clearTimeout(timer);resolve();}};try{await pc.setLocalDescription(await pc.createOffer());}catch(e){clearTimeout(timer);reject(e);}});return {candidates:rows};}finally{pc.close();}})()";
    var result=await Cdp(ws,expression,call++);
    var rows=result["candidates"]!.AsArray().OfType<JsonObject>().ToArray();
    var addresses=rows.SelectMany(row=>new[]{row["address"]?.GetValue<string>(),row["related"]?.GetValue<string>()}).Where(value=>IPAddress.TryParse(value,out _)).Select(value=>IPAddress.Parse(value!)).Where(ip=>!ip.Equals(IPAddress.Any)&&!ip.Equals(IPAddress.IPv6Any)).Distinct().ToArray();
    bool oracle(IPAddress address)=>address.Equals(IPAddress.Parse("152.67.156.100"))||address.Equals(IPAddress.Parse("2603:c020:c015:8100::10"));
    bool privateIp(IPAddress address)=>IPAddress.IsLoopback(address)||address.AddressFamily==AddressFamily.InterNetworkV6&&(address.IsIPv6LinkLocal||((address.GetAddressBytes()[0]&0xfe)==0xfc))||address.AddressFamily==AddressFamily.InterNetwork&&(address.GetAddressBytes()[0]==10||address.GetAddressBytes()[0]==192&&address.GetAddressBytes()[1]==168||address.GetAddressBytes()[0]==172&&address.GetAddressBytes()[1] is >=16 and <=31||address.GetAddressBytes()[0]==169&&address.GetAddressBytes()[1]==254);
    bool unexpected=addresses.Any(address=>!privateIp(address)&&!oracle(address));
    bool physicalExposed=addresses.Any(address=>PhysicalAddresses.Contains(address));
    bool physicalPrivateExposed=addresses.Any(address=>privateIp(address)&&PhysicalAddresses.Contains(address));
    string wanted=ipv6?"2603:c020:c015:8100::10":"152.67.156.100";
    bool verified=rows.Any(row=>row["type"]?.GetValue<string>()=="srflx"&&IPAddress.TryParse(row["address"]?.GetValue<string>(),out var address)&&address.Equals(IPAddress.Parse(wanted)));
    var observation=new JsonObject{["permission"]=permission,["stun_family"]=ipv6?6:4,["public_oracle_verified"]=verified,["unexpected_public"]=unexpected,["physical_address_disclosed"]=physicalExposed,["physical_private_address_disclosed"]=physicalPrivateExposed,["literal_private_count"]=addresses.Count(privateIp),["candidate_count"]=rows.Length};
    Results.Add(observation);Console.WriteLine("BROWSER_PERMISSION_RESULT="+observation.ToJsonString());
    Check(!unexpected,"REAL_EDGE_NO_FOREIGN_PUBLIC_CANDIDATE_"+permission+"_"+(ipv6?"V6":"V4"));
    Console.WriteLine("BROWSER_FAMILY_COVERAGE_"+(ipv6?"V6":"V4")+"="+(verified?"VERIFIED":"INCONCLUSIVE_NO_SRFLX"));
   }
   if(capture)await Cdp(ws,"(()=>{window.testMedia.getTracks().forEach(track=>track.stop());return {stopped:true};})()",call++);

  }finally{try{if(!process.HasExited)process.Kill(true);process.WaitForExit(5000);}catch{}try{Directory.Delete(profile,true);}catch{}}
 }
 sealed class PacketCounter:IDisposable {
  readonly string description,name;readonly string[] filters={"OPRtcA"+Guid.NewGuid().ToString("N")[..8],"OPRtcB"+Guid.NewGuid().ToString("N")[..8]};bool started;
  static string Run(params string[] arguments){var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"pktmon.exe")){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};foreach(var arg in arguments)start.ArgumentList.Add(arg);using var child=Process.Start(start)??throw new IOException("COUNTER_START_FAILED");var stdout=child.StandardOutput.ReadToEndAsync();var stderr=child.StandardError.ReadToEndAsync();if(!child.WaitForExit(10000)){child.Kill(true);throw new IOException("COUNTER_DEADLINE");}string output=stdout.GetAwaiter().GetResult();_ = stderr.GetAwaiter().GetResult();if(child.ExitCode!=0 || output.Length>512*1024)throw new IOException("COUNTER_COMMAND_FAILED");return output;}
  public PacketCounter(string adapterName,string adapterDescription){name=adapterName;description=adapterDescription;if(Run("status").Trim()!="Packet Monitor is not running." || !System.Text.RegularExpressions.Regex.IsMatch(Run("filter","list"),@"\A\s*Packet Filters:\s*None\s*\z"))throw new IOException("PREEXISTING_COUNTER_REFUSED");try{Run("filter","add",filters[0],"-t","UDP","-p","3478");Run("filter","add",filters[1],"-t","UDP","-p","19302");Run("start","--capture","--counters-only","--comp","all");started=true;}catch{Dispose();throw;}}
  static IEnumerable<JsonObject> Objects(JsonNode? node){if(node is JsonObject obj){yield return obj;foreach(var pair in obj)foreach(var child in Objects(pair.Value))yield return child;}else if(node is JsonArray array)foreach(var item in array)foreach(var child in Objects(item))yield return child;}
  public long Packets(){var root=JsonNode.Parse(Run("counters","--json"),new JsonNodeOptions{PropertyNameCaseInsensitive=true});var components=Objects(root).Where(o=>o["Group"] is JsonValue g && g.TryGetValue<string>(out var group) && !string.IsNullOrWhiteSpace(group) && !group.Contains("unassociated",StringComparison.OrdinalIgnoreCase) && !group.Equals("Other",StringComparison.OrdinalIgnoreCase) && !group.Contains("OracleProxy",StringComparison.OrdinalIgnoreCase) && !group.Contains("sing-tun",StringComparison.OrdinalIgnoreCase)).Select(o=>o["Components"]?.AsArray().FirstOrDefault()?.AsObject()).Where(o=>o is not null && o["Counters"] is JsonArray && !string.Equals(o["Name"]?.ToString(),"TCPIP",StringComparison.OrdinalIgnoreCase) && !(o["Name"]?.ToString()??"").Contains("sing-tun",StringComparison.OrdinalIgnoreCase)).Cast<JsonObject>().ToArray();if(components.Length==0){foreach(var obj in Objects(root).Where(o=>o["Group"] is not null).Take(20))Console.WriteLine("COUNTER_GROUP="+obj["Group"]);throw new IOException("PHYSICAL_COUNTER_COMPONENT_NOT_FOUND");}long total=0;int found=0;foreach(var component in components)foreach(var counter in component["Counters"]!.AsArray())if(counter?["Type"]?.GetValue<string>()=="Flows"){total+=counter["Outbound"]?["Packets"]?.GetValue<long>()??throw new IOException("PHYSICAL_COUNTER_SCHEMA_CHANGED");found++;}if(found==0)throw new IOException("PHYSICAL_FLOW_COUNTER_NOT_FOUND");return total;}
  public void Dispose(){if(started){Run("stop");started=false;}if(Run("status").Trim()!="Packet Monitor is not running.")throw new IOException("ACTIVE_COUNTER_CLEANUP_REFUSED");string list=Run("filter","list");if(System.Text.RegularExpressions.Regex.IsMatch(list,@"\A\s*Packet Filters:\s*None\s*\z"))return;var rows=System.Text.RegularExpressions.Regex.Matches(list,@"(?m)^\s*\d+\s+(\S+)\s+.+$").Select(m=>m.Groups[1].Value).ToArray();if(rows.Length==0 || rows.Any(n=>!filters.Contains(n)) || rows.Distinct().Count()!=rows.Length)throw new IOException("FOREIGN_COUNTER_FILTER_REFUSED");Run("filter","remove");}
 }
 static async Task ProbePhysical(uint index){
  var ip=(await Dns.GetHostAddressesAsync("stun.cloudflare.com")).First(a=>a.AddressFamily==AddressFamily.InterNetwork);
  using var socket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);socket.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder((int)index));
  try{await socket.ConnectAsync(new IPEndPoint(ip,3478));byte[] request=new byte[20];request[1]=1;request[4]=0x21;request[5]=0x12;request[6]=0xa4;request[7]=0x42;System.Security.Cryptography.RandomNumberGenerator.Fill(request.AsSpan(8));await socket.SendAsync(request,SocketFlags.None);}
  catch(SocketException error)when(error.SocketErrorCode==SocketError.AccessDenied){} // Absence of this error is not proof of wire delivery.
 }
 static async Task ProbePhysical6(NetworkInterface adapter){
  int index=adapter.GetIPProperties().GetIPv6Properties().Index;
  var local=adapter.GetIPProperties().UnicastAddresses.Select(a=>a.Address).FirstOrDefault(a=>a.AddressFamily==AddressFamily.InterNetworkV6 && a.IsIPv6LinkLocal);
  if(local is null)throw new IOException("PHYSICAL_IPV6_LINKLOCAL_REQUIRED");
  using var socket=new Socket(AddressFamily.InterNetworkV6,SocketType.Dgram,ProtocolType.Udp);
  socket.SetSocketOption(SocketOptionLevel.IPv6,SocketOptionName.MulticastInterface,index);
  var target=IPAddress.Parse("ff02::1");target.ScopeId=index;
  try{
   socket.Bind(new IPEndPoint(local,0));
   await socket.SendToAsync(new byte[]{0,1,0,0,0x21,0x12,0xa4,0x42,1,2,3,4,5,6,7,8,9,10,11,12},SocketFlags.None,new IPEndPoint(target,3478));
  }catch(SocketException error)when(error.SocketErrorCode==SocketError.AccessDenied){}
 }
 static async Task<int> Main(string[] args){
  if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
  long initial=0;
  var adapter=NetworkInterface.GetAllNetworkInterfaces().First(n=>n.OperationalStatus==OperationalStatus.Up && n.GetIPProperties().GatewayAddresses.Any(g=>g.Address.AddressFamily==AddressFamily.InterNetwork));uint physical=(uint)adapter.GetIPProperties().GetIPv4Properties().Index;
  if(args.SequenceEqual(new[]{"--counter-self-test"})){try{using var preflight=new PacketCounter(adapter.Name,adapter.Description);await ProbePhysical(physical);await Task.Delay(500);long v4=preflight.Packets();Check(v4>0,"REAL_PHYSICAL_STUN_COUNTER_SCHEMA_AND_BASELINE");await ProbePhysical6(adapter);await Task.Delay(500);Check(preflight.Packets()>v4,"REAL_PHYSICAL_IPV6_LINK_LOCAL_UDP_COUNTER_BASELINE");Console.WriteLine("PHYSICAL_V6_BASELINE_SCOPE=LINK_LOCAL_MULTICAST_NOT_PUBLIC_IPV6_INTERNET");await Browser(false);return 0;}catch(Exception error){if(System.Text.RegularExpressions.Regex.IsMatch(error.Message,"^[A-Z0-9_]{1,100}$"))Console.WriteLine("FAILED_PREFLIGHT="+error.Message);return 1;}}
  if(args.Length!=0 || Environment.GetEnvironmentVariable("GITHUB_REF")!="refs/heads/main")return 3;
  try{
   using var capture=new PacketCounter(adapter.Name,adapter.Description);await ProbePhysical(physical);await Task.Delay(500);long before=capture.Packets();Check(before>0,"BASELINE_RAW_STUN_PHYSICAL_COUNTER_POSITIVE");await ProbePhysical6(adapter);await Task.Delay(500);Check(capture.Packets()>before,"BASELINE_PHYSICAL_IPV6_LINK_LOCAL_UDP_POSITIVE");
   PhysicalAddresses=adapter.GetIPProperties().UnicastAddresses.Select(a=>a.Address).ToArray();
   StunV6=(await Dns.GetHostAddressesAsync("stun.cloudflare.com")).FirstOrDefault(a=>a.AddressFamily==AddressFamily.InterNetworkV6);
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
   Check(state["mode"]?.GetValue<string>()=="connected" && state["transport"]?.GetValue<string>()=="wireguard-udp" && state["guard"]?.GetValue<bool>()==true && state["ipv6_policy"]?.GetValue<string>()=="tunnel" && state["verified_exit_ipv6"]?.GetValue<string>()=="2603:c020:c015:8100::10" && state["transport_address"]?.GetValue<string>()=="141.147.78.44","PINNED_RC20_DUALSTACK_NATIVE_UDP_GUARD_CONNECTED");
   long connected=capture.Packets();await ProbePhysical(physical);await ProbePhysical6(adapter);try{foreach(string permission in new[]{"prompt","denied","granted","revoked"})await Browser(true,permission);}finally{await Task.Delay(500);long delta=capture.Packets()-connected;Console.WriteLine("RAW_STUN_PHYSICAL_TX_DELTA="+delta);Check(delta==0,"REAL_RAW_STUN_V4_AND_IPV6_LINK_LOCAL_HAVE_ZERO_PHYSICAL_EGRESS_WITH_VPN");}
   await Send("Quit");state=await Send("Status");long used=(state["peer_rx_bytes"]?.GetValue<long>()??-1)+(state["peer_tx_bytes"]?.GetValue<long>()??-1)-initial;
   Check(used>=0 && used<=16*1024*1024 && state["intent"]?.GetValue<bool>()==false && state["core_pid"]?.GetValue<uint>()==0,"WEBRTC_ACCEPTANCE_BOUNDED_USAGE_AND_CORE_STOPPED");
   await Send("Logout");
   Directory.CreateDirectory("dist/webrtc-review");
   File.WriteAllText("dist/webrtc-review/result.json",new JsonObject{["schema"]=1,["product"]="0.3.0-rc20+30f70a05110e5752581eccd8dd2ce1c97dffd682",["fake_media_devices"]=true,["physical_stun_egress_delta"]=0,["scenarios"]=Results.DeepClone()}.ToJsonString());
   bool full=Results.OfType<JsonObject>().All(row=>row["public_oracle_verified"]?.GetValue<bool>()==true && row["physical_address_disclosed"]?.GetValue<bool>()==false);
   Console.WriteLine("BROWSER_PERMISSION_MATRIX_FINAL="+(full?"PASS":"COVERAGE_OR_LOCAL_DISCLOSURE_REQUIRES_REVIEW"));
   return full?0:2;
  }catch(Exception error){Console.WriteLine("WEBRTC_ACCEPTANCE=FAILED_NO_RAW_BROWSER_OR_ACCOUNT_LOGS");if(System.Text.RegularExpressions.Regex.IsMatch(error.Message,"^[A-Z0-9_]{1,100}$"))Console.WriteLine("FAILED_CHECK="+error.Message);Console.WriteLine("FAILURE_CATEGORY="+error.GetType().Name);return 1;}finally{Directory.CreateDirectory("dist/webrtc-review");File.WriteAllText("dist/webrtc-review/scenarios.json",Results.ToJsonString());}
 }
}
