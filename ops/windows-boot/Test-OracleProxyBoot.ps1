param([ValidateSet('Prepare','Collect','Report','SelfTest','SelfTestConnected')][string]$Mode='Report')
$ErrorActionPreference='Stop'
if(-not [Environment]::Is64BitProcess){throw 'WINDOWS_X64_POWERSHELL_REQUIRED'}
$BootRoot=Join-Path $env:ProgramData 'OracleProxyBootAcceptance'
$TaskName='OracleProxyOneShotBootAcceptance'
$TrustedScript=Join-Path $BootRoot 'Test-OracleProxyBoot.ps1'
$ConfigFile=Join-Path $BootRoot 'config.json'
$ReportFile=Join-Path $BootRoot 'report.json'
$ExpectedVersion='0.3.0-rc20+30f70a05110e5752581eccd8dd2ce1c97dffd682'
$Admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$System=([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
if(-not ('OracleBootReadOnly' -as [type])){
Add-Type -ReferencedAssemblies @('System.dll','System.Core.dll','System.Net.Http.dll') -TypeDefinition @'
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
public static class OracleBootReadOnly {
 [StructLayout(LayoutKind.Sequential)]struct ServiceStatus {public uint Type,State,Accepted,Exit,Specific,Checkpoint,Wait,Pid,Flags;}
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]static extern IntPtr OpenSCManager(string a,string b,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)]static extern IntPtr OpenService(IntPtr m,string name,uint access);
 [DllImport("advapi32.dll")]static extern bool QueryServiceStatusEx(IntPtr s,int level,out ServiceStatus status,uint size,out uint needed);
 [DllImport("advapi32.dll")]static extern bool CloseServiceHandle(IntPtr s);
 [DllImport("kernel32.dll")]static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe,out uint pid);
 public static string Status(){
  using(var pipe=new NamedPipeClientStream(".","OracleProxy.Control.v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Impersonation)){
   pipe.Connect(700);uint pid;if(!GetNamedPipeServerProcessId(pipe.SafePipeHandle,out pid))throw new IOException("PIPE_PID_FAILED");
   IntPtr manager=OpenSCManager(null,null,1),service=IntPtr.Zero;
   if(manager==IntPtr.Zero)throw new IOException("SCM_READ_FAILED");
   try{service=OpenService(manager,"OracleProxyService",4);ServiceStatus state;uint needed;
    if(service==IntPtr.Zero||!QueryServiceStatusEx(service,0,out state,(uint)Marshal.SizeOf(typeof(ServiceStatus)),out needed)||state.State!=4||state.Pid!=pid)throw new IOException("SERVICE_IDENTITY_NOT_VERIFIED");
   }finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
   byte[] request=Encoding.UTF8.GetBytes("{\"version\":1,\"command\":\"Status\"}\n");pipe.Write(request,0,request.Length);pipe.Flush();
   byte[] buffer=new byte[65537];int count=0;var clock=Stopwatch.StartNew();
   while(count<65537){int left=1200-(int)clock.ElapsedMilliseconds;if(left<=0)throw new IOException("STATUS_TIMEOUT");
    var pending=pipe.ReadAsync(buffer,count,buffer.Length-count);if(!pending.Wait(left))throw new IOException("STATUS_TIMEOUT");int n=pending.Result;if(n==0)throw new IOException("STATUS_EOF");
    for(int i=count;i<count+n;i++)if(buffer[i]==10)return Encoding.UTF8.GetString(buffer,0,i);count+=n;
   }throw new IOException("STATUS_TOO_LARGE");
  }
 }
 [StructLayout(LayoutKind.Sequential)]struct EnumTemplate {public IntPtr Provider;public Guid Layer;public uint Type,Flags;public IntPtr Context;public uint Count;public IntPtr Conditions;public uint Actions;public IntPtr Callout;}
 [StructLayout(LayoutKind.Sequential)]struct FilterPrefix {public Guid Key;public IntPtr Name,Description;public uint Flags;}
 [DllImport("fwpuclnt.dll",CharSet=CharSet.Unicode)]static extern uint FwpmEngineOpen0(string server,uint auth,IntPtr identity,IntPtr session,out IntPtr engine);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmEngineClose0(IntPtr engine);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmProviderGetByKey0(IntPtr engine,ref Guid key,out IntPtr value);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterCreateEnumHandle0(IntPtr engine,ref EnumTemplate template,out IntPtr enumerator);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterEnum0(IntPtr engine,IntPtr enumerator,uint maximum,out IntPtr entries,out uint count);
 [DllImport("fwpuclnt.dll")]static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engine,IntPtr enumerator);
 [DllImport("fwpuclnt.dll")]static extern void FwpmFreeMemory0(ref IntPtr data);
 public static int[] GuardCounts(){
  IntPtr engine=IntPtr.Zero,enumerator=IntPtr.Zero,provider=Marshal.AllocHGlobal(16);int persistent=0,boot=0,total=0;
  try{Marshal.StructureToPtr(new Guid("4936aef1-9f84-4291-8872-3647198021a1"),provider,false);
   if(FwpmEngineOpen0(null,10,IntPtr.Zero,IntPtr.Zero,out engine)!=0)throw new IOException("WFP_READ_UNAVAILABLE");
   Guid key=new Guid("4936aef1-9f84-4291-8872-3647198021a1");IntPtr existing=IntPtr.Zero;uint found=FwpmProviderGetByKey0(engine,ref key,out existing);if(existing!=IntPtr.Zero)FwpmFreeMemory0(ref existing);if(found==0x80320005)return new int[]{0,0};if(found!=0)throw new IOException("WFP_PROVIDER_READ_FAILED");
   string[] layers={"c38d57d1-05a7-4c33-904f-7fbceee60e82","e1cd9fe7-f4b5-4273-96c0-592e487b8650","4a72393b-319f-44bc-84c3-ba54dcb3b6b4","a3b42c97-9f04-4672-b87e-cee9c483257f","09e61aea-d214-46e2-9b21-b26b0b2f28c8","5926dfc8-e3cf-4426-a283-dc393f5d0f9d","e1735bde-013f-4655-b351-a49e15762df0","634a869f-fc23-4b90-b0c1-bf620a36ae6f"};
   foreach(string layer in layers){
    var template=new EnumTemplate();template.Provider=provider;template.Layer=new Guid(layer);template.Actions=0xffffffff;template.Flags=0x18;
    if(FwpmFilterCreateEnumHandle0(engine,ref template,out enumerator)!=0)throw new IOException("WFP_ENUM_UNAVAILABLE");
    while(true){IntPtr entries=IntPtr.Zero;uint count;try{
     if(FwpmFilterEnum0(engine,enumerator,128,out entries,out count)!=0)throw new IOException("WFP_ENUM_FAILED");
     if(count==0)break;total+=(int)count;if(total>1024)throw new IOException("WFP_ENUM_LIMIT");
     for(int i=0;i<count;i++){var filter=(FilterPrefix)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(FilterPrefix));if((filter.Flags&1)!=0)persistent++;if((filter.Flags&2)!=0)boot++;}
    }finally{if(entries!=IntPtr.Zero)FwpmFreeMemory0(ref entries);}}
    FwpmFilterDestroyEnumHandle0(engine,enumerator);enumerator=IntPtr.Zero;
   }
   return new int[]{persistent,boot};
  }finally{if(enumerator!=IntPtr.Zero)FwpmFilterDestroyEnumHandle0(engine,enumerator);if(engine!=IntPtr.Zero)FwpmEngineClose0(engine);Marshal.FreeHGlobal(provider);}
 }
 [StructLayout(LayoutKind.Sequential)]struct Session {public int Id;public IntPtr Name;public int State;}
 [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode)]static extern bool WTSEnumerateSessions(IntPtr server,int reserved,int version,out IntPtr rows,out int count);
 [DllImport("wtsapi32.dll",CharSet=CharSet.Unicode)]static extern bool WTSQuerySessionInformation(IntPtr server,int id,int information,out IntPtr data,out int size);
 [DllImport("wtsapi32.dll")]static extern void WTSFreeMemory(IntPtr data);
 public static bool InteractiveUserPresent(){IntPtr rows;int count;if(!WTSEnumerateSessions(IntPtr.Zero,0,1,out rows,out count))throw new IOException("SESSION_READ_FAILED");
  try{for(int i=0;i<count;i++){var row=(Session)Marshal.PtrToStructure(IntPtr.Add(rows,i*Marshal.SizeOf(typeof(Session))),typeof(Session));if(row.Id==0)continue;IntPtr data;int size;
   if(!WTSQuerySessionInformation(IntPtr.Zero,row.Id,5,out data,out size))throw new IOException("SESSION_USER_READ_FAILED");try{if(size>2&&!String.IsNullOrEmpty(Marshal.PtrToStringUni(data)))return true;}finally{WTSFreeMemory(data);}
  }return false;}finally{WTSFreeMemory(rows);}
 }
 public sealed class PhysicalResult {public string Error="NONE";public bool AddressPresent,Sent,MatchingReply,Blocked;}
 public static PhysicalResult PhysicalProbe(int family,string target){
  var result=new PhysicalResult();AddressFamily af=family==4?AddressFamily.InterNetwork:AddressFamily.InterNetworkV6;
  var adapters=NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up&&n.Name!="OracleProxy"&&n.NetworkInterfaceType!=NetworkInterfaceType.Loopback&&n.NetworkInterfaceType!=NetworkInterfaceType.Tunnel&&n.GetIPProperties().GatewayAddresses.Any(g=>g.Address.AddressFamily==AddressFamily.InterNetwork));
  foreach(var adapter in adapters){var local=adapter.GetIPProperties().UnicastAddresses.Select(a=>a.Address).FirstOrDefault(a=>a.AddressFamily==af&&(family==4||!a.IsIPv6LinkLocal&&!a.IsIPv6SiteLocal&&(a.GetAddressBytes()[0]&0xfe)!=0xfc));if(local==null)continue;
   result.AddressPresent=true;using(var socket=new Socket(af,SocketType.Dgram,ProtocolType.Udp)){
    try{socket.ReceiveTimeout=750;socket.SendTimeout=750;int index=family==4?adapter.GetIPProperties().GetIPv4Properties().Index:adapter.GetIPProperties().GetIPv6Properties().Index;
     socket.SetSocketOption(family==4?SocketOptionLevel.IP:SocketOptionLevel.IPv6,(SocketOptionName)31,family==4?IPAddress.HostToNetworkOrder(index):index);
     socket.Bind(new IPEndPoint(local,0));socket.Connect(new IPEndPoint(IPAddress.Parse(target),3478));
     byte[] request=new byte[20],transaction=new byte[12];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(transaction);request[1]=1;request[4]=0x21;request[5]=0x12;request[6]=0xa4;request[7]=0x42;Buffer.BlockCopy(transaction,0,request,8,12);
     socket.Send(request);result.Sent=true;byte[] response=new byte[1024];int count=socket.Receive(response);
     result.MatchingReply=count>=20&&response[0]==1&&response[1]==1&&response.Skip(4).Take(16).SequenceEqual(request.Skip(4).Take(16));return result;
    }catch(SocketException error){result.Error=error.SocketErrorCode.ToString();result.Blocked=!result.Sent&&error.SocketErrorCode==SocketError.AccessDenied;return result;}
   }
  }result.Error="NO_NATIVE_PHYSICAL_ADDRESS";return result;
 }
 public static string DefaultExit(int family){
  try{using(var handler=new HttpClientHandler()){handler.UseProxy=false;handler.UseCookies=false;handler.AllowAutoRedirect=false;
   using(var client=new HttpClient(handler)){client.Timeout=TimeSpan.FromMilliseconds(3000);var response=client.GetAsync(family==4?"https://1.1.1.1/cdn-cgi/trace":"https://[2606:4700:4700::1111]/cdn-cgi/trace",HttpCompletionOption.ResponseHeadersRead).GetAwaiter().GetResult();
    using(response){response.EnsureSuccessStatusCode();using(var stream=response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()){byte[] bytes=new byte[8193];int count=0;var clock=Stopwatch.StartNew();while(count<bytes.Length){int left=3000-(int)clock.ElapsedMilliseconds;if(left<=0)return "UNAVAILABLE";var read=stream.ReadAsync(bytes,count,bytes.Length-count);if(!read.Wait(left))return "UNAVAILABLE";int n=read.Result;if(n==0)break;count+=n;}if(count>8192)return "INVALID_RESPONSE";
     string expected=family==4?"ip=152.67.156.100":"ip=2603:c020:c015:8100::10";return Encoding.UTF8.GetString(bytes,0,count).Split('\n').Any(line=>line.TrimEnd('\r')==expected)?"ORACLE":"OTHER_EXIT";
    }}
   }
  }}catch{return "UNAVAILABLE";}
 }
}
'@
}
function Get-CurrentBoot { ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime).ToUniversalTime().ToString('o') }
function Read-Status { try { [OracleBootReadOnly]::Status() | ConvertFrom-Json } catch { $null } }
function Own-Task {
 $task=Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
 if($task -and ($task.Actions.Count -ne 1 -or $task.Actions[0].Execute -ne "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -or $task.Actions[0].Arguments -notlike ('*"'+$TrustedScript+'"*'))){throw 'FOREIGN_TASK_REFUSED'}
 return $task
}
if($Mode -in @('SelfTest','SelfTestConnected')){
 if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'HOSTED_SELF_TEST_ONLY'}
 $counts=[OracleBootReadOnly]::GuardCounts();if($counts.Count -ne 2 -or $counts[0] -lt 0 -or $counts[1] -lt 0){throw 'WFP_ABI_FAILED'}
 [void][OracleBootReadOnly]::InteractiveUserPresent()
 if($Mode -eq 'SelfTestConnected'){
  $state=Read-Status
  if(-not $state -or $state.mode -ne 'connected' -or -not $state.guard -or $counts[0] -lt 16 -or $counts[1] -lt 8){throw 'CONNECTED_READ_ONLY_OBSERVATION_FAILED'}
  $target=[Net.Dns]::GetHostAddresses('stun.cloudflare.com') | Where-Object AddressFamily -eq InterNetwork | Select-Object -First 1
  $physical=[OracleBootReadOnly]::PhysicalProbe(4,$target.ToString())
  if(-not $physical.Blocked -or $physical.Sent){throw 'CONNECTED_PHYSICAL_DENIAL_REQUIRED'}
  $exit4=[OracleBootReadOnly]::DefaultExit(4);$exit6=[OracleBootReadOnly]::DefaultExit(6)
  Write-Host ('OBSERVER_DEFAULT_V4='+$exit4+';V6='+$exit6)
  if($exit4 -ne 'ORACLE' -or $exit6 -ne 'ORACLE'){throw 'CONNECTED_DEFAULT_DUALSTACK_PROBE_FAILED'}
  if(Test-Path $BootRoot){throw 'EXISTING_CLOUD_BOOT_FIXTURE_REFUSED'}
  try{
   & $PSCommandPath -Mode Prepare | Out-Null
   Start-ScheduledTask -TaskName $TaskName
   $limit=[Diagnostics.Stopwatch]::StartNew();$sameFile=Join-Path $BootRoot 'same-boot-check.json'
   while(-not (Test-Path $sameFile) -and $limit.Elapsed.TotalSeconds -lt 25){Start-Sleep -Milliseconds 250}
   if(-not (Test-Path $sameFile)){throw 'SYSTEM_STARTUP_OBSERVER_SELF_TEST_TIMEOUT'}
   $observed=Get-Content -Raw -LiteralPath $sameFile | ConvertFrom-Json
   if(-not $observed.not_reboot_acceptance -or -not $observed.service_observed -or $observed.mode -ne 'connected' -or $observed.persistent -lt 16 -or $observed.boot -lt 8 -or (Test-Path $ReportFile)){throw 'SAME_BOOT_MUST_NOT_CREATE_REBOOT_ACCEPTANCE'}
   Write-Host 'REAL_SYSTEM_TASK_CAN_OBSERVE_GUARD_WITHOUT_CLAIMING_REBOOT=PASS'
  }finally{
   if(Own-Task){Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false}
   if(Test-Path $BootRoot){
    if(-not (Test-Path $ConfigFile) -or (Get-Content -Raw -LiteralPath $ConfigFile | ConvertFrom-Json).owner -ne 'oracle-proxy-one-shot-boot'){throw 'FOREIGN_FIXTURE_FOLDER_REFUSED'}
    Remove-Item -LiteralPath $BootRoot -Recurse -Force
   }
  }

 }
 Write-Host 'READ_ONLY_BOOT_OBSERVER_ABI_AND_SCOPE=PASS'
 return
}
if($Mode -eq 'Prepare'){
 if(-not $Admin){throw 'ADMIN_REQUIRED'}
 if(Test-Path $BootRoot){throw 'EXISTING_BOOT_OBSERVER_FOLDER_REFUSED'}
 if(Own-Task){throw 'EXISTING_BOOT_OBSERVER_TASK_REFUSED'}
 $state=Read-Status
 if(-not $state -or $state.product_version -ne $ExpectedVersion -or $state.mode -ne 'connected' -or -not $state.intent -or -not $state.guard -or $state.ipv6_policy -ne 'tunnel'){throw 'CONNECT_PINNED_RC20_DUALSTACK_FIRST'}
 $counts=[OracleBootReadOnly]::GuardCounts();if($counts[0] -lt 16 -or $counts[1] -lt 8){throw 'PERSISTENT_BOOT_GUARD_NOT_OBSERVED'}
 $targets=@{};foreach($family in @(4,6)){
  $af=if($family -eq 4){[Net.Sockets.AddressFamily]::InterNetwork}else{[Net.Sockets.AddressFamily]::InterNetworkV6}
  $ip=[Net.Dns]::GetHostAddresses('stun.cloudflare.com') | Where-Object AddressFamily -eq $af | Select-Object -First 1
  if(-not $ip){throw 'PUBLIC_STUN_TARGET_REQUIRED'}
  $targets["v$family"]=$ip.ToString()
 }
 $preflight=[OracleBootReadOnly]::PhysicalProbe(4,$targets.v4)
 if(-not $preflight.Blocked -or $preflight.Sent){throw 'PHYSICAL_DENIAL_NOT_PROVEN_NO_TASK_CREATED'}
 New-Item -ItemType Directory $BootRoot | Out-Null
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 foreach($identifier in @('S-1-5-18','S-1-5-32-544')){
  $identity=New-Object Security.Principal.SecurityIdentifier($identifier)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
 }
 $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
 Set-Acl $BootRoot $acl
 Copy-Item -LiteralPath $PSCommandPath -Destination $TrustedScript
 $config=@{schema=1;owner='oracle-proxy-one-shot-boot';previous_boot=(Get-CurrentBoot);armed_utc=[DateTime]::UtcNow.ToString('o');version=$ExpectedVersion;v4=$targets.v4;v6=$targets.v6;script_sha256=(Get-FileHash $TrustedScript -Algorithm SHA256).Hash}
 $config | ConvertTo-Json | Set-Content -LiteralPath $ConfigFile -Encoding UTF8
 $action=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$TrustedScript+'" -Mode Collect')
 $trigger=New-ScheduledTaskTrigger -AtStartup
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
 try{Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User SYSTEM -RunLevel Highest -Description 'One-shot read-only Oracle Proxy boot observation; never initiates reboot' | Out-Null}
 catch{Remove-Item -LiteralPath $BootRoot -Recurse -Force;throw}
 Write-Host 'BOOT_OBSERVER=ARMED; NO_REBOOT_INITIATED'
 Write-Host 'Keep VPN connected. Restart Windows normally without closing/disconnecting Oracle Proxy. Wait 120 seconds at the sign-in screen, then sign in and run -Mode Report.'
 return
}
if($Mode -eq 'Collect'){
 if(-not $System){throw 'SYSTEM_COLLECTOR_REQUIRED'}
 $config=Get-Content -Raw -LiteralPath $ConfigFile | ConvertFrom-Json
 if($config.owner -ne 'oracle-proxy-one-shot-boot' -or $config.schema -ne 1 -or (Get-FileHash $TrustedScript -Algorithm SHA256).Hash -ne $config.script_sha256){throw 'OBSERVER_OWNERSHIP_FAILED'}
 $boot=Get-CurrentBoot
 if($boot -eq $config.previous_boot){
  $same=Read-Status;$sameCounts=[OracleBootReadOnly]::GuardCounts()
  @{not_reboot_acceptance=$true;service_observed=([bool]$same);mode=if($same){$same.mode}else{'unavailable'};persistent=$sameCounts[0];boot=$sameCounts[1]} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $BootRoot 'same-boot-check.tmp') -Encoding UTF8
  Move-Item -LiteralPath (Join-Path $BootRoot 'same-boot-check.tmp') -Destination (Join-Path $BootRoot 'same-boot-check.json') -Force
  Write-Host 'WAITING_FOR_REAL_REBOOT';return
 }
 $rows=New-Object Collections.Generic.List[object]
 try{
  if(([DateTime]::UtcNow-([DateTime]$config.armed_utc).ToUniversalTime()).TotalHours -gt 24){throw 'OBSERVER_ARM_EXPIRED'}
  $clock=[Diagnostics.Stopwatch]::StartNew()
  while($clock.Elapsed.TotalSeconds -lt 80){
   $state=Read-Status;$counts=@(-1,-1);try{$counts=[OracleBootReadOnly]::GuardCounts()}catch{}
   $interactive=$true;try{$interactive=[OracleBootReadOnly]::InteractiveUserPresent()}catch{}
   $v4=[OracleBootReadOnly]::PhysicalProbe(4,$config.v4);$v6=[OracleBootReadOnly]::PhysicalProbe(6,$config.v6)
   $rows.Add(@{at_utc=[DateTime]::UtcNow.ToString('o');interactive_user_present=$interactive;persistent_filters=$counts[0];boot_filters=$counts[1];service_mode=if($state){$state.mode}else{'unavailable'};intent=if($state){$state.intent}else{$null};guard=if($state){$state.guard}else{$null};version=if($state){$state.product_version}else{$null};physical_v4=$v4;physical_v6=$v6;default_v4=[OracleBootReadOnly]::DefaultExit(4);default_v6=[OracleBootReadOnly]::DefaultExit(6)})
   Start-Sleep -Seconds 2
  }
  @{schema=1;owner=$config.owner;boot_changed=$true;pre_login_scope='Only the observed startup-task interval; not all earliest kernel boot traffic';samples=$rows.ToArray()} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $ReportFile -Encoding UTF8
 }catch{
  @{schema=1;owner=$config.owner;boot_changed=$true;collection_error=$_.Exception.GetType().Name;samples=$rows.ToArray()} | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath $ReportFile -Encoding UTF8
 }finally{if(Own-Task){Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false}}
 return
}
if($Mode -eq 'Report'){
 if(-not (Test-Path $ReportFile)){Write-Host 'NO_COMPLETED_REAL_REBOOT_REPORT';return}
 $report=Get-Content -Raw -LiteralPath $ReportFile | ConvertFrom-Json
 if($report.owner -ne 'oracle-proxy-one-shot-boot' -or $report.schema -ne 1 -or -not $report.boot_changed){throw 'INVALID_BOOT_REPORT'}
 $samples=@($report.samples);$pre=@($samples | Where-Object {-not $_.interactive_user_present})
 $bad=@($samples | Where-Object {$_.physical_v4.Sent -or $_.physical_v6.Sent -or $_.physical_v4.MatchingReply -or $_.physical_v6.MatchingReply -or $_.default_v4 -eq 'OTHER_EXIT' -or $_.default_v6 -eq 'OTHER_EXIT'})
 $ready=@($pre | Where-Object {$_.version -eq $ExpectedVersion -and $_.service_mode -eq 'connected' -and $_.intent -and $_.guard -and $_.persistent_filters -ge 16 -and $_.boot_filters -ge 8 -and $_.default_v4 -eq 'ORACLE' -and $_.default_v6 -eq 'ORACLE'})
 $v4=@($pre | Where-Object {$_.physical_v4.AddressPresent -and $_.physical_v4.Blocked})
 $v6=@($pre | Where-Object {$_.physical_v6.AddressPresent -and $_.physical_v6.Blocked})
 @{boot_changed=$report.boot_changed;sample_count=$samples.Count;pre_login_samples=$pre.Count;pre_login_dualstack_ready_samples=$ready.Count;physical_v4_denied_samples=$v4.Count;physical_v6_denied_samples=$v6.Count;potential_egress_samples=$bad.Count;collector_error=$report.collection_error;result=if($report.collection_error -or $bad.Count -gt 0){'REVIEW_REQUIRED'}elseif($pre.Count -eq 0 -or $ready.Count -eq 0 -or $v4.Count -eq 0){'INCONCLUSIVE'}elseif($v6.Count -eq 0){'PASS_OBSERVED_BOOT_SCOPE_NATIVE_PHYSICAL_IPV6_NOT_COVERED'}else{'PASS_OBSERVED_BOOT_SCOPE'};scope='Observed pre-login interval only; a native IPv6 physical address is required for that family coverage';temporary_task_remaining=[bool](Own-Task)} | ConvertTo-Json -Depth 4
}
