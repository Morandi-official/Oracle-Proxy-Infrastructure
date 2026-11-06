# Non-shipped synthetic SCM/RPC proof. No VPN keys, login, server or routes.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'DISPOSABLE_HOSTED_WINDOWS_REQUIRED'}
if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){throw 'PREEXISTING_SERVICE_REFUSED'}
$collector=Join-Path (Split-Path $PSScriptRoot -Parent) 'Measure-NativeUdp.ps1'
. $collector -DefinitionsOnly
$rogue=[IO.Pipes.NamedPipeServerStream]::new('OracleProxy.Control.v1',[IO.Pipes.PipeDirection]::InOut,1,[IO.Pipes.PipeTransmissionMode]::Byte,[IO.Pipes.PipeOptions]::Asynchronous)
try{
 $pending=$rogue.WaitForConnectionAsync();$refused=$false
 try{$null=Invoke-OPDiagnosticControl 'StartUdpDiagnostics'}catch{if($_.Exception.Message -ne 'SERVICE_IDENTITY_NOT_VERIFIED'){throw};$refused=$true}
 if(-not $refused -or -not $pending.Wait(3000) -or $rogue.ReadByte() -ne -1){throw 'ROGUE_SERVICE_RECEIVED_DIAGNOSTIC_COMMAND'}
}finally{$rogue.Dispose()}
Write-Host 'AUTOMATIC_CONTRAST_SCM_IDENTITY_BEFORE_COMMAND=PASS'
$root=Join-Path $env:RUNNER_TEMP ('nic-rpc-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$exe=Join-Path $root 'Fixture.exe';$mode=Join-Path $root 'mode.txt';$log=Join-Path $root 'commands.txt'
[IO.File]::WriteAllText($mode,'normal')
$source=@'
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.ServiceProcess;
public class NicFixture:ServiceBase {
 string mode,log;volatile bool live;NamedPipeServerStream current;
 public NicFixture(string m,string l){ServiceName="OracleProxyService";mode=m;log=l;AutoLog=false;CanStop=true;}
 protected override void OnStart(string[] args){live=true;new Thread(Serve){IsBackground=true}.Start();}
 protected override void OnStop(){live=false;try{if(current!=null)current.Dispose();}catch{}}
 string Trials(){var result=new StringBuilder();foreach(string ip in new[]{"152.67.156.100","141.147.78.44"})foreach(int port in new[]{443,8443,51820}){
  if(result.Length>0)result.Append(",");result.Append("{\"address\":\""+ip+"\",\"port\":"+port+",\"verdict\":\"PASSED\",\"client\":{\"egress_verified\":true,\"token\":\"SYNTHETIC_PRIVATE_MARKER\",\"counters\":{\"tx_initiations\":1,\"rx_responses\":1}},\"server\":{\"capture\":{\"rx_initiations\":1,\"tx_responses\":1,\"complete_observation\":true}}}");}return result.ToString();}
 void Serve(){string id="";bool running=false,cancelled=false;int polls=0;while(live)try{
  using(var pipe=new NamedPipeServerStream("OracleProxy.Control.v1",PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.None)){
   current=pipe;pipe.WaitForConnection();string frame=new StreamReader(pipe,new UTF8Encoding(false,true),false,1024,true).ReadLine();
   string cmd=Regex.Match(frame??"","\"command\"\\s*:\\s*\"([A-Za-z]+)\"").Groups[1].Value;
   if(cmd!="Status"&&cmd!="StartUdpDiagnostics"&&cmd!="CancelUdpDiagnostics")throw new IOException();
   File.AppendAllText(log,cmd+"\n");string setting=File.ReadAllText(mode).Trim();
   if(cmd=="StartUdpDiagnostics"){id=Guid.NewGuid().ToString("D");running=true;cancelled=false;polls=0;}
   if(cmd=="CancelUdpDiagnostics"){running=false;cancelled=true;}
   if(cmd=="Status"&&running&&setting!="hold"&&++polls>=2)running=false;
   bool connected=setting=="connected";
   string diag=id.Length==0?"null":"{\"diagnostic_id\":\""+id+"\",\"running\":"+(running?"true":"false")+",\"phase\":\""+(running?"running":cancelled?"cancelled":"complete")+"\",\"server_capture_closed\":"+(!running?"true":"false")+",\"current_trial\":0,\"password\":\"SYNTHETIC_PRIVATE_MARKER\",\"trials\":["+Trials()+"]}";
   string response="{\"schema\":1,\"ok\":true,\"mode\":\""+(connected?"connected":"disconnected")+"\",\"intent\":"+(connected?"true":"false")+",\"guard\":"+(connected?"true":"false")+",\"login_authenticated\":true,\"device_registered\":true,\"udp_diagnostics_available\":true,\"token\":\"SYNTHETIC_PRIVATE_MARKER\",\"udp_diagnostic\":"+diag+"}";
   byte[] body=Encoding.UTF8.GetBytes(response+"\n");pipe.Write(body,0,body.Length);pipe.Flush();
  }
 }catch{if(!live)return;}}
 public static void Main(string[] args){ServiceBase.Run(new NicFixture(args[0],args[1]));}
}
'@
$null=Add-Type -TypeDefinition $source -ReferencedAssemblies @('System.dll','System.Core.dll','System.ServiceProcess.dll') -OutputAssembly $exe -OutputType ConsoleApplication
$created=$false
try{
 & sc.exe create OracleProxyService binPath= ('"'+$exe+'" "'+$mode+'" "'+$log+'"') start= demand | Out-Null
 if($LASTEXITCODE -ne 0){throw 'FIXTURE_CREATE_FAILED'};$created=$true
 & sc.exe start OracleProxyService | Out-Null
 $service=Get-Service OracleProxyService
 try{$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(10))}finally{$service.Dispose()}
 # Copy the public manual leftover pattern only while the global monitor is idle.
 if(-not (Test-OPIdle (Invoke-OPPktmon -Arguments @('status'))) -or -not (Test-OPNoFilters (Invoke-OPPktmon -Arguments @('filter','list')))){throw 'PREEXISTING_MONITOR_OR_FILTERS_REFUSED'}
 Invoke-OPPktmon -Arguments @('filter','add','ProxySecondary443','-i','141.147.78.44','-t','UDP','-p','443') | Out-Null
 $text=(& $collector -AutomaticContrast -ClearPreviousContrastFilter 6>&1 | Out-String)
 if($text.Contains('SYNTHETIC_PRIVATE_MARKER') -or $text -notmatch 'OBSERVED_ENDPOINT=152.67.156.100:443' -or $text -notmatch 'OBSERVED_ENDPOINT=141.147.78.44:443'){throw 'AUTOMATIC_REPORT_REDACTION_OR_TARGET_FAILED'}
 if(@(Get-Content $log | Where-Object {$_ -eq 'StartUdpDiagnostics'}).Count -ne 2){throw 'AUTOMATIC_TWO_ROUNDS_NOT_TRIGGERED_EXACTLY_ONCE'}
 if(-not (Test-OPIdle (Invoke-OPPktmon -Arguments @('status'))) -or -not (Test-OPNoFilters (Invoke-OPPktmon -Arguments @('filter','list')))){throw 'AUTOMATIC_CAPTURE_CLEANUP_FAILED'}
 Write-Host 'REAL_SCM_TWO_AUTOMATIC_SYNTHETIC_DIAGNOSES_COUNTER_CLEANUP_AND_REDACTION=PASS'
 [IO.File]::WriteAllText($mode,'connected');$before=@(Get-Content $log).Count;$refused=$false
 try{& $collector -AutomaticContrast}catch{if($_.Exception.Message -ne 'KEEP_PROXY_DISCONNECTED_FIRST'){throw};$refused=$true}
 if(-not $refused -or @(Get-Content $log).Count -ne $before+1){throw 'AUTOMATIC_CONNECTED_SESSION_WAS_MUTATED'}
 Write-Host 'CONNECTED_SESSION_REFUSED_WITH_STATUS_ONLY=PASS'
 [IO.File]::WriteAllText($mode,'hold');$initial=Invoke-OPDiagnosticControl 'Status';$refused=$false
 try{Invoke-OPAutomaticDiagnostic -Duration 1 -Initial $initial}catch{if($_.Exception.Message -ne 'DIAGNOSTIC_DEADLINE'){throw};$refused=$true}
 if(-not $refused -or @(Get-Content $log | Where-Object {$_ -eq 'CancelUdpDiagnostics'}).Count -ne 1){throw 'AUTOMATIC_DEADLINE_DID_NOT_CANCEL_OWN_DIAGNOSIS'}
 Write-Host 'OWNED_DIAGNOSTIC_DEADLINE_CANCELS_WITHOUT_DISCONNECT=PASS'
 if(Get-ChildItem -Path . -Filter '*.etl' -ErrorAction SilentlyContinue){throw 'AUTOMATIC_COUNTERS_CREATED_PACKET_LOG'}
}finally{
 if($created){
  & sc.exe stop OracleProxyService | Out-Null
  $service=Get-Service OracleProxyService -ErrorAction SilentlyContinue
  if($service){try{$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(15))}finally{$service.Dispose()}}
  & sc.exe delete OracleProxyService | Out-Null
 }
 Remove-Item -LiteralPath $root -Recurse -Force
}
