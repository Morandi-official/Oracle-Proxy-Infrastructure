# Synthetic service RPC proof only; no VPN, accounts, packets or production service.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable hosted Windows only'}
if(Get-Service OracleProxyService -ErrorAction SilentlyContinue){throw 'PREEXISTING_SERVICE_REFUSED'}
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'Test-LegacyNativePorts.ps1') -DefinitionsOnly
$directory=Join-Path $env:RUNNER_TEMP ('op-rpc-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $directory
$fixture=Join-Path $directory 'Fixture.exe';$mode=Join-Path $directory 'mode.txt';$log=Join-Path $directory 'commands.txt'
[IO.File]::WriteAllText($mode,'normal')
$source=@'
using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.ServiceProcess;
public class OPFixture:ServiceBase {
 string mode, log; volatile bool running; NamedPipeServerStream current;
 public OPFixture(string m,string l){ServiceName="OracleProxyService";mode=m;log=l;AutoLog=false;CanStop=true;}
 protected override void OnStart(string[] args){running=true;var worker=new Thread(Serve);worker.IsBackground=true;worker.Start();}
 protected override void OnStop(){running=false;try{if(current!=null)current.Dispose();}catch{}}
 void Serve(){bool connected=false;while(running){try{
  using(var pipe=new NamedPipeServerStream("OracleProxy.Control.v1",PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.None)){
   current=pipe;pipe.WaitForConnection();
   string frame=new StreamReader(pipe,new UTF8Encoding(false,true),false,1024,true).ReadLine();
   string command=Regex.Match(frame??"","\"command\"\\s*:\\s*\"([A-Za-z]+)\"").Groups[1].Value;
   if(command!="Status"&&command!="Disconnect"&&command!="PreferUdp"&&command!="Connect")throw new IOException();
   File.AppendAllText(log,command+"\n");string setting=File.ReadAllText(mode).Trim();
   if(setting=="delay"&&(command=="Disconnect"||command=="Connect"))Thread.Sleep(14000);
   if(setting=="timeout")Thread.Sleep(2000);
   if(command=="Connect")connected=true;if(command=="Disconnect")connected=false;
   string response="{\"schema\":1,\"ok\":true,\"device_registered\":true,\"mode\":\""+(connected?"connected":"disconnected")+"\",\"guard\":"+(connected?"true":"false")+",\"native_udp_port_preference\":0,\"native_udp_selected_port\":443,\"note\":\"中文\"}";
   if(setting=="oversize")response=new string('x',65537);
   if(setting=="truncated")response="{\"schema\":1";
   byte[] bytes=Encoding.UTF8.GetBytes(response+(setting=="truncated"?"":"\n"));
   if(setting=="fragment"){foreach(byte b in bytes){pipe.WriteByte(b);pipe.Flush();}}else{pipe.Write(bytes,0,bytes.Length);pipe.Flush();}
  }
 }catch{if(!running)return;}}}
 public static void Main(string[] args){ServiceBase.Run(new OPFixture(args[0],args[1]));}
}
'@
$null=Add-Type -TypeDefinition $source -ReferencedAssemblies @('System.dll','System.Core.dll','System.ServiceProcess.dll') -OutputAssembly $fixture -OutputType ConsoleApplication
$created=$false
try{
    $binary='"'+$fixture+'" "'+$mode+'" "'+$log+'"'
    & sc.exe create OracleProxyService binPath= $binary start= demand | Out-Null
    if($LASTEXITCODE -ne 0){throw 'FIXTURE_SERVICE_CREATE_FAILED'};$created=$true
    & sc.exe start OracleProxyService | Out-Null
    if($LASTEXITCODE -ne 0){throw 'FIXTURE_SERVICE_START_FAILED'}
    $service=Get-Service OracleProxyService
    try{$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running,[TimeSpan]::FromSeconds(10))}finally{$service.Dispose()}
    $state=Invoke-OPFixedControl 'Status'
    if($state.mode -ne 'disconnected'){throw 'REAL_SCM_PIPE_STATUS_FAILED'}
    [IO.File]::WriteAllText($mode,'delay')
    foreach($command in @('Disconnect','PreferUdp','Connect')){
        $watch=[Diagnostics.Stopwatch]::StartNew();$state=Invoke-OPFixedControl $command
        if($command -ne 'PreferUdp' -and $watch.ElapsedMilliseconds -lt 13000){throw 'DELAYED_RESPONSE_NOT_EXERCISED'}
    }
    if($state.mode -ne 'connected' -or $state.native_udp_port_preference -ne 0){throw 'FIXED_SEQUENCE_FAILED'}
    Write-Host 'REAL_SCM_DELAYED_14S_DISCONNECT_AND_CONNECT_RESPONSES=PASS'
    [IO.File]::WriteAllText($mode,'fragment')
    if((Invoke-OPFixedControl 'Status').note -ne '中文'){throw 'FRAGMENTED_UTF8_FRAME_FAILED'}
    Write-Host 'FRAGMENTED_UTF8_SERVICE_FRAME=PASS'
    foreach($case in @(@('oversize','SERVICE_FRAME_TOO_LARGE'),@('truncated','INCOMPLETE_SERVICE_FRAME_STATUS'),@('timeout','SERVICE_RESPONSE_TIMEOUT_STATUS'))){
        [IO.File]::WriteAllText($mode,$case[0]);$before=@(Get-Content $log).Count;$refused=$false
        try{$null=Invoke-OPFixedControl 'Status' -ResponseSeconds 1}catch{if($_.Exception.Message -ne $case[1]){throw};$refused=$true}
        Start-Sleep -Milliseconds 1500
        if(-not $refused -or @(Get-Content $log).Count -ne $before+1){throw 'MALFORMED_OR_TIMEOUT_FRAME_RETRY_OR_REFUSAL_FAILED'}
    }
    Write-Host 'FRAME_LIMIT_EOF_AND_DEADLINE_WITHOUT_MUTATING_RETRY=PASS'
}finally{
    if($created){
        & sc.exe stop OracleProxyService | Out-Null
        $service=Get-Service OracleProxyService -ErrorAction SilentlyContinue
        if($service){try{$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(15))}finally{$service.Dispose()}}
        & sc.exe delete OracleProxyService | Out-Null
    }
    Start-Sleep -Milliseconds 500
    Remove-Item -LiteralPath $directory -Recurse -Force
}
