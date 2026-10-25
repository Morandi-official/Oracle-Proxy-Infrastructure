# Diagnostic only: fixed authenticated service commands, never credentials or keys.
[CmdletBinding()]
param([switch]$DefinitionsOnly)
$ErrorActionPreference='Stop'
if(-not ('OracleProxyPortDiagnostic' -as [type])){
Add-Type @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class OracleProxyPortDiagnostic {
 [DllImport("kernel32.dll", SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
}
'@
}
function Invoke-OPFixedControl([ValidateSet('Status','Disconnect','PreferUdp','Connect')][string]$Command,[ValidateRange(1,60)][int]$ResponseSeconds=60){
    if($Command -ne 'Status'){Write-Host ('SERVICE_COMMAND_BEGIN='+$Command)}
    $pipe=[IO.Pipes.NamedPipeClientStream]::new('.', 'OracleProxy.Control.v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Impersonation)
    try{
        $pipe.Connect(3000)
        [uint32]$serverId=0
        if(-not [OracleProxyPortDiagnostic]::GetNamedPipeServerProcessId($pipe.SafePipeHandle,[ref]$serverId)){throw 'PIPE_IDENTITY_UNAVAILABLE'}
        $service=Get-CimInstance Win32_Service -Filter "Name='OracleProxyService'"
        if($null -eq $service -or $service.State -ne 'Running' -or $serverId -eq 0 -or $service.ProcessId -ne $serverId){throw 'SERVICE_IDENTITY_NOT_VERIFIED'}
        $frame=[Text.Encoding]::UTF8.GetBytes((@{version=1;command=$Command} | ConvertTo-Json -Compress)+"`n")
        $pipe.Write($frame,0,$frame.Length);$pipe.Flush()
        $buffer=New-Object byte[] 65537;$count=0;$clock=[Diagnostics.Stopwatch]::StartNew()
        while($count -lt $buffer.Length){
            $left=$ResponseSeconds*1000-[int]$clock.ElapsedMilliseconds
            if($left -le 0){throw ('SERVICE_RESPONSE_TIMEOUT_'+$Command.ToUpperInvariant())}
            $read=$pipe.ReadAsync($buffer,$count,[Math]::Min(4096,$buffer.Length-$count))
            if(-not $read.Wait($left)){throw ('SERVICE_RESPONSE_TIMEOUT_'+$Command.ToUpperInvariant())}
            if($read.Result -le 0){throw ('INCOMPLETE_SERVICE_FRAME_'+$Command.ToUpperInvariant())}
            $newline=[Array]::IndexOf($buffer,[byte]10,$count,$read.Result)
            $count+=$read.Result
            if($newline -ge 0){
                if($newline -gt 65536){throw 'SERVICE_FRAME_TOO_LARGE'}
                $state=[Text.UTF8Encoding]::new($false,$true).GetString($buffer,0,$newline) | ConvertFrom-Json
                if($state.schema -ne 1 -or $state.ok -ne $true){
                    if([string]$state.error -match '\A[A-Z0-9_]{1,100}\z'){Write-Host ('SERVICE_ERROR='+$state.error)}
                    throw ('FIXED_SERVICE_OPERATION_FAILED_'+$Command.ToUpperInvariant())
                }
                if($Command -ne 'Status'){Write-Host ('SERVICE_COMMAND_DONE='+$Command)}
                return $state
            }
            if($count -gt 65536){throw 'SERVICE_FRAME_TOO_LARGE'}
        }
        throw 'SERVICE_FRAME_TOO_LARGE'
    }finally{$pipe.Dispose()}
}
if($DefinitionsOnly){return}
$initial=Invoke-OPFixedControl 'Status'
if($initial.device_registered -ne $true){throw 'LOGIN_AND_CONFIRM_DEVICE_FIRST'}
Read-Host 'This diagnostic disconnects, then tests native UDP 51820/443. Keep the client open; press Enter to start'
try{
    $null=Invoke-OPFixedControl 'Disconnect'
    $null=Invoke-OPFixedControl 'PreferUdp'
    $null=Invoke-OPFixedControl 'Connect'
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do{
        Start-Sleep -Milliseconds 500
        $state=Invoke-OPFixedControl 'Status'
    }while($state.mode -ne 'connected' -and $watch.ElapsedMilliseconds -lt 65000)
    $report=[ordered]@{utc=[DateTime]::UtcNow.ToString('o')}
    foreach($key in @('product_version','mode','error','guard','transport','transport_preference','native_udp_port_preference','native_udp_selected_port','carrier_stage','client_handshake_reply','verified_exit_ip')){$report[$key]=$state.$key}
    if($state.native_udp_attempt){$report['native_attempt']=$state.native_udp_attempt}
    Write-Host '=== ORACLE_LEGACY_NATIVE_PORTS_BEGIN ==='
    Write-Host ($report | ConvertTo-Json -Depth 8)
    Write-Host '=== ORACLE_LEGACY_NATIVE_PORTS_END ==='
}catch{
    # A timeout does not cancel the command already executing in the service.
    # Do not submit an ambiguous second mutation or hide the first failure.
    Write-Host 'DIAGNOSTIC_STOPPED_NO_AUTOMATIC_RETRY'
    Write-Host 'Check the client status; use its normal disconnect/recovery action if needed.'
    throw
}
