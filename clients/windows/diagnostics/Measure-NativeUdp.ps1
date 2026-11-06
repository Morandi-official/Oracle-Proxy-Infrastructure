#requires -RunAsAdministrator
# Bounded counters only. No packet logging, firewall, route or adapter changes.
[CmdletBinding()]
param([ValidateRange(20,180)][int]$Seconds=40,[ValidateSet(51820,443,8443)][int]$Port=51820,
    [ValidateSet('152.67.156.100','141.147.78.44')][string]$RemoteAddress='152.67.156.100',
    [switch]$SixEntranceDiagnostic,[switch]$AutomaticContrast,[switch]$ClearPreviousContrastFilter,
    [switch]$AutoServiceDiagnostic,[switch]$DefinitionsOnly)
$ErrorActionPreference='Stop'
function Invoke-OPUtf8Process([string]$Executable,[string[]]$Arguments){
    # pktmon emits UTF-8 on redirected pipes even when the console is CP936.
    # Read those pipes explicitly; PowerShell 5.1 otherwise decodes with CP936.
    foreach($argument in $Arguments){
        if($argument -notmatch '\A[a-zA-Z0-9_.:-]+\z'){throw 'UNSUPPORTED_NATIVE_ARGUMENT'}
    }
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Executable
    $info.Arguments=$Arguments -join ' '
    $info.UseShellExecute=$false
    $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true
    $info.RedirectStandardError=$true
    $utf8=New-Object Text.UTF8Encoding($false,$true)
    $info.StandardOutputEncoding=$utf8
    $info.StandardErrorEncoding=$utf8
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$info
    try{
        if(-not $process.Start()){throw 'NATIVE_START_FAILED'}
        $stdout=$process.StandardOutput.ReadToEndAsync()
        $stderr=$process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $result=$stdout.GetAwaiter().GetResult()
        $errorText=$stderr.GetAwaiter().GetResult()
        if($process.ExitCode -ne 0){throw ('Packet Monitor failed: '+($Arguments -join ' '))}
        if($errorText.Trim()){throw 'UNEXPECTED_NATIVE_STDERR'}
        return $result
    }finally{$process.Dispose()}
}
function Invoke-OPPktmon([string[]]$Arguments){
    return Invoke-OPUtf8Process -Executable "$env:WINDIR\System32\pktmon.exe" -Arguments $Arguments
}
function Test-OPIdle([string]$Text){
    $value=$Text.Trim()
    return $value -eq 'Packet Monitor is not running.' -or $value -eq '数据包监视器没有运行。'
}
function Test-OPNoFilters([string]$Text){
    return $Text -match '\A\s*Packet Filters:\s*None\s*\z' -or $Text -match '\A\s*数据包筛选器:\s*无\s*\z'
}
function Clear-OPOwnedFilters([string[]]$Names){
    if(-not $Names.Count){return}
    if(-not (Test-OPIdle (Invoke-OPPktmon -Arguments @('status')))){throw 'ACTIVE_MONITOR_REFUSE_FILTER_CLEAR'}
    $current=Invoke-OPPktmon -Arguments @('filter','list')
    if(Test-OPNoFilters $current){return}
    $rows=@([regex]::Matches($current,'(?m)^\s*\d+\s+(\S+)\s+.+$'))
    $found=@($rows | ForEach-Object {$_.Groups[1].Value})
    if($found.Count -ne $Names.Count -or @($found | Select-Object -Unique).Count -ne $found.Count -or @($found | Where-Object {$Names -notcontains $_}).Count){throw 'FILTERS_CHANGED_REFUSE_CLEAR'}
    # This command removes ALL filters. Use it only after proving the entire
    # stopped list is still ours; never simulate selective removal by name.
    Invoke-OPPktmon -Arguments @('filter','remove') | Out-Null
    if(-not (Test-OPNoFilters (Invoke-OPPktmon -Arguments @('filter','list')))){throw 'FILTER_CLEANUP_NOT_VERIFIED'}
}
function Read-OPCounterText {
    # Keep pktmon's original localized text. Empty/no-traffic output is valid;
    # neither localized JSON property names nor a populated Group are required.
    $text=Invoke-OPPktmon -Arguments @('counters','--include-hidden','--drop-reason')
    if($text.Length -gt 1048576){throw 'COUNTER_OUTPUT_LIMIT'}
    return $text
}
function Get-OPSampleTargets([int]$Duration,[bool]$SixEntrance){
    $points=if($SixEntrance){@(5,15,30,60,90,120,$Duration)}else{@(5,10,15,$Duration)}
    return @($points | Where-Object {$_ -le $Duration} | Sort-Object -Unique)
}

# Fixed, credential-free RPC. Authenticate the pipe server through SCM before
# sending even a status command. Never accept arbitrary commands or arguments.
if(-not ('ProxyUdpNicPipe' -as [type])){
Add-Type @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class ProxyUdpNicPipe {
 [DllImport("kernel32.dll", SetLastError=true)]
 [return: MarshalAs(UnmanagedType.Bool)]
 public static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint pid);
}
'@
}
function Invoke-OPDiagnosticControl([ValidateSet('Status','StartUdpDiagnostics','CancelUdpDiagnostics')][string]$Command,[ValidateRange(1,45)][int]$ResponseSeconds=8){
    $pipe=[IO.Pipes.NamedPipeClientStream]::new('.', 'OracleProxy.Control.v1', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::Asynchronous, [Security.Principal.TokenImpersonationLevel]::Impersonation)
    try{
        $pipe.Connect(3000);[uint32]$serverId=0
        if(-not [ProxyUdpNicPipe]::GetNamedPipeServerProcessId($pipe.SafePipeHandle,[ref]$serverId)){throw 'PIPE_IDENTITY_UNAVAILABLE'}
        $service=Get-CimInstance Win32_Service -Filter "Name='OracleProxyService'"
        if($null -eq $service -or $service.State -ne 'Running' -or $serverId -eq 0 -or $service.ProcessId -ne $serverId){throw 'SERVICE_IDENTITY_NOT_VERIFIED'}
        $frame=[Text.Encoding]::UTF8.GetBytes((@{version=1;command=$Command} | ConvertTo-Json -Compress)+"`n")
        $pipe.Write($frame,0,$frame.Length);$pipe.Flush()
        $buffer=New-Object byte[] 65537;$count=0;$clock=[Diagnostics.Stopwatch]::StartNew()
        while($count -lt $buffer.Length){
            $left=$ResponseSeconds*1000-[int]$clock.ElapsedMilliseconds
            if($left -le 0){throw 'DIAGNOSTIC_SERVICE_RESPONSE_TIMEOUT'}
            $read=$pipe.ReadAsync($buffer,$count,[Math]::Min(4096,$buffer.Length-$count))
            if(-not $read.Wait($left)){throw 'DIAGNOSTIC_SERVICE_RESPONSE_TIMEOUT'}
            if($read.Result -le 0){throw 'INCOMPLETE_SERVICE_FRAME'}
            $newline=[Array]::IndexOf($buffer,[byte]10,$count,$read.Result);$count+=$read.Result
            if($newline -ge 0){
                if($newline -gt 65536){throw 'SERVICE_FRAME_TOO_LARGE'}
                $state=[Text.UTF8Encoding]::new($false,$true).GetString($buffer,0,$newline) | ConvertFrom-Json
                if($state.schema -ne 1 -or $state.ok -ne $true){throw 'DIAGNOSTIC_SERVICE_COMMAND_REFUSED'}
                return $state
            }
        }
        throw 'SERVICE_FRAME_TOO_LARGE'
    }catch{if($_.Exception.Message -match '\A[A-Z0-9_]{1,100}\z'){throw};throw 'DIAGNOSTIC_SERVICE_IO_FAILED'}finally{$pipe.Dispose()}
}
function Assert-OPDiagnosticReady($State){
    if($State.mode -ne 'disconnected' -or $State.intent -ne $false -or $State.guard -ne $false){throw 'KEEP_PROXY_DISCONNECTED_FIRST'}
    if($State.login_authenticated -ne $true -or $State.device_registered -ne $true){throw 'LOGIN_TO_EXISTING_REGISTERED_DEVICE_FIRST'}
    if($State.udp_diagnostics_available -ne $true){throw 'RC31_DIAGNOSTIC_SERVICE_REQUIRED'}
    if($State.udp_diagnostic.running -eq $true){throw 'ANOTHER_DIAGNOSTIC_IS_RUNNING'}
}
function Clear-OPPreviousContrastFilter {
    if(-not (Test-OPIdle (Invoke-OPPktmon -Arguments @('status')))){throw 'EXISTING_MONITOR_REFUSED'}
    $current=Invoke-OPPktmon -Arguments @('filter','list')
    if(Test-OPNoFilters $current){return}
    $rows=@([regex]::Matches($current,'(?m)^\s*\d+\s+(\S+)\s+.+$'))
    $known=@([regex]::Matches($current,'(?m)^\s*\d+\s+(ProxyPrimary443\s+UDP\s+152\.67\.156\.100|ProxySecondary443\s+UDP\s+141\.147\.78\.44)\s+443\s*$'))
    if($rows.Count -lt 1 -or $rows.Count -gt 2 -or $known.Count -ne $rows.Count){throw 'FOREIGN_OR_UNKNOWN_FILTERS_REFUSED'}
    # Explicit opt-in applies only to the manual contrast filters from this
    # investigation. Recheck immediately; do not clear anything that changed.
    if(-not (Test-OPIdle (Invoke-OPPktmon -Arguments @('status'))) -or (Invoke-OPPktmon -Arguments @('filter','list')) -ne $current){throw 'FILTERS_CHANGED_REFUSE_CLEAR'}
    Invoke-OPPktmon -Arguments @('filter','remove') | Out-Null
}
function Get-OPSafeDiagnostic($Diagnostic){
    $verdicts=@('PASSED','LOCAL_WRITE_ERROR','NO_INITIATION_SENT','SERVER_OBSERVATION_UNAVAILABLE','RETURN_OR_LOCAL_RECEIVE_PATH','REPLY_WITHOUT_VERIFIED_EGRESS','INSUFFICIENT_OBSERVATION','FORWARD_PATH_NOT_OBSERVED','SERVER_RESPONSE_NOT_OBSERVED')
    $result=[ordered]@{diagnostic_id=[string]$Diagnostic.diagnostic_id;phase=[string]$Diagnostic.phase;trials=@()}
    [Guid]$id=[Guid]::Empty
    if(-not [Guid]::TryParseExact($result.diagnostic_id,'D',[ref]$id) -or $result.phase -notin @('complete','cancelled','failed')){throw 'INVALID_DIAGNOSTIC_RESULT'}
    $result.server_capture_closed=$Diagnostic.server_capture_closed -eq $true
    foreach($trial in @($Diagnostic.trials | Select-Object -First 6)){
        if($trial.address -notin @('152.67.156.100','141.147.78.44') -or $trial.port -notin @(443,8443,51820)){continue}
        $row=[ordered]@{address=[string]$trial.address;port=[int]$trial.port;client=@{};server=@{}}
        if($trial.verdict -in $verdicts){$row.verdict=[string]$trial.verdict}
        foreach($key in @('tx_initiations','rx_responses','rx_cookies','read_errors','write_errors')){
            $value=$trial.client.counters.$key
            if($null -ne $value -and $value -is [ValueType] -and $value -isnot [bool] -and [decimal]$value -ge 0 -and [decimal]$value -le [uint32]::MaxValue){$row.client[$key]=$value}
        }
        $row.client.egress_verified=$trial.client.egress_verified -eq $true
        foreach($key in @('rx_initiations','tx_responses','tx_cookies','ring_evictions','socket_drops')){
            $value=$trial.server.capture.$key
            if($null -ne $value -and $value -is [ValueType] -and $value -isnot [bool] -and [decimal]$value -ge 0 -and [decimal]$value -le [uint32]::MaxValue){$row.server[$key]=$value}
        }
        $row.server.complete_observation=$trial.server.capture.complete_observation -eq $true
        $row.server.kernel_handshake_advanced=$trial.server.kernel_handshake_advanced -eq $true
        $result.trials+=,$row
    }
    return $result
}
function Invoke-OPAutomaticDiagnostic([int]$Duration,$Initial){
    Assert-OPDiagnosticReady $Initial
    $previous=[string]$Initial.udp_diagnostic.diagnostic_id;$ownedId=$null;$finished=$false;$lastTrial=-1
    $timer=[Diagnostics.Stopwatch]::StartNew()
    try{
        $null=Invoke-OPDiagnosticControl 'StartUdpDiagnostics' -ResponseSeconds 45
        while($timer.Elapsed.TotalSeconds -lt $Duration){
            $state=Invoke-OPDiagnosticControl 'Status';$diagnostic=$state.udp_diagnostic
            if($state.mode -ne 'disconnected' -or $state.guard -ne $false -or $state.intent -ne $false){throw 'DIAGNOSTIC_STATE_CHANGED'}
            [Guid]$id=[Guid]::Empty
            if([Guid]::TryParseExact([string]$diagnostic.diagnostic_id,'D',[ref]$id) -and [string]$diagnostic.diagnostic_id -ne $previous){
                if($null -eq $ownedId){$ownedId=[string]$diagnostic.diagnostic_id;Write-Host ('DIAGNOSTIC_ID='+$ownedId)}
                if([string]$diagnostic.diagnostic_id -ne $ownedId){throw 'DIAGNOSTIC_ID_CHANGED'}
                if($diagnostic.running -eq $false){
                    $finished=$true
                    Write-Host '=== PROXY_PAIRED_DIAGNOSTIC_BEGIN ==='
                    Write-Host ((Get-OPSafeDiagnostic $diagnostic) | ConvertTo-Json -Depth 12)
                    Write-Host '=== PROXY_PAIRED_DIAGNOSTIC_END ==='
                    if($diagnostic.phase -ne 'complete'){throw 'DIAGNOSTIC_DID_NOT_COMPLETE'}
                    return
                }
                if($null -ne $diagnostic.current_trial -and [int]$diagnostic.current_trial -ne $lastTrial){$lastTrial=[int]$diagnostic.current_trial;Write-Host ('正在自动诊断：'+($lastTrial+1)+'/6；无需点击软件。')}
            }
            Start-Sleep -Milliseconds 700
        }
        throw 'DIAGNOSTIC_DEADLINE'
    }finally{
        if(-not $finished -and $null -ne $ownedId){
            try{
                $state=Invoke-OPDiagnosticControl 'Status'
                if([string]$state.udp_diagnostic.diagnostic_id -eq $ownedId -and $state.udp_diagnostic.running -eq $true){
                    $null=Invoke-OPDiagnosticControl 'CancelUdpDiagnostics'
                    $ending=[Diagnostics.Stopwatch]::StartNew()
                    do{Start-Sleep -Milliseconds 500;$state=Invoke-OPDiagnosticControl 'Status'}while($state.udp_diagnostic.running -eq $true -and [string]$state.udp_diagnostic.diagnostic_id -eq $ownedId -and $ending.Elapsed.TotalSeconds -lt 35)
                    if($state.udp_diagnostic.running -eq $true){Write-Host 'DIAGNOSTIC_CANCEL_CONFIRMATION_UNAVAILABLE'}
                }
            }catch{Write-Host 'DIAGNOSTIC_CANCEL_CONFIRMATION_UNAVAILABLE'}
        }
    }
}

if($DefinitionsOnly){return}

if($AutomaticContrast){
    $initial=Invoke-OPDiagnosticControl 'Status';Assert-OPDiagnosticReady $initial
    if($ClearPreviousContrastFilter){Clear-OPPreviousContrastFilter}
    foreach($address in @('152.67.156.100','141.147.78.44')){
        Write-Host ('=== 自动对照 '+$address+':443；请保持软件已登录且断开，不用点击任何按钮 ===')
        & $PSCommandPath -Seconds 180 -RemoteAddress $address -Port 443 -SixEntranceDiagnostic -AutoServiceDiagnostic
        if(-not (Test-OPIdle (Invoke-OPPktmon -Arguments @('status'))) -or -not (Test-OPNoFilters (Invoke-OPPktmon -Arguments @('filter','list')))){throw 'COUNTER_CLEANUP_NOT_VERIFIED'}
    }
    return
}
if($AutoServiceDiagnostic){$initial=Invoke-OPDiagnosticControl 'Status';Assert-OPDiagnosticReady $initial}

$status=(Invoke-OPPktmon -Arguments @('status')).Trim()
$filters=(Invoke-OPPktmon -Arguments @('filter','list')).Trim()
$idle=Test-OPIdle $status
$empty=Test-OPNoFilters $filters
if(-not $idle -or -not $empty){throw 'Existing or unknown Packet Monitor state; nothing changed.'}
$owned=@();$started=$false
$prefix=if($SixEntranceDiagnostic){'PROXY_UDP_ENTRANCE'}else{'ORACLE_NATIVE_UDP'}
try{
    foreach($selectedPort in @($Port)){
        $name='OPN'+[Guid]::NewGuid().ToString('N').Substring(0,6)+$selectedPort
        Invoke-OPPktmon -Arguments @('filter','add',$name,'-i',$RemoteAddress,'-t','UDP','-p',[string]$selectedPort) | Out-Null
        $owned+=,$name
    }
    Write-Host (Invoke-OPPktmon -Arguments @('start','--capture','--counters-only','--comp','all'));$started=$true
    # Clear only this newly owned monitor's counters, never a preexisting run.
    Invoke-OPPktmon -Arguments @('reset') | Out-Null
    $guide=if($AutoServiceDiagnostic){'正在自动调用已登录服务；无需点击软件。'}elseif($SixEntranceDiagnostic){'保持 Proxy 已断开，点击“一键诊断六个 UDP 入口”；不要点击普通连接。'}elseif($Port -eq 8443){"点击原生 UDP 8443 测试，再直接连接；不要重选首选协议。"}else{"选择 WireGuard / UDP 并连接。"}
    $prefix=if($SixEntranceDiagnostic){'PROXY_UDP_ENTRANCE'}else{'ORACLE_NATIVE_UDP'}
    Write-Host "计数已开始（$RemoteAddress UDP/$Port）：$guide 请保持此窗口打开，$Seconds 秒内自动结束；期间不要启动其他抓包任务。"
    Write-Host '本工具没有启用数据包日志；无发送、网卡不可见或观察不完整时，不能据此认定网络丢包。'
    $watch=[Diagnostics.Stopwatch]::StartNew()
    Write-Host "=== ${prefix}_TIMELINE_BEGIN ==="
    $targets=Get-OPSampleTargets -Duration $Seconds -SixEntrance ([bool]$SixEntranceDiagnostic)
    if($AutoServiceDiagnostic){Invoke-OPAutomaticDiagnostic -Duration $Seconds -Initial $initial;$targets=@()}
    foreach($target in $targets){
        $remaining=[Math]::Max(0,[int]($target*1000-$watch.ElapsedMilliseconds))
        if($remaining){Start-Sleep -Milliseconds $remaining}
        Write-Host ('SAMPLE UTC8='+[DateTimeOffset]::UtcNow.ToOffset([TimeSpan]::FromHours(8)).ToString('o')+' ELAPSED_MS='+$watch.ElapsedMilliseconds+' ADDRESS='+$RemoteAddress+' PORT='+$Port)
        Write-Host (Read-OPCounterText)
    }
    Write-Host "=== ${prefix}_TIMELINE_END ==="
}finally{
    try{if($started){
        try{
            Write-Host "=== ${prefix}_COUNTERS_BEGIN ==="
            Write-Host ('OBSERVED_ENDPOINT='+$RemoteAddress+':'+$Port)
            Write-Host (Read-OPCounterText)
            Write-Host "=== ${prefix}_COUNTERS_END ==="
        }finally{Invoke-OPPktmon -Arguments @('stop') | Out-Null}
    }}
    finally{
        Clear-OPOwnedFilters -Names $owned
        Write-Host 'PKTMON_OWNED_CLEANUP=PASS'
    }
}
Write-Host '计数已结束，临时筛选器已清理；未记录数据包内容。请复制上方计数和客户端连接诊断。'
