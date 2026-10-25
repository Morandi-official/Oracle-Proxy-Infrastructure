#requires -RunAsAdministrator
# Bounded counters only. No packet logging, firewall, route or adapter changes.
[CmdletBinding()]
param([ValidateRange(20,45)][int]$Seconds=40,[ValidateSet(51820,443,8443)][int]$Port=51820,[switch]$DefinitionsOnly)
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
if($DefinitionsOnly){return}
$status=(Invoke-OPPktmon -Arguments @('status')).Trim()
$filters=(Invoke-OPPktmon -Arguments @('filter','list')).Trim()
$idle=Test-OPIdle $status
$empty=Test-OPNoFilters $filters
if(-not $idle -or -not $empty){throw 'Existing or unknown Packet Monitor state; nothing changed.'}
$owned=@();$started=$false
try{
    foreach($selectedPort in @($Port)){
        $name='OPNative'+$selectedPort
        Invoke-OPPktmon -Arguments @('filter','add',$name,'-i','152.67.156.100','-t','UDP','-p',[string]$selectedPort) | Out-Null
        $owned+=,$name
    }
    Write-Host (Invoke-OPPktmon -Arguments @('start','--capture','--counters-only','--comp','all'));$started=$true
    $guide=if($Port -eq 8443){"点击原生 UDP 8443 测试，再直接连接；不要重选首选协议。"}else{"选择 WireGuard / UDP 并连接。"}
    Write-Host "计数已开始（UDP/$Port）：$guide 请保持此窗口打开，$Seconds 秒内自动结束。"
    $watch=[Diagnostics.Stopwatch]::StartNew()
    Write-Host '=== ORACLE_NATIVE_UDP_TIMELINE_BEGIN ==='
    foreach($target in @(5,10,15,$Seconds)){
        $remaining=[Math]::Max(0,[int]($target*1000-$watch.ElapsedMilliseconds))
        if($remaining){Start-Sleep -Milliseconds $remaining}
        Write-Host ('SAMPLE UTC='+[DateTime]::UtcNow.ToString('o')+' ELAPSED_MS='+$watch.ElapsedMilliseconds+' PORT='+$Port)
        Write-Host (Read-OPCounterText)
    }
    Write-Host '=== ORACLE_NATIVE_UDP_TIMELINE_END ==='
    Write-Host '=== ORACLE_NATIVE_UDP_COUNTERS_BEGIN ==='
    Write-Host (Read-OPCounterText)
    Write-Host '=== ORACLE_NATIVE_UDP_COUNTERS_END ==='
}finally{
    try{if($started){Invoke-OPPktmon -Arguments @('stop') | Out-Null}}
    finally{
        Clear-OPOwnedFilters -Names $owned
        Write-Host 'PKTMON_OWNED_CLEANUP=PASS'
    }
}
Write-Host '计数已结束，临时筛选器已清理；未记录数据包内容。请复制上方计数和客户端连接诊断。'
