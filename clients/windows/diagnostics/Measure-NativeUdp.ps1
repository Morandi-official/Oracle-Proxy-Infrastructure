#requires -RunAsAdministrator
# Bounded counters only. No packet logging, firewall, route or adapter changes.
[CmdletBinding()]
param([ValidateRange(20,45)][int]$Seconds=40,[switch]$DefinitionsOnly)
$ErrorActionPreference='Stop'
function Invoke-OPPktmon([string[]]$Arguments){
    $result=(& "$env:WINDIR\System32\pktmon.exe" @Arguments 2>&1 | Out-String)
    if($LASTEXITCODE -ne 0){throw ('Packet Monitor failed: '+($Arguments -join ' '))}
    return $result
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
    if(-not (Test-OPIdle (Invoke-OPPktmon @('status')))){throw 'ACTIVE_MONITOR_REFUSE_FILTER_CLEAR'}
    $current=Invoke-OPPktmon @('filter','list')
    if(Test-OPNoFilters $current){return}
    $rows=@([regex]::Matches($current,'(?m)^\s*\d+\s+(\S+)\s+.+$'))
    $found=@($rows | ForEach-Object {$_.Groups[1].Value})
    if($found.Count -ne $Names.Count -or @($found | Select-Object -Unique).Count -ne $found.Count -or @($found | Where-Object {$Names -notcontains $_}).Count){throw 'FILTERS_CHANGED_REFUSE_CLEAR'}
    # This command removes ALL filters. Use it only after proving the entire
    # stopped list is still ours; never simulate selective removal by name.
    Invoke-OPPktmon @('filter','remove') | Out-Null
    if(-not (Test-OPNoFilters (Invoke-OPPktmon @('filter','list')))){throw 'FILTER_CLEANUP_NOT_VERIFIED'}
}
if($DefinitionsOnly){return}
$status=(Invoke-OPPktmon @('status')).Trim()
$filters=(Invoke-OPPktmon @('filter','list')).Trim()
$idle=Test-OPIdle $status
$empty=Test-OPNoFilters $filters
if(-not $idle -or -not $empty){throw 'Existing or unknown Packet Monitor state; nothing changed.'}
$owned=@();$started=$false
try{
    foreach($port in @(51820,443)){
        $name='OPNative'+$port
        Invoke-OPPktmon @('filter','add',$name,'-i','152.67.156.100','-t','UDP','-p',[string]$port) | Out-Null
        $owned+=,$name
    }
    Write-Host (Invoke-OPPktmon @('start','--capture','--counters-only','--comp','all'));$started=$true
    Write-Host "计数已开始：现在在 rc11 选择 UDP 并连接。请保持此窗口打开，$Seconds 秒内自动结束。"
    Start-Sleep -Seconds $Seconds
    Write-Host '=== ORACLE_NATIVE_UDP_COUNTERS_BEGIN ==='
    Write-Host (Invoke-OPPktmon @('counters','--include-hidden','--drop-reason'))
    Write-Host '=== ORACLE_NATIVE_UDP_COUNTERS_END ==='
}finally{
    try{if($started){Invoke-OPPktmon @('stop') | Out-Null}}
    finally{Clear-OPOwnedFilters $owned}
}
Write-Host '计数已结束，临时筛选器已清理；未记录数据包内容。请复制上方计数和客户端连接诊断。'
