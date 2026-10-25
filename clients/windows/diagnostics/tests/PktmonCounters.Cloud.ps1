# Disposable hosted Windows proof, not a product command or a user collector.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable GitHub-hosted Windows only'}
$parseErrors=$null;$parseTokens=$null
$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot -Parent) 'Measure-NativeUdp.ps1'),[ref]$parseTokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'PUBLIC_COLLECTOR_POWERSHELL_PARSE_FAILED'}
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'Measure-NativeUdp.ps1') -DefinitionsOnly
# Exercise real UTF-8 native pipes under CP936, not Unicode string literals alone.
$fixtureDirectory=Join-Path $env:RUNNER_TEMP ('op-utf8-'+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $fixtureDirectory
$fixture=Join-Path $fixtureDirectory 'NativeUtf8Fixture.exe'
$source=@'
using System;
using System.Text;
public class NativeUtf8Fixture {
    public static int Main(string[] args) {
        string text;
        switch(args[0]) {
            case "status": text="\r\n数据包监视器没有运行。\r\n"; break;
            case "filters": text="数据包筛选器:\r\n    无\r\n"; break;
            case "active": text="数据包监视器正在运行。\r\n"; break;
            case "foreign": text="数据包筛选器:\r\n 1 Other UDP 1.1.1.1 53\r\n"; break;
            default: text="unknown"; break;
        }
        byte[] bytes=Encoding.UTF8.GetBytes(text);
        var output=Console.OpenStandardOutput();
        output.Write(bytes,0,bytes.Length);output.Flush();
        return 0;
    }
}
'@
$null=Add-Type -TypeDefinition $source -OutputAssembly $fixture -OutputType ConsoleApplication
$previousEncoding=[Console]::OutputEncoding
try{
    [Console]::OutputEncoding=[Text.Encoding]::GetEncoding(936)
    $legacy=(& $fixture status | Out-String)
    if(Test-OPIdle $legacy){throw 'CP936_MOJIBAKE_REGRESSION_NOT_REPRODUCED'}
    $chineseStatus=Invoke-OPUtf8Process -Executable $fixture -Arguments @('status')
    $chineseFilters=Invoke-OPUtf8Process -Executable $fixture -Arguments @('filters')
    if(-not (Test-OPIdle $chineseStatus) -or -not (Test-OPNoFilters $chineseFilters)){throw 'CHINESE_NATIVE_UTF8_PIPE_FAILED'}
    if(Test-OPIdle (Invoke-OPUtf8Process -Executable $fixture -Arguments @('active'))){throw 'CHINESE_ACTIVE_MONITOR_ACCEPTED'}
    if(Test-OPNoFilters (Invoke-OPUtf8Process -Executable $fixture -Arguments @('foreign'))){throw 'CHINESE_FOREIGN_FILTER_ACCEPTED'}
    if(Test-OPIdle 'unknown'){throw 'UNKNOWN_STATE_ACCEPTED'}
    if([Console]::OutputEncoding.CodePage -ne 936){throw 'COLLECTOR_CHANGED_CONSOLE_ENCODING'}
    # The real pktmon read-only checks must also work with this console setting.
    if(-not (Test-OPIdle (Invoke-OPPktmon -Arguments @('status')))){throw 'REAL_CP936_PKTMON_STATUS_FAILED'}
    if(-not (Test-OPNoFilters (Invoke-OPPktmon -Arguments @('filter','list')))){throw 'REAL_CP936_PKTMON_FILTERS_FAILED'}
    Write-Host 'CHINESE_UTF8_NATIVE_CP936_REGRESSION_AND_FAIL_CLOSED=PASS'
}finally{
    [Console]::OutputEncoding=$previousEncoding
    Remove-Item -LiteralPath $fixtureDirectory -Recurse -Force
}
function Run-Pktmon([string[]]$Arguments){
  $text=(& "$env:WINDIR\System32\pktmon.exe" @Arguments 2>&1 | Out-String)
  if($LASTEXITCODE -ne 0){throw ('PKTMON_COMMAND_FAILED: '+($Arguments -join ' ')+': '+$text)}
  return $text
}
$state=Run-Pktmon -Arguments @('status');Write-Host $state
$filters=Run-Pktmon -Arguments @('filter','list');Write-Host $filters
Write-Host (Run-Pktmon -Arguments @('start','help'))
if($state -notmatch '\A\s*Packet Monitor is not running\.\s*\z' -or $filters -notmatch '\A\s*Packet Filters:\s*None\s*\z'){throw 'PREEXISTING_OR_UNKNOWN_MONITOR_STATE_REFUSED'}
$nonce=[Guid]::NewGuid().ToString('N').Substring(0,12)
$own='OPC_'+$nonce
$other='OPX_'+$nonce
$added=@();$started=$false
try{
  Run-Pktmon -Arguments @('filter','add',$own,'-i','1.1.1.1','-t','UDP','-p','53') | Out-Null;$added+=,$own
  Run-Pktmon -Arguments @('filter','add',$other,'-i','1.1.1.1','-t','UDP','-p','54') | Out-Null;$added+=,$other
  Write-Host (Run-Pktmon -Arguments @('start','--capture','--counters-only','--comp','all'));$started=$true
  # No traffic has been sent yet. This was a legitimate early sample on MetaWise.
  $null=Read-OPCounterText
  Write-Host 'REAL_EMPTY_EARLY_TEXT_SAMPLE_ACCEPTED=PASS'
  # Public, synthetic example.com DNS lookup; never uses product credentials.
  [byte[]]$query=0x57,0x47,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1
  $udp=New-Object Net.Sockets.UdpClient
  try{
    $udp.Client.ReceiveTimeout=4000;$udp.Connect('1.1.1.1',53)
    [void]$udp.Send($query,$query.Length)
    $remote=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0)
    $reply=$udp.Receive([ref]$remote)
    if($reply.Length -lt 12 -or $reply[0] -ne 0x57 -or $reply[1] -ne 0x47){throw 'PUBLIC_DNS_REPLY_NOT_VERIFIED'}
    Write-Host 'PUBLIC_SYNTHETIC_DNS_SOCKET_RESPONSE=PASS'
  }finally{$udp.Dispose()}
  $counters=Run-Pktmon -Arguments @('counters','--json');$parsed=$counters | ConvertFrom-Json
  $flows=@($parsed | ForEach-Object {$_.Components} | ForEach-Object {$_.Counters} | Where-Object {$_.Type -eq 'Flows'})
  if(-not $flows.Count){throw 'FLOW_COUNTER_SCHEMA_NOT_FOUND'}
  if(@($flows | Where-Object {$_.Inbound.Packets -gt 0 -and $_.Outbound.Packets -gt 0}).Count -lt 1){throw 'REAL_TX_RX_COUNTERS_NOT_POSITIVE'}
  $text=Read-OPCounterText
  if($text -notmatch 'Rx' -or $text -notmatch 'Tx'){throw 'REAL_TEXT_FLOW_DIRECTIONS_MISSING'}
  Write-Host 'REAL_TIMELINE_NATIVE_TEXT_AND_POSITIVE_COUNTERS=PASS'
  Write-Host 'COUNTERS_ONLY_JSON_BEGIN';Write-Host $counters;Write-Host 'COUNTERS_ONLY_JSON_END'
  Run-Pktmon -Arguments @('stop') | Out-Null;$started=$false
  $before=Run-Pktmon -Arguments @('filter','list');$refused=$false
  try{Clear-OPOwnedFilters -Names @($own)}catch{if($_.Exception.Message -ne 'FILTERS_CHANGED_REFUSE_CLEAR'){throw};$refused=$true}
  $remaining=Run-Pktmon -Arguments @('filter','list')
  if(-not $refused -or $before -ne $remaining){throw 'FOREIGN_FILTER_WAS_NOT_PRESERVED'}
  Write-Host 'FOREIGN_FILTER_CAUSES_REFUSAL_WITHOUT_CHANGES=PASS'
}finally{
  if($started){Run-Pktmon -Arguments @('stop') | Out-Null}
  Clear-OPOwnedFilters -Names $added
}
Write-Host (Run-Pktmon -Arguments @('status'));Write-Host (Run-Pktmon -Arguments @('filter','list'))
$probe=Start-Job -ScriptBlock {
  Start-Sleep -Seconds 5
  $udp=New-Object Net.Sockets.UdpClient
  try{
    $udp.Connect('152.67.156.100',8443)
    # One invalid synthetic initiation tests counting only, never authentication.
    $packet=New-Object byte[] 148;$packet[0]=1
    [void]$udp.Send($packet,$packet.Length)
  }finally{$udp.Dispose()}
}
try{
  & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Measure-NativeUdp.ps1') -Seconds 20 -Port 8443
  $null=Wait-Job $probe -Timeout 10
  if($probe.State -ne 'Completed'){throw 'SYNTHETIC_NATIVE_COUNTER_PROBE_FAILED'}
  Receive-Job $probe -ErrorAction Stop | Out-Null
}finally{Remove-Job $probe -Force}
if(Get-ChildItem -Path . -Filter '*.etl' -ErrorAction SilentlyContinue){throw 'COUNTERS_ONLY_UNEXPECTED_ETL_FILE'}
Write-Host 'REAL_WINDOWS_COUNTERS_ONLY_NO_PACKET_LOG_AND_OWNED_CLEANUP=PASS'
