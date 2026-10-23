# Disposable hosted Windows proof, not a product command or a user collector.
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted'){throw 'Disposable GitHub-hosted Windows only'}
$parseErrors=$null;$parseTokens=$null
$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot -Parent) 'Measure-NativeUdp.ps1'),[ref]$parseTokens,[ref]$parseErrors)
if($parseErrors.Count){throw 'PUBLIC_COLLECTOR_POWERSHELL_PARSE_FAILED'}
function Run-Pktmon([string[]]$Arguments){
  $text=(& "$env:WINDIR\System32\pktmon.exe" @Arguments 2>&1 | Out-String)
  if($LASTEXITCODE -ne 0){throw ('PKTMON_COMMAND_FAILED: '+($Arguments -join ' ')+': '+$text)}
  return $text
}
$state=Run-Pktmon @('status');Write-Host $state
$filters=Run-Pktmon @('filter','list');Write-Host $filters
Write-Host (Run-Pktmon @('start','help'))
if($state -notmatch '\A\s*Packet Monitor is not running\.\s*\z' -or $filters -notmatch '\A\s*Packet Filters:\s*None\s*\z'){throw 'PREEXISTING_OR_UNKNOWN_MONITOR_STATE_REFUSED'}
$nonce=[Guid]::NewGuid().ToString('N').Substring(0,12)
$own='OPC_'+$nonce
$other='OPX_'+$nonce
$added=@();$started=$false
try{
  Run-Pktmon @('filter','add',$own,'-i','1.1.1.1','-t','UDP','-p','53') | Out-Null;$added+=,$own
  Run-Pktmon @('filter','add',$other,'-i','1.1.1.1','-t','UDP','-p','54') | Out-Null;$added+=,$other
  Write-Host (Run-Pktmon @('start','--capture','--counters-only','--comp','all'));$started=$true
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
  $counters=Run-Pktmon @('counters','--json');$parsed=$counters | ConvertFrom-Json
  $flows=@($parsed | ForEach-Object {$_.Components} | ForEach-Object {$_.Counters} | Where-Object {$_.Type -eq 'Flows'})
  if(-not $flows.Count){throw 'FLOW_COUNTER_SCHEMA_NOT_FOUND'}
  if(@($flows | Where-Object {$_.Inbound.Packets -gt 0 -and $_.Outbound.Packets -gt 0}).Count -lt 1){throw 'REAL_TX_RX_COUNTERS_NOT_POSITIVE'}
  Write-Host 'COUNTERS_ONLY_JSON_BEGIN';Write-Host $counters;Write-Host 'COUNTERS_ONLY_JSON_END'
  Run-Pktmon @('stop') | Out-Null;$started=$false
  Run-Pktmon @('filter','remove',$own) | Out-Null;$added=@($other)
  $remaining=Run-Pktmon @('filter','list')
  Write-Host $remaining
  if($remaining -notmatch [regex]::Escape($other) -or $remaining -match [regex]::Escape($own)){throw 'NAMED_REMOVAL_DID_NOT_PRESERVE_OTHER_FILTER'}
  Write-Host 'NAMED_FILTER_REMOVAL_PRESERVES_INDEPENDENT_FILTER=PASS'
}finally{
  if($started){Run-Pktmon @('stop') | Out-Null}
  foreach($name in $added){Run-Pktmon @('filter','remove',$name) | Out-Null}
}
Write-Host (Run-Pktmon @('status'));Write-Host (Run-Pktmon @('filter','list'))
if(Get-ChildItem -Path . -Filter '*.etl' -ErrorAction SilentlyContinue){throw 'COUNTERS_ONLY_UNEXPECTED_ETL_FILE'}
Write-Host 'REAL_WINDOWS_COUNTERS_ONLY_NO_PACKET_LOG_AND_OWNED_CLEANUP=PASS'
