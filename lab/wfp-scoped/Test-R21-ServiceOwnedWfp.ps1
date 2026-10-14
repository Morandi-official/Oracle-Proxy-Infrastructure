# R21: packet-level proof for CI-only WFP rule installed by SYSTEM manager.
# TEST PROCESS ONLY, not whole-device or a production kill switch.
param([ValidateSet('Baseline','Blocked','Restored')]
      [Parameter(Mandatory=$true)][string]$Phase)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ruleName='OracleProxy-R21-CI-SystemOwner-v1'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows') {
    throw 'R21_REFUSED: disposable hosted Windows only'
}
$program=(Get-Process -Id $PID -ErrorAction Stop).Path
$fixed=Join-Path $env:ProgramFiles 'PowerShell/7/pwsh.exe'
if (-not [string]::Equals($program,$fixed,[StringComparison]::OrdinalIgnoreCase)) {
    throw 'R21_REFUSED: bound program does not match CI runner'
}
function Tcp([string]$hostIp) {
    $ip=[System.Net.IPAddress]::Parse($hostIp)
    $client=[System.Net.Sockets.TcpClient]::new($ip.AddressFamily)
    try {
        $task=$client.ConnectAsync($ip,443)
        return $task.Wait(2500) -and $client.Connected
    } catch { return $false }
    finally {$client.Dispose()}
}
function Dns([string]$hostIp) {
    $ip=[System.Net.IPAddress]::Parse($hostIp)
    $client=[System.Net.Sockets.UdpClient]::new($ip.AddressFamily)
    try {
        $client.Connect($ip,53)
        $id=[System.Security.Cryptography.RandomNumberGenerator]::GetInt32(1,65536)
        $buffer=[System.Collections.Generic.List[byte]]::new()
        $buffer.AddRange([byte[]]@([byte]($id -shr 8),[byte]($id -band 255),1,0,0,1,0,0,0,0,0,0))
        foreach($label in @('example','com')) {
            $bytes=[System.Text.Encoding]::ASCII.GetBytes($label)
            $buffer.Add([byte]$bytes.Length)
            $buffer.AddRange($bytes)
        }
        $buffer.AddRange([byte[]]@(0,0,1,0,1))
        $query=$buffer.ToArray()
        [void]$client.Send($query,$query.Length)
        $recv=$client.ReceiveAsync()
        if(-not $recv.Wait(2200)) { return $false }
        $result=$recv.Result.Buffer
        if($result.Length -lt 12) { return $false }
        return (([int]$result[0] -shl 8) -bor [int]$result[1]) -eq $id -and
            ($result[2] -band 128) -ne 0 -and ($result[3] -band 15) -eq 0 -and
            (([int]$result[6] -shl 8) -bor [int]$result[7]) -gt 0
    } catch {return $false}
    finally {$client.Dispose()}
}
$targets=@('1.1.1.1','8.8.8.8')
if($Phase -eq 'Baseline') {
    $tcp=$targets | Where-Object { (Tcp $_) -and (Tcp $_) } | Select-Object -First 1
    $dns=$targets | Where-Object { (Dns $_) -and (Dns $_) } | Select-Object -First 1
    if(-not $tcp -or -not $dns) {
        throw 'R21_INCONCLUSIVE: repeatable public IPv4 TCP and UDP DNS baseline missing'
    }
    if(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
        throw 'R21_REFUSED: preexisting rule'
    }
    Write-Host 'R21_REAL_NETWORK_BASELINE_PASS'
    return
}
$rule=Get-NetFirewallRule -Name $ruleName -PolicyStore ActiveStore -ErrorAction SilentlyContinue
if($Phase -eq 'Blocked') {
    if(-not $rule) {throw 'R21_FAIL: service did not install active WFP rule'}
    $app=$rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $port=$rule | Get-NetFirewallPortFilter -ErrorAction Stop
    if($rule.Action -ne 'Block' -or $rule.Direction -ne 'Outbound' -or
        [string]$rule.Enabled -ne 'True' -or
        -not [string]::Equals($app.Program,$program,[StringComparison]::OrdinalIgnoreCase) -or
        [string]$port.Protocol -notin @('Any','256')) {
        throw 'R21_FAIL: wrong active WFP rule'
    }
    Start-Sleep -Milliseconds 700
    foreach($target in $targets) {
        if((Tcp $target) -or (Dns $target)) {
            throw 'R21_FAIL: test app physical IPv4 TCP or raw UDP DNS escaped'
        }
    }
    Write-Host 'R21_SYSTEM_OWNED_WFP_DENIED_TCP_UDP_PASS'
    return
}
if($rule) {throw 'R21_FAIL: exact WFP rule still present after service release'}
$tcp=$targets | Where-Object { (Tcp $_) -and (Tcp $_) } | Select-Object -First 1
$dns=$targets | Where-Object { (Dns $_) -and (Dns $_) } | Select-Object -First 1
if(-not $tcp -or -not $dns) {
    throw 'R21_FAIL: external TCP/UDP DNS did not recover'
}
Write-Host 'R21_SYSTEM_RELEASE_RESTORED_TCP_UDP_PASS'
