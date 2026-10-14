# R21: actual SYSTEM SCM process owns persistent WFP policy installation.
# CI only; no global production protection.
# R21: real Windows WFP-backed all-protocol, program-scoped block,
# active while genuine GUI/SCM WireGuard traffic flows. CI ONLY.
# This is NOT a whole-device kill switch.
param([switch]$LiveCheck)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R21_REFUSED: elevated GitHub hosted disposable runner only'
}
if ((Get-Service BFE).Status -ne 'Running' -or
    (Get-Service MpsSvc).Status -ne 'Running') {
    throw 'R21_REFUSED: WFP services not running'
}
$program = (Get-Process -Id $PID -ErrorAction Stop).Path
if (-not $program.EndsWith('pwsh.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'R21_REFUSED: unexpected process'
}
function Tcp([string]$ip) {
    $target = [System.Net.IPAddress]::Parse($ip)
    $socket = [System.Net.Sockets.TcpClient]::new($target.AddressFamily)
    try {
        $task = $socket.ConnectAsync($target, 443)
        return $task.Wait(3000) -and $socket.Connected
    } catch { return $false }
    finally { $socket.Dispose() }
}
function Dns([string]$ip) {
    $target = [System.Net.IPAddress]::Parse($ip)
    $client = [System.Net.Sockets.UdpClient]::new($target.AddressFamily)
    try {
        $client.Connect($target, 53)
        $id = [System.Security.Cryptography.RandomNumberGenerator]::GetInt32(1,65536)
        $buf = [System.Collections.Generic.List[byte]]::new()
        $buf.AddRange([byte[]]@([byte]($id -shr 8),[byte]($id -band 255),1,0,0,1,0,0,0,0,0,0))
        foreach ($label in @('example','com')) {
            [byte[]]$b = [System.Text.Encoding]::ASCII.GetBytes($label)
            $buf.Add([byte]$b.Length)
            $buf.AddRange($b)
        }
        $buf.AddRange([byte[]]@(0,0,1,0,1))
        [byte[]]$q = $buf.ToArray()
        [void]$client.Send($q, $q.Length)
        $answer = $client.ReceiveAsync()
        if (-not $answer.Wait(3000)) { return $false }
        [byte[]]$r = $answer.Result.Buffer
        if ($r.Length -lt 12) { return $false }
        return (([int]$r[0] -shl 8) -bor [int]$r[1]) -eq $id -and
            ($r[2] -band 128) -ne 0 -and ($r[3] -band 15) -eq 0 -and
            (([int]$r[6] -shl 8) -bor [int]$r[7]) -gt 0
    } catch { return $false }
    finally { $client.Dispose() }
}
function VerifyGuard([string]$name) {
    if ($name -notmatch '^OracleProxy-R21-CI-SYSTEM-OnlyGuard$') {
        throw 'R21_FAIL: unowned filter identifier'
    }
    $rule = Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop
    $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $addr = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    if ($rule.Action -ne 'Block' -or $rule.Direction -ne 'Outbound' -or
        [string]$rule.Enabled -ne 'True' -or
        [string]$port.Protocol -notin @('Any','256') -or
        [string]$port.RemotePort -ne 'Any' -or
        [string]$addr.RemoteAddress -ne 'Any' -or
        -not [string]::Equals($app.Program,$program,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'R21_FAIL: active WFP guard scope incorrect'
    }
}
function Denied([string]$tcp,[string]$dns,[string]$v6) {
    Start-Sleep -Milliseconds 750
    if (Tcp $tcp) { throw 'R21_FAIL: IPv4 physical TCP escaped WFP' }
    if ((Dns $dns) -or (Dns $dns)) {
        throw 'R21_FAIL: direct raw UDP DNS escaped WFP'
    }
    if ($v6 -and (Tcp $v6)) {
        throw 'R21_FAIL: IPv6 physical TCP escaped WFP'
    }
}
if ($LiveCheck) {
    $name = $env:ORACLE_R21_GUARD_NAME
    $tcp = $env:ORACLE_R21_TCP
    $dns = $env:ORACLE_R21_DNS
    $v6 = $env:ORACLE_R21_IPV6
    if (-not $name -or $tcp -notin @('1.1.1.1','8.8.8.8') -or
        $dns -notin @('1.1.1.1','8.8.8.8') -or
        ($v6 -and $v6 -notin @('2606:4700:4700::1111','2001:4860:4860::8888'))) {
        throw 'R21_FAIL: invalid live guard binding'
    }
    VerifyGuard $name
    Denied $tcp $dns $v6
    Write-Host 'R21_LIVE_WG_WFP_TCP_UDP_DNS_DENY_PASS'
    return
}
# Observe external TCP/DNS first. Win11 may autonomously initialize an OS
# network rule on the first socket. Record the firewall baseline AFTER that.
$beforeRules = @()
$before = -1
$profiles = @()
$name = 'OracleProxy-R21-CI-SYSTEM-OnlyGuard'
$owned = $false
try {
    $tcp = @('1.1.1.1','8.8.8.8') |
        Where-Object { (Tcp $_) -and (Tcp $_) } | Select-Object -First 1
    $dns = @('1.1.1.1','8.8.8.8') |
        Where-Object { (Dns $_) -and (Dns $_) } | Select-Object -First 1
    if (-not $tcp -or -not $dns) {
        throw 'R21_BASELINE_UNAVAILABLE: no repeatable IPv4 TCP and UDP DNS'
    }
    $v6 = @('2606:4700:4700::1111','2001:4860:4860::8888') |
        Where-Object { (Tcp $_) -and (Tcp $_) } | Select-Object -First 1
    if (-not $v6) {
        Write-Host 'R21_IPV6_EXTERNAL_UNAVAILABLE: no IPv6 packet-denial proof'
    }
    $beforeRules = @(Get-NetFirewallRule -ErrorAction Stop | Select-Object -ExpandProperty Name)
    $before = $beforeRules.Count
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop |
        Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
    # NetSecurity's -Name missing lookup can throw a terminating CIM exception.
    # Enumerate the ActiveStore instead; do not treat a lookup error as absence.
    $existing = @(Get-NetFirewallRule -ErrorAction Stop |
        Where-Object Name -eq $name)
    if ($existing.Count -ne 0) {
        throw 'R21_REFUSED: preexisting filter'
    }
    # SYSTEM SCM service owns WFP; test PowerShell never creates it.
    $owned = $true
    $env:ORACLE_R21_SYSTEM_GUARD = 'CI_FIXED_SYSTEM_POLICY'
    $env:ORACLE_R19_CRASH_TEST = 'CI_OWNED_MANAGER_ONLY'
    $env:ORACLE_R21_GUARD_NAME = $name
    $env:ORACLE_R21_TCP = $tcp
    $env:ORACLE_R21_DNS = $dns
    $env:ORACLE_R21_IPV6 = $v6
    & ./clients/windows/lab/run-admin-controlled-scm.ps1
    if ($LASTEXITCODE -ne 0) { throw 'R21_FAIL: GUI/SCM tunnel lab failed' }
    VerifyGuard $name
    Denied $tcp $dns $v6
    Write-Host 'R21_SYSTEM_GUARD_SURVIVED_SYSTEM_MANAGER_CRASH_PASS'
    Remove-NetFirewallRule -Name $name -ErrorAction Stop
    $owned = $false
    Start-Sleep -Milliseconds 650
    if (-not (Tcp $tcp) -or -not (Dns $dns)) {
        throw 'R21_FAIL: IPv4 TCP/UDP did not restore'
    }
    if ($v6 -and -not (Tcp $v6)) {
        throw 'R21_FAIL: IPv6 TCP not restored'
    }
    Write-Host 'R21_EXPLICIT_RELEASE_TCP_UDP_RESTORED_PASS'
} catch {
    # Keep the FIRST real failure visible even if strict cleanup checks fail.
    $reason = $_.Exception.GetType().Name
    $detail = $_.Exception.Message
    if ($detail.Length -gt 180) { $detail = $detail.Substring(0,180) }
    Write-Host "R21_PRIMARY_FAILURE: type=$reason detail=$detail"
    throw
}
finally {
    foreach ($key in @('ORACLE_R21_GUARD_NAME','ORACLE_R21_TCP',
                       'ORACLE_R21_DNS','ORACLE_R21_IPV6',
                       'ORACLE_R21_SYSTEM_GUARD','ORACLE_R19_CRASH_TEST')) {
        Remove-Item -Path ('Env:' + $key) -ErrorAction SilentlyContinue
    }
    if ($owned -and @(Get-NetFirewallRule -ErrorAction Stop |
        Where-Object Name -eq $name).Count -gt 0) {
        VerifyGuard $name
        Remove-NetFirewallRule -Name $name -ErrorAction Stop
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop |
        Where-Object Name -eq $name).Count -gt 0) {
        throw 'R21_FAIL: owned filter survived cleanup'
    }
    $afterRules = @(Get-NetFirewallRule -ErrorAction Stop | Select-Object -ExpandProperty Name)
    if ($before -lt 0) {
        Write-Host "R21_EARLY_ABORT: before actual WFP baseline; no R21 service installation occurred"
        return
    }
    if ($afterRules.Count -ne $before -or
        @(Compare-Object -ReferenceObject $beforeRules -DifferenceObject $afterRules).Count -gt 0) {
        $difference = @(Compare-Object -ReferenceObject $beforeRules -DifferenceObject $afterRules)
        Write-Host "R21_FIREWALL_BASELINE_MISMATCH: before=$before after=$($afterRules.Count)"
        foreach ($entry in $difference | Select-Object -First 12) {
            $ruleId = [string]$entry.InputObject
            if ($ruleId.Length -gt 100) { $ruleId = $ruleId.Substring(0,100) }
            Write-Host "R21_FIREWALL_DELTA: side=$($entry.SideIndicator) name=$ruleId"
        }
        throw 'R21_FAIL: firewall rule inventory changed'
    }
    $after = @(Get-NetFirewallProfile -ErrorAction Stop |
        Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
    if (($after -join '|') -ne ($profiles -join '|')) {
        throw 'R21_FAIL: firewall profile states changed'
    }
    Write-Host 'R21_WFP_CLEANUP_PASS'
}
