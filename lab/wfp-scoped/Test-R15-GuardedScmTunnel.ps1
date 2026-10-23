# R15: WFP-backed narrow guard + two genuine WireGuard SCM peers in ONE CI run.
# DISPOSABLE GitHub Windows CI ONLY. Blocks only CI pwsh -> one verified external
# IPv4 TCP/443 destination; NOT whole-device, IPv6, UDP/DNS or reboot fail-close.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R15_REFUSED: elevated disposable GitHub Windows runner required'
}
if ((Get-Service BFE -ErrorAction Stop).Status -ne 'Running' -or
    (Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running') {
    throw 'R15_REFUSED: existing Windows WFP/Firewall service not running'
}

$processPath = (Get-Process -Id $PID -ErrorAction Stop).Path
if (-not $processPath.EndsWith('pwsh.exe', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'R15_REFUSED: unexpected test executable'
}

# Deliberately does not send HTTP, DNS query, credentials or user traffic.
function Test-R15FreshExternalTcp([string]$address) {
    $ip = [System.Net.IPAddress]::Parse($address)
    $socket = [System.Net.Sockets.TcpClient]::new($ip.AddressFamily)
    try {
        $connect = $socket.ConnectAsync($ip, 443)
        return $connect.Wait(3000) -and $socket.Connected
    } catch { return $false }
    finally { $socket.Dispose() }
}

function Assert-R15Guard([string]$name, [string]$remote, [string]$program) {
    if ($name -notmatch '^OracleProxy-R15-CI-[a-f0-9]{32}$') {
        throw 'R15_FAIL: unsafe test filter identity'
    }
    $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
    $port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
    $address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    $app = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
    if ($rule.Action -ne 'Block' -or $rule.Direction -ne 'Outbound' -or
        [string]$rule.Enabled -ne 'True' -or
        [string]$port.Protocol -notin @('TCP','6') -or
        [string]$port.RemotePort -ne '443' -or
        [string]$address.RemoteAddress -ne $remote -or
        -not [string]::Equals($app.Program, $program,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'R15_FAIL: active WFP guard is missing or wider than expected'
    }
    Start-Sleep -Milliseconds 650
    if (Test-R15FreshExternalTcp $remote) {
        throw 'R15_FAIL: real outbound TCP still succeeded despite WFP-backed guard'
    }
}

$baselineCount = @(Get-NetFirewallRule -ErrorAction Stop).Count
$baselineProfiles = @(Get-NetFirewallProfile -ErrorAction Stop |
    Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
$ruleName = 'OracleProxy-R15-CI-' + [guid]::NewGuid().ToString('N')
$created = $false
$remote = $null
try {
    foreach ($candidate in @('1.1.1.1','8.8.8.8')) {
        if ((Test-R15FreshExternalTcp $candidate) -and
            (Test-R15FreshExternalTcp $candidate)) {
            $remote = $candidate
            break
        }
    }
    if (-not $remote) {
        throw 'R15_IPV4_BASELINE_UNAVAILABLE: cannot claim packet-denial integration'
    }
    if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
        throw 'R15_REFUSED: test rule already exists'
    }
    New-NetFirewallRule -Name $ruleName -DisplayName $ruleName `
        -PolicyStore PersistentStore -Direction Outbound -Action Block `
        -Protocol TCP -RemoteAddress $remote -RemotePort 443 `
        -Program $processPath -Profile Any -Enabled True `
        -ErrorAction Stop | Out-Null
    $created = $true
    Assert-R15Guard $ruleName $remote $processPath
    Write-Host 'R15_GUARD_PRETUNNEL_PASS: persistent, precise WFP rule denied actual IPv4 TCP packets'

    # Downstream script invokes this same exact live OS guard verification
    # while BOTH real SCM WireGuard peers are up and after verified app traffic.
    $env:ORACLE_R15_GUARD_NAME = $ruleName
    $env:ORACLE_R15_GUARD_REMOTE = $remote
    $env:ORACLE_R15_GUARD_PROGRAM = $processPath
    & ./clients/windows/lab/run-admin-controlled-scm.ps1
    if ($LASTEXITCODE -ne 0) {
        throw 'R15_FAIL: native SCM tunnel integration returned nonzero'
    }
    Assert-R15Guard $ruleName $remote $processPath
    Write-Host 'R15_GUARD_POSTTUNNEL_PASS: WFP rule persisted throughout connect/data/disconnect'

    Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
    $created = $false
    Start-Sleep -Milliseconds 650
    if (-not (Test-R15FreshExternalTcp $remote) -or
        -not (Test-R15FreshExternalTcp $remote)) {
        throw 'R15_FAIL: external TCP did not recover after exact guard release'
    }
    Write-Host 'R15_GUARD_EXPLICIT_RELEASE_PASS: exact rule removed and TCP restored'
}
finally {
    Remove-Item Env:ORACLE_R15_GUARD_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:ORACLE_R15_GUARD_REMOTE -ErrorAction SilentlyContinue
    Remove-Item Env:ORACLE_R15_GUARD_PROGRAM -ErrorAction SilentlyContinue
    if ($created) {
        Remove-NetFirewallRule -Name $ruleName -ErrorAction Stop
    }
    if (Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue) {
        throw 'R15_FAIL: job-owned guard still exists'
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop).Count -ne $baselineCount) {
        throw 'R15_FAIL: firewall baseline rule count differs after cleanup'
    }
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop |
        Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
    if (($profiles -join '|') -ne ($baselineProfiles -join '|')) {
        throw 'R15_FAIL: firewall profile enabled state changed'
    }
    Write-Host 'R15_WFP_ROLLBACK_PASS: owned filter removed, original firewall baseline restored'
}
