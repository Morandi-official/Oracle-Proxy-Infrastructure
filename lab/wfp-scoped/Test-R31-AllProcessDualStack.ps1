# R31 disposable Windows OS WFP proof: all-application outbound blocking,
# fixed external test destinations ONLY. NEVER a production kill switch.
# Intentionally does not change default routes, DNS, profiles or global policy.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R31_NARROW_OS_WFP -ne 'CI_ONLY' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R31_REFUSED: disposable elevated Windows CI only'
}
if ((Get-Service BFE).Status -ne 'Running' -or
    (Get-Service MpsSvc).Status -ne 'Running') {
    throw 'R31_REFUSED: Windows filtering services unavailable'
}
$name = 'OracleProxy-R31-CI-AllApps-FixedDestination'
# Use fixed public resolvers as targets; MUST NEVER block entire physical
# interface or all Internet connectivity of a CI-hosted runner.
$destinations = @('1.1.1.1', '8.8.8.8',
                  '2606:4700:4700::1111', '2001:4860:4860::8888')
$existing = @(Get-NetFirewallRule -ErrorAction Stop |
    Where-Object DisplayName -eq $name)
if ($existing.Count -ne 0) { throw 'R31_REFUSED: owned rule already exists' }
$routesBefore = @(Get-NetRoute -ErrorAction Stop |
    Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
    Sort-Object ifIndex,DestinationPrefix,NextHop |
    ForEach-Object { "$($_.ifIndex):$($_.DestinationPrefix):$($_.NextHop):$($_.RouteMetric)" })
$profilesBefore = @(Get-NetFirewallProfile -ErrorAction Stop |
    Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
$created = $false
try {
    New-NetFirewallRule -Name $name -DisplayName $name -Enabled True `
        -Direction Outbound -Action Block -Profile Any -Protocol Any `
        -RemoteAddress $destinations -InterfaceType Any `
        -ErrorAction Stop | Out-Null
    $created = $true
    $live = @(Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop)
    if ($live.Count -ne 1 -or $live[0].Direction -ne 'Outbound' -or
        $live[0].Action -ne 'Block' -or
        [string]$live[0].Enabled -ne 'True') {
        throw 'R31_FAIL: OS outbound rule missing or mutated'
    }
    $app = $live[0] | Get-NetFirewallApplicationFilter -ErrorAction Stop
    $port = $live[0] | Get-NetFirewallPortFilter -ErrorAction Stop
    $addr = $live[0] | Get-NetFirewallAddressFilter -ErrorAction Stop
    if ([string]$app.Program -ne 'Any' -or
        [string]$port.Protocol -notin @('Any','256') -or
        [string]$port.RemotePort -ne 'Any') {
        throw 'R31_FAIL: not a genuine all-process all-protocol rule'
    }
    # NetSecurity projects this property as a string array on some Windows
    # versions and a delimited scalar on others. Normalize both, and compare
    # numeric IP identities (IPv6 canonical text can differ).
    $actual = @($addr.RemoteAddress | ForEach-Object {
        @([string]$_ -split '[,; ]+') | Where-Object { $_ } | ForEach-Object {
            [System.Net.IPAddress]::Parse($_).ToString()
        }
    } | Sort-Object -Unique)
    $expected = @($destinations | ForEach-Object {
        [System.Net.IPAddress]::Parse($_).ToString()
    } | Sort-Object -Unique)
    if (($actual -join '|') -ne ($expected -join '|')) {
        throw 'R31_FAIL: target addresses altered'
    }
    Write-Host 'R31_OS_ALL_APPLICATION_IPV4_IPV6_WFP_RULE_ACTIVE_PASS'
    # OS metadata verifies cross-process applicability but not real remote
    # packet denial: no packet-level claim without independent witness.
}
finally {
    if ($created) {
        $matches = @(Get-NetFirewallRule -ErrorAction Stop |
            Where-Object DisplayName -eq $name)
        if ($matches.Count -ne 1 -or $matches[0].Name -ne $name) {
            throw 'R31_FAIL: refusing unsafe firewall cleanup'
        }
        Remove-NetFirewallRule -Name $name -ErrorAction Stop
    }
    if (@(Get-NetFirewallRule -ErrorAction Stop |
          Where-Object DisplayName -eq $name).Count -ne 0) {
        throw 'R31_FAIL: CI WFP filter survived cleanup'
    }
    $routesAfter = @(Get-NetRoute -ErrorAction Stop |
        Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
        Sort-Object ifIndex,DestinationPrefix,NextHop |
        ForEach-Object { "$($_.ifIndex):$($_.DestinationPrefix):$($_.NextHop):$($_.RouteMetric)" })
    $profilesAfter = @(Get-NetFirewallProfile -ErrorAction Stop |
        Sort-Object Name | ForEach-Object { "$($_.Name):$($_.Enabled)" })
    if (($routesBefore -join '|') -ne ($routesAfter -join '|') -or
        ($profilesBefore -join '|') -ne ($profilesAfter -join '|')) {
        throw 'R31_FAIL: unrelated routes or firewall profiles changed'
    }
    Write-Host 'R31_OWNED_WFP_RELEASE_AND_OS_BASELINE_PASS'
}
