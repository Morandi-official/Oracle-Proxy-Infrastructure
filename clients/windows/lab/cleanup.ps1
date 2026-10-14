$ErrorActionPreference = 'Stop'
$keyFile = Join-Path $env:RUNNER_TEMP 'wg-lab-session.bin'
if (Test-Path $keyFile -PathType Leaf) {
    Remove-Item -LiteralPath $keyFile -Force
}
$snapshot = Join-Path $env:RUNNER_TEMP 'wg-route-before.json'
if (Test-Path $snapshot) {
    $before = @(Get-Content -LiteralPath $snapshot -Raw | ConvertFrom-Json)
    $after = @(Get-NetRoute -ErrorAction Stop | Where-Object {
        $_.DestinationPrefix -in @('0.0.0.0/0','::/0')
    } | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
    $old = @($before | ForEach-Object {
        "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)"
    } | Sort-Object)
    $new = @($after | ForEach-Object {
        "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)"
    } | Sort-Object)
    if (($old -join ';') -ne ($new -join ';')) {
        throw 'Default routes changed; GitHub will destroy this disposable VM'
    }
    Write-Host 'PASS: IPv4/IPv6 default routes unchanged'
}
$remaining = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'OracleLabTest*' })
if ($remaining.Count -ne 0) {
    throw 'Experiment adapter persisted; GitHub disposable VM will be destroyed'
}
Write-Host 'PASS: no temporary adapter present, private keys removed; runner destruction is independent recovery'

# R6: Verify DNS/firewall/default-route baseline, not only route count.
# Never run on a live user machine or outside a hosted throwaway runner.
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows') {
    throw 'R6_REFUSED: rollback baseline verifier only runs in Windows GitHub CI'
}
$baselinePath = Join-Path $env:RUNNER_TEMP 'oracle-r6-network-before.json'
if (Test-Path -LiteralPath $baselinePath -PathType Leaf) {
    $base = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json -ErrorAction Stop
    $currentDefaults = @(Get-NetRoute -ErrorAction Stop |
        Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
        Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        ConvertTo-Json -Compress -Depth 5) -join ''
    $currentDns = @(Get-DnsClientServerAddress -ErrorAction Stop |
        Select-Object InterfaceIndex,AddressFamily,ServerAddresses |
        Sort-Object InterfaceIndex,AddressFamily |
        ConvertTo-Json -Compress -Depth 6) -join ''
    $firewallCount = @(Get-NetFirewallRule -ErrorAction Stop).Count
    $scopedRules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'OracleProxy-G14-TEMP-*' })
    if ($currentDefaults -ne $base.defaultRoutes -or
        $currentDns -ne $base.dns -or
        $firewallCount -ne $base.firewallCount -or $scopedRules.Count -gt 0) {
        throw 'R6_FAIL: Windows default routes, DNS or Firewall did not return to original baseline'
    }
    Write-Host 'R6_OS_RESTORE_PASS: IPv4/IPv6 default routes, DNS servers and Windows Firewall rules restored'
    Remove-Item -LiteralPath $baselinePath -Force
}
