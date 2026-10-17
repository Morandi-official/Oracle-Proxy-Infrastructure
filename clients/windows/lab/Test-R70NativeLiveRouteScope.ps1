# R70: read-only live Windows OS route+DNS assertion while TWO real WireGuardNT
# CI SCM services are running. Must never run against a user's Windows system.
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R70_NATIVE_SCOPE -ne 'CI_ONLY') {
    throw 'R70_REFUSED: requires exact disposable Windows GitHub runner context'
}
$root = Join-Path $env:ProgramData 'OracleProxyLab'
$owner = Join-Path $root '.ci-control-approved'
if (!(Test-Path -LiteralPath $owner -PathType Leaf) -or
    (Get-Content -LiteralPath $owner -Raw).Trim() -ne 'DISPOSABLE_GITHUB_RUNNER_ONLY') {
    throw 'R70_REFUSED: independently owned CI lab missing'
}
$routeBaseline = Join-Path $env:RUNNER_TEMP 'wg-route-before.json'
$networkBaseline = Join-Path $env:RUNNER_TEMP 'oracle-r6-network-before.json'
if (!(Test-Path -LiteralPath $routeBaseline -PathType Leaf) -or
    !(Test-Path -LiteralPath $networkBaseline -PathType Leaf)) {
    throw 'R70_REFUSED: independent prior-activation OS baseline missing'
}
$baseRoutes = @(Get-Content -LiteralPath $routeBaseline -Raw | ConvertFrom-Json)
$baseOs = Get-Content -LiteralPath $networkBaseline -Raw | ConvertFrom-Json
$liveDefaults = @(Get-NetRoute -ErrorAction Stop |
    Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
    Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
    Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
function Route-Fingerprint([object[]]$entries) {
    return (@($entries | ForEach-Object {
        "$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)|$($_.RouteMetric)"
    } | Sort-Object) -join ';')
}
if ((Route-Fingerprint $baseRoutes) -ne (Route-Fingerprint $liveDefaults)) {
    throw 'R70_FAIL: live native WireGuardNT changed a physical IPv4/IPv6 default route'
}
$expected = @{
    'lab-peer-a'=@('10.249.129.2/32','fd42:14::2/128')
    'lab-peer-b'=@('10.249.129.1/32','fd42:14::1/128')
}
$indexes = @()
foreach ($name in @('lab-peer-a','lab-peer-b')) {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop |
        Where-Object { $_.Name -ceq $name })
    if ($adapters.Count -ne 1 -or $adapters[0].ifIndex -le 0) {
        throw 'R70_FAIL: owned test NIC identity missing or ambiguous'
    }
    $idx = [int]$adapters[0].ifIndex
    if ($idx -in $indexes) { throw 'R70_FAIL: duplicate native interface index' }
    $indexes += $idx
    $allOnAdapter = @(Get-NetRoute -InterfaceIndex $idx -ErrorAction Stop)
    $prefixes = @($allOnAdapter | ForEach-Object { [string]$_.DestinationPrefix })
    foreach ($target in $expected[$name]) {
        if ($target -notin $prefixes) {
            throw 'R70_FAIL: pinned narrow inner route not installed on expected native adapter'
        }
    }
    foreach ($route in $allOnAdapter) {
        if ($route.DestinationPrefix -in @(
            '0.0.0.0/0','::/0','10.249.129.0/24','fd42:14::/64')) {
            throw 'R70_FAIL: native adapter has widened route scope'
        }
    }
}
# The two newly created adapter records are expected to appear; no DNS server
# may be configured on them, and EXISTING interfaces' DNS must be unaltered.
$dnsAll = @(Get-DnsClientServerAddress -ErrorAction Stop)
foreach ($record in @($dnsAll | Where-Object { $_.InterfaceIndex -in $indexes })) {
    if (@($record.ServerAddresses | Where-Object { $_ }).Count -ne 0) {
        throw 'R70_FAIL: unexpected DNS server on native test adapter'
    }
}
$currentPhysicalDns = @( $dnsAll |
    Where-Object { $_.InterfaceIndex -notin $indexes } |
    Select-Object InterfaceIndex,AddressFamily,ServerAddresses |
    Sort-Object InterfaceIndex,AddressFamily |
    ConvertTo-Json -Compress -Depth 6 ) -join ''
if ($currentPhysicalDns -ne [string]$baseOs.dns) {
    throw 'R70_FAIL: preexisting interface DNS changed while native tunnel active'
}
Write-Host 'R70_ACTIVE_NATIVE_ROUTES_AND_DNS_NARROW_PASS: independent OS route/DNS evidence, CI-only; no public path or WFP leak proof'
