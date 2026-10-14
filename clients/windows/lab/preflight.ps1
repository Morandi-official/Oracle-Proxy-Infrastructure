$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Not an isolated administrator lab'
}
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Refuse to execute outside disposable GitHub-hosted Windows runner'
}
if (@(Get-NetAdapter | Where-Object { $_.Name -like 'OracleLabTest*' }).Count -ne 0) {
    throw 'Preexisting test adapters detected; fail closed'
}
$routes = @(Get-NetRoute -ErrorAction Stop | Where-Object {
    $_.DestinationPrefix -in @('0.0.0.0/0','::/0')
} | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
    Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric)
ConvertTo-Json -InputObject $routes -Depth 4 |
    Set-Content -LiteralPath (Join-Path $env:RUNNER_TEMP 'wg-route-before.json') -Encoding UTF8
Write-Host "PASS: GitHub disposable runner verified, default route count=$($routes.Count)"

# R6 rollback baseline is captured BEFORE any temporary adapter or SCM tunnel.
# The per-runner file is never uploaded or printed (may include local DNS IPs).
$rootPath = Join-Path $env:RUNNER_TEMP 'oracle-r6-network-before.json'
if (Test-Path -LiteralPath $rootPath) {
    throw 'Refuse to overwrite an existing R6 baseline'
}
$labNames = @('lab-peer-a','lab-peer-b')
if (@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -in $labNames }).Count -gt 0) {
    throw 'Preexisting lab peer adapter; no service test allowed'
}
$scoped = @('10.249.129.1/32','10.249.129.2/32','fd42:14::1/128','fd42:14::2/128')
if (@(Get-NetRoute -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in $scoped }).Count -gt 0) {
    throw 'Synthetic tunnel route already exists before test'
}
function R6-NetworkFingerprint {
    $routes = @(Get-NetRoute -ErrorAction Stop |
        Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } |
        Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        ConvertTo-Json -Compress -Depth 5) -join ''
    $dns = @(Get-DnsClientServerAddress -ErrorAction Stop |
        Select-Object InterfaceIndex,AddressFamily,ServerAddresses |
        Sort-Object InterfaceIndex,AddressFamily |
        ConvertTo-Json -Compress -Depth 6) -join ''
    $fwCount = @(Get-NetFirewallRule -ErrorAction Stop).Count
    return [pscustomobject]@{
        defaultRoutes = $routes
        dns = $dns
        firewallCount = $fwCount
    }
}
R6-NetworkFingerprint | ConvertTo-Json -Compress -Depth 4 |
    Set-Content -LiteralPath $rootPath -Encoding utf8 -ErrorAction Stop
Write-Host 'R6_PRECHECK_PASS: real Windows network baseline securely held in disposable CI temporary directory'
