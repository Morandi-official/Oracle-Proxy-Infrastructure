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
