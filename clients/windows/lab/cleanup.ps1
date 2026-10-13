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
