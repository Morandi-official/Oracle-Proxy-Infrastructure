$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'SCM cleanup is restricted to a disposable GitHub-hosted runner'
}
$marker = Join-Path $env:RUNNER_TEMP 'oracle-lab-owned.flag'
$root = Join-Path $env:ProgramData 'OracleProxyLab'
# Never touch a preexisting installation that this job did not create.
if (Test-Path $marker -PathType Leaf) {
    if ((Get-Content -LiteralPath $marker -Raw).Trim() -ne 'created-by-disposable-github-runner') {
        throw 'Lab ownership marker invalid, refusing deletion'
    }
    foreach ($profile in @('lab-peer-b', 'lab-peer-a')) {
        $svc = 'WireGuardTunnel$' + $profile
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {}
            & sc.exe delete $svc | Out-Null
        }
    }
    for ($attempt = 0; $attempt -lt 5; $attempt++) {
        try {
            if (Test-Path $root) {
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
            }
            break
        }
        catch {
            if ($attempt -eq 4) {
                Write-Warning 'Temporary lab files remain until GitHub discards the ephemeral VM'
            }
            Start-Sleep -Milliseconds 500
        }
    }
    Remove-Item -LiteralPath $marker -Force
}
# Delete ephemeral private key file even if staging failed.
$key = Join-Path $env:RUNNER_TEMP 'wg-lab-session.bin'
if (Test-Path $key) { Remove-Item -LiteralPath $key -Force }
# Confirm the only route prefixes this lab can add are absent once stopped.
# Network adapter removal may lag SCM Stop/Delete. Wait briefly for the
# actual IPv4/IPv6 kernel routes to disappear, not just the service state.
$scopedRoutePrefixes = @(
    '10.249.129.1/32', '10.249.129.2/32',
    'fd42:14::1/128', 'fd42:14::2/128'
)
$deadline = [DateTime]::UtcNow.AddSeconds(18)
do {
    $leftovers = @(Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -in $scopedRoutePrefixes })
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('lab-peer-a','lab-peer-b') })
    $services = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('WireGuardTunnel$lab-peer-a','WireGuardTunnel$lab-peer-b') })
    if ($leftovers.Count -eq 0 -and $adapters.Count -eq 0 -and $services.Count -eq 0) {
        break
    }
    Start-Sleep -Milliseconds 600
} while ([DateTime]::UtcNow -lt $deadline)

if ($leftovers.Count -gt 0 -or $adapters.Count -gt 0 -or $services.Count -gt 0) {
    throw "R6_FAIL: residual lab IPv4/IPv6 routes=$($leftovers.Count) adapters=$($adapters.Count) services=$($services.Count)"
}
Write-Host 'R6_TUNNEL_ROLLBACK_PASS: no synthetic IPv4/IPv6 routes, adapters or SCM peer services remain'
Write-Host 'LAB_CLEANUP: only owned test services/files stopped/deleted, fresh keys removed'
