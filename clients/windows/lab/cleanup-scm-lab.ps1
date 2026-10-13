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
$leftovers = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {
    $_.DestinationPrefix -in @('10.249.129.1/32', '10.249.129.2/32')
})
if ($leftovers.Count -gt 0) {
    throw 'Narrow lab routes remain; disposable VM is destroyed after this job'
}
Write-Host 'LAB_CLEANUP: only owned test services/files stopped/deleted, fresh keys removed'
