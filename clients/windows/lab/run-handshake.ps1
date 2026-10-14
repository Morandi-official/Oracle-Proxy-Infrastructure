$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Only disposable GitHub-hosted Windows runners are eligible'
}
if (-not (Test-Path $env:WG_LAB_EPHEMERAL_KEY_FILE -PathType Leaf)) {
    throw 'Ephemeral peer secrets are unavailable'
}
$exe = (Resolve-Path './dist/loopback/wgnt-loopback.exe').Path
& $exe $env:WG_LAB_DLL $env:WG_LAB_EPHEMERAL_KEY_FILE
if ($LASTEXITCODE -ne 0) {
    throw 'Isolated real two-peer WireGuardNT handshake did not complete'
}
Write-Host 'PASS: both driver-reported LastHandshake counters nonzero'
