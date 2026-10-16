$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Only disposable GitHub-hosted Windows runners are eligible'
}
if (-not (Test-Path $env:WG_LAB_EPHEMERAL_KEY_FILE -PathType Leaf)) {
    throw 'Ephemeral peer secrets are unavailable'
}
if ($env:ORACLE_R44_DPAPI_TEST -eq 'CI_ONLY') {
    $exe = (Resolve-Path './dist/loopback/wgnt-r44-dpapi-native.exe').Path
    $savedRunner = $env:RUNNER_ENVIRONMENT
    try {
        $env:RUNNER_ENVIRONMENT = 'not-authorized'
        & $exe $env:WG_LAB_DLL $env:WG_LAB_EPHEMERAL_KEY_FILE
        if ($LASTEXITCODE -ne 4) {
            throw 'R44 native decryption accepted non-disposable environment'
        }
    }
    finally { $env:RUNNER_ENVIRONMENT = $savedRunner }
}
else { $exe = (Resolve-Path './dist/loopback/wgnt-loopback.exe').Path }
& $exe $env:WG_LAB_DLL $env:WG_LAB_EPHEMERAL_KEY_FILE
if ($LASTEXITCODE -ne 0) {
    throw 'Isolated real two-peer WireGuardNT handshake did not complete'
}
Write-Host 'PASS: both driver-reported LastHandshake counters nonzero'
