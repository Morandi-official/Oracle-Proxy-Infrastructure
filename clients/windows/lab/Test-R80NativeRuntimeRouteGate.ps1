# R80 disposable Windows CI: prove the actual service's pre-LoadLibrary
# route/peer grammar guard refuses a CONFIG + MANIFEST jointly repinned
# to a malicious default route, not just a stale SHA-256 hash.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R80 -ne 'CI_ONLY' -or
    $env:ORACLE_R79 -ne 'CI_ONLY') {
    throw 'R80_REFUSED: hosted CI only'
}
$exe=(Resolve-Path ./dist/service-host/OracleProxy.WireGuardHost.exe).Path
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$profile=Join-Path (Join-Path $root 'config') 'lab-peer-a.conf'
$pins=Join-Path (Join-Path $root 'lab-peer-a') 'engine-pins.json'
$marker=Join-Path $root '.ci-control-approved'
if (!(Test-Path -LiteralPath $profile -PathType Leaf) -or
    !(Test-Path -LiteralPath $pins -PathType Leaf) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'DISPOSABLE_GITHUB_RUNNER_ONLY' -or
    (Get-Service -Name 'WireGuardTunnel$lab-peer-a' -ErrorAction SilentlyContinue)) {
    throw 'R80_REFUSED: exact owned files missing or native service already active'
}
& $exe --ci-r80-scope-self-test
if ($LASTEXITCODE -ne 0) { throw 'R80 strict in-process grammar mutation selftests failed' }
& $exe --ci-r80-owned-scope-review
if ($LASTEXITCODE -ne 0) { throw 'R80 actual pre-start config refused' }
$beforeProfile=[IO.File]::ReadAllBytes($profile)
$beforePins=[IO.File]::ReadAllBytes($pins)
try {
    $original=[IO.File]::ReadAllText($profile,[Text.Encoding]::ASCII)
    $target='AllowedIPs = 10.249.129.2/32, fd42:14::2/128'
    $bad='AllowedIPs = 0.0.0.0/0, ::/0'
    if (!$original.Contains($target)) { throw 'R80 expected exact disposable peer missing' }
    [IO.File]::WriteAllText($profile,$original.Replace($target,$bad),
        [Text.Encoding]::ASCII)
    $manifest=[IO.File]::ReadAllText($pins) | ConvertFrom-Json -ErrorAction Stop
    $manifest.config_sha256=(Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($pins,($manifest | ConvertTo-Json -Compress -Depth 3),
        [Text.Encoding]::ASCII)
    # R79 integrity/ACL verification alone can pass a malicious config if
    # its SHA pin is jointly replaced. R80's independent runtime grammar
    # must still deny the widened inner AllowedIPs *before* DLL loading.
    & $exe --ci-r79-native-bundle-review
    if ($LASTEXITCODE -ne 0) { throw 'R80 cannot isolate scope check from re-pinned integrity guard' }
    & $exe --ci-r80-owned-scope-review
    if ($LASTEXITCODE -ne 3) { throw 'R80 admitted jointly-repinned broad routes' }
}
finally {
    [IO.File]::WriteAllBytes($profile,$beforeProfile)
    [IO.File]::WriteAllBytes($pins,$beforePins)
    [Array]::Clear($beforeProfile,0,$beforeProfile.Length)
    [Array]::Clear($beforePins,0,$beforePins.Length)
}
& $exe --ci-r80-owned-scope-review
if ($LASTEXITCODE -ne 0) { throw 'R80 did not recover original narrow config' }
& $exe --ci-r79-native-bundle-review
if ($LASTEXITCODE -ne 0) { throw 'R80 restored config or manifest integrity failed' }
Write-Host 'R80_RUNTIME_NATIVE_PRE_DLL_ROUTE_SCOPE_REPIN_TAMPER_REFUSED_PASS'
