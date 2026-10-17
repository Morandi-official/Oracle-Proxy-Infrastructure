# R79: pre-activation signed, pinned bundle & protected ACL review of real
# G14 CI native files. Must run BEFORE either SCM tunnel service starts.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R79 -ne 'CI_ONLY') {
    throw 'R79_REFUSED: disposable GitHub Windows VM only'
}
$exe=(Resolve-Path ./dist/service-host/OracleProxy.WireGuardHost.exe).Path
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$marker=Join-Path $root '.ci-control-approved'
$manifest=Join-Path (Join-Path $root 'lab-peer-a') 'engine-pins.json'
$jobMarker=Join-Path $env:RUNNER_TEMP 'oracle-lab-owned.flag'
if (!(Test-Path -LiteralPath $marker -PathType Leaf) -or
    !(Test-Path -LiteralPath $manifest -PathType Leaf) -or
    !(Test-Path -LiteralPath $jobMarker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'DISPOSABLE_GITHUB_RUNNER_ONLY' -or
    (Get-Content -LiteralPath $jobMarker -Raw).Trim() -ne 'created-by-disposable-github-runner') {
    throw 'R79_REFUSED: independently owned native lab staging absent'
}
$services=@('WireGuardTunnel$lab-peer-a','WireGuardTunnel$lab-peer-b')
foreach ($name in $services) {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        throw 'R79_REFUSED: native service already exists before audit'
    }
}
$env:RUNNER_ENVIRONMENT='forbidden'
& $exe --ci-r79-native-bundle-review
if ($LASTEXITCODE -ne 3) { throw 'R79 hosted runner refusal bypassed' }
$env:RUNNER_ENVIRONMENT='github-hosted'
& $exe --ci-r79-native-bundle-review
if ($LASTEXITCODE -ne 0) {
    throw 'R79 native service host refused actual staged signed bundle'
}
$original=[IO.File]::ReadAllBytes($manifest)
try {
    # Manifest is not secret, but do not print or upload anything from the
    # protected directory. Corrupt only this exact owned hash pin temporarily.
    $text=[IO.File]::ReadAllText($manifest)
    $document=$text | ConvertFrom-Json -ErrorAction Stop
    $document.tunnel_sha256=('0' * 64)
    [IO.File]::WriteAllText($manifest,
        ($document | ConvertTo-Json -Compress -Depth 4),
        [Text.Encoding]::ASCII)
    & $exe --ci-r79-native-bundle-review
    if ($LASTEXITCODE -ne 3) {
        throw 'R79 tampered native tunnel DLL pin was not refused'
    }
}
finally {
    [IO.File]::WriteAllBytes($manifest,$original)
    [Array]::Clear($original,0,$original.Length)
}
& $exe --ci-r79-native-bundle-review
if ($LASTEXITCODE -ne 0) {
    throw 'R79 host did not recover strict pin verification after test restoration'
}
foreach ($name in $services) {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        throw 'R79 offline audit started a forbidden native service'
    }
}
Write-Host 'R79_REAL_SIGNED_NATIVE_BUNDLE_PREACTIVATION_AND_TAMPER_REFUSAL_PASS'
