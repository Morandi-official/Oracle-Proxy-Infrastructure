$ErrorActionPreference = 'Stop'
python -m pip install --disable-pip-version-check 'cryptography==45.0.7'
if ($LASTEXITCODE -ne 0) { throw 'Pinned cryptography dependency unavailable' }
if ($env:ORACLE_R44_DPAPI_TEST -eq 'CI_ONLY') {
    $keyFile = Join-Path $env:RUNNER_TEMP 'wg-r44-session.dpapi'
    $env:WG_LAB_EPHEMERAL_KEY_FILE = $keyFile
    python './clients/windows/lab/generate_lab_keys_dpapi.py'
    if ($LASTEXITCODE -ne 0 -or !(Test-Path $keyFile -PathType Leaf) -or
        (Get-Item $keyFile).Length -le 128 -or (Get-Item $keyFile).Length -gt 4096) {
        throw 'R44 cannot stage sealed ephemeral configuration'
    }
    if (Test-Path (Join-Path $env:RUNNER_TEMP 'wg-lab-session.bin')) {
        throw 'R44 refuses any raw CI secret bundle'
    }
}
else {
    $keyFile = Join-Path $env:RUNNER_TEMP 'wg-lab-session.bin'
    $env:WG_LAB_EPHEMERAL_KEY_FILE = $keyFile
    python './clients/windows/lab/generate_lab_keys.py'
    if ($LASTEXITCODE -ne 0 -or !(Test-Path $keyFile -PathType Leaf) -or
        (Get-Item $keyFile).Length -ne 128) {
        throw 'Failed to create fresh, ephemeral test-only private keys'
    }
}
$userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls.exe $keyFile /inheritance:r /grant:r "*$($userSid):(F)" '*S-1-5-18:(F)' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect ephemeral test keys' }
"WG_LAB_EPHEMERAL_KEY_FILE=$keyFile" >> $env:GITHUB_ENV
Write-Host 'PASS: two fresh X25519 keypairs generated in isolated temporary storage; no secrets logged'
