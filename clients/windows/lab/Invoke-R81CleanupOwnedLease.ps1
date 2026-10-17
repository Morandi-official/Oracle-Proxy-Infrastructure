# R81 always-run exact-owned transient field lease removal (hosted CI only).
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R81 -ne 'CI_ONLY') {
    throw 'R81_REFUSED: hosted Windows CI only'
}
$root=Join-Path $env:ProgramData 'OracleProxyLab'
if (!(Test-Path -LiteralPath $root)) {
    Write-Host 'R81_OWNED_FIELD_LEASE_ABSENT_PASS'
    exit 0
}
$marker=Join-Path $root '.r81-owned'
if ((Get-Item -LiteralPath $root).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'CI_R81_ONLY_DISPOSABLE_GITHUB_VM') {
    throw 'R81_REFUSED: not our exact owned directory'
}
$configFolder=Join-Path $root 'config'
$rootEntries=@(Get-ChildItem -LiteralPath $root -Force)
if (@($rootEntries|Where-Object {
    $_.Name -notin @('.r81-owned','config') -or
    $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)
}).Count -ne 0) {
    throw 'R81_REFUSED: foreign root entry'
}
if (Test-Path -LiteralPath $configFolder) {
    $contents=@(Get-ChildItem -LiteralPath $configFolder -Force)
    if (@($contents|Where-Object {
        $_.Name -notin @('lab-field.conf','lab-field-lease.json') -or
        $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)
    }).Count -ne 0) { throw 'R81_REFUSED: foreign secret files' }
    foreach ($name in @('lab-field.conf','lab-field-lease.json')) {
        $path=Join-Path $configFolder $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    Remove-Item -LiteralPath $configFolder -Force -ErrorAction Stop
}
Remove-Item -LiteralPath $marker -Force -ErrorAction Stop
Remove-Item -LiteralPath $root -Force -ErrorAction Stop
if (Test-Path -LiteralPath $root) {
    throw 'R81_FAIL: synthetic field lease or secret survived'
}
Write-Host 'R81_EXACT_PROTECTED_FIELD_LEASE_AND_CONFIG_CLEANUP_PASS'
