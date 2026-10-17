# R77 unconditional exact-owned ephemeral profile cleanup on disposable CI.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R77 -ne 'CI_ONLY') {
    throw 'R77_REFUSED: only hosted Windows CI may cleanup'
}
$root=Join-Path $env:ProgramData 'OracleProxyR77Only'
if (!(Test-Path -LiteralPath $root)) {
    Write-Host 'R77_PROTECTED_PROFILE_ABSENT_PASS'
    exit 0
}
$marker=Join-Path $root '.r77-owned'
if ((Get-Item -LiteralPath $root).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
    !(Test-Path -LiteralPath $marker -PathType Leaf) -or
    (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'CI_R77_ONLY_DISPOSABLE_GITHUB_VM') {
    throw 'R77_REFUSED: stage not provably owned'
}
$entries=@(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop)
if (@($entries | Where-Object {
    $_.Name -notin @('.r77-owned','lab-peer-a.conf') -or
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
}).Count -ne 0) {
    throw 'R77_REFUSED: unexpected or linked stage entry'
}
$file=Join-Path $root 'lab-peer-a.conf'
if (Test-Path -LiteralPath $file -PathType Leaf) {
    Remove-Item -LiteralPath $file -Force -ErrorAction Stop
}
Remove-Item -LiteralPath $marker -Force -ErrorAction Stop
Remove-Item -LiteralPath $root -Force -ErrorAction Stop
if (Test-Path -LiteralPath $root) {
    throw 'R77_FAIL: protected temporary config persisted'
}
Write-Host 'R77_NO_PLAINTEXT_PROFILE_OR_OWNED_STAGE_RESIDUAL_PASS'
