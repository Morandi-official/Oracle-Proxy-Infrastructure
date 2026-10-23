[CmdletBinding()]
param([switch]$CiHarness)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'R86-Common.ps1')
Assert-R86-Environment ([bool]$CiHarness)
if (Test-Path -LiteralPath $script:R86Root) {
    throw 'R86_REFUSED: dedicated test directory already exists. Do not overwrite.'
}
if (Get-Service -Name $script:R86Service -ErrorAction SilentlyContinue) {
    throw 'R86_REFUSED: test SCM service already exists'
}
if (Get-ScheduledTask -TaskName $script:R86Task -TaskPath '\' -ErrorAction SilentlyContinue) {
    throw 'R86_REFUSED: scheduled task already exists'
}
$binary=Join-Path $PSScriptRoot 'R86NoNetworkMock.exe'
if (!(Test-Path -LiteralPath $binary -PathType Leaf) -or
    (Get-Item -LiteralPath $binary).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
    throw 'R86_REFUSED: standalone no-network mock executable missing'
}
$size=(Get-Item -LiteralPath $binary).Length
if ($size -lt 10000 -or $size -gt 90000000) {
    throw 'R86_REFUSED: mock executable size outside expected range'
}
if (@(Get-NetRoute -ErrorAction Stop |
    Where-Object DestinationPrefix -in @('10.77.72.1/32','10.77.72.2/32')).Count -ne 0) {
    throw 'R86_REFUSED: old test-specific native routes already present'
}
$digest=Get-R86-NetworkDigest
Write-Host 'R86_PREFLIGHT_PASS: attended admin, BFE/Firewall, no preexisting owned service/task/dir'
Write-Host 'R86_NO_NETWORK_CHANGES_PERFORMED=true'
Write-Host "R86_OS_NETWORK_FINGERPRINT=$digest"
