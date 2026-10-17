[CmdletBinding()]
param([switch]$CiHarness)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'R86-Common.ps1')
Assert-R86-Environment ([bool]$CiHarness)
$task=Get-ScheduledTask -TaskPath '\' -TaskName $script:R86Task -ErrorAction SilentlyContinue
$service=Get-Service -Name $script:R86Service -ErrorAction SilentlyContinue
$exists=Test-Path -LiteralPath $script:R86Root
if (!$task -and !$service -and !$exists) {
    Write-Host 'R86_ALREADY_CLEAN: no owned artifacts'
    exit 0
}
Assert-R86-Ownership
foreach ($name in @('R86NoNetworkMock.exe','owner.txt','state.txt','baseline.sha256','expired.ok')) {
    $path=Join-Path $script:R86Root $name
    if (Test-Path -LiteralPath $path) {
        if ((Get-Item -LiteralPath $path).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -or
            (Get-Item -LiteralPath $path).PSIsContainer) {
            throw 'R86_REFUSED: foreign or linked owned file'
        }
    }
}
$foreign=@(Get-ChildItem -LiteralPath $script:R86Root -Force -ErrorAction Stop |
    Where-Object { $_.Name -notin @(
        'R86NoNetworkMock.exe','owner.txt','state.txt','baseline.sha256','expired.ok') })
if ($foreign.Count -ne 0) {
    throw 'R86_REFUSED: unexpected files; no recursive deletion'
}
if ($task) {
    Assert-R86-TaskRecord | Out-Null
    Unregister-ScheduledTask -TaskPath '\' -TaskName $script:R86Task -Confirm:$false -ErrorAction Stop
}
if ($service) {
    Assert-R86-ServiceRecord | Out-Null
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $script:R86Service -ErrorAction Stop
        (Get-Service -Name $script:R86Service).WaitForStatus(
            [ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(25))
    }
    & sc.exe delete $script:R86Service | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'R86_FAIL: exact service delete failed' }
    $max=[DateTime]::UtcNow.AddSeconds(20)
    while ((Get-Service -Name $script:R86Service -ErrorAction SilentlyContinue) -and
           [DateTime]::UtcNow -lt $max) {
        Start-Sleep -Milliseconds 500
    }
    if (Get-Service -Name $script:R86Service -ErrorAction SilentlyContinue) {
        throw 'R86_FAIL: exact service still registered'
    }
}
$oldPath=Join-Path $script:R86Root 'baseline.sha256'
$old=if (Test-Path -LiteralPath $oldPath -PathType Leaf) {
    (Get-Content -LiteralPath $oldPath -Raw).Trim()
} else { '' }
foreach ($name in @('expired.ok','state.txt','baseline.sha256','owner.txt','R86NoNetworkMock.exe')) {
    $path=Join-Path $script:R86Root $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
    }
}
Remove-Item -LiteralPath $script:R86Root -Force -ErrorAction Stop
if ((Test-Path -LiteralPath $script:R86Root) -or
    (Get-Service -Name $script:R86Service -ErrorAction SilentlyContinue) -or
    (Get-ScheduledTask -TaskPath '\' -TaskName $script:R86Task -ErrorAction SilentlyContinue)) {
    throw 'R86_FAIL: owned SCM/task/directory residual'
}
Write-Host 'R86_EXACT_TEST_SERVICE_TASK_AND_FILES_REMOVED_PASS'
if ($old -and $old -ceq (Get-R86-NetworkDigest)) {
    Write-Host 'R86_DEFAULT_ROUTES_DNS_FIREWALL_RESTORED_PASS'
} else {
    Write-Warning 'R86_NETWORK_BASELINE_NOT_MATCHED: inspect ordinary network; no firewall/route change attempted.'
}
Write-Host 'R86_CHECK_UU_AND_ORDINARY_WEB_MANUALLY'
