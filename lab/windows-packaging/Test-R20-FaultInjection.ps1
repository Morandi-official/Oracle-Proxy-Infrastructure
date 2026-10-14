# R20 CI-only installer fault injection for STATUS-ONLY manager (NOT VPN).
param([Parameter(Mandatory=$true)][string]$ManagerExe,
      [Parameter(Mandatory=$true)][string]$GuiExe)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$id = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    -not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R20_REFUSED: only disposable administrator runner'
}
$root = Join-Path $env:RUNNER_TEMP 'OracleProxyR5StatusOnly'
$name = 'OracleProxyLabManager'
function Baseline() {
    $routes = @(Get-NetRoute -ErrorAction Stop |
        Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
        Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        ConvertTo-Json -Compress -Depth 5) -join ''
    $dns = @(Get-DnsClientServerAddress -ErrorAction Stop |
        Select-Object InterfaceIndex,AddressFamily,ServerAddresses |
        Sort-Object InterfaceIndex,AddressFamily |
        ConvertTo-Json -Compress -Depth 6) -join ''
    $rules = @(Get-NetFirewallRule -ErrorAction Stop).Count
    return ($routes + '|' + $dns + '|' + $rules)
}
$expectedBaseline = Baseline
function Assert-Recovered([string]$phase) {
    if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or
        (Test-Path -LiteralPath $root)) {
        throw "R20_FAIL: owned SCM service or stage remains after $phase"
    }
    if ((Baseline) -ne $expectedBaseline) {
        throw "R20_FAIL: default routes/DNS/firewall changed after $phase"
    }
}
Assert-Recovered 'preflight'
foreach ($phase in @('AfterStage','AfterScmCreate','AfterScmStart')) {
    $expected = switch ($phase) {
        'AfterStage' { 'R20_INJECTED_AFTER_STAGE' }
        'AfterScmCreate' { 'R20_INJECTED_AFTER_SCM_CREATE' }
        'AfterScmStart' { 'R20_INJECTED_AFTER_SCM_START' }
    }
    $received = $false
    try {
        & ./lab/windows-packaging/Test-DisposableLifecycle.ps1 -ManagerExe $ManagerExe -GuiExe $GuiExe -InjectFailureAt $phase
    }
    catch {
        if ($_.Exception.Message -notlike "*$expected*") { throw }
        $received = $true
    }
    if (-not $received) { throw "R20_FAIL: $phase did not inject expected failure" }
    Assert-Recovered $phase
    Write-Host "R20_$($phase.ToUpperInvariant())_ROLLBACK_PASS"
}
# Preexisting user path is never modified or recursively removed.
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
$sentinel = Join-Path $root 'PREEXISTING_USER_DATA.txt'
try {
    'MUST_PRESERVE' | Set-Content -LiteralPath $sentinel -Encoding ascii
    $refused = $false
    try {
        & ./lab/windows-packaging/Test-DisposableLifecycle.ps1 -ManagerExe $ManagerExe -GuiExe $GuiExe
    }
    catch {
        if ($_.Exception.Message -notlike '*preexisting install directory*') { throw }
        $refused = $true
    }
    if (-not $refused -or !(Test-Path -LiteralPath $sentinel) -or
        (Get-Content -LiteralPath $sentinel -Raw).Trim() -ne 'MUST_PRESERVE') {
        throw 'R20_FAIL: preexisting user data overwritten'
    }
    Write-Host 'R20_PREEXISTING_DATA_PRESERVED_PASS'
}
finally {
    # Delete only the exact sentinel/empty folder created by this test.
    if (Test-Path -LiteralPath $sentinel) {
        Remove-Item -LiteralPath $sentinel -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -ErrorAction Stop
    }
}
Assert-Recovered 'path-refusal'
& ./lab/windows-packaging/Test-DisposableLifecycle.ps1 -ManagerExe $ManagerExe -GuiExe $GuiExe
if (-not $?) { throw 'R20_FAIL: clean reinstall not possible after faults' }
Assert-Recovered 'normal-retry'
Write-Host 'R20_INSTALLER_FAILURE_RECOVERY_PASS: install fail injections and clean retry verified'
