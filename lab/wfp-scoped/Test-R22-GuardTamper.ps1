# R22: destructive CI fault injection against the exact synthetic
# SYSTEM-owned program-specific guard; NEVER run on user devices.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R22_TAMPER_TEST -ne 'CI_ONLY' -or
    $env:ORACLE_R21_SYSTEM_GUARD -ne 'CI_FIXED_SYSTEM_POLICY' -or
    -not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R22_REFUSED: only disposable admin Windows CI'
}
$name = 'OracleProxy-R21-CI-SYSTEM-OnlyGuard'
$program = (Get-Process -Id $PID -ErrorAction Stop).Path
$manager = Get-CimInstance Win32_Service -Filter "Name='OracleProxyLabManager'" -ErrorAction Stop
if ($manager.State -ne 'Running' -or $manager.ProcessId -le 4) {
    throw 'R22_REFUSED: actual SCM manager not running'
}
foreach ($profile in @('lab-peer-a','lab-peer-b')) {
    if ((Get-Service -Name ('WireGuardTunnel$' + $profile) -ErrorAction Stop).Status -ne 'Running') {
        throw 'R22_REFUSED: synthetic WireGuard peers not running'
    }
}
$matches = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
    Where-Object DisplayName -eq $name)
if ($matches.Count -ne 1) { throw 'R22_REFUSED: exact original WFP rule absent' }
$rule = $matches[0]
$port = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
$app = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
if ($rule.Action -ne 'Block' -or $rule.Direction -ne 'Outbound' -or
    [string]$port.Protocol -notin @('Any','256') -or
    -not [string]::Equals($app.Program, $program,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'R22_REFUSED: WFP rule not original narrow test policy'
}
$type = [Type]::GetTypeFromProgID('HNetCfg.FwPolicy2',$true)
$policy = [Activator]::CreateInstance($type)
try {
    $original = @($policy.Rules | Where-Object {
        [string]::Equals([string]$_.Name,$name,[StringComparison]::Ordinal)
    })
    if ($original.Count -ne 1 -or [int]$original[0].Action -ne 0 -or
        [int]$original[0].Protocol -ne 256 -or
        -not [string]::Equals([string]$original[0].ApplicationName,
            $program,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'R22_REFUSED: COM rule identity changed'
    }
    $policy.Rules.Remove($name)
}
finally {
    if ($null -ne $policy -and [Runtime.InteropServices.Marshal]::IsComObject($policy)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($policy)
    }
}
if (@(Get-NetFirewallRule -ErrorAction Stop |
    Where-Object DisplayName -eq $name).Count -ne 0) {
    throw 'R22_FAIL: injected policy deletion did not take effect'
}
# Manager must independently observe the rule is now missing and stop both
# native test peers. No unprotected traffic is sent from the tunnel.
$deadline = [DateTime]::UtcNow.AddSeconds(28)
do {
    Start-Sleep -Milliseconds 500
    $statuses = @('lab-peer-a','lab-peer-b') | ForEach-Object {
        (Get-Service -Name ('WireGuardTunnel$' + $_) -ErrorAction Stop).Status
    }
} while (@($statuses | Where-Object { $_ -ne 'Stopped' }).Count -gt 0 -and
         [DateTime]::UtcNow -lt $deadline)
if (@($statuses | Where-Object { $_ -ne 'Stopped' }).Count -gt 0) {
    throw 'R22_FAIL: manager failed to terminate exposed synthetic tunnels'
}
Write-Host 'R22_SYSTEM_WFP_TAMPER_STOPPED_BOTH_WG_PEERS_PASS'
# GUI authenticates and asks manager to re-enable a peer. It MUST fail,
# even if an attacker later re-adds a rule with the same friendly name.
$gui = (Resolve-Path './dist/lab-client-gui/OracleProxy.Windows.Preview.exe').Path
$probe = Start-Process -FilePath $gui -ArgumentList '--ci-lab-start-a' -Wait -PassThru
if ($probe.ExitCode -eq 0) {
    throw 'R22_FAIL: GUI/SCM accepted new start without actual WFP guard'
}
if ((Get-Service -Name 'WireGuardTunnel$lab-peer-a').Status -ne 'Stopped') {
    throw 'R22_FAIL: peer A started despite removed WFP'
}
Write-Host 'R22_SYSTEM_REFUSED_UNPROTECTED_RECONNECT_PASS'
