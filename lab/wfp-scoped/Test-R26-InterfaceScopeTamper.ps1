# R26: mutate the exact CI-only SYSTEM-owned WFP filter, WITHOUT deleting it.
# Proves that a narrowed COM rule is not mistaken for whole test-process safety.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$admin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R26_INTERFACE_TAMPER -ne 'CI_ONLY' -or
    $env:ORACLE_R21_SYSTEM_GUARD -ne 'CI_FIXED_SYSTEM_POLICY' -or
    -not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R26_REFUSED: only disposable elevated GitHub runner'
}
$name = 'OracleProxy-R21-CI-SYSTEM-OnlyGuard'
$probeExe = (Get-Process -Id $PID -ErrorAction Stop).Path
if (-not $probeExe.EndsWith('pwsh.exe',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'R26_REFUSED: unexpected WFP test app'
}
$svc = Get-CimInstance Win32_Service -Filter "Name='OracleProxyLabManager'" -ErrorAction Stop
if (-not $svc -or $svc.State -ne 'Running' -or $svc.StartName -ne 'LocalSystem') {
    throw 'R26_REFUSED: expected LocalSystem manager absent'
}
foreach ($profile in @('lab-peer-a','lab-peer-b')) {
    if ((Get-Service -Name ('WireGuardTunnel$' + $profile)).Status -ne 'Running') {
        throw 'R26_REFUSED: test peers are not both running'
    }
}
$type = [Type]::GetTypeFromProgID('HNetCfg.FwPolicy2',$true)
$policy = [Activator]::CreateInstance($type)
$mutated = $false
try {
    $matches = @($policy.Rules | Where-Object {
        [string]::Equals([string]$_.Name,$name,[StringComparison]::Ordinal)
    })
    if ($matches.Count -ne 1) { throw 'R26_REFUSED: exact SYSTEM guard missing' }
    $rule = $matches[0]
    Write-Host ("R26_OBSERVED_POLICY: action={0} direction={1} protocol={2} profiles={3} local={4} interface={5} probe_exe_matches={6}" -f
        [int]$rule.Action, [int]$rule.Direction, [int]$rule.Protocol,
        [int]$rule.Profiles, [string]$rule.LocalAddresses,
        [string]$rule.InterfaceTypes,
        [string]::Equals([string]$rule.ApplicationName,$probeExe,
            [StringComparison]::OrdinalIgnoreCase))
    if ([int]$rule.Action -ne 0 -or [int]$rule.Direction -ne 2 -or
        [int]$rule.Protocol -ne 256 -or [int]$rule.Profiles -ne 2147483647 -or
        [string]$rule.LocalAddresses -ne '*' -or
        [string]$rule.InterfaceTypes -ne 'All' -or
        -not [string]::Equals([string]$rule.ApplicationName,$probeExe,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'R26_REFUSED: guard was not original fixed, all-interface policy'
    }

    # Narrow the block to only Wireless interfaces: its friendly
    # name/action/program/protocol remain identical, but it no longer protects
    # general egress. Old weak verifiers would incorrectly accept this.
    $rule.InterfaceTypes = 'Wireless'
    $mutated = $true
    if ([string]$policy.Rules.Item($name).InterfaceTypes -ne 'Wireless') {
        throw 'R26_FAIL: interface-type tamper did not persist'
    }
    Write-Host 'R26_WFP_INTERFACE_SCOPE_TAMPER_INJECTED_PASS'

    $deadline = [DateTime]::UtcNow.AddSeconds(28)
    do {
        Start-Sleep -Milliseconds 450
        $states = @('lab-peer-a','lab-peer-b') | ForEach-Object {
            (Get-Service -Name ('WireGuardTunnel$' + $_) -ErrorAction Stop).Status
        }
    } while (@($states | Where-Object { $_ -ne 'Stopped' }).Count -gt 0 -and
             [DateTime]::UtcNow -lt $deadline)
    if (@($states | Where-Object { $_ -ne 'Stopped' }).Count -ne 0) {
        throw 'R26_FAIL: live manager accepted narrowed WFP interface scope'
    }
    Write-Host 'R26_NARROWED_WFP_TRIGGERED_SYSTEM_TUNNEL_STOP_PASS'

    $gui = (Resolve-Path './dist/lab-client-gui/OracleProxy.Windows.Preview.exe').Path
    $attempt = Start-Process -FilePath $gui -ArgumentList '--ci-lab-start-a' -Wait -PassThru
    if ($attempt.ExitCode -eq 0 -or
        (Get-Service 'WireGuardTunnel$lab-peer-a').Status -ne 'Stopped') {
        throw 'R26_FAIL: GUI/SCM accepted connect after interface tamper'
    }
    Write-Host 'R26_NARROWED_WFP_RECONNECT_DENIED_PASS'

    # Repair the original narrow TEST rule, then confirm manager's latched
    # compromise flag prevents start even after a rule reappears identical.
    $rule.InterfaceTypes = 'All'
    $mutated = $false
    if ([string]$policy.Rules.Item($name).InterfaceTypes -ne 'All') {
        throw 'R26_FAIL: original scope could not be restored'
    }
    $attempt = Start-Process -FilePath $gui -ArgumentList '--ci-lab-start-a' -Wait -PassThru
    if ($attempt.ExitCode -eq 0 -or
        (Get-Service 'WireGuardTunnel$lab-peer-a').Status -ne 'Stopped') {
        throw 'R26_FAIL: manager reset compromised latch on restored all-interface rule'
    }
    Write-Host 'R26_REPAIRED_WFP_STILL_DENIES_RECONNECT_PASS'
}
finally {
    # Never leave weakened firewall policy behind on the hosted runner.
    if ($mutated) {
        try {
            $original = $policy.Rules.Item($name)
            if ([string]$original.InterfaceTypes -eq 'Wireless') {
                $original.InterfaceTypes = 'All'
            }
        } catch { throw 'R26_FAIL: cannot restore CI guard after failed assertion' }
    }
    $guard = @($policy.Rules | Where-Object {
        [string]::Equals([string]$_.Name,$name,[StringComparison]::Ordinal)
    })
    if ($guard.Count -eq 1) {
        $ownedRule = $guard[0]
        Write-Host ("R26_FINAL_RULE: action={0} protocol={1} interface={2} same_program={3}" -f
            [int]$ownedRule.Action, [int]$ownedRule.Protocol,
            [string]$ownedRule.InterfaceTypes,
            [string]::Equals([string]$ownedRule.ApplicationName,$probeExe,
                [StringComparison]::OrdinalIgnoreCase))
        if ([int]$ownedRule.Action -ne 0 -or
            [int]$ownedRule.Direction -ne 2 -or
            [int]$ownedRule.Protocol -ne 256 -or
            -not [string]::Equals([string]$ownedRule.ApplicationName,$probeExe,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'R26_FAIL: refusing to remove wrong-owner test policy'
        }
        # Only exact named, CI-pinned policy is removed. It may legitimately
        # still be narrowed after injected failure; NEVER leave it installed.
        $policy.Rules.Remove($name)
    }
    if ($null -ne $policy -and
        [Runtime.InteropServices.Marshal]::IsComObject($policy)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($policy)
    }
}
if (@(Get-NetFirewallRule -ErrorAction Stop |
    Where-Object DisplayName -eq $name).Count -ne 0) {
    throw 'R26_FAIL: WFP test rule survived cleanup'
}
Write-Host 'R26_INTERFACE_TAMPER_CLEANUP_PASS'
