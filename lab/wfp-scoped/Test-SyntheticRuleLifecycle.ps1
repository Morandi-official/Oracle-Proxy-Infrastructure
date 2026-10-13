# R7: actual Windows Defender Firewall rule API on reserved synthetic targets.
# Strict CI disposable only. Does NOT prove a functional kill switch.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R7_REFUSED: hosted disposable elevated Windows CI only'
}
$bfe = Get-Service -Name BFE -ErrorAction Stop
$fw = Get-Service -Name MpsSvc -ErrorAction Stop
if ($bfe.Status -ne 'Running' -or $fw.Status -ne 'Running') {
    throw 'R7_REFUSED: WFP/BFE and Firewall services must already run'
}
$program = (Get-Process -Id $PID -ErrorAction Stop).Path
if (-not $program -or -not $program.EndsWith('pwsh.exe',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'R7_REFUSED: exact CI PowerShell process binary not identified'
}
$baseline = @(Get-NetFirewallRule -ErrorAction Stop).Count
$token = [Guid]::NewGuid().ToString('N')
$rules = @(
    @{ Name="OracleProxy-R7-CI-$token-v4"; Ip='203.0.113.19'; Port='54991' },
    @{ Name="OracleProxy-R7-CI-$token-v6"; Ip='2001:db8::19'; Port='54992' }
)
$created = New-Object 'System.Collections.Generic.List[string]'
try {
    foreach ($spec in $rules) {
        if (Get-NetFirewallRule -Name $spec.Name -ErrorAction SilentlyContinue) {
            throw 'R7_REFUSED: firewall rule name pre-exists'
        }
        $options = @{
            Name=$spec.Name; DisplayName=$spec.Name; PolicyStore='PersistentStore'
            Direction='Outbound'; Action='Block'; Protocol='UDP'
            RemoteAddress=$spec.Ip; RemotePort=$spec.Port; Program=$program
            Profile='Any'; Enabled='True'; ErrorAction='Stop'
        }
        New-NetFirewallRule @options | Out-Null
        $created.Add($spec.Name)
        $got = Get-NetFirewallRule -PolicyStore ActiveStore -Name $spec.Name -ErrorAction Stop
        if ($got.Action -ne 'Block' -or $got.Direction -ne 'Outbound' -or
            [string]$got.Enabled -ne 'True') {
            throw 'R7_WFP_FAIL: synthetic rule not active as narrow outbound block'
        }
        $ports = $got | Get-NetFirewallPortFilter
        $addresses = $got | Get-NetFirewallAddressFilter
        $applications = $got | Get-NetFirewallApplicationFilter
        if ([string]$ports.Protocol -notin @('UDP','17') -or
            ([string[]]$ports.RemotePort) -notcontains $spec.Port -or
            @([string[]]$addresses.RemoteAddress | Where-Object { $_ -eq $spec.Ip }).Count -ne 1 -or
            $applications.Program -ne $program) {
            throw 'R7_WFP_FAIL: program, address, protocol or port constraint widened'
        }
    }
    Write-Host 'R7_ACTIVE_RULES_PASS: real WFP-backed Windows Firewall active store has two UDP block rules scoped to CI executable, reserved addresses and ports'
}
finally {
    foreach ($name in $created) {
        Remove-NetFirewallRule -Name $name -ErrorAction Stop
    }
    foreach ($item in $rules) {
        if (Get-NetFirewallRule -Name $item.Name -ErrorAction SilentlyContinue) {
            throw 'R7_FAIL: created Firewall filter persisted after rollback'
        }
    }
    $after = @(Get-NetFirewallRule -ErrorAction Stop).Count
    if ($after -ne $baseline) {
        throw 'R7_FAIL: Firewall rule count did not return to original baseline'
    }
    Write-Host 'R7_RULE_REMOVE_PASS: two narrow synthetic filters removed; firewall rule count restored'
}
