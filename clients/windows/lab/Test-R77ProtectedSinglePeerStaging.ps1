# R77 hosted Windows, ADMIN/SYSTEM-only single-peer plaintext candidate staging.
# No tunnel, network, registry, WFP, route, DNS or SCM mutation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R77 -ne 'CI_ONLY') {
    throw 'R77_REFUSED: disposable CI only'
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
try {
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'R77_REFUSED: OS administrator required'
    }
} finally { $identity.Dispose() }
$root=Join-Path $env:ProgramData 'OracleProxyR77Only'
if (Test-Path -LiteralPath $root) { throw 'R77_REFUSED: stage already exists' }
if (Get-Service -Name 'WireGuardTunnel$lab-peer-a' -ErrorAction SilentlyContinue) {
    throw 'R77_REFUSED: existing native service'
}
if (@(Get-NetRoute -ErrorAction Stop | Where-Object {
        $_.DestinationPrefix -eq '10.77.72.2/32'
    }).Count -ne 0) {
    throw 'R77_REFUSED: preexisting inner route'
}
function Fingerprint-OS {
    $defaults = @(Get-NetRoute -ErrorAction Stop |
        Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
        Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        ConvertTo-Json -Compress -Depth 4) -join ''
    $dns = @(Get-DnsClientServerAddress -ErrorAction Stop |
        Select-Object InterfaceIndex,AddressFamily,ServerAddresses |
        Sort-Object InterfaceIndex,AddressFamily |
        ConvertTo-Json -Compress -Depth 6) -join ''
    $fw = @(Get-NetFirewallRule -ErrorAction Stop).Count
    return ($defaults + '|' + $dns + '|' + $fw)
}
$before=Fingerprint-OS
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
$admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($admin)
$acl.SetAccessRuleProtection($true,$false)
$inherit=([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)
foreach ($sid in @($admin,$system)) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow))
}
Set-Acl -LiteralPath $root -AclObject $acl -ErrorAction Stop
$marker=Join-Path $root '.r77-owned'
'CI_R77_ONLY_DISPOSABLE_GITHUB_VM' |
    Set-Content -LiteralPath $marker -Encoding ascii -NoNewline -ErrorAction Stop
# R78: give individual files explicit protected DACLs (native host refuses
# inherited ACEs even when the parent is already Admin/SYSTEM-only).
function Protect-OwnedSecretFile([string]$path) {
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'R78_FAIL: owned candidate file missing before DACL protection'
    }
    $fileAcl=Get-Acl -LiteralPath $path -ErrorAction Stop
    $fileAcl.SetOwner($admin)
    $fileAcl.SetAccessRuleProtection($true,$true)
    Set-Acl -LiteralPath $path -AclObject $fileAcl -ErrorAction Stop
    if (!(Get-Acl -LiteralPath $path).AreAccessRulesProtected) {
        throw 'R78_FAIL: owned candidate still inherits ACLs'
    }
}
Protect-OwnedSecretFile $marker
$aclr=Get-Acl -LiteralPath $root -ErrorAction Stop
foreach ($path in @($root,$marker)) {
    $control=Get-Acl -LiteralPath $path -ErrorAction Stop
    $rules=@($control.GetAccessRules($true,$true,
        [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -lt 2 -or
        @($rules | Where-Object {
            $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $_.AccessControlType -ne 'Allow'
        }).Count -ne 0) {
        throw 'R77_FAIL: insecure ownership DACL before key file creation'
    }
}
python ./lab/field-windows/r77_stage_owned_candidate.py --stage-owned-ci
if ($LASTEXITCODE -ne 0) { throw 'R77: test config stage refused' }
$file=Join-Path $root 'lab-peer-a.conf'
if (!(Test-Path -LiteralPath $file -PathType Leaf)) {
    throw 'R77: protected config missing'
}
Protect-OwnedSecretFile $file
$fileAcl=Get-Acl -LiteralPath $file -ErrorAction Stop
$access=@($fileAcl.GetAccessRules($true,$true,
    [Security.Principal.SecurityIdentifier]))
if ($access.Count -lt 2 -or
    @($access | Where-Object {
        $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
        $_.AccessControlType -ne 'Allow'
    }).Count -ne 0) {
    throw 'R77_FAIL: config has untrusted principal ACL'
}
if ((Fingerprint-OS) -cne $before -or
    (Get-Service -Name 'WireGuardTunnel$lab-peer-a' -ErrorAction SilentlyContinue)) {
    throw 'R77_FAIL: OS network/SCM changed during private config staging'
}
Write-Host 'R77_PROTECTED_SINGLE_PEER_STAGING_AND_NO_OS_NETWORK_CHANGE_PASS'
