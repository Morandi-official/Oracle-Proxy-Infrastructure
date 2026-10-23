[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Confirm,
    [switch]$CiHarness
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($Confirm -cne 'R86-SECOND-PC-NO-VPN-ONLY') {
    throw 'R86_REFUSED: explicit attended no-network confirmation missing'
}
. (Join-Path $PSScriptRoot 'R86-Common.ps1')
& (Join-Path $PSScriptRoot 'R86-Preflight.ps1') -CiHarness:$CiHarness
$baseline=Get-R86-NetworkDigest
$binarySource=Join-Path $PSScriptRoot 'R86NoNetworkMock.exe'
$created=$false
try {
    New-Item -ItemType Directory -Path $script:R86Root -ErrorAction Stop | Out-Null
    $created=$true
    # Set an explicit inherited-only Admin/SYSTEM DACL before writing any
    # operational information. This mock has no key or secrets.
    $admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($admin)
    $acl.SetAccessRuleProtection($true,$false)
    $inherit=([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit)
    foreach ($sid in @($admin,$system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,[Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,[Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $script:R86Root -AclObject $acl -ErrorAction Stop
    'R86-ATTENDED-OWNED-NO-NETWORK-ONLY' |
        Set-Content -LiteralPath (Join-Path $script:R86Root 'owner.txt') -Encoding ascii -NoNewline
    Assert-R86-Ownership
    Copy-Item -LiteralPath $binarySource -Destination $script:R86Binary -ErrorAction Stop
    $hash=(Get-FileHash -LiteralPath $script:R86Binary -Algorithm SHA256).Hash
    $sourceHash=(Get-FileHash -LiteralPath $binarySource -Algorithm SHA256).Hash
    if ($hash -cne $sourceHash) { throw 'R86 copied executable hash changed' }
    $due=[DateTime]::UtcNow.AddMinutes(3).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $token=[guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllLines($script:R86State,
        [string[]]@($due,$token,$hash),[Text.Encoding]::ASCII)
    $baseline | Set-Content -LiteralPath (Join-Path $script:R86Root 'baseline.sha256') -Encoding ascii -NoNewline
    $image=('"{0}" --r86-no-network-mock' -f $script:R86Binary)
    New-Service -Name $script:R86Service -BinaryPathName $image -StartupType Manual -ErrorAction Stop | Out-Null
    Assert-R86-ServiceRecord | Out-Null

    # Independent OS-owned recovery is registered BEFORE service activation.
    $action=New-ScheduledTaskAction -Execute $script:R86Binary -Argument ("--r86-expire {0} {1}" -f $due,$token)
    $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3).AddSeconds(7)
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -StartWhenAvailable
    $reg=@{TaskName=$script:R86Task;TaskPath='\';Action=$action;Trigger=$trigger;
        Principal=$principal;Settings=$settings;ErrorAction='Stop'}
    Register-ScheduledTask @reg | Out-Null
    Assert-R86-TaskRecord | Out-Null
    Start-Service -Name $script:R86Service -ErrorAction Stop
    (Get-Service -Name $script:R86Service).WaitForStatus(
        [ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(25))
    if ((Get-R86-NetworkDigest) -cne $baseline) {
        throw 'R86 changed OS network fingerprint during mock startup'
    }
    Write-Host "R86_MOCK_RUNNING_WITH_SYSTEM_AUTOSTOP_PASS; UTC_DUE=$due"
    Write-Host 'R86_NO_VPN_DRIVER_OR_TUNNEL=true'
    Write-Host 'R86_WAIT_FOR_AUTOMATIC_STOP_THEN_RUN_VERIFY'
}
catch {
    Write-Warning 'R86 setup failed. Starting exact-owned emergency cleanup.'
    if ($created) {
        try { & (Join-Path $PSScriptRoot 'R86-EmergencyCleanup.ps1') -CiHarness:$CiHarness }
        catch { Write-Warning 'R86 automated cleanup not verified; follow emergency cleanup procedure immediately.' }
    }
    throw
}
