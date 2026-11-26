$ErrorActionPreference='Stop'
$ns='root/StandardCimv2'
$guid=[guid]'62e2af98-7089-6f2c-246b-4a5960cfc978'
$luid=[uint64]$env:ORACLE_TEST_CREATED_LUID
$stage=$env:ORACLE_TEST_AUDIT_STAGE
function BindingHash($entries,[bool]$forceIpOff) {
    [string[]]$tokens=@(foreach ($binding in $entries) {
        if (!$binding.ComponentID -or !$binding.InstanceID -or $null -eq $binding.Enabled) {throw 'INVALID_BINDING_ROW'}
        $enabled=[bool]$binding.Enabled
        if ($forceIpOff -and $binding.ComponentID -in 'ms_tcpip','ms_tcpip6') {$enabled=$false}
        ConvertTo-Json -InputObject @([string]$binding.InterfaceDescription,[string]$binding.ComponentID,[string]$binding.InstanceID,$enabled) -Compress
    })
    if (!$tokens.Count) {return ''}
    [Array]::Sort($tokens,[StringComparer]::Ordinal)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($tokens -join "`n")))).Replace('-','')}
    finally {$sha.Dispose()}
}
try {
    if ($stage -notin 'before','unbound','restored' -or !$luid) { throw 'STAGE' }
    $all=@(Get-CimInstance -Namespace $ns MSFT_NetAdapter -OperationTimeoutSec 5)
    $owned=@($all | Where-Object { $_.NetLuid -eq $luid -and $_.InterfaceGuid -and [guid]$_.InterfaceGuid -eq $guid })
    $pnp=$env:ORACLE_TEST_BASELINE_PNP
    $desc=$env:ORACLE_TEST_BASELINE_DESC
    if ($stage -eq 'before') {
        if ($owned.Count -ne 1) {throw 'IDENTITY'}
        $pnp=$owned[0].PNPDeviceID
        $desc=$owned[0].InterfaceDescription
    }
    if ($pnp -notlike 'SWD\WINTUN\*' -or !$desc -or $owned.Count -gt 1) {throw 'IDENTITY'}
    if ($owned.Count -eq 1 -and ($owned[0].PNPDeviceID -ne $pnp -or $owned[0].InterfaceDescription -ne $desc -or $owned[0].HardwareInterface -ne $false -or $owned[0].Name -ne 'OracleProxy')) {throw 'IDENTITY'}
    if (@($all | Where-Object { $_.InterfaceDescription -eq $desc -and ($_.NetLuid -ne $luid -or !$_.InterfaceGuid -or [guid]$_.InterfaceGuid -ne $guid) }).Count) {throw 'AMBIGUOUS'}
    $nodes=@(Get-PnpDevice -PresentOnly -InstanceId $pnp -ErrorAction Stop | Where-Object InstanceId -eq $pnp)
    $allBindings=@(Get-CimInstance -Namespace $ns MSFT_NetAdapterBindingSettingData -OperationTimeoutSec 8)
    $others=@($allBindings | Where-Object InterfaceDescription -ne $desc)
    $hash=BindingHash $others $false
    if (!$hash) {throw 'NO_COMPARISON'}
    # An unrelated adapter hash alone says nothing about rollback on this device.
    # Use its CIM association from the exact LUID+GUID+PnP identity. Missing or
    # ambiguous protocol rows remain unknown rather than implying disabled.
    $targetCount=0; $targetHash=''; $targetOffHash=''; $ip4=-1; $ip6=-1
    if ($owned.Count -eq 1) {
        try {
            $target=@(Get-CimAssociatedInstance -InputObject $owned[0] -Association MSFT_NetAdapterBindingElementSetting -ResultClassName MSFT_NetAdapterBindingSettingData -OperationTimeoutSec 5)
            if (@($target | Where-Object { $_.InterfaceDescription -ne $desc }).Count) {throw 'AMBIGUOUS'}
            $four=@($target | Where-Object ComponentID -eq 'ms_tcpip')
            $six=@($target | Where-Object ComponentID -eq 'ms_tcpip6')
            $targetCount=$target.Count
            $targetHash=BindingHash $target $false
            $targetOffHash=BindingHash $target $true
            if ($four.Count -eq 1 -and $null -ne $four[0].Enabled) {$ip4=[int][bool]$four[0].Enabled}
            if ($six.Count -eq 1 -and $null -ne $six[0].Enabled) {$ip6=[int][bool]$six[0].Enabled}
        } catch {$targetCount=0; $targetHash=''; $targetOffHash=''; $ip4=-1; $ip6=-1}
    }
    [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
    [Console]::WriteLine((ConvertTo-Json -Compress -InputObject ([ordered]@{
        pnp=$pnp; description=$desc; present=($nodes.Count -eq 1); matching=($owned.Count -eq 1); count=$others.Count; hash=$hash
        targetCount=$targetCount; targetHash=$targetHash; targetOffHash=$targetOffHash; ip4=$ip4; ip6=$ip6
    })))
} catch {exit 1}
