$ErrorActionPreference='Stop'
$ns='root/StandardCimv2'
$guid=[guid]'62e2af98-7089-6f2c-246b-4a5960cfc978'
$luid=[uint64]$env:ORACLE_TEST_CREATED_LUID
$stage=$env:ORACLE_TEST_AUDIT_STAGE
# Only these target-adapter transport dependents were observed to be disabled by
# NetCfg when both IP protocols are unbound. Each candidate may only turn a flag off.
$dependentOffBits=@{'ms_msclient'=1; 'ms_netbios'=2; 'ms_netbt'=4; 'ms_server'=8}
function BindingHash($entries,[bool]$forceIpOff,[int]$dependentOffMask=0) {
    [string[]]$tokens=@(foreach ($binding in $entries) {
        if (!$binding.ComponentID -or !$binding.InstanceID -or $null -eq $binding.Enabled) {throw 'INVALID_BINDING_ROW'}
        $enabled=[bool]$binding.Enabled
        if ($forceIpOff -and ($binding.ComponentID -in 'ms_tcpip','ms_tcpip6' -or
            ($dependentOffMask -band ([int]$dependentOffBits[[string]$binding.ComponentID])) -ne 0)) {$enabled=$false}
        ConvertTo-Json -InputObject @([string]$binding.InterfaceDescription,[string]$binding.ComponentID,[string]$binding.InstanceID,$enabled) -Compress
    })
    if (!$tokens.Count) {return ''}
    [Array]::Sort($tokens,[StringComparer]::Ordinal)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($tokens -join "`n")))).Replace('-','')}
    finally {$sha.Dispose()}
}
# Only opaque, per-experiment HMAC tokens leave the CIM reader for target row diagnostics.
function RowToken([string]$field,[string]$value) {
    $bytes=[Text.Encoding]::UTF8.GetBytes($field+[char]0+$value)
    return ([BitConverter]::ToString($rowHmac.ComputeHash($bytes))).Replace('-','').Substring(0,24).ToLowerInvariant()
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
    $targetUnique=$false; $allowedUnbound=@()
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
            $components=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $instances=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $availableMask=0; $targetUnique=($targetCount -ge 2 -and $targetCount -le 128)
            foreach ($binding in $target) {
                if (!$components.Add([string]$binding.ComponentID)) {$targetUnique=$false}
                if (!$instances.Add([string]$binding.InstanceID)) {$targetUnique=$false}
                if ($binding.Enabled) {$availableMask=$availableMask -bor ([int]$dependentOffBits[[string]$binding.ComponentID])}
            }
            if ($stage -eq 'before' -and $targetUnique) {
                # Compare the full exact rows, including unchanged identities, descriptions,
                # component sets and enabled states. Never qualify on the short report tokens.
                $allowedUnbound=@(foreach ($mask in 0..15) {
                    if (($mask -band $availableMask) -eq $mask) {BindingHash $target $true $mask}
                })
            }
            if ($four.Count -eq 1 -and $null -ne $four[0].Enabled) {$ip4=[int][bool]$four[0].Enabled}
            if ($six.Count -eq 1 -and $null -ne $six[0].Enabled) {$ip6=[int][bool]$six[0].Enabled}
        } catch {$targetUnique=$false; $allowedUnbound=@(); $targetCount=0; $targetHash=''; $targetOffHash=''; $ip4=-1; $ip6=-1}
    }
    $targetRows=@()
    if ($targetCount -gt 0 -and $targetCount -le 128 -and $targetHash) {
        $rowHmac=[Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($env:ORACLE_TEST_BINDING_REPORT_KEY))
        try {
            $targetRows=@(foreach ($binding in $target) {
                $id=[string]$binding.ComponentID
                [ordered]@{
                    kind=(RowToken 'kind' ($id.ToLowerInvariant())); raw=(RowToken 'component' $id)
                    instance=(RowToken 'instance' ([string]$binding.InstanceID))
                    descriptor=(RowToken 'description' ([string]$binding.InterfaceDescription))
                    enabled=[bool]$binding.Enabled
                }
            })
        } finally {$rowHmac.Dispose()}
    }
    [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
    [Console]::WriteLine((ConvertTo-Json -Depth 4 -Compress -InputObject ([ordered]@{
        pnp=$pnp; description=$desc; present=($nodes.Count -eq 1); matching=($owned.Count -eq 1); count=$others.Count; hash=$hash
        targetUnique=$targetUnique; allowedUnbound=$allowedUnbound
        targetRows=$targetRows; targetCount=$targetCount; targetHash=$targetHash; targetOffHash=$targetOffHash; ip4=$ip4; ip6=$ip6
    })))
} catch {exit 1}
