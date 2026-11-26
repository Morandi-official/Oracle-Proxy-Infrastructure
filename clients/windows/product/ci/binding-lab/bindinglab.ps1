$ErrorActionPreference = 'Stop'
$ns = 'root/StandardCimv2'
$guid = [guid]'62e2af98-7089-6f2c-246b-4a5960cfc978'
$luid = [uint64]$env:ORACLE_TEST_CREATED_LUID
function Owned {
    $rows = @(Get-CimInstance -Namespace $ns MSFT_NetAdapter -OperationTimeoutSec 5 |
        Where-Object { $_.NetLuid -eq $luid -and $_.InterfaceGuid -and [guid]$_.InterfaceGuid -eq $guid })
    if ($rows.Count -ne 1 -or $rows[0].HardwareInterface -ne $false -or
        $rows[0].PNPDeviceID -notlike 'SWD\WINTUN\*' -or $rows[0].Name -ne 'OracleProxy') { throw 'IDENTITY' }
    if ($pnp -and $rows[0].PNPDeviceID -ne $pnp) { throw 'REPLACED' }
    $rows[0]
}
function Evidence([string]$stage) {
    $node=-1; $nic=-1
    try {
        $items=@(Get-PnpDevice -PresentOnly -InstanceId $pnp -ErrorAction Stop | Where-Object InstanceId -eq $pnp)
        $node=[int]($items.Count -eq 1)
    }catch{}
    try {
        $rows=@(Get-CimInstance -Namespace $ns MSFT_NetAdapter -Filter "NetLuid = $luid" -OperationTimeoutSec 5 |
            Where-Object { $_.InterfaceGuid -and [guid]$_.InterfaceGuid -eq $guid -and $_.PNPDeviceID -eq $pnp })
        $nic=[int]($rows.Count -eq 1)
    }catch{}
    [Console]::Out.WriteLine("IDENTITY $stage $node $nic")
}
function Bindings {
    $owned = Owned
    $bindings = @(Get-CimAssociatedInstance -InputObject $owned -Association MSFT_NetAdapterBindingElementSetting `
        -ResultClassName MSFT_NetAdapterBindingSettingData -OperationTimeoutSec 5 |
        Where-Object { $_.ComponentID -in 'ms_tcpip','ms_tcpip6' })
    if ($bindings.Count -ne 2 -or ($bindings.ComponentID | Sort-Object -Unique).Count -ne 2 -or
        @($bindings | Where-Object { $_.InterfaceDescription -ne $owned.InterfaceDescription }).Count) { throw 'BINDINGS' }
    $bindings
}
function Others {
    $description = (Owned).InterfaceDescription
    @(Get-CimInstance -Namespace $ns MSFT_NetAdapterBindingSettingData -OperationTimeoutSec 5 |
        Where-Object { $_.InterfaceDescription -ne $description } |
        ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.InterfaceDescription,$_.ComponentID,$_.InstanceID,$_.Enabled } | Sort-Object)
}
function SetOwned([string]$id, [bool]$enable) {
    $binding = @(Bindings | Where-Object ComponentID -eq $id)
    if ($binding.Count -ne 1) { throw 'AMBIGUOUS' }
    if ($binding[0].Enabled -ne $enable) {
        $method = if ($enable) { 'Enable' } else { 'Disable' }
        $result = Invoke-CimMethod -InputObject $binding[0] -MethodName $method -OperationTimeoutSec 5
        if ($result.ReturnValue -ne 0) { throw 'BINDING_CHANGE' }
    }
}
try {
    $pnp = (Owned).PNPDeviceID
    Evidence 'before'
    $baseline = @(Others)
    $original = @(Bindings)
    # Measure only a normal freshly dual-stack-capable lab adapter. Unknown or
    # originally disabled bindings are never enabled by this experiment.
    if (@($original | Where-Object { $_.Enabled -ne $true }).Count) { throw 'BASELINE' }
    try {
        foreach ($item in $original) { SetOwned $item.ComponentID $false }
        Evidence 'unbound'
        $readback = $false
        try { $readback = @(Bindings | Where-Object Enabled).Count -eq 0 } catch {}
        [Console]::Out.WriteLine("READBACK $([int]$readback)")
        [Console]::Out.WriteLine('UNBOUND')
        if ([Console]::In.ReadLine() -ne 'RESTORE') { throw 'PARENT_ENDED' }
    } finally {
        $failed = $false
        foreach ($item in $original) {
            try { SetOwned $item.ComponentID $item.Enabled } catch { $failed = $true }
        }
        if ($failed -or @(Bindings | Where-Object { $_.Enabled -ne $true }).Count) { throw 'ROLLBACK' }
    }
    [Console]::Out.WriteLine('RESTORED')
    if (Compare-Object $baseline @(Others)) { throw 'OTHER_BINDINGS_CHANGED' }
    [Console]::Out.WriteLine('OTHERS_UNCHANGED')
} catch {
    # A failed device/provider identity aborts this trial. No provider strings,
    # known network addresses, physical inventory or interface names are logged.
    $reason = $_.Exception.Message
    if ($reason -notin 'IDENTITY','REPLACED','BINDINGS','AMBIGUOUS','BINDING_CHANGE','BASELINE','STILL_BOUND','PARENT_ENDED','ROLLBACK','OTHER_BINDINGS_CHANGED') { $reason='PROVIDER' }
    [Console]::Out.WriteLine("FAILED_$reason"); exit 1
}
