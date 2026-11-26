# Read-only witnesses on disposable Windows runners. Native transitions never use PowerShell.
function Get-OtherAdapterBindingState {
    $rows = @(Get-NetAdapterBinding -Name '*' -IncludeHidden -AllBindings -ErrorAction Stop |
        Where-Object { $_.Name -ne 'OracleProxy' } |
        ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.Name,$_.InstanceID,$_.ComponentID,$_.Enabled } |
        Sort-Object -CaseSensitive)
    if (!$rows.Count) { throw 'NO_INDEPENDENT_WINDOWS_BINDING_BASELINE' }
    $rows
}

function Assert-OtherAdapterBindingState([string[]]$Baseline) {
    if (!$Baseline.Count -or @(Compare-Object -CaseSensitive $Baseline @(Get-OtherAdapterBindingState)).Count) {
        throw 'UNRELATED_WINDOWS_ADAPTER_BINDING_CHANGED'
    }
    Write-Host 'ACTUAL_OTHER_WINDOWS_ADAPTER_BINDINGS_PRESERVED=PASS'
}

function Assert-OwnedIpBindings([uint64]$ExpectedLuid,[bool]$Enabled) {
    $namespace = 'root/StandardCimv2'
    $guid = [guid]'62e2af98-7089-6f2c-246b-4a5960cfc978'
    $owned = @(Get-CimInstance -Namespace $namespace -ClassName MSFT_NetAdapter -Filter "NetLuid = $ExpectedLuid" -ErrorAction Stop |
        Where-Object { $_.InterfaceGuid -and [guid]$_.InterfaceGuid -eq $guid -and $_.Name -eq 'OracleProxy' -and $_.HardwareInterface -eq $false -and $_.PNPDeviceID -like 'SWD\WINTUN\*' })
    if ($owned.Count -ne 1) { throw 'OWNED_BINDING_ADAPTER_NOT_IDENTIFIED' }
    $rows = @(Get-CimAssociatedInstance -InputObject $owned[0] -Association MSFT_NetAdapterBindingElementSetting -ResultClassName MSFT_NetAdapterBindingSettingData -ErrorAction Stop |
        Where-Object { $_.ComponentID -in 'ms_tcpip','ms_tcpip6' })
    if ($rows.Count -ne 2 -or @($rows.ComponentID | Sort-Object -Unique).Count -ne 2 -or
        @($rows | Where-Object { $_.Enabled -ne $Enabled -or $_.InterfaceDescription -ne $owned[0].InterfaceDescription }).Count) {
        throw 'OWNED_DUAL_STACK_BINDING_STATE_INVALID'
    }
    Write-Host "ACTUAL_OWNED_IPV4_AND_IPV6_BINDINGS_ENABLED=$Enabled"
}
