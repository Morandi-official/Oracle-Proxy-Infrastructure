$ErrorActionPreference='Stop'
$ns='root/StandardCimv2'
$guid=[guid]'62e2af98-7089-6f2c-246b-4a5960cfc978'
$luid=[uint64]$env:ORACLE_TEST_CREATED_LUID
$stage=$env:ORACLE_TEST_AUDIT_STAGE
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
    [string[]]$rows=@(Get-CimInstance -Namespace $ns MSFT_NetAdapterBindingSettingData -OperationTimeoutSec 8 |
        Where-Object InterfaceDescription -ne $desc | ForEach-Object {
            ConvertTo-Json -InputObject @([string]$_.InterfaceDescription,[string]$_.ComponentID,[string]$_.InstanceID,[bool]$_.Enabled) -Compress
        })
    [Array]::Sort($rows,[StringComparer]::Ordinal)
    if (!$rows.Count) {throw 'NO_COMPARISON'}
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$hash=[BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($rows -join "`n")))).Replace('-','')}
    finally {$sha.Dispose()}
    [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
    [Console]::WriteLine((ConvertTo-Json -Compress -InputObject ([ordered]@{
        pnp=$pnp; description=$desc; present=($nodes.Count -eq 1); matching=($owned.Count -eq 1); count=$rows.Count; hash=$hash
    })))
} catch {exit 1}
