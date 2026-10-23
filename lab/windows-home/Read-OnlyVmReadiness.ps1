# Windows 11 Home virtualization readiness - STRICTLY READ ONLY.
# Safe to inspect source without executing. No elevation, network traffic,
# adapters, routes, firewall, drivers, services, registry or settings changes.
# No machine name, username, hardware serial, IP or WireGuard keys collected.
param([switch]$SelfTest)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-TruthOrUnknown($value) {
    if ($null -eq $value) { return 'unknown' }
    if ([bool]$value) { return 'enabled' }
    return 'not_reported_enabled'
}

function Get-SanitizedVmReadiness {
    param(
        [Parameter(Mandatory=$true)]$Os,
        [Parameter(Mandatory=$true)]$Computer,
        [Parameter(Mandatory=$true)]$Processor,
        [Parameter(Mandatory=$true)]$Disk
    )
    $caption = [string]$Os.Caption
    $build = [int]$Os.BuildNumber
    $edition = if ($caption -match '(?i)Windows 11' -and $caption -match '(?i)(Home|家庭)') {
        'Windows 11 Home'
    } elseif ($caption -match '(?i)Windows 11') {
        'Windows 11 (edition not confirmed as Home)'
    } else {
        'Other Windows edition (details intentionally omitted)'
    }
    $memoryGiB = [math]::Round(([double]$Computer.TotalPhysicalMemory / 1GB), 1)
    $diskGiB = [math]::Round(([double]$Disk.FreeSpace / 1GB), 1)
    $virtualization = Get-TruthOrUnknown $Processor.VirtualizationFirmwareEnabled
    $sLat = Get-TruthOrUnknown $Processor.SecondLevelAddressTranslationExtensions
    $logical = [int]$Processor.NumberOfLogicalProcessors

    # These are planning hints, not proof the VM can be safely installed.
    $suitableHardware = ($memoryGiB -ge 16 -and $diskGiB -ge 100 -and
                         $logical -ge 4 -and $virtualization -eq 'enabled')
    $needsReview = @()
    if ($memoryGiB -lt 16) { $needsReview += 'RAM under recommended 16 GiB' }
    if ($diskGiB -lt 100) { $needsReview += 'System drive free space under recommended 100 GiB' }
    if ($logical -lt 4) { $needsReview += 'Fewer than 4 logical CPU threads' }
    if ($virtualization -ne 'enabled') {
        $needsReview += 'Firmware virtualization not confirmed by WMI (may be masked by VBS)'
    }
    if ($sLat -ne 'enabled') { $needsReview += 'SLAT support not confirmed by WMI' }
    return [pscustomobject]@{
        schema_version = 1
        collection_mode = 'read_only_cim'
        edition = $edition
        os_build = $build
        ram_gib = $memoryGiB
        free_system_drive_gib = $diskGiB
        logical_processors = $logical
        firmware_virtualization = $virtualization
        slat = $sLat
        preliminary_hardware_fit = $suitableHardware
        review_notes = @($needsReview)
        actual_vm_installed = 'not_checked'
        independent_snapshot_rollback_tested = $false
        production_network_changed = $false
        safe_to_install_virtual_network_drivers_unattended = $false
        actual_wfp_fail_closed_verified = $false
    }
}

if ($SelfTest) {
    $testOs = [pscustomobject]@{ Caption = 'Microsoft Windows 11 Home'; BuildNumber = 26100 }
    $testComputer = [pscustomobject]@{ TotalPhysicalMemory = 16GB }
    $testCpu = [pscustomobject]@{
        NumberOfLogicalProcessors = 8
        VirtualizationFirmwareEnabled = $true
        SecondLevelAddressTranslationExtensions = $true
    }
    $testDisk = [pscustomobject]@{ FreeSpace = 130GB }
    $good = Get-SanitizedVmReadiness $testOs $testComputer $testCpu $testDisk
    if ($good.edition -ne 'Windows 11 Home' -or !$good.preliminary_hardware_fit -or
        $good.safe_to_install_virtual_network_drivers_unattended -or
        $good.independent_snapshot_rollback_tested -or $good.actual_wfp_fail_closed_verified) {
        throw 'Windows Home or safety boundary regression'
    }
    $testComputer.TotalPhysicalMemory = 8GB
    $testCpu.VirtualizationFirmwareEnabled = $false
    $poor = Get-SanitizedVmReadiness $testOs $testComputer $testCpu $testDisk
    if ($poor.preliminary_hardware_fit -or $poor.review_notes.Count -lt 2 -or
        $poor.firmware_virtualization -ne 'not_reported_enabled') {
        throw 'Unsafe virtual hardware readiness classification'
    }
    $testCpu.VirtualizationFirmwareEnabled = $null
    $uncertain = Get-SanitizedVmReadiness $testOs $testComputer $testCpu $testDisk
    if ($uncertain.firmware_virtualization -ne 'unknown') {
        throw 'Unknown hypervisor ability must stay unknown'
    }
    Write-Host 'PASS: Windows Home and fail-safe virtualization-readiness mock checks'
    exit 0
}

# Only local CIM queries, no child processes or Windows network operations.
# Callers can use -SelfTest on a CI machine without collecting its hardware.
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
$cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
    Select-Object -First 1
$systemDrive = [string]$os.SystemDrive
$drive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$systemDrive'" -ErrorAction Stop
if ($null -eq $drive) { throw 'Cannot safely read free system-drive space' }
$report = Get-SanitizedVmReadiness $os $computer $cpu $drive
$report | ConvertTo-Json -Depth 5 -Compress
