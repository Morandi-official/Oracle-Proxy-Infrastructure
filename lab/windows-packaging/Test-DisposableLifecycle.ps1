# R5: install/query/uninstall a STATUS-ONLY SCM manager on throwaway Windows CI.
# Never installs a VPN engine, WireSock, WFP, a firewall rule or a network route.
# Hard CI gate; NOT FOR USER MACHINES.
param([Parameter(Mandatory=$true)][string]$ManagerExe,
      [Parameter(Mandatory=$true)][string]$GuiExe,
      [ValidateSet('None','AfterStage','AfterScmCreate','AfterScmStart')]
      [string]$InjectFailureAt = 'None')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'R5_REFUSED: only an elevated disposable GitHub-hosted Windows runner'
}
$serviceName = 'OracleProxyLabManager'
$installRoot = Join-Path $env:RUNNER_TEMP 'OracleProxyR5StatusOnly'
$manager = (Resolve-Path -LiteralPath $ManagerExe -ErrorAction Stop).Path
$gui = (Resolve-Path -LiteralPath $GuiExe -ErrorAction Stop).Path
$knownManager = (Resolve-Path -LiteralPath './dist/r5-manager').Path
$knownGui = (Resolve-Path -LiteralPath './dist/r5-gui').Path
if (-not $manager.StartsWith($knownManager + '\',[StringComparison]::OrdinalIgnoreCase) -or
    -not $gui.StartsWith($knownGui + '\',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'R5_REFUSED: only artifacts built from this CI checkout'
}
foreach ($name in @($serviceName,'WireGuardTunnel$lab-peer-a','WireGuardTunnel$lab-peer-b')) {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        throw 'R5_REFUSED: preexisting service, refuse to overwrite'
    }
}
if (Test-Path -LiteralPath $installRoot) {
    throw 'R5_REFUSED: preexisting install directory, refuse to overwrite'
}
function Get-NetworkBaseline {
    $defaultRoutes = @(Get-NetRoute -ErrorAction Stop | Where-Object {
        $_.DestinationPrefix -in @('0.0.0.0/0','::/0')
    } | Select-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        Sort-Object DestinationPrefix,InterfaceIndex,NextHop,RouteMetric |
        ConvertTo-Json -Compress -Depth 5) -join ''
    $dns = @(Get-DnsClientServerAddress -ErrorAction Stop |
        Select-Object InterfaceIndex,AddressFamily,ServerAddresses |
        Sort-Object InterfaceIndex,AddressFamily |
        ConvertTo-Json -Compress -Depth 5) -join ''
    $rules = @(Get-NetFirewallRule -ErrorAction Stop).Count
    return [pscustomobject]@{ DefaultRoutes=$defaultRoutes; Dns=$dns; RuleCount=$rules }
}
$baseline = Get-NetworkBaseline
$createdDirectory = $false
$createdService = $false
$marker = Join-Path $installRoot '.r5-ci-owned.json'
$stagedExe = Join-Path $installRoot 'OracleProxy.LabManager.exe'
try {
    New-Item -Path $installRoot -ItemType Directory -ErrorAction Stop | Out-Null
    $createdDirectory = $true
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($administrators)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($administrators,$system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,[Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $installRoot -AclObject $security -ErrorAction Stop
    Copy-Item -LiteralPath $manager -Destination $stagedExe -ErrorAction Stop
    # R39: verify staged executable inherits only Admin/SYSTEM access.
    # An unexpected inherited ACE, reparse point or source/stage mismatch
    # fails before any SCM registration. No ACL repair on user-owned paths.
    foreach ($file in @($stagedExe)) {
        $info = Get-Item -LiteralPath $file -ErrorAction Stop
        if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'R39_REFUSED: staged executable reparse point'
        }
        $access = Get-Acl -LiteralPath $file -ErrorAction Stop
        $allowed = @('S-1-5-18','S-1-5-32-544')
        foreach ($entry in $access.Access) {
            $sid = $entry.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value
            if ($entry.AccessControlType -eq 'Allow' -and $sid -notin $allowed) {
                throw 'R39_REFUSED: untrusted staged executable access'
            }
        }
        if ($access.AreAccessRulesProtected -ne $true) {
            throw 'R39_REFUSED: inherited executable permissions'
        }
    }
    $sourceHash = (Get-FileHash -LiteralPath $manager -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceHash -ne (Get-FileHash -LiteralPath $stagedExe -Algorithm SHA256).Hash.ToLowerInvariant()) {
        throw 'R39_REFUSED: copied manager executable hash differs from built artifact'
    }
    $hash = (Get-FileHash -LiteralPath $stagedExe -Algorithm SHA256).Hash.ToLowerInvariant()
    $record = [ordered]@{
        schema_version = 1; channel = 'ci-only-status-manager'
        executable_sha256 = $hash; owner = 'R5_DISPOSABLE_GITHUB_RUNNER'
    }
    $record | ConvertTo-Json -Compress |
        Set-Content -LiteralPath $marker -Encoding ascii -ErrorAction Stop
    if ($InjectFailureAt -eq 'AfterStage') { throw 'R20_INJECTED_AFTER_STAGE' }
    $execArg = '"' + $stagedExe + '" --manager-service'
    & sc.exe create $serviceName 'binPath=' $execArg 'start=' 'demand' 'obj=' 'LocalSystem' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'R5 SCM create failed' }
    $createdService = $true
    if ($InjectFailureAt -eq 'AfterScmCreate') { throw 'R20_INJECTED_AFTER_SCM_CREATE' }
    $registered = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if (-not $registered -or $registered.StartMode -ne 'Manual' -or
        $registered.StartName -ne 'LocalSystem' -or
        $registered.PathName -notlike "*OracleProxyR5StatusOnly*") {
        throw 'R5 installed SCM registration does not match expected narrow service'
    }
    & sc.exe start $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'R5 status-only SCM start failed' }
    (Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    if ($InjectFailureAt -eq 'AfterScmStart') { throw 'R20_INJECTED_AFTER_SCM_START' }    (Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(20))
    $result = & $stagedExe --ipc-status
    if ($LASTEXITCODE -ne 0) { throw 'R5 status IPC request failed' }
    $json = $result | ConvertFrom-Json -ErrorAction Stop
    if (-not $json.ok -or $json.code -ne 'STATUS_ONLY' -or
        $json.manager_mode -ne 'read_only_real_windows_service' -or
        -not $json.authenticated_status_pipe -or $json.mutating_commands_available -or
        $json.native_dll_loaded -or $json.leak_protection -ne 'unverified' -or
        $json.wireguard_tunnel_connected -ne 'unverified') {
        throw 'R5 status-only safety contract violated'
    }
    $guiProcess = Start-Process -FilePath $gui -ArgumentList '--manager-status-self-test' -Wait -PassThru
    if ($guiProcess.ExitCode -ne 0) { throw 'R5 GUI status pipe cannot be queried' }
    Write-Host 'R5_INSTALL_SMOKE_PASS: status-only LocalSystem service deployed from protected staging dir; GUI reads authenticated IPC'
}
finally {
    if ($createdService) {
        # Delete only the fixed service that THIS CI invocation created, and
        # verify its command line still points at this invocation's staging dir.
        $existing = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue
        if ($existing -and $existing.PathName -like '*OracleProxyR5StatusOnly*') {
            try { Stop-Service -Name $serviceName -ErrorAction SilentlyContinue } catch {}
            & sc.exe delete $serviceName | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'R5 service deletion failed' }
            $deadline = [DateTime]::UtcNow.AddSeconds(25)
            while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and
                   [DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Milliseconds 450
            }
            if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
                throw 'R5 service still registered after uninstaller'
            }
        }
        else { throw 'R5 service identity changed; refusing to delete other service' }
    }
    if ($createdDirectory) {
        if (!(Test-Path -LiteralPath $marker -PathType Leaf)) {
            throw 'R5 ownership marker lost; refusing recursive removal'
        }
        $owned = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
        if ($owned.owner -ne 'R5_DISPOSABLE_GITHUB_RUNNER' -or
            $owned.channel -ne 'ci-only-status-manager' -or
            $owned.executable_sha256 -ne
                (Get-FileHash -LiteralPath $stagedExe -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw 'R5 owned install manifest hash mismatched; refusing removal'
        }
        Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction Stop
    }
    $after = Get-NetworkBaseline
    if ($after.DefaultRoutes -ne $baseline.DefaultRoutes -or
        $after.Dns -ne $baseline.Dns -or
        $after.RuleCount -ne $baseline.RuleCount) {
        throw 'R5 observed network baseline changed; not approved'
    }
    Write-Host 'R5_UNINSTALL_SMOKE_PASS: exact created service, stage and marker deleted; default routes/DNS/firewall rule count unchanged'
}
