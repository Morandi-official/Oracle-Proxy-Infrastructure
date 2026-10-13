$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Never permit this service experiment outside disposable GitHub CI'
}
$root = Join-Path $env:ProgramData 'OracleProxyLab'
if (!(Test-Path (Join-Path $root '.ci-control-approved') -PathType Leaf)) {
    throw 'Protected disposable-lab control authorization missing'
}
$managerName = 'OracleProxyLabManager'
$managerExe = (Resolve-Path './dist/lab-admin-manager/OracleProxy.LabManager.exe').Path
$guiExe = (Resolve-Path './dist/lab-client-gui/OracleProxy.Windows.Preview.exe').Path
$observer = (Resolve-Path './dist/loopback/wgnt-service-observe.exe').Path
if (Get-Service -Name $managerName -ErrorAction SilentlyContinue) {
    throw 'Refuse to modify a preexisting manager service'
}
foreach ($profile in @('lab-peer-a', 'lab-peer-b')) {
    if (Get-Service -Name ('WireGuardTunnel$' + $profile) -ErrorAction SilentlyContinue) {
        throw 'Refuse to modify a preexisting tunnel service'
    }
}

function Run-GuiAdminLab([string]$operation) {
    $process = Start-Process -FilePath $guiExe -ArgumentList $operation -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Authenticated GUI client could not complete fixed operation: $operation"
    }
}

$createdServices = New-Object 'System.Collections.Generic.List[string]'
try {
    # Registration is separate from activation. SCM can only start fixed test
    # peers via the manager's protected named pipe once approved.
    foreach ($profile in @('lab-peer-a', 'lab-peer-b')) {
        $service = 'WireGuardTunnel$' + $profile
        $exe = Join-Path (Join-Path $root $profile) 'OracleProxy.WireGuardHost.exe'
        $cmd = ('"{0}" --wireguard-service {1}' -f $exe, $profile)
        & sc.exe create $service 'binPath=' $cmd 'start=' 'demand' 'depend=' 'Nsi/TcpIp' 'obj=' 'LocalSystem' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Cannot create lab tunnel service' }
        $createdServices.Add($service)
        & sc.exe sidtype $service 'unrestricted' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Lab tunnel Service SID could not be secured' }
    }

    $managerArgs = ('"{0}" --manager-service --ci-lab-control' -f $managerExe)
    & sc.exe create $managerName 'binPath=' $managerArgs 'start=' 'demand' 'obj=' 'LocalSystem' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create admin-only isolated manager' }
    $createdServices.Add($managerName)
    & sc.exe start $managerName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot start isolated SCM manager' }
    $mgr = Get-Service -Name $managerName
    $mgr.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))

    # The *real* GUI executable, not a direct sc.exe or powershell command,
    # issues authenticated StartLabPeerA/B requests over the admin-only pipe.
    Run-GuiAdminLab '--ci-lab-start-a'
    Run-GuiAdminLab '--ci-lab-start-b'

    & $observer $env:WG_LAB_DLL
    if ($LASTEXITCODE -ne 0) { throw 'Actual peer LastHandshake records absent' }
    $dataProbe = (Resolve-Path './dist/loopback/wgnt-data-plane.exe').Path
    & $dataProbe $env:WG_LAB_DLL
    if ($LASTEXITCODE -ne 0) {
        throw 'Real IPv4 UDP data did not traverse both native WireGuardNT interfaces'
    }

    $appDnsProbe = (Resolve-Path './dist/loopback/wgnt-app-dns.exe').Path
    & $appDnsProbe $env:WG_LAB_DLL
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows application-layer UDP and synthetic DNS delivery did not succeed across isolated WireGuard peers'
    }

    Run-GuiAdminLab '--ci-lab-stop-b'
    Run-GuiAdminLab '--ci-lab-stop-a'
    foreach ($profile in @('lab-peer-b', 'lab-peer-a')) {
        $s = Get-Service -Name ('WireGuardTunnel$' + $profile)
        $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    }
    Write-Host 'ADMIN_LAB_PASS: genuine native GUI -> OS admin-token IPC -> LocalSystem manager -> SCM tunnel start/stop -> real two-sided handshake'
}
finally {
    # Worst-case independent cleanup does not require the IPC/GUI to work.
    # Clean ONLY services created by this exact disposable job.
    foreach ($svc in @('WireGuardTunnel$lab-peer-b','WireGuardTunnel$lab-peer-a', $managerName)) {
        if ($createdServices.Contains($svc)) {
            try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {}
            & sc.exe delete $svc | Out-Null
        }
    }
}
