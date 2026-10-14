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
    # The CI runner may drop inbound virtual-adapter UDP at its default
    # Windows Firewall. Never disable or globally relax the firewall.
    # Exact program, synthetic IP pairs, protocol and destination ports only.
    $ruleSuffix = [guid]::NewGuid().ToString('N')
    $appRules = @(
        @{ Suffix='B-app'; Local='10.249.129.2'; Remote='10.249.129.1'; Port='55141' },
        @{ Suffix='A-app'; Local='10.249.129.1'; Remote='10.249.129.2'; Port='55142' },
        @{ Suffix='B-dns'; Local='10.249.129.2'; Remote='10.249.129.1'; Port='53' },
        @{ Suffix='B-app6'; Local='fd42:14::2'; Remote='fd42:14::1'; Port='55161' },
        @{ Suffix='A-app6'; Local='fd42:14::1'; Remote='fd42:14::2'; Port='55162' },
        @{ Suffix='B-dns6'; Local='fd42:14::2'; Remote='fd42:14::1'; Port='53' }
    )
    $createdRuleNames = New-Object 'System.Collections.Generic.List[string]'
    try {
        foreach ($setting in $appRules) {
            $name = "OracleProxy-G14-TEMP-$ruleSuffix-$($setting.Suffix)"
            if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
                throw 'Refuse to replace any preexisting firewall rule'
            }
            $ruleArgs = @{
                Name=$name; DisplayName=$name; Direction='Inbound'; Action='Allow'
                Protocol='UDP'; LocalAddress=$setting.Local; RemoteAddress=$setting.Remote
                LocalPort=$setting.Port; Program=$appDnsProbe; Profile='Any'
                Enabled='True'; ErrorAction='Stop'
            }
            New-NetFirewallRule @ruleArgs | Out-Null
            $createdRuleNames.Add($name)
        }
        & $appDnsProbe $env:WG_LAB_DLL
        if ($LASTEXITCODE -ne 0) {
            throw 'Windows application UDP or synthetic DNS not delivered despite narrowly scoped CI test allow-rules'
        }
    }
    finally {
        foreach ($name in $createdRuleNames) {
            Remove-NetFirewallRule -Name $name -ErrorAction Stop
        }
        Write-Host 'G14_FW_CLEANUP: exact temporary per-program test firewall rules removed'
    }

    # R15: while the real native SCM tunnels are UP, independently prove
    # that a narrow, persistent WFP-backed guard still denies its own
    # public IPv4 TCP test socket. This is NOT a global VPN kill switch.
    if ($env:ORACLE_R15_GUARD_NAME) {
        $name = $env:ORACLE_R15_GUARD_NAME
        $remote = $env:ORACLE_R15_GUARD_REMOTE
        $program = $env:ORACLE_R15_GUARD_PROGRAM
        if ($name -notmatch '^OracleProxy-R15-CI-[a-f0-9]{32}    Run-GuiAdminLab '--ci-lab-stop-a'
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
 -or
            $remote -notin @('1.1.1.1','8.8.8.8') -or
            -not [string]::Equals($program, (Get-Process -Id $PID).Path,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'R15_FAIL: invalid guard binding during live tunnel'
        }
        $live = Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop
        $portFilter = $live | Get-NetFirewallPortFilter -ErrorAction Stop
        $addressFilter = $live | Get-NetFirewallAddressFilter -ErrorAction Stop
        $appFilter = $live | Get-NetFirewallApplicationFilter -ErrorAction Stop
        if ($live.Direction -ne 'Outbound' -or $live.Action -ne 'Block' -or
            [string]$portFilter.Protocol -notin @('TCP','6') -or
            [string]$portFilter.RemotePort -ne '443' -or
            [string]$addressFilter.RemoteAddress -ne $remote -or
            -not [string]::Equals($appFilter.Program, $program,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'R15_FAIL: scope of active guard changed while tunnel connected'
        }
        Start-Sleep -Milliseconds 700
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $connected = $false
        try {
            $ip = [System.Net.IPAddress]::Parse($remote)
            $task = $tcp.ConnectAsync($ip, 443)
            $connected = $task.Wait(2000) -and $tcp.Connected
        } catch { $connected = $false }
        finally { $tcp.Dispose() }
        if ($connected) {
            throw 'R15_FAIL: real outbound TCP bypassed WFP guard while WireGuard SCM tunnel was UP'
        }
        Write-Host 'R15_LIVE_TUNNEL_WFP_DENY_PASS: genuine WireGuard handshake and app/DNS packets succeeded while narrowly scoped physical TCP was denied'
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
