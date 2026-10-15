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
    if ($env:ORACLE_R21_SYSTEM_GUARD) {
        if ($env:ORACLE_R21_SYSTEM_GUARD -ne 'CI_FIXED_SYSTEM_POLICY' -or
            ($env:ORACLE_R19_CRASH_TEST -ne 'CI_OWNED_MANAGER_ONLY' -and
             $env:ORACLE_R22_TAMPER_TEST -ne 'CI_ONLY' -and
              $env:ORACLE_R24_NARROW_TAMPER -ne 'CI_ONLY')) {
            throw 'R21_REFUSED: only CI manager crash + pinned guard proof'
        }
        $managerArgs += ' --ci-wfp-guard'
    }
    & sc.exe create $managerName 'binPath=' $managerArgs 'start=' 'demand' 'obj=' 'LocalSystem' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot create admin-only isolated manager' }
    $createdServices.Add($managerName)
    & sc.exe start $managerName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot start isolated SCM manager' }
    $mgr = Get-Service -Name $managerName
    try {
        $mgr.WaitForStatus('Running', [TimeSpan]::FromSeconds(25))
    }
    catch {
        if ($env:ORACLE_R21_SYSTEM_GUARD) {
            $status = Get-CimInstance Win32_Service -Filter "Name='$managerName'" -ErrorAction SilentlyContinue
            if ($status) {
                Write-Host "R21_SCM_STARTUP_DIAGNOSTIC: state=$($status.State) exit_code=$($status.ExitCode) service_code=$($status.ServiceSpecificExitCode) has_pid=$([bool]($status.ProcessId -gt 0))"
            }
            $recent = @(Get-WinEvent -FilterHashtable @{
                LogName='System'; ProviderName='Service Control Manager'
                StartTime=[DateTime]::Now.AddMinutes(-3)
            } -ErrorAction SilentlyContinue | Where-Object {
                $_.Message -like '*OracleProxyLabManager*'
            } | Select-Object -Last 6)
            foreach ($ev in $recent) {
                Write-Host "R21_SCM_EVENT_ID=$($ev.Id)"
            }
        }
        throw
    }
    if ($env:ORACLE_R21_SYSTEM_GUARD) {
        & ./lab/wfp-scoped/Test-R21-SystemOwnedGuard.ps1 -LiveCheck
        if (-not $?) { throw 'R21_FAIL: SYSTEM policy absent before tunnel activation' }
        Write-Host 'R21_SYSTEM_WFP_BEFORE_TUNNEL_PASS'
    }

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

    if ($env:ORACLE_R21_SYSTEM_GUARD) {
        & ./lab/wfp-scoped/Test-R21-SystemOwnedGuard.ps1 -LiveCheck
        if (-not $?) { throw 'R21_FAIL: WFP did not remain during encrypted traffic' }
        Write-Host 'R21_SYSTEM_WFP_LIVE_NATIVE_TUNNEL_PASS'
    }

    if ($env:ORACLE_R22_TAMPER_TEST) {
        & ./lab/wfp-scoped/Test-R22-GuardTamper.ps1
        if (-not $?) { throw 'R22_FAIL: tamper-response verification failed' }
    }
    if ($env:ORACLE_R24_NARROW_TAMPER) {
        & ./lab/wfp-scoped/Test-R24-AddressScopeTamper.ps1
        if (-not $?) { throw 'R24_FAIL: address-scope tamper response failed' }
    }

    # R18: independently verify active process-scoped all-protocol WFP
    # while BOTH native WireGuard SCM peers carry real app and DNS UDP data.
    if ($env:ORACLE_R18_GUARD_NAME) {
        & ./lab/wfp-scoped/Test-R18-MultiProtocolGuard.ps1 -LiveCheck
        if (-not $?) { throw 'R18 live WG/WFP verification failed' }
    }

    # R15: WFP guard remains enforced while real WireGuard SCM peers are active.
    # Proves only one CI PowerShell process, public IPv4 TCP/443 endpoint.
    if ($env:ORACLE_R15_GUARD_NAME) {
        $name = $env:ORACLE_R15_GUARD_NAME
        $remote = $env:ORACLE_R15_GUARD_REMOTE
        $program = $env:ORACLE_R15_GUARD_PROGRAM
        if ($name -notmatch '^OracleProxy-R15-CI-[a-f0-9]{32}$' -or
            $remote -notin @('1.1.1.1','8.8.8.8') -or
            -not [string]::Equals($program, (Get-Process -Id $PID).Path,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'R15_FAIL: invalid WFP guard binding while tunnel connected'
        }
        $live = Get-NetFirewallRule -Name $name -PolicyStore ActiveStore -ErrorAction Stop
        $ports = $live | Get-NetFirewallPortFilter -ErrorAction Stop
        $addresses = $live | Get-NetFirewallAddressFilter -ErrorAction Stop
        $app = $live | Get-NetFirewallApplicationFilter -ErrorAction Stop
        if ($live.Direction -ne 'Outbound' -or $live.Action -ne 'Block' -or
            [string]$ports.Protocol -notin @('TCP','6') -or
            [string]$ports.RemotePort -ne '443' -or
            [string]$addresses.RemoteAddress -ne $remote -or
            -not [string]::Equals($app.Program, $program,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'R15_FAIL: WFP scope widened or changed during live tunnel'
        }
        Start-Sleep -Milliseconds 650
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $escaped = $false
        try {
            $destination = [System.Net.IPAddress]::Parse($remote)
            $connect = $tcp.ConnectAsync($destination, 443)
            $escaped = $connect.Wait(2500) -and $tcp.Connected
        } catch { $escaped = $false }
        finally { $tcp.Dispose() }
        if ($escaped) { throw 'R15_FAIL: external TCP socket bypassed WFP guard' }
        Write-Host 'R15_LIVE_TUNNEL_WFP_DENY_PASS: encrypted peers and synthetic app/DNS worked while narrow external TCP blocked'
    }

    if ($env:ORACLE_R19_CRASH_TEST) {
        # R19: kill ONLY the manager service this disposable job just created,
        # never any user/system service. The two native tunnel peers continue
        # until separate CI-owned recovery removes them in finally.
        if ($env:ORACLE_R19_CRASH_TEST -ne 'CI_OWNED_MANAGER_ONLY' -or
            $env:GITHUB_ACTIONS -ne 'true' -or
            $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
            -not $createdServices.Contains($managerName) -or
            -not ($env:ORACLE_R18_GUARD_NAME -or $env:ORACLE_R21_SYSTEM_GUARD)) {
            throw 'R19_REFUSED: no exact owned manager and WFP guard'
        }
        $serviceRecord = Get-CimInstance Win32_Service -Filter "Name='$managerName'" -ErrorAction Stop
        if (-not $serviceRecord -or $serviceRecord.State -ne 'Running' -or
            $serviceRecord.ProcessId -le 4) {
            throw 'R19_REFUSED: expected dedicated running SCM manager absent'
        }
        $managerPid = [int]$serviceRecord.ProcessId
        $process = Get-CimInstance Win32_Process -Filter "ProcessId=$managerPid" -ErrorAction Stop
        if (-not $process -or -not $process.ExecutablePath -or
            -not [string]::Equals(
                [System.IO.Path]::GetFullPath($process.ExecutablePath),
                [System.IO.Path]::GetFullPath($managerExe),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'R19_REFUSED: SCM PID does not point at this CI manager binary'
        }
        Stop-Process -Id $managerPid -Force -ErrorAction Stop
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 350
            $status = (Get-Service -Name $managerName -ErrorAction Stop).Status
        } while ($status -ne 'Stopped' -and [DateTime]::UtcNow -lt $deadline)
        if ($status -ne 'Stopped') { throw 'R19_FAIL: manager process was not stopped' }
        foreach ($profile in @('lab-peer-a','lab-peer-b')) {
            if ((Get-Service -Name ('WireGuardTunnel$' + $profile) -ErrorAction Stop).Status -ne 'Running') {
                throw 'R19_FAIL: native WireGuard tunnel did not outlive crashed manager'
            }
        }
        # OS-stored persistent WFP rule MUST survive the controller crash
        # and continue denying physical TCP and direct UDP DNS on test app.
        if ($env:ORACLE_R21_SYSTEM_GUARD) {
            & ./lab/wfp-scoped/Test-R21-SystemOwnedGuard.ps1 -LiveCheck
            if (-not $?) { throw 'R21_FAIL: SYSTEM-owned WFP lost on hard manager crash' }
            Write-Host 'R21_SYSTEM_OWNED_WFP_SURVIVED_MANAGER_CRASH_PASS'
        } else {
            & ./lab/wfp-scoped/Test-R18-MultiProtocolGuard.ps1 -LiveCheck
            if (-not $?) { throw 'R19_FAIL: WFP leaked after manager crash' }
        }
        Write-Host 'R19_MANAGER_KILLED_WG_STILL_UP_WFP_PERSISTENT_PASS'
        if ($env:ORACLE_R25_RESTART_TEST) {
            if ($env:ORACLE_R25_RESTART_TEST -ne 'CI_ONLY' -or
                $env:ORACLE_R21_SYSTEM_GUARD -ne 'CI_FIXED_SYSTEM_POLICY' -or
                $env:ORACLE_R19_CRASH_TEST -ne 'CI_OWNED_MANAGER_ONLY') {
                throw 'R25_REFUSED: not a fixed disposable protected restart'
            }
            $rule = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object DisplayName -eq 'OracleProxy-R21-CI-SYSTEM-OnlyGuard')
            if ($rule.Count -ne 1) { throw 'R25_FAIL: guard absent/duplicate before restart' }
            & sc.exe start $managerName | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'R25_FAIL: SYSTEM manager refused valid preserved guard'
            }
            (Get-Service -Name $managerName).WaitForStatus('Running',
                [TimeSpan]::FromSeconds(25))
            $restarted = Get-CimInstance Win32_Service -Filter "Name='$managerName'" -ErrorAction Stop
            if ($restarted.State -ne 'Running' -or $restarted.ProcessId -le 4 -or
                $restarted.ProcessId -eq $managerPid) {
                throw 'R25_FAIL: did not start a new manager process'
            }
            $newProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($restarted.ProcessId)" -ErrorAction Stop
            if (-not $newProcess -or -not [string]::Equals(
                [IO.Path]::GetFullPath($newProcess.ExecutablePath),
                [IO.Path]::GetFullPath($managerExe),
                [StringComparison]::OrdinalIgnoreCase)) {
                throw 'R25_FAIL: newly running manager has wrong executable'
            }
            & ./lab/wfp-scoped/Test-R21-SystemOwnedGuard.ps1 -LiveCheck
            if (-not $?) { throw 'R25_FAIL: rebooted manager reused unverified WFP' }
            $rulesAfter = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object DisplayName -eq 'OracleProxy-R21-CI-SYSTEM-OnlyGuard')
            if ($rulesAfter.Count -ne 1) {
                throw 'R25_FAIL: WFP guard duplicated at SCM restart'
            }
            Write-Host 'R25_CRASH_RESTART_STRICT_WFP_ADOPTION_PASS'

            # Authenticated native GUI -> restarted SCM manager can still
            # safely control the fixed lab peers; exact persistent rule stays.
            Run-GuiAdminLab '--ci-lab-stop-a'
            (Get-Service -Name 'WireGuardTunnel$lab-peer-a').WaitForStatus(
                'Stopped',[TimeSpan]::FromSeconds(20))
            Run-GuiAdminLab '--ci-lab-start-a'
            (Get-Service -Name 'WireGuardTunnel$lab-peer-a').WaitForStatus(
                'Running',[TimeSpan]::FromSeconds(20))
            & $observer $env:WG_LAB_DLL
            if ($LASTEXITCODE -ne 0) {
                throw 'R25_FAIL: real native WG handshake lost after manager restart'
            }
            & ./lab/wfp-scoped/Test-R21-SystemOwnedGuard.ps1 -LiveCheck
            if (-not $?) { throw 'R25_FAIL: WFP lost after reconnect' }
            Run-GuiAdminLab '--ci-lab-stop-b'
            Run-GuiAdminLab '--ci-lab-stop-a'
            foreach ($profile in @('lab-peer-b','lab-peer-a')) {
                (Get-Service -Name ('WireGuardTunnel$' + $profile)).WaitForStatus(
                    'Stopped',[TimeSpan]::FromSeconds(20))
            }
            Write-Host 'R25_AUTHENTICATED_GUI_RECONNECT_AND_SAFE_STOP_PASS'
        }

    } else {
        Run-GuiAdminLab '--ci-lab-stop-b'
        Run-GuiAdminLab '--ci-lab-stop-a'
        foreach ($profile in @('lab-peer-b', 'lab-peer-a')) {
            $s = Get-Service -Name ('WireGuardTunnel$' + $profile)
            $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
        }
        Write-Host 'ADMIN_LAB_PASS: genuine native GUI -> OS admin-token IPC -> LocalSystem manager -> SCM tunnel start/stop -> real two-sided handshake'
    }
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
