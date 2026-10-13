$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Real tunnel service test is restricted to disposable GitHub-hosted Windows runner'
}
$root = Join-Path $env:ProgramData 'OracleProxyLab'
foreach ($profile in @('lab-peer-a', 'lab-peer-b')) {
    $service = 'WireGuardTunnel$' + $profile
    $exe = Join-Path (Join-Path $root $profile) 'OracleProxy.WireGuardHost.exe'
    if (!(Test-Path $exe) -or (Get-Service -Name $service -ErrorAction SilentlyContinue)) {
        throw 'Refuse to overwrite an existing SCM service or run without audited host'
    }
}
try {
    foreach ($profile in @('lab-peer-a', 'lab-peer-b')) {
        $service = 'WireGuardTunnel$' + $profile
        $exe = Join-Path (Join-Path $root $profile) 'OracleProxy.WireGuardHost.exe'
        $binArg = ('"{0}" --wireguard-service {1}' -f $exe, $profile)
        & sc.exe create $service 'binPath=' $binArg 'start=' 'demand' 'depend=' 'Nsi/TcpIp' 'obj=' 'LocalSystem' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not register the isolated WireGuard tunnel service' }
        & sc.exe sidtype $service 'unrestricted' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not set mandatory upstream Service SID policy' }
    }
    foreach ($profile in @('lab-peer-a', 'lab-peer-b')) {
        $service = 'WireGuardTunnel$' + $profile
        & sc.exe start $service | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Native embeddable service did not start' }
    }
    $observer = (Resolve-Path './dist/loopback/wgnt-service-observe.exe').Path
    & $observer $env:WG_LAB_DLL
    if ($LASTEXITCODE -ne 0) {
        throw 'Real service tunnel handshake not verified from both driver LastHandshake fields'
    }
    Write-Host 'PASS: two real upstream tunnel.dll SCM services completed a localhost WireGuard handshake'
}
finally {
    # May run again in the ALWAYS cleanup job; deleting only our two fixed
    # test service names. Does not touch WireSock, Oracle or existing VPNs.
    foreach ($profile in @('lab-peer-b', 'lab-peer-a')) {
        $service = 'WireGuardTunnel$' + $profile
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            try { Stop-Service -Name $service -Force -ErrorAction SilentlyContinue } catch {}
            & sc.exe delete $service | Out-Null
        }
    }
}
