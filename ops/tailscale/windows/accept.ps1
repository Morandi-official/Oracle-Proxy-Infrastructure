param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$BundleDirectory,
    [switch]$Live,
    [switch]$RetentionExperiment,
    [switch]$BlockSystemDns,
    [switch]$CoordinatorProxyOnly,
    [switch]$MixedCoordinatorRoute
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    -not [Environment]::Is64BitProcess) { throw 'HOSTED_WINDOWS_ACCEPTANCE_REQUIRED' }
if ($Live -and $env:GITHUB_REF -ne 'refs/heads/main') { throw 'MAIN_ONLY_ORACLE_ACCEPTANCE_REQUIRED' }
if ($RetentionExperiment -and (!$Live -or $env:TOP_LEVEL_PUSH -ne 'true')) {
    throw 'WINDOWS_RETENTION_REQUIRES_FOCUSED_MAIN_WORKFLOW'
}
if ($BlockSystemDns -and (!$Live -or $RetentionExperiment -or $env:TOP_LEVEL_PUSH -ne 'true')) {
    throw 'WINDOWS_DNS_FAULT_REQUIRES_FOCUSED_MAIN_WORKFLOW'
}
if (($CoordinatorProxyOnly -or $MixedCoordinatorRoute) -and
    (!$Live -or $RetentionExperiment -or $BlockSystemDns -or ($CoordinatorProxyOnly -and $MixedCoordinatorRoute) -or
     $env:TOP_LEVEL_PUSH -ne 'true')) {
    throw 'WINDOWS_PROXY_FAULT_REQUIRES_FOCUSED_MAIN_WORKFLOW'
}
$credentials = @{}
foreach ($name in @('ORACLE_CLIENT_ACCEPTANCE_USERNAME', 'ORACLE_CLIENT_ACCEPTANCE_PASSWORD')) {
    $credentials[$name] = [Environment]::GetEnvironmentVariable($name)
    [Environment]::SetEnvironmentVariable($name, $null)
}

function Invoke-BoundedProcess([string]$File, [string[]]$Arguments, [int]$Milliseconds) {
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -PassThru
    try {
        if (!$process.WaitForExit($Milliseconds)) {
            # The client owns its engine in a kill-on-close Windows Job Object.
            Stop-Process -Id $process.Id -Force
            throw 'WINDOWS_ACCEPTANCE_PROCESS_DEADLINE'
        }
        return $process.ExitCode
    }
    finally { $process.Dispose() }
}

$out = (Resolve-Path -LiteralPath $BundleDirectory).Path
$stem = "Proxy-$Version-win-x64"
$names = @("$stem.zip", "$stem-setup.exe")
$manifest = Get-Content -LiteralPath (Join-Path $out 'SHA256SUMS.txt')
if ($manifest.Count -ne $names.Count) { throw 'WINDOWS_BUNDLE_MANIFEST_INCOMPLETE' }
foreach ($name in $names) {
    $digest = (Get-FileHash -LiteralPath (Join-Path $out $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ("$digest  $name" -cnotin $manifest) { throw 'WINDOWS_BUNDLE_DIGEST_MISMATCH' }
}

$desktop = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OracleProxyTailscale'
$registration = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{2A208744-D1F3-46FD-88FB-1845663512AE}_is1'
$shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'Oracle Proxy/Oracle Proxy.lnk'
if ((Test-Path -LiteralPath $desktop) -or (Test-Path -LiteralPath $registration) -or
    (Test-Path -LiteralPath $shortcut)) { throw 'PREEXISTING_PROXY_INSTALLATION_REFUSED' }
$work = Join-Path $env:RUNNER_TEMP ('proxy-acceptance-' + [guid]::NewGuid().ToString('N'))
$portable = Join-Path $work 'portable'
$null = New-Item -ItemType Directory $work
$silent = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')
$installAttempted = $false

try {
    Expand-Archive -LiteralPath (Join-Path $out $names[0]) -DestinationPath $portable
    $installAttempted = $true
    if ((Invoke-BoundedProcess (Join-Path $out $names[1]) $silent 120000) -ne 0) {
        throw 'WINDOWS_EXE_INSTALL_FAILED'
    }
    if (!(Test-Path -LiteralPath $shortcut) -or !(Test-Path -LiteralPath $registration) -or
        (Get-ItemProperty -LiteralPath $registration).DisplayVersion -ne $Version) {
        throw 'WINDOWS_SETUP_REGISTRATION_MISSING'
    }
    foreach ($file in Get-ChildItem -LiteralPath $portable -Recurse -File) {
        $relative = [IO.Path]::GetRelativePath($portable, $file.FullName)
        $installed = Join-Path $desktop $relative
        if (!(Test-Path -LiteralPath $installed -PathType Leaf) -or
            (Get-FileHash -LiteralPath $file.FullName).Hash -ne (Get-FileHash -LiteralPath $installed).Hash) {
            throw 'WINDOWS_INSTALLED_AND_PORTABLE_PAYLOAD_DIFFER'
        }
    }
    Write-Output 'WINDOWS_SETUP_AND_PORTABLE_PAYLOAD_ACCEPTED'

    if ($Live) {
        $reportName = if ($RetentionExperiment) { 'RETAINED_COORDINATOR.json' }
            elseif ($CoordinatorProxyOnly) { 'PROXY_COORDINATOR_ACCEPTANCE.json' }
            elseif ($MixedCoordinatorRoute) { 'MIXED_COORDINATOR_ACCEPTANCE.json' }
            else { 'ACCEPTANCE.json' }
        $argument = if ($RetentionExperiment) { '--acceptance-retained-coordinator' } else { '--acceptance' }
        $report = Join-Path $work $reportName
        $dnsRule = $null
        $firewall = @()
        $relay = $null
        $savedProxy = $env:HTTPS_PROXY
        $savedNoProxy = $env:NO_PROXY
        $coordinator = 'vpn-admin.morandi.dpdns.org'
        try {
            if ($BlockSystemDns) {
                $dnsRule = Add-DnsClientNrptRule -Namespace $coordinator -NameServers '127.0.0.1' `
                    -Comment "Disposable Proxy acceptance $($env:GITHUB_RUN_ID)" -PassThru
                Clear-DnsClientCache
                $records = Resolve-DnsName -Name $coordinator -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
                if ($records | Where-Object { $_.IPAddress }) { throw 'WINDOWS_SYSTEM_DNS_FAULT_NOT_OBSERVED' }
                $env:ORACLE_CLIENT_ACCEPTANCE_BLOCK_SYSTEM_DNS = 'true'
                Write-Output 'WINDOWS_COORDINATOR_SYSTEM_DNS_BLOCKED'
            }
            if ($CoordinatorProxyOnly -or $MixedCoordinatorRoute) {
                $records = @(Resolve-DnsName -Name $coordinator -Type A_AAAA -DnsOnly)
                $origin = $records | Where-Object Type -eq 'A' | Select-Object -First 1 -ExpandProperty IPAddress
                if (!$origin) { throw 'WINDOWS_PROXY_TEST_ORIGIN_UNAVAILABLE' }
                $addresses = @($records | Where-Object IPAddress | Select-Object -ExpandProperty IPAddress -Unique)
                $ready = Join-Path $work 'coordinator-proxy.port'
                $script = Join-Path $PSScriptRoot 'coordinator_proxy.py'
                $python = Get-Command python.exe -CommandType Application | Select-Object -First 1 -ExpandProperty Path
                $relayMode = if ($MixedCoordinatorRoute) { 'mixed' } else { 'proxy-only' }
                $relay = Start-Process -FilePath $python -PassThru `
                    -ArgumentList @(('"' + $script + '"'), $origin, ('"' + $ready + '"'), $relayMode)
                $deadline = [DateTime]::UtcNow.AddSeconds(8)
                while (!(Test-Path -LiteralPath $ready) -and !$relay.HasExited -and [DateTime]::UtcNow -lt $deadline) {
                    Start-Sleep -Milliseconds 50
                }
                if (!(Test-Path -LiteralPath $ready) -or $relay.HasExited) { throw 'WINDOWS_PROXY_TEST_RELAY_UNAVAILABLE' }
                $port = Get-Content -LiteralPath $ready -Raw
                if ($port -cnotmatch '^[1-9][0-9]{0,4}$') { throw 'WINDOWS_PROXY_TEST_PORT_INVALID' }
                $protocols = if ($MixedCoordinatorRoute) { @('TCP') } else { @('TCP', 'UDP') }
                foreach ($relative in @('Proxy.exe', 'engine/tailscaled.exe')) {
                    foreach ($protocol in $protocols) {
                        $program = [IO.Path]::GetFullPath((Join-Path $desktop $relative))
                        $rule = New-NetFirewallRule -Name ('ProxyAcceptance-' + [guid]::NewGuid().ToString('N')) `
                            -DisplayName 'Disposable coordinator route acceptance' -Program $program `
                            -Direction Outbound -Action Block -RemoteAddress $addresses -RemotePort 443 -Protocol $protocol
                        $firewall += $rule
                    }
                }
                $env:HTTPS_PROXY = "http://127.0.0.1:$port"
                $env:NO_PROXY = ''
                if ($MixedCoordinatorRoute) {
                    $env:ORACLE_CLIENT_ACCEPTANCE_MIXED_COORDINATOR_ROUTE = 'true'
                    Write-Output 'WINDOWS_DIRECT_COORDINATOR_TCP_BLOCKED_QUIC_AVAILABLE'
                }
                else {
                    $env:ORACLE_CLIENT_ACCEPTANCE_PROXY_ONLY = 'true'
                    Write-Output 'WINDOWS_DIRECT_COORDINATOR_TRANSPORT_BLOCKED'
                }
            }
            foreach ($name in $credentials.Keys) { [Environment]::SetEnvironmentVariable($name, $credentials[$name]) }
            $status = Invoke-BoundedProcess (Join-Path $desktop 'Proxy.exe') @($argument, ('"' + $report + '"')) 270000
        }
        finally {
            try {
                if ($dnsRule) {
                    Remove-DnsClientNrptRule -Name $dnsRule.Name -Force
                    Clear-DnsClientCache
                }
                foreach ($rule in $firewall) {
                    Remove-NetFirewallRule -Name $rule.Name
                }
            }
            finally {
                if ($relay) {
                    if (!$relay.HasExited) { $relay.Kill() }
                    $relay.Dispose()
                }
                [Environment]::SetEnvironmentVariable('HTTPS_PROXY', $savedProxy)
                [Environment]::SetEnvironmentVariable('NO_PROXY', $savedNoProxy)
                Remove-Item Env:ORACLE_CLIENT_ACCEPTANCE_USERNAME,Env:ORACLE_CLIENT_ACCEPTANCE_PASSWORD,Env:ORACLE_CLIENT_ACCEPTANCE_BLOCK_SYSTEM_DNS,Env:ORACLE_CLIENT_ACCEPTANCE_PROXY_ONLY,Env:ORACLE_CLIENT_ACCEPTANCE_MIXED_COORDINATOR_ROUTE -ErrorAction SilentlyContinue
            }
        }
        if (!(Test-Path -LiteralPath $report -PathType Leaf)) { throw 'WINDOWS_LIVE_REPORT_MISSING' }
        $evidence = Get-Content -LiteralPath $report -Raw
        $summary = $evidence | ConvertFrom-Json
        Write-Output $evidence
        if ($RetentionExperiment) {
            if ($summary.experiment -cne 'retained-coordinator') { throw 'WINDOWS_RETENTION_REPORT_MISMATCH' }
            Copy-Item -LiteralPath $report -Destination (Join-Path $out $reportName)
        }
        if ($status -ne 0 -or !$summary.accepted) { throw 'WINDOWS_ORACLE_ACCEPTANCE_FAILED' }
        if (!$RetentionExperiment) { Copy-Item -LiteralPath $report -Destination (Join-Path $out $reportName) }
    }
}
finally {
    try {
        $uninstaller = Join-Path $desktop 'unins000.exe'
        if ($installAttempted -and (Test-Path -LiteralPath $uninstaller -PathType Leaf)) {
            if ((Invoke-BoundedProcess $uninstaller $silent 120000) -ne 0 -or
                (Test-Path -LiteralPath (Join-Path $desktop 'Proxy.exe')) -or
                (Test-Path -LiteralPath $registration) -or (Test-Path -LiteralPath $shortcut)) {
                throw 'WINDOWS_EXE_UNINSTALL_FAILED'
            }
            Write-Output 'WINDOWS_EXE_UNINSTALL_ACCEPTED'
        }
    }
    finally { Remove-Item -LiteralPath $work -Recurse -Force }
}
