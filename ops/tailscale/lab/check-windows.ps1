$ErrorActionPreference = 'Stop'
$version = '1.104.7'
$work = Join-Path $env:RUNNER_TEMP ('proxy-tailscale-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $work
$daemon = $null

try {
    $msi = Join-Path $work 'tailscale.msi'
    Invoke-WebRequest "https://pkgs.tailscale.com/stable/tailscale-setup-$version-amd64.msi" -OutFile $msi -TimeoutSec 90
    $signature = Get-AuthenticodeSignature -LiteralPath $msi
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Tailscale Inc\.?(,|$)') {
        throw 'TAILSCALE_MSI_PUBLISHER_VERIFICATION_FAILED'
    }

    # An administrative extraction leaves any existing Windows services alone.
    $extract = Join-Path $work 'extracted'
    $install = Start-Process msiexec.exe -ArgumentList @('/a', ('"' + $msi + '"'), '/qn', ('TARGETDIR="' + $extract + '"')) -Wait -PassThru
    if ($install.ExitCode -ne 0) { throw "TAILSCALE_MSI_EXTRACTION_FAILED: $($install.ExitCode)" }
    $engineFiles = @(Get-ChildItem -LiteralPath $extract -Recurse -Filter 'tailscaled.exe' -File)
    $cliFiles = @(Get-ChildItem -LiteralPath $extract -Recurse -Filter 'tailscale.exe' -File)
    if ($engineFiles.Count -ne 1 -or $cliFiles.Count -ne 1) { throw 'TAILSCALE_ENGINE_NOT_FOUND' }
    $cli = $cliFiles[0].FullName
    if ((& $cli version | Select-Object -First 1) -ne $version) { throw 'TAILSCALE_ENGINE_VERSION_MISMATCH' }

    $instance = 'Lab-' + $PID
    $pipe = '\\.\pipe\ProtectedPrefix\Administrators\OracleProxyTailscale-' + $instance
    $state = Join-Path $work 'state'
    $configuration = [Diagnostics.ProcessStartInfo]::new($engineFiles[0].FullName)
    $configuration.WorkingDirectory = $engineFiles[0].DirectoryName
    $configuration.UseShellExecute = $false
    $configuration.CreateNoWindow = $true
    $configuration.Environment['TS_NO_LOGS_NO_SUPPORT'] = 'true'
    foreach ($argument in @("--socket=$pipe", "--state=$state", '--tun=userspace-networking', '--port=0')) {
        $configuration.ArgumentList.Add($argument)
    }
    $daemon = [Diagnostics.Process]::Start($configuration)
    $ready = $false
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($daemon.HasExited) { throw "TAILSCALE_PROCESS_STOPPED: $($daemon.ExitCode)" }
        $statusJson = & $cli "--socket=$pipe" status --json 2>$null
        if ($statusJson) {
            $status = $statusJson | ConvertFrom-Json
            if ($status.BackendState -in @('NeedsLogin', 'Stopped') -and !$status.HaveNodeKey) {
                $ready = $true
                break
            }
        }
        Start-Sleep -Milliseconds 250
    }
    if (!$ready) { throw 'TAILSCALE_PROTECTED_PIPE_UNREACHABLE' }
    Write-Output 'TAILSCALE_WINDOWS_ISOLATED_LOCAL_CONTROL=PASS'
    & dotnet run --project "$PSScriptRoot/windows-control/WindowsControl.csproj" -- $instance
    if ($LASTEXITCODE -ne 0) { throw 'TAILSCALE_WINDOWS_DIRECT_PROTECTED_PIPE_FAILED' }
}
finally {
    if ($null -ne $daemon) {
        if (!$daemon.HasExited) {
            $daemon.Kill($true)
            $daemon.WaitForExit()
        }
        $daemon.Dispose()
    }
    Remove-Item -LiteralPath $work -Recurse -Force
}
