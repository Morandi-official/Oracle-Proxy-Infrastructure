param([string]$ClientArtifact, [string]$BundleDir)

$ErrorActionPreference = 'Stop'
$version = '1.104.7'
$work = Join-Path $env:RUNNER_TEMP ('proxy-tailscale-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $work

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

    $state = Join-Path $work 'state'
    $engine = $engineFiles[0].FullName
    $null = New-Item -ItemType Directory $state
    & dotnet run --project "$PSScriptRoot/windows-control/WindowsControl.csproj" -- $engine $state
    if ($LASTEXITCODE -ne 0) { throw 'TAILSCALE_WINDOWS_DIRECT_PROTECTED_PIPE_FAILED' }

    if ($ClientArtifact -or $BundleDir) {
        $client = if ($BundleDir) { [IO.Path]::GetFullPath($BundleDir) } else { Join-Path $work 'client' }
        if (Test-Path -LiteralPath $client) { throw 'TAILSCALE_BUNDLE_MUST_BE_NEW' }
        & dotnet publish "$PSScriptRoot/../../../clients/windows/tailscale-app/Proxy.Tailscale.csproj" `
            --configuration Release --runtime win-x64 --self-contained true -p:DebugType=None --output $client
        if ($LASTEXITCODE -ne 0) { throw 'TAILSCALE_WINDOWS_CANDIDATE_BUILD_FAILED' }
        $runtime = Join-Path $client 'engine'
        $null = New-Item -ItemType Directory $runtime
        Copy-Item -LiteralPath $engine -Destination $runtime
        $dll = Join-Path (Split-Path -Parent $engine) 'wintun.dll'
        if (Test-Path -LiteralPath $dll -PathType Leaf) { Copy-Item -LiteralPath $dll -Destination $runtime }
        if ($BundleDir) {
            $licenses = Join-Path $client 'licenses'
            $null = New-Item -ItemType Directory $licenses
            Invoke-WebRequest "https://raw.githubusercontent.com/tailscale/tailscale/v$version/LICENSE" `
                -OutFile (Join-Path $licenses 'Tailscale-LICENSE.txt') -TimeoutSec 45
            & $cli licenses | Set-Content -LiteralPath (Join-Path $licenses 'Tailscale-dependencies.txt') -Encoding utf8
            if ($LASTEXITCODE -ne 0) { throw 'TAILSCALE_LICENSE_NOTICE_UNAVAILABLE' }
            $dotnetRoot = Split-Path -Parent (Get-Command dotnet -CommandType Application).Source
            $dotnetLicense = Join-Path $dotnetRoot 'LICENSE.txt'
            $dotnetNotices = Join-Path $dotnetRoot 'ThirdPartyNotices.txt'
            Copy-Item -LiteralPath $dotnetLicense -Destination (Join-Path $licenses 'DotNet-LICENSE.txt')
            Copy-Item -LiteralPath $dotnetNotices -Destination (Join-Path $licenses 'DotNet-ThirdPartyNotices.txt')
            Copy-Item -LiteralPath "$PSScriptRoot/../../../clients/windows/product/COPYING" `
                -Destination (Join-Path $licenses 'OracleProxy-GPL-3.0.txt')
            @(
                "Oracle Proxy source: https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/tree/$env:GITHUB_SHA/clients/windows"
                "Tailscale engine $version source: https://github.com/tailscale/tailscale/tree/v$version"
                'Upstream Windows engine distribution: https://pkgs.tailscale.com/stable/'
            ) | Set-Content -LiteralPath (Join-Path $licenses 'Source.txt') -Encoding utf8
        }
        if ($ClientArtifact) { Compress-Archive -Path "$client/*" -DestinationPath $ClientArtifact }
    }
}
finally {
    # Console-host and antivirus handles can outlive the daemon briefly.
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        if (!(Test-Path -LiteralPath $work)) { break }
        try {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Stop
            break
        } catch {
            if ($attempt -eq 11) { throw }
            Start-Sleep -Milliseconds 250
        }
    }
}
