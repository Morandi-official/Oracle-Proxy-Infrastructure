param([string]$ClientArtifact, [string]$BundleDir, [string]$EngineSource, [switch]$RetentionExperiment)

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
    $dll = Join-Path (Split-Path -Parent $engine) 'wintun.dll'
    if ($EngineSource) {
        $source = (Resolve-Path -LiteralPath $EngineSource).Path
        $sourceCommit = 'cbc74fe48ef1b1649f69a4d9a602319427e25102'
        if ((& git -C $source rev-parse HEAD) -cne $sourceCommit -or $LASTEXITCODE -ne 0) {
            throw 'TAILSCALE_ENGINE_SOURCE_REVISION_MISMATCH'
        }
        if (!(Test-Path -LiteralPath $dll -PathType Leaf)) {
            # Version and digest are pinned by the same Tailscale release.
            $wintun = Join-Path $work 'wintun.zip'
            Invoke-WebRequest 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $wintun -TimeoutSec 90
            if ((Get-FileHash -LiteralPath $wintun -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51') {
                throw 'WINTUN_ZIP_DIGEST_MISMATCH'
            }
            Expand-Archive -LiteralPath $wintun -DestinationPath (Join-Path $work 'wintun')
            $dll = Join-Path $work 'wintun/wintun/bin/amd64/wintun.dll'
        }
        $patched = Join-Path $work 'engine'
        $null = New-Item -ItemType Directory $patched
        $engine = Join-Path $patched 'tailscaled.exe'
        Copy-Item -LiteralPath $dll -Destination $patched

        $patch = Join-Path $work 'coordinator-tls-timeout.patch'
        $utf8 = [Text.UTF8Encoding]::new($false)
        $originalPatch = (Resolve-Path -LiteralPath "$PSScriptRoot/../windows/coordinator-tls-timeout.patch").Path
        [IO.File]::WriteAllText($patch, [IO.File]::ReadAllText($originalPatch).Replace("`r`n", "`n"), $utf8)
        foreach ($relative in @('net/dnscache/dnscache.go', 'control/controlhttp/client.go',
                'control/controlclient/direct.go', 'control/ts2021/client.go')) {
            $sourceFile = Join-Path $source $relative
            [IO.File]::WriteAllText($sourceFile, [IO.File]::ReadAllText($sourceFile).Replace("`r`n", "`n"), $utf8)
        }
        Push-Location $source
        try {
            & git -c core.autocrlf=false apply --check $patch
            if ($LASTEXITCODE -ne 0) { throw 'COORDINATOR_TLS_PATCH_MISMATCH' }
            & git -c core.autocrlf=false apply $patch
            if ($LASTEXITCODE -ne 0) { throw 'COORDINATOR_TLS_PATCH_FAILED' }
            $env:CGO_ENABLED = '0'
            Copy-Item -LiteralPath "$PSScriptRoot/../windows/coordinator-noise_test.go" -Destination 'control/ts2021/proxy_coordinator_test.go'
            & go test -v -count=1 -timeout=90s -run '^TestProxyAppCoordinatorDelayedNoise$' ./control/ts2021
            if ($LASTEXITCODE -ne 0) { throw 'COORDINATOR_DELAYED_NOISE_TEST_FAILED' }
            & go build -trimpath -buildvcs=false -ldflags "-s -w -X tailscale.com/version.shortStamp=$version -X tailscale.com/version.longStamp=$version-proxy.$($sourceCommit.Substring(0, 10))" -o $engine ./cmd/tailscaled
            if ($LASTEXITCODE -ne 0) { throw 'TAILSCALE_PINNED_SOURCE_BUILD_FAILED' }
        }
        finally { Pop-Location }
        $dll = Join-Path $patched 'wintun.dll'
    }
    $null = New-Item -ItemType Directory $state
    & dotnet run --project "$PSScriptRoot/windows-control/WindowsControl.csproj" -- $engine $state
    if ($LASTEXITCODE -ne 0) { throw 'TAILSCALE_WINDOWS_DIRECT_PROTECTED_PIPE_FAILED' }

    if ($ClientArtifact -or $BundleDir) {
        $client = if ($BundleDir) { [IO.Path]::GetFullPath($BundleDir) } else { Join-Path $work 'client' }
        if (Test-Path -LiteralPath $client) { throw 'TAILSCALE_BUNDLE_MUST_BE_NEW' }
        $probe = $RetentionExperiment.IsPresent.ToString().ToLowerInvariant()
        & dotnet publish "$PSScriptRoot/../../../clients/windows/tailscale-app/Proxy.Tailscale.csproj" `
            --configuration Release --runtime win-x64 --self-contained true -p:DebugType=None `
            "-p:RetainedCoordinatorProbe=$probe" --output $client
        if ($LASTEXITCODE -ne 0) { throw 'TAILSCALE_WINDOWS_CANDIDATE_BUILD_FAILED' }
        $runtime = Join-Path $client 'engine'
        $null = New-Item -ItemType Directory $runtime
        Copy-Item -LiteralPath $engine -Destination $runtime
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
            $engineSource = if ($EngineSource) {
                "Source build: https://github.com/tailscale/tailscale/commit/$sourceCommit with the Windows coordinator TLS timeout patch in Oracle Proxy source."
            } else { 'Upstream Windows engine distribution: https://pkgs.tailscale.com/stable/' }
            @(
                "Oracle Proxy source: https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/tree/$env:GITHUB_SHA/clients/windows"
                "Tailscale engine $version source: https://github.com/tailscale/tailscale/tree/v$version"
                $engineSource
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
