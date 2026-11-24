param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'HOSTED_WINDOWS_PACKAGING_REQUIRED'
}

$app = "$PSScriptRoot/../../../clients/windows/tailscale-app/Proxy.Tailscale.csproj"
$project = [xml](Get-Content -LiteralPath $app -Raw)
if ($project.Project.PropertyGroup.Version -ne $Version) { throw 'WINDOWS_PROJECT_VERSION_MISMATCH' }

$out = [IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory $out
$work = Join-Path $env:RUNNER_TEMP ('proxy-release-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $work
try {
    $payload = Join-Path $work 'payload'
    & "$PSScriptRoot/../lab/check-windows.ps1" -BundleDir $payload
    if (!(Test-Path -LiteralPath (Join-Path $payload 'Proxy.exe'))) { throw 'WINDOWS_CLIENT_MISSING' }

    $iscc = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6/ISCC.exe'
    if (!(Test-Path -LiteralPath $iscc)) { throw 'WINDOWS_SETUP_COMPILER_MISSING' }
    Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $iscc) 'license.txt') `
        -Destination (Join-Path $payload 'licenses/InnoSetup-LICENSE.txt')
    & $iscc '/Qp' "/DBundleDir=$payload" "/DOutputDir=$out" "/DProductVersion=$Version" "$PSScriptRoot/Proxy.iss"
    if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_SETUP_BUILD_FAILED' }

    $stem = "Proxy-$Version-win-x64"
    Compress-Archive -Path "$payload/*" -DestinationPath (Join-Path $out "$stem.zip")
    @("$stem.zip", "$stem-setup.exe") | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath (Join-Path $out $_) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $_"
    } | Set-Content -LiteralPath (Join-Path $out 'SHA256SUMS.txt') -Encoding utf8
}
finally { Remove-Item -LiteralPath $work -Recurse -Force }
