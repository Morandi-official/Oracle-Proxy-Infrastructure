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
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
