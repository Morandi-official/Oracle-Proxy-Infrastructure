param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$BundleDirectory,
    [switch]$Live
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    -not [Environment]::Is64BitProcess) { throw 'HOSTED_WINDOWS_ACCEPTANCE_REQUIRED' }
if ($Live -and $env:GITHUB_REF -ne 'refs/heads/main') { throw 'MAIN_ONLY_ORACLE_ACCEPTANCE_REQUIRED' }

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
        $report = Join-Path $work 'ACCEPTANCE.json'
        $status = Invoke-BoundedProcess (Join-Path $desktop 'Proxy.exe') @('--acceptance', ('"' + $report + '"')) 270000
        if (!(Test-Path -LiteralPath $report -PathType Leaf)) { throw 'WINDOWS_LIVE_REPORT_MISSING' }
        $evidence = Get-Content -LiteralPath $report -Raw
        $summary = $evidence | ConvertFrom-Json
        Write-Output $evidence
        if ($status -ne 0 -or !$summary.accepted) { throw 'WINDOWS_ORACLE_ACCEPTANCE_FAILED' }
        Copy-Item -LiteralPath $report -Destination (Join-Path $out 'ACCEPTANCE.json')
    }
}
finally {
    Remove-Item Env:ORACLE_CLIENT_ACCEPTANCE_USERNAME,Env:ORACLE_CLIENT_ACCEPTANCE_PASSWORD -ErrorAction SilentlyContinue
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
