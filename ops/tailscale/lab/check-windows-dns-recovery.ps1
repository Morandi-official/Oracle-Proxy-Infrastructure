param(
    [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
    [Parameter(Mandatory)][string]$BundleDirectory
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_EVENT_NAME -ne 'pull_request' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'DISPOSABLE_WINDOWS_RUNNER_REQUIRED'
}

$work = Join-Path $env:RUNNER_TEMP ('proxy-dns-lab-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory $work
$rule = $null
try {
    Expand-Archive -LiteralPath (Join-Path $BundleDirectory "Proxy-$Version-win-x64.zip") -DestinationPath $work
    $state = Join-Path $work 'lab-state'
    $null = New-Item -ItemType Directory $state
    $hostName = 'vpn-admin.morandi.dpdns.org'
    $rule = Add-DnsClientNrptRule -Namespace $hostName -NameServers '127.0.0.1' `
        -Comment "Disposable Proxy DNS lab $($env:GITHUB_RUN_ID)" -PassThru
    Clear-DnsClientCache
    $records = Resolve-DnsName -Name $hostName -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
    if ($records | Where-Object { $_.IPAddress }) { throw 'WINDOWS_LAB_SYSTEM_DNS_FAULT_NOT_OBSERVED' }
    & dotnet run --project "$PSScriptRoot/windows-control/WindowsControl.csproj" -- `
        (Join-Path $work 'engine/tailscaled.exe') $state --dns-recovery
    if ($LASTEXITCODE -ne 0) { throw 'WINDOWS_DNS_RECOVERY_LAB_FAILED' }
}
finally {
    try {
        if ($rule) {
            Remove-DnsClientNrptRule -Name $rule.Name -Force
            Clear-DnsClientCache
        }
    }
    finally { Remove-Item -LiteralPath $work -Recurse -Force }
}
