$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
    throw 'Never stage outside a disposable GitHub-hosted runner'
}
$root = Join-Path $env:ProgramData 'OracleProxyLab'
if (Test-Path $root) { throw 'Refuse to touch any existing lab installation' }
$services = @('WireGuardTunnel$lab-peer-a', 'WireGuardTunnel$lab-peer-b')
foreach ($name in $services) {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        throw 'Refuse to change an existing tunnel service'
    }
}
$admin = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
function Protect-LabPath([string]$path) {
    if (!(Test-Path -LiteralPath $path)) { throw 'Expected lab file not found' }
    $item = Get-Item -LiteralPath $path
    if ($item.PSIsContainer) {
        $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    } else {
        $acl = [System.Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetOwner($admin)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($admin, $system)) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}
New-Item -ItemType Directory -Path $root | Out-Null
# Only this disposable runner may create the ownership flag; cleanup NEVER
# removes a preexisting directory if staging refused it.
'created-by-disposable-github-runner' | Set-Content -LiteralPath (Join-Path $env:RUNNER_TEMP 'oracle-lab-owned.flag') -Encoding ascii
Protect-LabPath $root
$cfgdir = Join-Path $root 'config'
New-Item -ItemType Directory -Path $cfgdir | Out-Null
Protect-LabPath $cfgdir

$env:WG_LAB_EPHEMERAL_KEY_FILE = Join-Path $env:RUNNER_TEMP 'wg-lab-session.bin'
python ./clients/windows/lab/generate_service_pair.py
if ($LASTEXITCODE -ne 0) { throw 'Temporary service configs could not be generated' }
foreach ($profile in @('lab-peer-a', 'lab-peer-b')) {
    $configFile = Join-Path $cfgdir "$profile.conf"
    Protect-LabPath $configFile

    $hostdir = Join-Path $root $profile
    New-Item -ItemType Directory -Path $hostdir | Out-Null
    Protect-LabPath $hostdir
    $destinations = @{
        'OracleProxy.WireGuardHost.exe' = './dist/service-host/OracleProxy.WireGuardHost.exe'
        'tunnel.dll' = './dist/upstream-test/tunnel.dll'
        'wireguard.dll' = $env:WG_LAB_DLL
    }
    foreach ($key in $destinations.Keys) {
        $destination = Join-Path $hostdir $key
        Copy-Item -LiteralPath $destinations[$key] -Destination $destination
        Protect-LabPath $destination
    }
    $pins = [ordered]@{
        schema_version = 1
        tunnel_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $hostdir 'tunnel.dll')).Hash.ToLowerInvariant()
        wireguard_sha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $hostdir 'wireguard.dll')).Hash.ToLowerInvariant()
        config_sha256 = (Get-FileHash -Algorithm SHA256 $configFile).Hash.ToLowerInvariant()
    }
    $manifest = Join-Path $hostdir 'engine-pins.json'
    $pins | ConvertTo-Json -Compress | Set-Content -LiteralPath $manifest -Encoding ascii
    Protect-LabPath $manifest
}
Write-Host 'PASS: two fixed lab profiles, protected source-built DLLs and SHA-256 manifest files staged; no service started'
