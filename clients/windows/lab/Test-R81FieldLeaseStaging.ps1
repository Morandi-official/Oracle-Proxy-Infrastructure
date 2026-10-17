# R81: stage exactly ONE synthetic field lease and candidate for a
# READ-ONLY CI audit. Never register/start any native service or driver.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or
    $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
    $env:RUNNER_OS -ne 'Windows' -or
    $env:ORACLE_R81 -ne 'CI_ONLY') {
    throw 'R81_REFUSED: disposable hosted Windows CI only'
}
$root=Join-Path $env:ProgramData 'OracleProxyLab'
$cfgdir=Join-Path $root 'config'
if (Test-Path -LiteralPath $root) { throw 'R81_REFUSED: field test root already exists' }
if (Get-Service -Name 'WireGuardTunnel$lab-field' -ErrorAction SilentlyContinue) {
    throw 'R81_REFUSED: native field service preexists'
}
$admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$system=[Security.Principal.SecurityIdentifier]::new('S-1-5-18')
function Protect-Owned([string]$path) {
    $item=Get-Item -LiteralPath $path -ErrorAction Stop
    $acl=if ($item.PSIsContainer) {
        [Security.AccessControl.DirectorySecurity]::new()
    } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetOwner($admin)
    $acl.SetAccessRuleProtection($true,$false)
    $inherit=if ($item.PSIsContainer) {
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit)
    } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @($admin,$system)) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid,[Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,[Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    }
    Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
}
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
Protect-Owned $root
$owned=Join-Path $root '.r81-owned'
'CI_R81_ONLY_DISPOSABLE_GITHUB_VM' |
    Set-Content -LiteralPath $owned -Encoding ascii -NoNewline
Protect-Owned $owned
New-Item -ItemType Directory -Path $cfgdir -ErrorAction Stop | Out-Null
Protect-Owned $cfgdir
$client=[byte[]](1..32)
$server=[byte[]](33..64)
$clientKey=[Convert]::ToBase64String($client)
$serverKey=[Convert]::ToBase64String($server)
$profile=Join-Path $cfgdir 'lab-field.conf'
$leasePath=Join-Path $cfgdir 'lab-field-lease.json'
$lf=[char]10
$config=(@(
    '[Interface]',"PrivateKey = $clientKey",'Address = 10.77.72.2/32',
    '','[Peer]',"PublicKey = $serverKey",
    'AllowedIPs = 10.77.72.1/32','Endpoint = 8.8.8.8:51828',
    'PersistentKeepalive = 25'
) -join $lf)+$lf
[IO.File]::WriteAllText($profile,$config,[Text.Encoding]::ASCII)
Protect-Owned $profile
$now=[DateTimeOffset]::UtcNow
$manifest=[ordered]@{
    schema_version=1
    mode='supervised_single_peer_no_default'
    client_inner_ipv4='10.77.72.2/32'
    server_inner_ipv4='10.77.72.1/32'
    allowed_ips=@('10.77.72.1/32')
    server_endpoint_ipv4='8.8.8.8'
    server_udp_port=51828
    server_public_key=$serverKey
    config_sha256=(Get-FileHash -LiteralPath $profile -Algorithm SHA256).Hash
    issued_utc=$now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    expires_utc=$now.AddMinutes(8).ToString('yyyy-MM-ddTHH:mm:ssZ')
    separate_operator_approval_required=$true
    operator_confirmation_recorded=$true
}
[IO.File]::WriteAllText($leasePath,($manifest|ConvertTo-Json -Compress -Depth 4),
    [Text.Encoding]::ASCII)
Protect-Owned $leasePath
[Array]::Clear($client,0,$client.Length)
[Array]::Clear($server,0,$server.Length)
foreach ($file in @($profile,$leasePath,$owned)) {
    $acl=Get-Acl -LiteralPath $file -ErrorAction Stop
    $aces=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    if (!$acl.AreAccessRulesProtected -or $aces.Count -lt 2 -or
        @($aces|Where-Object {
            $_.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -or
            $_.AccessControlType -ne 'Allow'
        }).Count -ne 0) { throw 'R81_FAIL: insecure lease or config DACL' }
}
Write-Host 'R81_PROTECTED_SYNTHETIC_FIELD_LEASE_STAGED_READONLY_PASS'
