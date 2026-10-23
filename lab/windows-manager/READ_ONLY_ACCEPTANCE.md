# Windows read-only acceptance baseline (G15)

This is a **non-mutating** inspection. It requires neither administrator
privileges nor a VM and does not operate WireSock, Oracle, UU or firewall
policy. It is safe to run while those services remain active.

## On an attended Windows 11 computer

Open ordinary PowerShell and run:

```powershell
$os = Get-CimInstance Win32_OperatingSystem
$service = Get-Service -Name 'OracleProxyLabManager' -ErrorAction SilentlyContinue
[pscustomobject]@{
  OS = $os.Caption
  Build = $os.BuildNumber
  Architecture = $os.OSArchitecture
  ManagerInstalled = [bool]$service
  ManagerStatus = if ($service) { [string]$service.Status } else { 'NotInstalled' }
  IPv4DefaultRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue).Count
  IPv6DefaultRoutes = @(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue).Count
  ActiveAdapters = @(Get-NetAdapter | Where-Object Status -eq 'Up').Count
} | Format-List
```

Report counts/status only; never upload WireGuard private keys, IP
endpoints, serial numbers or detailed peer configs.

**No installation, no changes, no success claims about VPN connectivity.**

The current manager and Windows preview are not approved for installation
on the user's UU-dependent PC. G15 real crash/restart and secure rollback
remain unverified and are blocked until an independently recoverable test
host and reviewed control procedure exist.
