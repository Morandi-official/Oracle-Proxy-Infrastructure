# Oracle Proxy Windows native preview (W2)

**This is a real Windows desktop executable but is NOT a working VPN client.**
It displays sanitized local WireSock/UU diagnostics and runs a pure offline
fail-close policy demonstration. It cannot start WireGuard, modify firewall
rules, or enforce leak protection.

The preview is intentionally independent of the live Oracle VM and WireSock
UDP 443 session. It does not need administrator privileges or any keys.

## Build from Windows

Requires .NET 8 SDK.

```powershell
dotnet publish .\clients\windows\app\OracleProxy.Windows.Preview.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o .\dist\windows-win-x64
```

Offline smoke checks:

```powershell
& ".\dist\windows-win-x64\OracleProxy.Windows.Preview.exe" --self-test
$LASTEXITCODE
& ".\dist\windows-win-x64\OracleProxy.Windows.Preview.exe" --diagnostics-self-test
$LASTEXITCODE
```

Each returns exit code 0 on success. `--diagnostics-self-test` reads local
sanitized Windows state and requires the adjacent `diagnostics` files.

## Downloading the GitHub build

The `Windows native preview build` GitHub Actions run uploads
`oracle-proxy-windows-preview-win-x64`. Download and extract the **entire ZIP**
to a noncritical Windows 10/11 x64 test computer. Keep its `diagnostics`
folder beside the executable. Run `OracleProxy.Windows.Preview.exe` normally
without administrator elevation.

Preview artifacts are **unsigned**. Do not disable security software or
bypass alerts to run them. Do not deploy to the UU-dependent remote Windows PC.

## Limitations / acceptance

The GUI displays:
- Whether a local physical network adapter/default route is detected;
- Whether a known WireSock/WireGuard service or driver is running;
- Whether the UU GameViewerServer.exe process is present;
- A clearly labeled **simulation** of allowing verified UU direct egress
  while denying other physical egress if the VPN unexpectedly disconnects.

A process/service name cannot prove executable identity or VPN connectivity.
The UI always labels real VPN connection and real network-lock state unknown.

Successful GitHub CI validates packaging, pure .NET policy checks and the
local sanitized collector on a Windows hosted runner. It does **not** prove
graphics usability on Windows 11 or actual UU continuity. Those require
controlled manual testing and an independent rollback before riskier stages.
