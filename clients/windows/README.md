# Windows client — read-only diagnostics prototype (W0)

This is the **first, non-invasive building block** for an independent Windows client.
It is separate from the existing Oracle WireGuard dataplane and the backend M0 pull request.

## Run on the second Windows PC

From a PowerShell prompt at the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\clients\windows\diagnostics\Collect-ReadOnly.ps1
```

This prints sanitized JSON to the console. Nothing is uploaded or sent across the network.
It does not require Oracle SSH access or any WireGuard private key.

## What it checks

- Whether known WireSock/WireGuard services and drivers are present and running.
- Whether a short, explicit allowlist of WireSock and UU processes is present.
- Whether active physical network adapters have IPv4/IPv6 default routes.

Only allowlisted component names, states, boolean indicators, counts and a UTC time are emitted.
The result excludes IP/MAC addresses, gateways, process IDs, command lines, file paths,
WireGuard peer addresses and cryptographic keys.

**Important limitations:** running services do not prove an active VPN handshake; a
physical default route does not itself imply an IP leak; this module does not verify
WireSock split tunneling or fail-closed behavior. Fields for VPN connectivity and
network lock deliberately remain `unknown`.

## Test

On Windows, from the repository root:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\clients\windows\diagnostics\tests\Diagnostics.Tests.ps1
```

GitHub Actions also runs the same tests on a Windows runner. They require no Oracle
server, WireSock installation, VPN session, network access or firewall changes.

## Security boundary

This prototype intentionally does **not**:
- start/stop WireSock or WireGuard, or alter the Oracle VM;
- manipulate Windows routes, network filters, firewall, DNS or registry;
- implement a kill switch or guarantee no IP leak.

The production goal remains: UU remote can connect directly, while all other
applications fail closed **only when the user has enabled VPN mode**. That needs
a separate design, rollback mechanism, and isolated tests before deployment.
Keep the existing working UDP 443 WireSock profile unchanged during development.
