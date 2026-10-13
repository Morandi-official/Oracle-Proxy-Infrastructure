# Offline protection policy simulator (W1 prototype)

**THIS IS NOT A KILL SWITCH.** This module only models decisions given artificial
inputs. It does not read the operating system, install a driver, observe real packets,
contact the Oracle VM, or change routes, firewall rules, DNS, WireSock, or UU.

The test harness runs on GitHub-hosted Windows using both **Windows PowerShell 5.1**
and **PowerShell 7**. No administrator privileges or Oracle credentials are needed.

## Policy states under test

| Explicit user intent | Tunnel observation | Verified UU application | Ordinary application | Verified VPN transport |
| --- | --- | --- | --- | --- |
| Enabled | Connected, fresh handshake **and** verified route | Physical direct allowed | Tunnel only | Physical UDP/IPv4 to verified endpoint only |
| Enabled | Connecting | Physical direct allowed | Denied | Physical UDP/IPv4 to verified endpoint only |
| Enabled | Handshake failed / stale | Physical direct allowed | Denied | Physical UDP/IPv4 to verified endpoint only |
| Enabled | Disconnected / service crashed | Physical direct allowed | Denied | Physical UDP/IPv4 to verified endpoint only |
| Disabled **by explicit user action** | Any | Normal direct networking | Normal direct networking | No VPN transport required |

The tests cover IPv4, IPv6, TCP, UDP and DNS; both physical and tunnel paths;
a forged/unverified UU identity; an unverified VPN endpoint; and cases where
an app UI claims Connected but handshake or route verification is missing.

Run offline from repository root on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\clients\windows\simulation\tests\ProtectionPolicy.Tests.ps1
```

## Design notes before any real enforcement

- `VpnIntent=Enabled` must be a separately persisted user choice. An application
  crash, adapter loss, failed handshake or UI Disconnect event must **not**
  silently turn the intent Off.
- `IdentityVerified`, `EndpointVerified`, `HandshakeFresh`, and
  `TunnelRouteVerified` are **mocked trusted inputs** in these tests. The
  simulator does not prove them. A real Windows service must attest executable
  identities and tightly restrict the configured Oracle UDP endpoint; trusting
  a process's self-declared name would be unsafe.
- A real implementation must enforce decisions early enough at WFP/driver
  layers for both families, DNS and background services, without blocking UU.
  WFP interoperability with WireSock.sys is unknown. A simulated permission
  does not imply actual packet delivery or real-world leak prevention.
- A native service crash must not leave unrestricted physical access when
  VPN intent remains Enabled. The eventual design needs a persistent policy,
  boot-time fail-closed behavior, independent local rollback, and on-site
  recovery before any risky deployment.
- No hardcoded private keys, MAC addresses, client IPs, peer endpoints, or
  identifiers appear in the test fixtures.
- This is purposefully independent from the read-only diagnostic collector and
  the existing production WireSock profile. **Do not use this simulation as
  proof that the existing Windows computer is protected.**
