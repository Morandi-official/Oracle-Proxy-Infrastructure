# R80 — exact native lab route scope enforced INSIDE real service before DLL load

Until R79, real host native DLL signature + owned-file hash/ACL protection were checked, and R69 independent Python pre-start profile auditing refused route widening. However a privileged actor able to replace **both** a lab config and its local SHA256 manifest could otherwise cause a native service to consume a widened `AllowedIPs` value. A mutable manifest alone is not a production authorization mechanism.

## Runtime guard

- Add `NativeLabInnerScopeGate.Require(files.Config, profile)` directly to the **actual `OfficialTunnelBridge.InvokeFromService`** after existing `EngineBundle.Verify`, NTFS ConfigAclGate and trusted signed WireGuardNT driver checks, but **before LoadLibraryEx loads upstream tunnel.dll**.
- Restrict only the TWO fixed G14 native lab profiles to one Interface / one Peer, exact localhost endpoints/ports, separate /32 and /128 inner v4/v6 routes, canonical nonzero 32-byte key fields, fixed keepalive, and absolutely no extra DNS, scripts, broadened route, default route or additional peer. Legacy `lab-only` ABI lab is explicitly left under its existing checks; no new external-public profile or service is enabled.
- CI adds an in-process negative grammar suite for each fixed peer. It also temporarily modifies **only the disposable owned** `lab-peer-a.conf` to default-route `AllowedIPs = 0.0.0.0/0, ::/0` AND re-pins the companion `engine-pins.json` SHA256 to that malicious profile. R79 integrity/driver/ACL review still accepts a jointly re-pinned bundle, proving hash checks alone do not enforce route policy, but the new exact pre-DLL runtime parser must reject the same profile. Both original file byte arrays are restored before any native service starts; no secret is printed or uploaded.
- Once original protected files are restored, rerun both positive native-host audits, then execute real GUI → authenticated admin IPC → SYSTEM manager → native SCM WireGuardNT localhost encrypted data, IPv6/UDP/synthetic DNS, active OS default-route/DNS checks, and always-run SCM, route, adapter, key and firewall restoration.

## Constraints and required future work

This is defense in depth **for synthetic dual-peer localhost G14 CI profiles only**. It neither accepts nor activates the R76 single-public-/32 candidate. It is not a full-device WFP leak filter, production key vault, robust signed installer, physical reboot/recovery proof, public Oracle handshake, or authenticated production connect/Off. The shipped `UnavailableProductionKernel` remains default and GA blocker #34 remains open. Real Windows service/driver staging and any Oracle UDP/NSG change still require **separate user authorization** after further safety review.
