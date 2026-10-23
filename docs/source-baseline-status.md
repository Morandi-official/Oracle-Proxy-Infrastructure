# Source baseline evidence — NOT a functional end-user VPN

Checked against integrated GitHub source commit a982e66dcef718820851f21384130ee222f44e19
(the last G13/G14/G17/R4–R9 fully successful cloud regression before
moving source into the default branch).

| Gate | Evidence | What it does NOT prove |
| --- | --- | --- |
| G13 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413521728 | Two public Internet hosts, Windows leak protection |
| G14 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413520915 | Production DNS resolver or actual public-network route |
| G17 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413521603 | End-to-end Internet IPv6 or IPv6 fail-close |
| R4 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413521061 | Real WFP state, persistently verified OFF/ON |
| R5 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413521835 | Full tunnel installation or robust rollback on user PC |
| R6 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413522122 | Kill-switch crash recovery or all-app leak prevention |
| R7 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413521473 | Packet denial proof |
| R8 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413520607 | UDP/DNS/full-device leak protection or externally verified IPv6 |
| R9 | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413520513 | Oracle SSH access or isolated sidecar deployed |
| Release fail-closed gate | https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/38413520728 | Evidence of product acceptance or approval to tag GA |

The GUI is a **read-only Windows preview**. Native CI lab VPN control
must not be enabled in a distributable build.

## Work remaining before any functional Alpha installation on user PC

- A new secure production GUI-to-SYSTEM control adapter for named, pinned
  service profiles; current existing Lab control must remain CI-only.
- Verified trust chain for bundled native WireGuard modules, safe protected
  installed paths and key lifecycle.
- OS-enforced packet policy, correct boot ordering, explicit controlled OFF
  semantics and fail-closed on crash/handshake stale, independently tested.
- Actual rollback with independent console even with no network interface.
- Independent cross-host and UU remote-control checks with physical capture.
- Signed installer, per-file signature verification and support/runbook.

## Narrow cloud test versus user acceptance

Windows CI runners have true OS service and packet-filter APIs but share
one host for test peers. Linux G13 peers use isolated network namespaces
on a single temporary VM. None replace a genuine client-to-separate-public-
server run or a noncritical recoverable Windows test machine.

The user uses two computers: the first for cloud management, the second
runs WireSock and UU. Existing Oracle Linux SSH over port 22 previously
timed out; serial console opened only a password-based Ubuntu login. R9
probes are **not** proof of host access. Do not make any remote Oracle
network/firewall changes until an independently usable management path
and rollback are confirmed.

**Release blocker stays enforced.** This document lists historical CI runs,
not a signed validation report.

## 2026-10-17 addendum — R68 official Windows client / external host

An operator-confirmed **manual** experiment now demonstrates an independent
public-network WireGuard data path from the **official Windows WireGuard
client** to a separate pre-existing Linux server. A single tunnel-only
inner address was pinged three times with three replies (0% lost, 288 ms
mean). An isolated Linux test interface and its owned firewall rules were
observed absent afterward, the test-only cloud NSG VNIC association was
undone, and normal Windows networking and UU were reported working.

This is **not** a success claim for the repository's native WireGuardNT
client or signed release, and no independent external IPv6/WFP leak proof,
all-device route, long-lived UU failure continuity, post-ping handshake
counter capture, or production test-server guarantee was obtained. The
older CI references above remain same-runner lab evidence. A transient
cleanup timer and serial rescue account were used; removal of all auxiliary
resources requires separate confirmation.

Details and remaining checks: [R68 narrow manual evidence](r68-public-path-official-wireguard-manual-evidence.md).
GA blocker #34 remains OPEN.
