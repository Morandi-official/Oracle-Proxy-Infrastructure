# R15 — real Windows WireGuard SCM + narrow WFP deny/restore in a single CI job

**Not a VPN product, whole-device kill switch, IPv6 leak proof, or user installer.**

The isolated Windows GitHub runner compiles the pinned official WireGuard
embeddable tunnel and a separate LocalSystem manager. The real GUI executable
uses the existing lab-only OS-token-authenticated admin pipe to start/stop two
strictly fixed, local synthetic WireGuard peers. The test proves genuine
handshake, UDP application delivery and synthetic IPv4/IPv6/DNS data plane.

R15 adds a genuine WFP-backed Windows Firewall filter to the same lifecycle.
It first verifies real fresh external IPv4 TCP/443 connectivity, applies a
*precisely scoped* persistent outbound deny for **only the disposable CI
PowerShell executable, selected public IP, TCP port 443**, and proves a new
socket fails. While the actual tunnel peers are connected and passing lab
traffic, it verifies the original exact filter is active and another public
TCP socket cannot escape. It then stops peers via the real GUI, verifies the
filter persisted throughout start/data/stop, removes only its own filter,
proves public TCP recovers and compares firewall state to the initial baseline.

All operations are restricted to a GitHub-hosted Windows VM, admin token and a
specific PR branch. Refusal before authorized CI is tested. Tunnel secrets are
ephemeral and scoped to protected temp directories; cleanup always attempts to
remove only created SCM services, synthetic adapters/routes/configs and
temporary firewall rules; default routes, DNS and firewall baseline
fingerprints are validated. Nothing talks to Oracle or the user's UU device.

**Boundary:** external TCP testing is conducted from PowerShell, not from all
apps or the tunneled WireGuard process. R15 proves *one narrow real Windows
WFP rule coexists with one genuine tunnel lifecycle*. It does not prevent
physical IPv4/IPv6 DNS/UDP leaks from other processes, does not survive or
test reboot/crash, does not authorize SafeControlGate production connect
requests, and cannot be used as a general kill switch.

Production implementation remains blocked on independently verified
persistent fail-closed OS policy across all families/protocols, signed and
ACL-protected binaries and keys, secure rollback, true cross-host Internet
testing, UU continuity and reproducible signed packaging. See issue #34.
