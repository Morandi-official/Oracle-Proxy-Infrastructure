# R8 — actual WFP-backed Windows socket denial / recovery on hosted CI

This builds on R7 policy rule-lifecycle tests. On a disposable GitHub-hosted
Windows runner, it opens a *new* direct TCP/443 connection from the test
PowerShell process to a public, fixed numeric IP endpoint. Once baseline
connectivity is proved, the test adds one outbound Windows Firewall (WFP
backed) block, explicitly scoped to the exact running executable, remote
IP and TCP destination port. It verifies a *new* connection fails, removes
the filter, and verifies TCP recovers.

IPv4 endpoint: 1.1.1.1 (Cloudflare). The second attempt uses Cloudflare
IPv6 2606:4700:4700::1111, but only reports IPv6 packet-block PASS when
the hosted runner independently establishes an IPv6 baseline. If there is
no outbound IPv6, it explicitly emits BASELINE_UNAVAILABLE, never success.

The probe sends no HTTP, DNS or application payload; only establishes TCP.
No user account, private VPN key or production server endpoint is used.
Neither WireSock nor Oracle/UU are installed or modified. Synthetic rules
are removed in an unconditional finally block; final CI checks ensure no
test rule remains.

**Limitations:** this proves a *precisely scoped, temporary, outbound TCP
block in a hosted Windows VM*; not a persistent VPN network lock, not
whole-device IPv4/IPv6/DNS fail-close, not UDP, not cold-boot protection,
not leak-proof UU bypass and not independent real-host WireGuard transfer.
No version should claim "kill switch passed" on the basis of this test.
