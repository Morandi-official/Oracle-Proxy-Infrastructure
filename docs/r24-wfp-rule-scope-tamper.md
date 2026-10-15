# R24: fail-closed on silently narrowed WFP guard scope

Previous R21/R22 disposable SYSTEM-owned guard tests inspected whether a WFP
rule existed and whether its process, protocol, action, direction and enabled
state matched. This could be a **false positive**: someone with elevated
privileges might narrow its remote addresses or Windows firewall profiles,
leaving a rule with the same name but not blocking real external traffic.

R24 pins explicit ANY local/remote addresses and ALL profiles when the
LocalSystem manager installs its program-scoped policy. Its live COM
verification requires these fields to remain identical. In a disposable
Windows GitHub runner, CI then starts actual WireGuardNT SCM test peers
through GUI administrator-authenticated IPC, verifies real handshake and
synthetic IPv4/IPv6 app/DNS delivery under real OS WFP restrictions, and
**mutates only that exact CI-owned WFP rule's RemoteAddresses field** to a
documentation-only address. The manager's independent WFP verifier must
detect the narrowed rule, stop both test peer services and refuse a new GUI
start. Restoring the original rule is NOT allowed to silently clear the
latched unsafe state; another start must still be refused. The CI test
then removes only its own restored filter, proves external TCP and UDP DNS
recover and checks no altered WFP rule/SCM service/route remains.

Scope limitations: Windows Firewall COM guard continues to cover ONLY
the known CI PowerShell binary, not all traffic. Periodic verification is
not packet-atomic, does not prevent administrative modifications, and
does not prove physical IPv6/DNS/UU-safe whole-device enforcement. Never
activate a production tunnel or ship the synthetic system guard to users.
No production Oracle, WireSock, UU or Windows machine is modified.

Tracked release blocker: #34.

Validation requirement: R24's **own** Windows G11 CI run must complete
successfully. A cancelled run is not acceptance evidence, even if a stacked
branch passed. Keep this PR unmerged until that direct run confirms the
rule-scope tamper response and exact cleanup.
