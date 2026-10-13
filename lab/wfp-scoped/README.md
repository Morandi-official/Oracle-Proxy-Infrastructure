# R7 — real Windows Firewall rule lifecycle, *not* a kill switch

On a disposable cloud-hosted Windows CI machine, this test exercises the
actual Windows Defender Firewall cmdlets (which use Windows Filtering
Platform). It checks BFE and MpsSvc are running, then creates a pair of
temporary **outbound UDP block rules**, limited to the current CI PowerShell
executable, reserved documentation targets and unassigned high ports:

- 203.0.113.19 UDP/54991
- 2001:db8::19 UDP/54992

The test reads rules back from Windows *ActiveStore*, checks scope and
block action, then deletes the exact created rules and confirms original
rule count. It also tests that a non-GitHub-runner invocation is refused.

**This does NOT send any test packet** and does not establish packet
enforcement, fail-close, DNS protection, UU continuity, persistent
boot-time WFP policies or protection of a physical default route.
The synthetic policy would be unsafe to reuse as a VPN kill switch:
it matches two reserved hosts, not a physical-interface kill switch.

It never touches production Oracle, WireSock or the Windows user's PC.
The only environment allowed is an elevated disposable hosted CI VM.
A passed R7 is just the real OS-rule lifecycle precondition for later
isolated packet blocking and safe policy rollback tests.
