# R18: actual Windows WFP-backed multi-protocol guard and native WG peers

On ONE disposable Windows GitHub VM, the test first proves real external IPv4
TCP/443 and raw UDP/53 DNS replies (fresh random transaction IDs), then
applies a **persistent** Windows Firewall WFP-backed outbound block for the
CI PowerShell executable across *all* protocols, ports and destination IPs.
It checks the exact active policy filters, real TCP+DNS denial, then starts
two genuine signed WireGuardNT peers via authenticated GUI-to-SYSTEM SCM
control. With encrypted native app UDP and synthetic IPv4/IPv6 DNS flowing
through the two peers, an independent live probe verifies TCP and external
raw DNS are **still blocked** for the specified test process. The guard
remains active through explicit tunnel stop. Exact rule removal must restore
both external TCP and raw UDP DNS; always-clean checks compare Windows
Firewall count and profile state, routes and adapters.

External IPv6 TCP checks run only if the runner has an independently verified
repeatable IPv6 baseline; if unavailable, no IPv6 packet-denial claim is made.

**BOUNDARY:** the filter is intentionally restricted to one test executable
to keep GitHub runners online. It is not a whole-device WFP kill switch,
cannot arbitrate a UU process allowlist against explicit physical-interface
deny filters, and has not been tested across Windows reboot, network change
or manager crash. No production WFP control, routing, DNS or encrypted key
storage is enabled. Not a replacement for WireSock.

The full production kill switch will need a separately reviewed native WFP
engine with pinned per-process/per-interface exceptions and deny rules,
persistent nonbypassable boot policy, state transitions, physical UU capture
and independent offline rescue. See issue #34.
