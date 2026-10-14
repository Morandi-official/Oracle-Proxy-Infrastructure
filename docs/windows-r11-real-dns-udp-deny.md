# R11 — external DNS UDP packet suppression on disposable Windows only

This cloud-only experiment sends fresh raw DNS A queries for example.com
to public IPv4 and, if externally reachable, IPv6 UDP/53 resolver IPs.
Two baseline DNS answers must be received. Then a Windows Firewall rule
filters only the CI PowerShell program, one destination IP and UDP port 53.
Two new queries must fail to receive responses. The exact rule is deleted
and two new queries must again succeed.

The script checks Windows BFE/MpsSvc, the effective rule's program/IP/port,
all owned-rule cleanup, total rule count and firewall profile states. It
refuses execution unless administrator on an ephemeral GitHub-hosted
Windows runner. The exact script must NOT run on an end-user or Oracle host.

If external IPv4 UDP/53 cannot be proven, R11 fails without pretending
packet denial. If IPv6 external baseline is unavailable, output states
that no real external IPv6 packet-denial proof exists.

This does NOT prove device-wide Windows DNS coverage, DoH, DoT, split DNS,
tunnel crash/reboot fail-close, WireSock or UU coexistence, or overall
IPv6 leak protection. No production user device or Oracle is changed.
