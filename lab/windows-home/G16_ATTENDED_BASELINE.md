# G16 — Windows 11 Home attended read-only acceptance

This provides a zero-network-change baseline to run while the operator is
physically present at the UU/WireSock computer. No local VM, elevated account,
Windows driver, VPN switch, firewall change or Oracle server change required.

Open ordinary PowerShell. Review the script source, download its raw file,
and run from its local directory using the command:

    powershell -NoProfile -File .\Read-OnlyVpnAcceptance.ps1

Do not pipe remote scripts into PowerShell. The collector emits one sanitized
JSON object containing OS build, service statuses and **counts only**; no
IP addresses, user account, host ID, adapter names, DNS addresses, secrets
or WireGuard endpoints. It does not contact Internet hosts.

A successful report proves ONLY the read-only collection functions operate.
Neither an on-site operator nor BFE running means WFP kill-switch recovery
is proved. Active packet blocking, VPN switch operations, UU remote-loss
experiments and WireSock replacement remain forbidden on this critical PC
until reviewed independent recovery and remote-host packet evidence exist.

The special SelfTest mode uses fake data. Passing CI cannot certify the
user's actual machine.