# Product delivery evidence — 2026-10-21

Scope: Windows 10/11 x64 independent client and the administrator-only Oracle
web console. This is an unsigned acceptance candidate, not completed GA.

## Delivered acceptance build

- Main source: `3f2f4de2803a7de4313f09104a728910690119c9`.
- Actual Oracle/Windows workflow: https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39583383887
- Portable client artifact (about 78 MiB): https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39583383887/artifacts/12338617059
- Corresponding source artifact: https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39583383887/artifacts/12339296939
- Artifacts expire 2026-11-04. Both contain the same build metadata and ZIP hash
  manifest. The client retains all required packaged notices; the source ZIP
  includes actual vendored Go dependencies and generated payload hash pins.

The client uses its own WinForms UI and an owner-authenticated SYSTEM service,
with source-built sing-box WireGuard/TUN and the official signed Wintun 0.14.1
bytes. No WireSock, official WireGuard GUI, FlClash or daily SSH is required.
First installation, upgrade, uninstall and emergency recovery require UAC.
Ordinary login/connect/disconnect use fixed authenticated pipe operations.

Cloud evidence includes real owner/nonowner IPC, SYSTEM DPAPI and protected
bundle extraction, actual WireGuard TCP/fresh UDP DNS, physical traffic blocking,
peer/core loss, stale TUN permit rejection, missing encrypted state, emergency
recovery, failed-upgrade rollback and uninstall. Dedicated-account Oracle
acceptance additionally passed automatic enrollment, actual Oracle public exit,
GUI loss, service crash protection and SCM recovery, preserved device identity,
server usage linkage and restoration of direct access after explicit OFF.

The owner corrected an initial positive report: the local client is actually
disconnected because UU trust verification found zero acceptable programs.
A screenshot confirms UU_TRUST_NOT_VERIFIED; the underlying cause (certificate
cache versus file/directory trust) is under diagnosis. Windows reports a valid
signature for the actual installed version 4.40.1.2090; refreshing still rejects
it. The rc2 change adds bounded path/reason/status diagnostics without changing
the trust policy, and adds static official-installer inspection for that version. Live UU compatibility,
core/service-failure tests and physical restart are pending. No local pass is claimed.

## Oracle administrator console

https://vpn-admin.morandi.dpdns.org/

Only the configured GitHub owner with recent OAuth and MFA manages the console.
There is no public user signup. A unified form creates/edits/deletes ordinary
client credentials, quota, expiry, enabled state and device cap (default three).
Deletion revokes access before removing credentials; accounting/audit are retained.
Client devices enroll with locally generated public keys; private keys and bearer
credentials are SYSTEM-encrypted. Per-user quota/expiry/revocation are enforced by
server kernel leases, including existing TCP flows and controller failure cases.

Owner-configured read-only instance-principal IAM is now verified. Both Monitoring
and Usage API return data. The latest reviewed Monitoring observation was
2,123,639,166 VNIC outbound bytes (219 hourly points). Billing query now uses
completed UTC days; SKU units and historical coverage are under review.
No official real-time remaining allowance is claimed from incomplete observations.

## Remaining delivery requirements

- Live UU continuity through core/service failure, reconnect and physical reboot.
- Actual reboot/pre-login protection evidence; same-boot filter counts are insufficient.
- Oracle IPv6 VCN/VNIC/routing and guest forwarding, address allocation and
  dual-stack acceptance. Current client policy deliberately blocks IPv6.
- Reviewed automatic monthly allowance baseline, live counter linkage and global
  cap enforcement without presenting delayed billing as a live balance.
- Reviewed update distribution/publisher signing and durable release downloads.
- Restricted server configuration/port changes with rollback; current web
  capabilities still advertise configuration=false.

Future deployment authorization was explicitly granted by the owner. Continue
within that scope; do not ask for SSH/API private keys in chat or expose a
command execution interface in the web console.
