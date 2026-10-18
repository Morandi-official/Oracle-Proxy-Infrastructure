# Isolated Windows lab — recovery and leak-test acceptance (G10 gate)

**Not a WFP driver, filter, firewall or automated leak test.** This package
defines what external evidence must exist **before** touching real WFP or UU
split-tunnel settings. It cannot attest an OS test from Boolean flags.

## Restore first, then consider WFP

A different, noncritical Windows VM must have a hypervisor snapshot and a
console that works when every interface, DNS service and guest network packet
is completely blocked. The operator must **demonstrate a revert** without
the guest OS network. Automated rollback should be implemented as a separate
failsafe whose persistence/boot order has been independently verified.
`Stop-Service` is not an adequate recovery for persistent WFP filters.

No automatic firewall/driver installation or production machine commands
are included here.

## Independent capture acceptance matrix

The evidence collector must observe packets **outside** the guest
(preferably hypervisor virtual-switch capture plus server-side WireGuard
counters), not simply report the client's UI state.

| Condition | Expected packet evidence |
| --- | --- |
| User intent ON; real tunnel fresh and route verified | Other apps use tunnel only, no plaintext physical egress |
| Intent ON; handshake stale/failed/disconnected | All ordinary IPv4 TCP/UDP, IPv6 TCP/UDP, and DNS blocked from physical route |
| Intent ON; tunnel service crash/restart | Ordinary direct remains blocked before and after service restart |
| Intent ON; guest cold boot, before sign-in | No transient direct traffic for ordinary processes |
| Intent ON; verified UU client P2P | UU UDP path direct and interactive remote session continues after VPN failure |
| Intent ON; unknown process impersonates UU | Physical exception denied |
| User explicitly OFF (authorized) | Ordinary networking returns direct; no stale tunnel route |
| IPv6 enabled, no IPv6 VPN peer | Physical IPv6 still denied for ordinary apps when ON |
| External hypervisor rollback | VM recoverable with guest network fully unavailable |

The test must capture actual traffic by family and protocol and distinguish
DNS delivered through physical adapters, including UDP/TCP port 53 and
encrypted DNS configurations. TCP/UDP/IPv6 packet evidence cannot be
replaced by `curl` timeouts or a process-name check.

## Checklist parser

`assess_readiness.py` rejects incomplete synthetic readiness evidence.
Its example `unverified-example.json` intentionally contains only false
values. CI expects **BLOCKED_UNVERIFIED**.

Even when an operator supplies all `true` fields, this program emits only
`DOCUMENT_CHECKLIST_COMPLETE_NOT_SECURITY_ATTESTED`. It does **not**
validate signed capture files, prove a real WFP rule is installed, test UU,
verify a network route or authorize real deployment.

## Absolutely prohibited on the UU-dependent Windows PC

No new WFP filters, Firewall reset/import, WireSock Network Lock toggles,
service/driver start-stop, IPv6 route manipulation, reboot, VPN disconnect,
or disabling UU remote control before a separate explicit approval and
verified on-site recovery. Existing Oracle/UDP443 and UU remote connection
must stay unchanged.


## R95 single physical disk alternative: inventory only, not WFP eligibility

The second Windows PC has one present system disk (~799 GB free), with UU remote control and no VM software. See `docs/r95-single-disk-baremetal-recovery-readonly-preflight.md` for optional **interactive read-only** Windows/WinRE/BitLocker/disk checks and a minimum-cost external backup/recovery plan. Free space, a separate partition or dual boot on the same disk cannot count as an independent backup. A USB recovery drive is not a backup of personal files or the current OS configuration; any future creation erases the selected USB.

This does **not change the G10 requirement for a separately controlled recovery console and externally validated restoration** before real persistent WFP/driver tests. Avoid testing fail-close on a UU-dependent single-disk daily installation. Any additional native field activity remains blocked by R83/GA issue #34; PowerShell execution-policy refusal is a required STOP condition, not a reason to bypass Windows security.
