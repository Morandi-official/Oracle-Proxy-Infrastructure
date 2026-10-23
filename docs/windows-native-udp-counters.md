# Native UDP receive isolation

rc11 MetaWise sent one initiation on each native port but exported no socket
response/invalid/obsolete/error event. Earlier paired Oracle header counters saw
fresh requests and replies on both ports. Do not infer ISP-wide blocking or a
Windows firewall cause from these observations alone.

`clients/windows/diagnostics/Measure-NativeUdp.ps1` runs in administrator
PowerShell. It uses Windows Packet Monitor with `--capture --counters-only`:
no packet contents are logged, no ETL/PCAP is requested, and no firewall, route,
adapter, UU permissions, keys or VPN configuration are changed.

The script refuses a running monitor, nonempty filters or unknown status text.
It supports the exact English and simplified Chinese idle output observed on
the hosted runner and MetaWise. After starting, click WireGuard UDP in rc11.
The bounded observation lasts40seconds by default (20–45 allowed). It displays
flow/drop counters, stops its monitoring and verifies cleanup.

The fixed target is152.67.156.100, default UDP51820. A separate invocation may
select `-Port443`; only51820/443 are accepted. Observe ports separately because
443 is also used by ordinary browser HTTP3 and an aggregate receive count would
not uniquely identify a WireGuard response.

Packet Monitor on the tested Windows version removes ALL filters, even when an
unsupported name argument follows `filter remove`. The collector therefore
requires a stopped monitor and a final list containing exclusively the names it
created before issuing the all-filter remove command. Foreign/unknown entries
cause a refusal that preserves the list. Never manually clear other filters.
Keep the PowerShell window open until completion; if externally interrupted,
query status/filters before any manual cleanup.

Positive NIC receive counters with zero application response narrow investigation
to local processing, but counters alone do not authenticate a WG packet. Zero
NIC receive means no matching return was observed at that intercept point; it
does not distinguish hotspot/NAT, upstream path or pre-intercept driver loss.
Match a fresh client attempt, and use the group/component/edge/drop rows to
avoid treating duplicated stack counts as distinct network packets.

The isolated Windows cloud fixture verifies real synthetic public DNS Tx/Rx,
refusal when another filter exists, cleanup when all remaining entries are owned,
the public collector's real bounded lifecycle, and absence of ETL files. Its
invalid one-packet WG-shaped probe is only a counter test, never proof of a VPN.

Microsoft references:
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-start
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-filter
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/pktmon-counters
