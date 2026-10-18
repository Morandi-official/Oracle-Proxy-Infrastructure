# R94 — independently review captured underlay packets for direct IPv4/IPv6/DNS bypass

The current repository has no independently recoverable, noncritical Windows VM or signed WFP/driver product, and **no real pre-login capture was taken**. The GH G13 Linux namespace capture is genuine Linux WireGuard traffic but cannot establish Windows WFP behavior. R94 adds a bounded **offline, standard-library-only** PCAP parser for eventual externally captured test packets. It creates no sockets, interface filters, packet captures, drivers, VPN service, firewall rules or route changes.

## Inputs and narrow, falsifiable decisions

`release/r94_pcap_triage.py` accepts **classic Ethernet PCAP only** (v2.4; no PCAPNG, unsupported link layers or ambiguous IPv4 fragments), explicit local source IP inventory and one fixed WireGuard outer peer IP/UDP port. The packet bytes, source-inventory data and capture origin are UNTRUSTED; they require separate external signer/controller verification. Size, packet-count, header bounds and protocol parsing are limited to avoid silent truncation and unbounded allocation.

For the observed underlay source addresses, the analyzer counts precisely pinned outer UDP destination packets as **eligible shapes**, not validated encryption. Any other outgoing IP packet (direct DNS UDP/53, DoT/853, TCP/443, wrong peer on same port, IPv6 direct path, unrecognized IP protocols) is a **potential leak blocking finding**. It prints no packet payloads, IPs, private keys, third-party connection identities or user data. Test fixtures synthesize allowed underlay, wrong peer, direct IPv4 and IPv6 DNS, TCP, VLAN, zero-packet capture, truncated headers, fragments and missing interface inventory.

## What it cannot establish

- A clean PCAP might have been taken on the wrong adapter, with omitted traffic or before the relevant challenge was sent. Even **zero packets** is not proof of a functional WFP kill switch.
- An outer UDP packet to the pinned peer could be a forged or plaintext payload; the parser does **not** cryptographically verify WireGuard encryption.
- A TCP/UDP capture does not attribute traffic to UU executable identity, and cannot certify UU remote-control continuity or exemptions. A separate independent live UU observer is mandatory.
- PCAPNG, dynamic tunnels, IPv6 extension headers, non-Ethernet or ambiguous fragments are not silently treated as safe; convert captures in a trusted independent process only after review.
- This is not Windows boot/pre-login evidence; only a separately controlled VM and outside packet observer with witnessed challenge delivery can supply that.
- The analyzer always returns `proves_wfp_failclosed=False`, `proves_real_uu_continuity=False` and `authorizes_release=False`, including when no bypass is seen.

Actual R83 native field activation remains blocked; production `UnavailableProductionKernel` remains denial-only and GA Issue #34 stays OPEN. This CI-only review tooling never changes Oracle wg0/NSG, the user's Windows execution policy, WireSock/UU, any real Windows WFP/DNS/route settings, or a public host.

Once an independent recoverable test VM and externally witnessed capture exist, a separate security reviewer must establish both positive WFP enforcement and negative observed leakage using actual TCP/UDP/IPv4/IPv6/DNS traffic, not this parser alone.
