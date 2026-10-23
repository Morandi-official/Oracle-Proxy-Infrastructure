# R100 — no-uplink Linux QEMU guest NIC and independent observer preflight

The user explicitly approved real, isolated WireGuardNT/WFP experiments **only on free cloud Windows VMs**; this step first validates the future NIC's Linux host isolation. R99 Windows kernel-boot proof is a separate hard gate. R100 alone does **not** boot a Windows guest, install any driver, change guest WFP, send outside packets, open host routing/NAT, enable DNS, or create a public test peer.

The disposable public GitHub Actions standard Ubuntu runner creates a **unique, allowlisted network namespace** containing only loopback and a TAP device (`tap0`) assigned `198.18.100.1/30`, from the RFC 2544/benchmarking IPv4 range. It installs no default IPv4/IPv6 route, no veth uplink, bridge to host NIC, NAT, DNS forwarder, RDP port, or QEMU WAN. Attempts to find external IPv4/IPv6 routes must fail. This makes external packet egress structurally unavailable by design, before any Windows network mutation.

An independent Linux host-side observer (`tcpdump`) captures an internal ARP request on that synthetic TAP. The tiny PCAP file is removed locally and **never uploaded**. The script then deletes only its exact unique Linux namespace, TAP and capture. A failed route test, missing observer packet, foreign interface or cleanup residual marks CI failure.

This establishes Linux host network isolation and local packet observer mechanics only. It is **not** evidence of Microsoft Windows WFP coverage, fail-closed boot filters, real UU traffic, WireGuardNT cryptography, or Windows driver function. To perform the future Windows experiment, the actual Windows VM would need to be placed in the previously verified namespace, and the outside observer would have to witness IPv4/IPv6/DNS egress and native safe stop with recoverable snapshot. R83 production native activation remains blocked and GA Issue #34 remains OPEN. No Oracle `wg0`/NSG or user machine settings are changed.

Only standard free GitHub-hosted Runner in the existing public repository, no paid/larger runner, no stored artifact, no external cloud or hardware changes.
