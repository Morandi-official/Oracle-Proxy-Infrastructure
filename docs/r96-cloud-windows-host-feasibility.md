# R96 — GitHub Actions nested Windows VM feasibility, READ ONLY

## Why

The project has already tested genuine WireGuardNT data transfer, SYSTEM independent stop and exact cleanup on GitHub-hosted Windows CI (R89). **No real Windows reboot, pre-login WFP leak control, signed installer or UU field coexistence has been proven.** The user has no new cloud platform and does not want virtualization software on the second Windows PC. Before considering any cloud Windows guest, R96 performs a strictly no-mutation capability check **only** on disposable GitHub-hosted Linux CI.

## Candidate technology (outside this PR's execution)

- [QEMU](https://www.qemu.org/) with QEMU qcow2 disk overlays and snapshots is a realistic hypervisor route for an actual Microsoft Windows guest, not Wine or a fake desktop.
- [dockur/windows](https://github.com/dockur/windows) is an open-source Docker wrapper around a real Windows VM, but requires KVM support and **at least 32 GB free disk** (project README). Its default 2 cores/4 GB guest memory allocation does not prove any driver is loadable or WFP works. Review its image source/install code and trust before any use.
- ReactOS/Wine cannot replace native modern Windows kernel/WFP/WireGuardNT tests. ReactOS aims at older NT compatibility and explicitly warns it is alpha.
- GitHub's [standard public-repo runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) list 4 cores/16 GB RAM/**14 GB** available SSD for normal ubuntu-24.04, far below the documented dockur/windows installation prerequisite without changes. Its [nested virtualization](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners) is **experimental and unsupported**, not a guaranteed test interface.
- A Windows Server evaluation [ISO/VHD](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025) is a real Windows kernel (180-day evaluation subject to licensing rules), but no image/license is downloaded or represented as available in R96. Testing client WireSock/UU coexistence would still require genuine Windows client and live UU, not simply a Server VM.

## What CI inspects

The Ubuntu hosted runner reads only `/proc/cpuinfo`, `/proc/meminfo`, whether `/dev/kvm` exists and is accessible, workspace filesystem free bytes and logical CPU count. It logs safe, rounded resource facts and hard-blocking reason codes. The pure classifier has negative tests for missing KVM, denied KVM access, missing virtualization flags, less than 32 GiB free disk, low RAM/CPU, and an unauthenticated/foreign machine. **Even all resource gates positive is only `R96_CAPACITY_PREFLIGHT_ONLY_NO_GUEST_OR_SECURITY_APPROVAL`.**

CI does **not** download an ISO, invoke docker/qemu/libvirt, run a Windows VM, create snapshots, reboot Linux/Windows, test driver signing, create public network listeners, open firewall, disable AV/UAC, connect Oracle or install/modify WFP/routes/DNS. Output is only aggregate metadata; no secrets, process/user/network addresses or packet captures are uploaded.

## If capacity and KVM appear feasible

A future proposal—not authorized by this source-only preflight—would require separately vetted authentic Microsoft licensed images, storage headroom and build times, a QEMU host console/QMP and qcow2 overlay restored **from outside the Windows guest**, isolated networking by default, independent packet observer and a real power-cycle through the hypervisor. It should first prove VM boot/rollback with NO VPN/WFP, then only attempt native driver and WFP in that truly recoverable guest after a new narrowly scoped review/authorization. It would still not establish physical client UU/WireSock behavior or actual public cross-host transfer.

If the hosted runner lacks resources, fail closed and continue existing disposable Windows-only CI (R89) and offline evidence tools (R92–R94); do not repurpose production Oracle, create a paid cloud account or touch the user's second PC. GA Issue #34 remains OPEN, R83 native field activation denied, and production `UnavailableProductionKernel` is unchanged.
