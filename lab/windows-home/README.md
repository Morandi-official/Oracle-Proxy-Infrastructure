# Windows 11 Home 24H2 — VM readiness gate (UU/WireSock remote PC)

Target reference supplied by user: **Windows 11 Home Chinese, version 24H2,
build 26100.8037**.

## What we can safely conclude

- Windows 11 Home does not include the usual full Hyper-V Manager role
  or Windows Sandbox entitlement. Do NOT use unofficial "force-enable
  Hyper-V on Home" scripts, which change system virtualization/network state.
- A supported third-party desktop hypervisor (e.g. Oracle VirtualBox 7.2
  or current VMware Workstation Pro) is a *candidate*, not yet approved.
- Installation of VMware/VirtualBox may install virtual network adapters,
  NDIS components and system drivers, which can temporarily affect UU remote
  control. **DO NOT install on the critical remote PC unattended.**
- Choose an isolated **NAT-only** guest with no bridged adapter, USB network
  passthrough, host physical route change, DNS redirect or WFP manipulation.
- Snapshot/revert capabilities do not replace a host recovery mechanism:
  a broken host network driver can strand UU even if the guest is snapshotted.
- A Windows 11 guest needs a lawful OS installation/license. A "free VM"
  hypervisor does not automatically include a free Windows guest license.

## Step zero: read-only hardware preflight

The checked-in PowerShell script `Read-OnlyVmReadiness.ps1` collects only
sanitized local information through Windows CIM:

- Windows edition/build (not Windows product key)
- RAM size, logical CPU count, firmware virtualization and SLAT signals
- Free system drive storage

It **does not query** computer name, username, IPs, MACs, serial numbers,
VPN profiles, credentials, UU processes, routes, DNS, services or firewall
policies. It does not change Windows settings. It needs **no admin elevation**.

You can also inspect the script source instead of running it.

A hypothetical 16 GiB RAM, 100 GiB free disk and 4 logical processors are
conservative **planning suggestions**, not requirements or proof of
compatibility. The script intentionally reports 'unknown' for uncertain
firmware virtualization support and sets all real security verification
fields false. Even a "preliminary_hardware_fit=true" is NOT permission to
install a virtual network driver or run a WFP fail-close test.

Manual built-in read-only alternative:
Task Manager -> Performance -> CPU -> "Virtualization: Enabled/Disabled".
The Memory section shows installed RAM. Use This PC to inspect free disk
space. These observations do not alter the UU connection.

## Controlled on-site install gate (NOT executed by this PR)

Before asking the user to install any hypervisor on the UU-dependent remote
host, require all of these to be true:

1. User remains physically **at the machine** with local screen/keyboard.
2. A known-good host recovery/rollback plan exists for the installer driver
   and network components, not just the guest snapshot.
3. Current UU remote and WireSock connection are preserved, and network
   configuration is backed up without changing filters or routes.
4. Installation is separately approved by the user and scheduled when losing
   UU control would not disrupt needed work.
5. If a VM is available, NAT-only, no host bridge and take a guest snapshot
   **before** running any native VPN/driver tests.
6. A hypervisor **outside guest networking** can revert the test guest if WFP
   blocks all IP traffic. The host itself must still be independently
   recoverable.

## What remains unavailable

No VM software was installed by this PR. No local Windows hardware report
was supplied beyond the WinVer screenshot. No independent Oracle cloud VM or
recoverable disposable Windows VM has been provisioned. No UU app-level
continuity, real IPv4/IPv6/DNS fail-close, or guest hypervisor rollback
has been tested.

## Official references

- Windows Sandbox supported editions, Microsoft Learn:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview
- VirtualBox Windows host support, Oracle:
  https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/Introduction.html
- VMware Workstation Pro availability/licensing:
  https://www.vmware.com/docs/desktop-hypervisor-faqs

*The current VPN service and network configuration on the UU remote
machine must remain unchanged.*
