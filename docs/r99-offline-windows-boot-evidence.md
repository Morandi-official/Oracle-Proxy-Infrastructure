# R99 — independent Windows NT boot witness, prior to actual isolated WireGuardNT / WFP

**Authorization:** The user approved free, isolated GitHub cloud Windows VM experiments (including genuine WireGuardNT/WFP after safety gates). R97 succeeded in disposable host-controlled QEMU guest hardware reset and qcow2 disk overlay rollback, but explicitly **did not prove** the Windows NT kernel had booted. R99 adds a distinct and stricter prerequisite. The Microsoft evaluation VM remains `-nic none`; R99 does **not** yet install a driver, enable a VPN, add WFP rules or touch Windows execution policies.

A preloaded Windows Server 2025 evaluation VHD does not include our trusted serial-response agent. Injecting privileged boot executables or silently bypassing Windows startup policies to answer a one-time host serial challenge would undermine the intended security proof. R99 instead reads native Microsoft Windows System event log records from the *powered-off guest disk*, using a separately controlled Linux host and a strictly read-only Linux loop/NTFS mount of an ephemeral RAW conversion. The original `guestfish` appliance failed even on an empty synthetic disk in GitHub CI, so it has not been accepted as evidence.

Microsoft officially identifies System event 12 from `Microsoft-Windows-Kernel-General` as Windows OS startup and event 6005 from `EventLog` as the start of its event log service: [Microsoft boot log troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs).

## Evidence standard

1. Confirm the public GitHub repository and standard hosted Ubuntu runner. Use Microsoft's official evaluation VHD, `QEMU/KVM`, an independent disposable QCOW2 overlay, no guest NIC and no public QMP/VNC port.
2. Before guest start, **read only** extract any baseline `Windows/System32/winevt/Logs/System.evtx`. If not present in the uninitialized evaluation image, do not fabricate it.
3. Timestamp the independent Linux host start/end interval, run isolated virtual hardware, externally reset guest once and shut it down.
4. With QEMU no longer running, **read only** extract `System.evtx` from the overlay, no Windows executable or guest agent required. `python-evtx==0.8.1` is pinned to the official SHA256 `46336b854dbe0a1e75873ae30db5f583c9d2262ff1d21bdb6b1e624ecfa18ddb`.
5. Require two corroborating, fresh records: Kernel-General event ID 12 followed by EventLog event ID 6005. Both require Windows provider identity, monotonic record IDs beyond any baseline, UTC timestamps within a short bounded host-observed interval and changed guest event log content. Stale, fake, partial, wrong-provider and unchanged log records fail closed.
6. Only after this proof may the isolated hypervisor reset-and-overlay-recreation path conclude. Every virtual disk and extracted guest log is deleted in ephemeral job cleanup. CI prints only verdict/counts, not guest log contents, addresses or secrets.

A fail or inability to mount an official VHD/overlay produces `R99_...DENY` or a failed job; there is **no fallback to QMP/framebuffer SHA hashes** as a substitute for genuine OS startup. Even a valid event pair is *not a guest-initiated reboot*. For later stage, Windows native WireGuardNT and WFP would need separate isolation, bounded keys, independent virtual NIC packet witness, stable driver signing, rollback and timeouts; none of those are claimed here.

The positive witness confirms actual kernel/eventlog activity during the cloud trial, but is not a cryptographic remote attestation of the trustworthiness of the entire guest OS. External platform and image identity remain crucial. R83 field native refusal, compiled production `UnavailableProductionKernel`, and GA Issue #34 remain unchanged. No physical computer, WireSock/UU environment, Oracle `wg0`/OCI NSG, DNS/routes or Windows execution policy is modified.

**Costs:** Only standard free GitHub Actions on this public repo, no paid/larger runner, no new provider, no artifact/cache/persistent Windows disk, no purchased Microsoft license or signature. QEMU nested virtualization is experimental and not an SLA.

## Revised host extraction path and verified prerequisite

R99 originally tried `libguestfs` OS autoinspection and explicit filesystem enumeration. Both failed; a separate tiny blank-disk libguestfs smoke on GitHub runner also failed with an appliance launch error. **This proves a host tooling limitation and says nothing by itself about Windows guest NT startup.** We do not weaken Windows or GitHub host security settings to coerce that appliance.

An independent standard GitHub-hosted Linux CI [run #39110124352](https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/actions/runs/39110124352) instead validated a synthesized NTFS partition can be mounted strictly RO through an exact-owned Linux loop device, then unmounted and detached with zero residual. R99 now uses `qemu-img convert -O raw -S 4k` to create *disposable sparse clones only after QEMU has stopped*. It attaches the clone to a read-only loop, tests at most 16 bounded NTFS partitions for `Windows/System32/winevt/Logs/System.evtx`, and copies the bounded file to temporary Linux host storage. All loop mounts are closed in `finally` or exact-owned shell trap cleanup. The real guest VHD and QCOW2 backing remain unchanged.

The native Windows event-corrobation gate remains unchanged: absent/old/unreadable events must fail R99. No WireGuardNT, WFP or virtual guest NIC may be activated before genuine Windows kernel evidence passes. The next real VHD attempt is an experiment, **not** a passing kernel boot, real guest reboot or production authorization until CI actually verifies it.
