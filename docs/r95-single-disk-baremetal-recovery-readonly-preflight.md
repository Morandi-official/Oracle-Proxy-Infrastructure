# R95 — One-disk Windows PC: read-only preflight and independent bare-metal recovery

**Target constraints (operator-reported, not independently measured):** a second Windows PC used for UU remote control; one current physical system disk with approximately 799 GB *free*, no additional cloud provider or hypervisor, previous R86 PowerShell `PSSecurityException` before preflight execution, ordinary web and UU stayed normal afterward.

**THIS MILESTONE PERFORMS NO PHYSICAL WINDOWS ACTION.** This runbook contains only separate, interactive, read-only commands that the operator may choose to type locally. No .ps1 execution, policy bypass, Defender/SmartScreen override, disk partitioning, boot mode change, backup creation, WFP/SCM/driver mutation, route/DNS modification, restart or production Oracle action is authorized by R95.

## Stage 0: non-mutating local inventory (operator-assisted)

At a physically attended second PC, use an existing interactive Windows PowerShell console, *not* a downloaded script. Run commands separately:

```powershell
reagentc /info
manage-bde -status C:
Get-Disk | Select-Object Number,PartitionStyle,HealthStatus,OperationalStatus,Size
Get-Partition -DriveLetter C | Select-Object DiskNumber,PartitionNumber,Size
Get-Volume -DriveLetter C | Select-Object FileSystem,HealthStatus,SizeRemaining,Size
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version
Get-ExecutionPolicy -List
```

These are queries, not switches. Record only broad facts:

- `Windows RE status`: Enabled / Disabled / unknown. `reagentc /info` is documented as reporting the current recovery environment status. Do not run `/enable`, `/disable` or `/boottore`.
- `manage-bde -status C:`: BitLocker Device Encryption and Protection Status. **Do not print, copy into chat, or upload** any recovery password, recovery key, account token, serial number, GUID or protectors. Never run `-off`, `-protectors -get` or `-forcerecovery`.
- `Get-Disk`, `Get-Partition`, `Get-Volume`: count physical system disks, identify which disk contains C:, GPT/MBR, current volume size/remaining capacity and health. The operator's approximate **799 GB available is not total image size or backup capacity**. Do not launch DiskPart editing, Disk Management's resize/format actions, `diskpart clean`, shrink, repartition, change EFI/WinRE or create dual boot.
- `Get-CimInstance`: Windows version/build family, including end-of-support implications. `Get-ExecutionPolicy -List` only checks Windows PowerShell effective execution-policy scope. If blocked, **stop**; do not bypass group policies or re-run blocked R86 scripts.
- The operator may share redacted results only; never request BitLocker secrets or contents of personal files.

### What this proves

These outputs help choose a recovery strategy. They **do not prove** a recovery USB can boot, a backup image can be restored, the OS is configured for pre-login WFP fail-close, or that UU survives a VPN crash. A writable physical restore procedure is never implied by a read-only preflight.

## Cost-controlled offline backup & recovery plan (future operator steps, NOT executed now)

1. **Inventory what is actually used**, including WinRE/EFI/system and data partitions. Protect personal data separately. Do not allocate the entire 799 GB just because it is free. A new C:/D: partition or second Windows installation on the SAME physical drive shares the drive hardware and boot chain and is **not independent rollback**.
2. Before risky activity, acquire/reuse a **separate removable USB recovery stick** (Windows Recovery Drive may format/erase it), plus an **independent physical external disk or other truly separate storage** for a verifiable full-disk system image. Capacity depends on *all partitions and actual used data*, not free space. A recovery USB can assist bare-metal reinstall but **does not include personal files or a full clone of the current configured Windows**.
3. If system encryption is enabled, confirm off-device custody of the BitLocker recovery key **privately**, without pasting the key into CI, chat or logs. Keep the key separate from the encrypted host and ensure the chosen recovery process supports that encryption state. Do not turn encryption off to simplify testing.
4. Prefer a currently supported, independently verified signed full-disk imaging tool with a vendor-authenticated recovery environment. The old `Backup and Restore (Windows 7)` system-image solution is deprecated and not a strong unattended rollback assumption. A Windows System Restore Point or File History-only copy is **not** a bare-metal recovery image.
5. With physical keyboard, screen and reliable power, demonstrate the external recovery USB actually reaches the recovery environment and can **see the externally stored image**. **Exit without pressing Recover, Reset, Clean, Format, Delete, Restore or changing a boot configuration**. Record only whether boot/drive discovery succeeds. A full image restore must separately be verified on spare hardware/media; avoid destructive trial restoration to the only disk.
6. Only when an independent recovery method is externally validated and an owner is onsite should a separately approved disposable native/WFP experiment be considered. The one-disk UU-dependent current Windows install is still **not equivalent to a snapshot-recoverable VM with an independent control plane**. An on-device scheduled task or R89 manual AtStartup simulation alone is insufficient if persistent WFP locks out all network paths.

If independent media, verified backup and a safe restore target remain unavailable, **STOP BEFORE ANY REAL NATIVE DRIVER, persistent WFP, forced reboot or UU remote-session-impacting test**. Continue source code, isolated GitHub CI and policy-compliant non-network review only.

## R86 status and authorization boundary

The R86 seven-file SHA256 check passed, but Windows PowerShell prohibited `R86-Preflight.ps1` with `PSSecurityException`; the R86 mock SCM service and SYSTEM expiry were **not** launched. The operator confirmed normal web and UU afterward. Do not treat the previous limited no-network permission as authorization to use `ExecutionPolicy Bypass`, disable Windows security, install a fresh unsigned EXE, perform native WFP changes or restart the machine.

## Source-only status contract

`release/r95_single_disk_recovery.py` and negative CI tests explicitly record that same-disk free space, a second partition, an untested image, a Recovery Drive or even *all self-reported True* fields cannot authorize driver/WFP/reboot execution. Code deliberately exposes no ability to authorize actual physical testing.

R83 native field denial, production `UnavailableProductionKernel` and GA Issue #34 remain OPEN. Existing WireSock/UU, Oracle wg0, OCI NSG and Windows network configuration remain untouched.

### Official Windows documentation checked 2026-10-18

- Windows recovery and backup: https://support.microsoft.com/en-US/Windows/Experience/Backup-Recovery/backup-restore-and-recovery-in-windows
- Recovery Drive, including the warning that creating a USB recovery drive erases its prior contents and it contains no personal data: https://support.microsoft.com/zh-cn/windows/experience/backup-recovery/recovery-drive
- REAgentC `/info`: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11
- BitLocker `manage-bde -status`: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/manage-bde-status
- Legacy Windows 7 Backup and Restore deprecation: https://learn.microsoft.com/en-us/windows/compatibility/windows-7-backup-and-restore-deprecated
