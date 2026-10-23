"""R95: non-executing single-disk recovery readiness checklist.

All fields are operator statements, not Windows attestations. No disk, boot,
BitLocker, service, VPN, WFP, UU, OCI or networking APIs are called.
Even a fully checked checklist NEVER licenses native/WFP or reboot tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class RecoveryStage(Enum):
    READ_ONLY_INSPECTION_ONLY = auto()
    INDEPENDENT_BACKUP_MISSING = auto()
    BITLOCKER_KEY_CUSTODY_UNVERIFIED = auto()
    BOOTABLE_RECOVERY_NOT_DEMONSTRATED = auto()
    COMPLETE_RESTORE_NOT_INDEPENDENTLY_TESTED = auto()
    EXTERNAL_SECURITY_REVIEW_REQUIRED = auto()


@dataclass(frozen=True)
class SingleDiskRecoveryFacts:
    physical_disk_count: int
    system_volume_bytes_free: int
    winre_enabled: bool
    bitlocker_protection_enabled: bool | None
    recovery_key_retrievable_off_device: bool
    separate_external_backup_medium: bool
    verified_full_disk_image_outside_system_disk: bool
    bootable_recovery_usb_tested_on_machine: bool
    offline_console_keyboard_display_available: bool
    image_restore_verified_on_spare_media: bool

    def checklist_stage(self) -> RecoveryStage:
        if (type(self.physical_disk_count) is not int or
                self.physical_disk_count != 1 or
                type(self.system_volume_bytes_free) is not int or
                self.system_volume_bytes_free < 0):
            return RecoveryStage.READ_ONLY_INSPECTION_ONLY
        if (not self.separate_external_backup_medium or
                not self.verified_full_disk_image_outside_system_disk):
            return RecoveryStage.INDEPENDENT_BACKUP_MISSING
        if (self.bitlocker_protection_enabled is None or
                self.bitlocker_protection_enabled and
                not self.recovery_key_retrievable_off_device):
            return RecoveryStage.BITLOCKER_KEY_CUSTODY_UNVERIFIED
        if (not self.winre_enabled or
                not self.bootable_recovery_usb_tested_on_machine or
                not self.offline_console_keyboard_display_available):
            return RecoveryStage.BOOTABLE_RECOVERY_NOT_DEMONSTRATED
        if not self.image_restore_verified_on_spare_media:
            return RecoveryStage.COMPLETE_RESTORE_NOT_INDEPENDENTLY_TESTED
        return RecoveryStage.EXTERNAL_SECURITY_REVIEW_REQUIRED

    # All booleans above are intentionally NOT a cryptographic root of trust.
    # Neither local single-disk partitioning, a USB recovery drive, a clean
    # status-only CLI, nor a JSON with all True proves full WFP rollback.
    @property
    def authorizes_driver_or_wfp_test(self) -> bool:
        return False

    @property
    def authorizes_real_reboot_experiment(self) -> bool:
        return False

    @property
    def authorizes_execution_policy_override(self) -> bool:
        return False

    @property
    def authorizes_native_tunnel_activation(self) -> bool:
        return False

    @property
    def authorizes_uu_or_wiresock_change(self) -> bool:
        return False


def unverified_single_disk_baseline(free_bytes: int = 0) -> SingleDiskRecoveryFacts:
    """Only a hypothesis for documentation until actual read-only inspection."""
    return SingleDiskRecoveryFacts(
        physical_disk_count=1,
        system_volume_bytes_free=free_bytes,
        winre_enabled=False,
        bitlocker_protection_enabled=None,
        recovery_key_retrievable_off_device=False,
        separate_external_backup_medium=False,
        verified_full_disk_image_outside_system_disk=False,
        bootable_recovery_usb_tested_on_machine=False,
        offline_console_keyboard_display_available=False,
        image_restore_verified_on_spare_media=False,
    )
