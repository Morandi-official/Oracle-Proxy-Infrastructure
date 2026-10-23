"""R95 negative tests: never touch Windows/BitLocker/SCM/WFP/disk."""
from dataclasses import replace
import unittest

from r95_single_disk_recovery import (
    RecoveryStage,
    unverified_single_disk_baseline,
)


class SingleDiskRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.base = unverified_single_disk_baseline(799 * 1024**3)

    def deny(self, facts):
        self.assertFalse(facts.authorizes_driver_or_wfp_test)
        self.assertFalse(facts.authorizes_real_reboot_experiment)
        self.assertFalse(facts.authorizes_native_tunnel_activation)
        self.assertFalse(facts.authorizes_uu_or_wiresock_change)
        self.assertFalse(facts.authorizes_execution_policy_override)

    def test_799_gib_free_is_not_external_backup(self):
        self.deny(self.base)
        self.assertEqual(self.base.checklist_stage(),
                         RecoveryStage.INDEPENDENT_BACKUP_MISSING)

    def test_another_partition_on_same_disk_does_not_create_independent_copy(self):
        facts = replace(self.base, system_volume_bytes_free=2000 * 1024**3)
        self.deny(facts)
        self.assertEqual(facts.checklist_stage(),
                         RecoveryStage.INDEPENDENT_BACKUP_MISSING)

    def test_claimed_external_image_without_separate_media_not_enough(self):
        facts = replace(self.base, verified_full_disk_image_outside_system_disk=True)
        self.deny(facts)
        self.assertEqual(facts.checklist_stage(),
                         RecoveryStage.INDEPENDENT_BACKUP_MISSING)

    def test_bitlocker_key_not_to_be_shared_in_logs(self):
        facts = replace(self.base, separate_external_backup_medium=True,
                        verified_full_disk_image_outside_system_disk=True,
                        bitlocker_protection_enabled=True)
        self.deny(facts)
        self.assertEqual(facts.checklist_stage(),
                         RecoveryStage.BITLOCKER_KEY_CUSTODY_UNVERIFIED)

    def test_unverified_encryption_state_blocks(self):
        facts = replace(self.base, separate_external_backup_medium=True,
                        verified_full_disk_image_outside_system_disk=True)
        self.deny(facts)
        self.assertEqual(facts.checklist_stage(),
                         RecoveryStage.BITLOCKER_KEY_CUSTODY_UNVERIFIED)

    def test_recovery_usb_absent_blocks_even_with_image(self):
        facts = replace(self.base, separate_external_backup_medium=True,
                        verified_full_disk_image_outside_system_disk=True,
                        bitlocker_protection_enabled=False,
                        winre_enabled=True)
        self.deny(facts)
        self.assertEqual(facts.checklist_stage(),
                         RecoveryStage.BOOTABLE_RECOVERY_NOT_DEMONSTRATED)

    def test_local_console_missing_is_not_recoverable(self):
        facts = replace(self.base, separate_external_backup_medium=True,
                        verified_full_disk_image_outside_system_disk=True,
                        bitlocker_protection_enabled=False,
                        winre_enabled=True, bootable_recovery_usb_tested_on_machine=True,
                        offline_console_keyboard_display_available=False)
        self.deny(facts)
        self.assertEqual(facts.checklist_stage(),
                         RecoveryStage.BOOTABLE_RECOVERY_NOT_DEMONSTRATED)

    def test_not_restored_on_spare_disk_is_still_unproven(self):
        facts = replace(self.base, separate_external_backup_medium=True,
                        verified_full_disk_image_outside_system_disk=True,
                        bitlocker_protection_enabled=False,
                        winre_enabled=True, bootable_recovery_usb_tested_on_machine=True,
                        offline_console_keyboard_display_available=True)
        self.deny(facts)
        self.assertEqual(facts.checklist_stage(),
                         RecoveryStage.COMPLETE_RESTORE_NOT_INDEPENDENTLY_TESTED)

    def test_even_every_checkbox_true_cannot_start_native_or_wfp(self):
        facts = replace(self.base, separate_external_backup_medium=True,
                        verified_full_disk_image_outside_system_disk=True,
                        bitlocker_protection_enabled=True,
                        recovery_key_retrievable_off_device=True,
                        winre_enabled=True, bootable_recovery_usb_tested_on_machine=True,
                        offline_console_keyboard_display_available=True,
                        image_restore_verified_on_spare_media=True)
        self.deny(facts)
        self.assertEqual(facts.checklist_stage(),
                         RecoveryStage.EXTERNAL_SECURITY_REVIEW_REQUIRED)

    def test_unknown_or_multi_disk_hardware_requires_reassessment(self):
        for number in (0, 2, -1, True):
            facts = replace(self.base, physical_disk_count=number)
            self.deny(facts)
            self.assertEqual(facts.checklist_stage(),
                             RecoveryStage.READ_ONLY_INSPECTION_ONLY)

    def test_invalid_free_space_never_establishes_readiness(self):
        for free in (-1, 0.5, "799GB"):
            facts = replace(self.base, system_volume_bytes_free=free)
            self.deny(facts)
            self.assertEqual(facts.checklist_stage(),
                             RecoveryStage.READ_ONLY_INSPECTION_ONLY)


if __name__ == "__main__":
    unittest.main()
