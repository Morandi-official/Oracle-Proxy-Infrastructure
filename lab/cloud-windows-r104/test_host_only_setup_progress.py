"""Offline synthetic safety tests; no QEMU, host drive or Windows access."""
import unittest
from host_only_setup_progress import classify, MIN_PROGRESS_512_BLOCKS


class HostOnlyProgressTests(unittest.TestCase):
    def test_before_12_minutes_never_assert_windows(self):
        for m in (0, 1, 5, 11):
            self.assertEqual(classify(300, 300, m),
                             "R104_HOST_ALLOCATION_OBSERVING_NOT_WINDOWS_PROOF")

    def test_unchanged_disk_at_12_minutes_denies(self):
        self.assertEqual(classify(300, 300, 12),
                         "R104_HOST_DISK_ALLOCATION_STALLED_DENY")

    def test_insufficient_allocation_denies(self):
        self.assertEqual(classify(10, 10 + MIN_PROGRESS_512_BLOCKS - 1, 12),
                         "R104_HOST_DISK_ALLOCATION_STALLED_DENY")

    def test_growth_never_mislabels_windows_boot(self):
        self.assertEqual(classify(100, 100 + MIN_PROGRESS_512_BLOCKS, 12),
                         "R104_HOST_DISK_ALLOCATION_PROGRESS_NOT_WINDOWS_BOOT_PROOF")

    def test_metadata_refusal(self):
        for values in ((-1, 20, 12), (100, 99, 12), (1, 3, -1),
                       (1, 999, 26), (True, 20, 12)):
            self.assertTrue(classify(*values).endswith("_DENY"))


if __name__ == "__main__":
    unittest.main()
