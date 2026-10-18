"""Synthetic fail-closed preflight tests. No real VM, privileged API or network."""
from dataclasses import replace
import unittest

from read_only_probe import GIB, RunnerFacts, classify


class R96ReadOnlyHostPreflightTests(unittest.TestCase):
    def setUp(self):
        self.facts = RunnerFacts(True, True, True, True,
                                 64 * GIB, 12 * GIB, 4)

    def test_even_ideal_resource_claim_is_not_guest_authorization(self):
        self.assertEqual(classify(self.facts),
            ("R96_CAPACITY_PREFLIGHT_ONLY_NO_GUEST_OR_SECURITY_APPROVAL",))

    def test_not_hosted_linux_hard_refusal(self):
        self.assertEqual(classify(replace(self.facts, hosted_linux=False)),
                         ("R96_REFUSED_NOT_GITHUB_HOSTED_LINUX",))

    def test_kvm_missing_refusal(self):
        self.assertIn("KVM_ACCESS_OR_NESTED_VIRT_NOT_VERIFIED",
                      classify(replace(self.facts, kvm_device_exists=False)))

    def test_kvm_permission_refusal(self):
        self.assertIn("KVM_ACCESS_OR_NESTED_VIRT_NOT_VERIFIED",
                      classify(replace(self.facts, kvm_device_rw=False)))

    def test_hw_virtualization_flags_refusal(self):
        self.assertIn("KVM_ACCESS_OR_NESTED_VIRT_NOT_VERIFIED",
                      classify(replace(self.facts, hardware_virt_flag=False)))

    def test_just_below_documented_windows_disk_refused(self):
        self.assertIn("WINDOWS_VM_DISK_HEADROOM_BELOW_32GIB",
                      classify(replace(self.facts,
                                       free_workspace_disk_bytes=32 * GIB - 1)))

    def test_32gib_is_not_product_security_evidence(self):
        v = replace(self.facts, free_workspace_disk_bytes=32 * GIB)
        self.assertIn("NO_GUEST_OR_SECURITY_APPROVAL", classify(v)[0])

    def test_14gib_standard_runner_is_insufficient(self):
        self.assertIn("WINDOWS_VM_DISK_HEADROOM_BELOW_32GIB",
                      classify(replace(self.facts,
                                       free_workspace_disk_bytes=14 * GIB)))

    def test_ram_and_cpu_failures_detected_independently(self):
        r = classify(replace(self.facts,
                             available_memory_bytes=5 * GIB, cpu_count=1))
        self.assertIn("WINDOWS_VM_AVAILABLE_RAM_BELOW_6GIB", r)
        self.assertIn("WINDOWS_VM_CPU_BELOW_2", r)


if __name__ == "__main__":
    unittest.main()
