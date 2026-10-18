"""Source-only, deterministic negative tests; never run Windows executables."""
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from r88_artifact_policy import (
    ArtifactRefused, R86_CI_DIGESTS, REVIEWED_PRODUCTION_PUBLISHER_THUMBPRINTS,
    PRODUCTION_RELEASE_ENABLED, production_release_verdict, verify_exact_kit,
    verify_r86_kit,
)


class R88IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name) / "kit"
        self.root.mkdir()
        # Independent expected hashes, deliberately generated OUTSIDE fixture
        # kit to show the role of an independent root of integrity.
        import hashlib
        self.contents = {"safe.txt": b"test data only", "another.ps1": b"# inert text\n"}
        self.expected = {n: hashlib.sha256(v).hexdigest()
                         for n, v in self.contents.items()}
        for name, value in self.contents.items():
            (self.root / name).write_bytes(value)
        (self.root / "SHA256SUMS.txt").write_text("UNTRUSTED", encoding="ascii")

    def test_kit_is_integrity_only(self):
        self.assertIn("NOT_EXECUTION_AUTHORIZATION",
                      verify_exact_kit(self.root, self.expected))

    def test_changes_even_when_kit_manifest_claims_success(self):
        (self.root / "safe.txt").write_bytes(b"modified")
        (self.root / "SHA256SUMS.txt").write_text("signed:true\nall_valid:true\n")
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(self.root, self.expected)

    def test_foreign_file_rejected(self):
        (self.root / "malicious.exe").write_bytes(b"x")
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(self.root, self.expected)

    def test_nested_directory_rejected(self):
        (self.root / "nested").mkdir()
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(self.root, self.expected)

    def test_missing_manifest_rejected(self):
        (self.root / "SHA256SUMS.txt").unlink()
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(self.root, self.expected)

    def test_missing_file_rejected(self):
        (self.root / "safe.txt").unlink()
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(self.root, self.expected)

    def test_malicious_external_pin_name_rejected(self):
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(self.root, {"../escape.exe": "a" * 64})
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(self.root, {"C:drive": "a" * 64})

    def test_pin_must_be_normalized_sha256(self):
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(self.root, {"safe.txt": "B" * 64})

    def test_symlink_root_rejected(self):
        link = self.root.parent / "link"
        try:
            link.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("runner cannot create a symlink")
        with self.assertRaises(ArtifactRefused):
            verify_exact_kit(link, self.expected)

    def test_sha_list_cannot_be_provenance(self):
        self.assertEqual(len(R86_CI_DIGESTS), 7)
        self.assertEqual(set(R86_CI_DIGESTS),
                         {"R86NoNetworkMock.exe", "R86-Common.ps1",
                          "R86-Preflight.ps1", "R86-Start.ps1",
                          "R86-Verify.ps1", "R86-EmergencyCleanup.ps1",
                          "README-R86.txt"})
        with self.assertRaises(ArtifactRefused):
            verify_r86_kit(self.root)

    def test_all_self_declared_production_assertions_still_denied(self):
        self.assertFalse(PRODUCTION_RELEASE_ENABLED)
        self.assertFalse(REVIEWED_PRODUCTION_PUBLISHER_THUMBPRINTS)
        fake = dict(externally_authenticated_ci_provenance=True,
                    authenticode_verified_by_windows=True,
                    verified_publisher_thumbprint="b" * 64,
                    independently_pinned_installer_hash=True,
                    reviewed_ga_evidence=True)
        self.assertIn("DENIED", production_release_verdict(**fake))
        fake["authenticode_verified_by_windows"] = False
        self.assertIn("DENIED", production_release_verdict(**fake))
        fake["authenticode_verified_by_windows"] = True
        fake["verified_publisher_thumbprint"] = ""
        self.assertIn("DENIED", production_release_verdict(**fake))


if __name__ == "__main__":
    unittest.main()
