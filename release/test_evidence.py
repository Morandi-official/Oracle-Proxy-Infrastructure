import json
import pathlib
import tempfile
import unittest
from check_evidence import REQUIRED, validate


class ReleaseGateTests(unittest.TestCase):
    def test_missing_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaises(ValueError):
                validate({"schema_version": 1, "version": "v1.0.0", "evidence": {}}, pathlib.Path(name))

    def test_claims_only_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            fake = {gate: {"sha256": "0"*64, "path": f"release/evidence/{gate}.txt"} for gate in REQUIRED}
            with self.assertRaises(ValueError):
                validate({"schema_version": 1, "version": "v1.0.0", "evidence": fake}, pathlib.Path(name))

    def test_directory_escape_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            fake = {gate: {"sha256": "1"*64, "path": f"release/evidence/{gate}.txt"} for gate in REQUIRED}
            fake[REQUIRED[0]]["path"] = "release/evidence/../../secret.txt"
            with self.assertRaises(ValueError):
                validate({"schema_version": 1, "version": "v1.0.0", "evidence": fake}, pathlib.Path(name))


if __name__ == "__main__":
    unittest.main()
