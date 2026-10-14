import unittest

from assess_readiness import CHECKS, readiness, report


class RecoveryGateTests(unittest.TestCase):
    def test_empty_or_false_never_grants_ready(self):
        for obj in ({}, None, "ready", {k: False for k in CHECKS}):
            ok, missing = readiness(obj)
            self.assertFalse(ok)
            self.assertGreater(len(missing), 0)

    def test_unknown_or_missing_item_is_blocked(self):
        for absent in CHECKS:
            obj = {k: True for k in CHECKS}
            obj.pop(absent)
            obj["some_unrelated_claim"] = True
            ok, missing = readiness(obj)
            self.assertFalse(ok)
            self.assertIn(absent, missing)

    def test_pretend_all_true_remains_only_document_checklist(self):
        ok, missing = readiness({k: True for k in CHECKS})
        self.assertTrue(ok)
        self.assertEqual(missing, ())
        self.assertNotIn("production", "CHECKLIST_ONLY")
        # A true JSON claim does NOT prove an installed WFP filter or packet trace.

    def test_example_is_intentionally_incomplete(self):
        from pathlib import Path
        example = Path(__file__).with_name("unverified-example.json")
        self.assertTrue(report(str(example)).startswith("BLOCKED_UNVERIFIED:"))


if __name__ == "__main__":
    unittest.main()
