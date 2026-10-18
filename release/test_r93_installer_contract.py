"""Pure safe lifecycle contract tests, no Windows API or install action."""
from dataclasses import replace
import unittest

from r93_installer_contract import (
    APPROVED_PRODUCT_SIGNERS, PRODUCT_INSTALLER_ACTIVATION_ENABLED,
    INSTALL_STEPS, SAFE_OFF_UNINSTALL_STEPS, REVIEW_OWNERS,
    REQUIRED_INDEPENDENT_PROOFS, UnsafeDeliveryPlan,
    default_review_plan, inspect_review_plan, production_install_decision,
)


class R93SourceInstallReviewTests(unittest.TestCase):
    def setUp(self):
        self.base = default_review_plan()

    def deny(self, changed):
        with self.assertRaises(UnsafeDeliveryPlan):
            inspect_review_plan(changed)

    def test_expected_lifecycle_only_never_install(self):
        self.assertIn("NO_INSTALL_AUTHORIZATION", inspect_review_plan(self.base))
        self.assertIn("DENY", production_install_decision(self.base))
        self.assertFalse(APPROVED_PRODUCT_SIGNERS)
        self.assertFalse(PRODUCT_INSTALLER_ACTIVATION_ENABLED)

    def test_all_trust_claims_self_asserted_cannot_unlock(self):
        fake = replace(self.base, claimed_proofs={
            key: True for key in REQUIRED_INDEPENDENT_PROOFS})
        self.assertIn("DENY", production_install_decision(fake))

    def test_wrong_release_channel_refused(self):
        self.deny(replace(self.base, channel="PRODUCTION"))

    def test_guards_must_exist_before_native_activation(self):
        steps = list(INSTALL_STEPS)
        steps[5], steps[7] = steps[7], steps[5]
        self.deny(replace(self.base, install_steps=tuple(steps)))

    def test_signed_identity_and_source_both_before_stage(self):
        steps = list(INSTALL_STEPS)
        steps[3], steps[4] = steps[4], steps[3]
        self.deny(replace(self.base, install_steps=tuple(steps)))

    def test_rollback_must_not_release_wfp_before_native_stop(self):
        steps = list(SAFE_OFF_UNINSTALL_STEPS)
        steps[1], steps[6] = steps[6], steps[1]
        self.deny(replace(self.base, uninstall_steps=tuple(steps)))

    def test_rollback_must_not_delete_before_os_audit(self):
        steps = list(SAFE_OFF_UNINSTALL_STEPS)
        steps[5], steps[8] = steps[8], steps[5]
        self.deny(replace(self.base, uninstall_steps=tuple(steps)))

    def test_foreign_uu_or_wiresock_is_not_owned(self):
        for bad in ("WireSock", "UU", "OracleProxy.*", "C:\\Windows\\System32",
                    "OracleProxy.Future.*"):
            self.deny(replace(self.base, owned_resources=REVIEW_OWNERS | {bad}))

    def test_missing_owner_is_not_full_rollback_scope(self):
        self.deny(replace(self.base,
                          owned_resources=frozenset(REVIEW_OWNERS - {
                              "OracleProxy.Future.RecoveryTask"})))

    def test_fake_signed_metadata_not_accepted(self):
        self.deny(replace(self.base, claimed_proofs={
            **self.base.claimed_proofs, "signed": True}))

    def test_incomplete_or_non_boolean_external_evidence(self):
        values = dict(self.base.claimed_proofs)
        del values["real_uu_remote_control_failure_continuity"]
        self.deny(replace(self.base, claimed_proofs=values))
        values = dict(self.base.claimed_proofs)
        values["external_ga_issue_34_review"] = "true"
        self.deny(replace(self.base, claimed_proofs=values))


if __name__ == "__main__":
    unittest.main()
