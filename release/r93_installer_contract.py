"""R93 signed Windows installer lifecycle *source-only* review contract.

No install, uninstall, service, Task Scheduler, WFP, driver, network,
code signing, credentials or other OS operations. A plan is not authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

INSTALL_STEPS = (
    "inspect_os_policy_read_only",
    "prove_independent_out_of_band_restore",
    "verify_genuine_windows_authenticode_publisher_and_revocation",
    "verify_independent_git_source_provenance_and_package_hash",
    "stage_only_owned_signed_components",
    "arm_exact_owned_independent_system_recovery",
    "prove_persistent_all_device_wfp_guard",
    "permit_reviewed_fixed_native_activation_only",
    "verify_ipv4_ipv6_dns_wfp_and_uu_continuity",
)
SAFE_OFF_UNINSTALL_STEPS = (
    "retain_persistent_guard_and_quarantine",
    "stop_only_exact_owned_native_service",
    "independently_prove_native_tunnel_stopped",
    "stage_exact_owned_routes_and_dns_restore",
    "durably_commit_signed_explicit_off_intent",
    "independently_audit_owned_wfp_and_all_interfaces",
    "release_only_proven_owned_wfp_after_safe_os_state",
    "verify_real_network_baseline_and_uu",
    "delete_only_exact_owned_service_task_files_and_keys",
    "verify_zero_owned_residual_and_revoke_ephemeral_keys",
)
# Future owner *names* for contract review, not real SCM/task/WFP objects.
REVIEW_OWNERS = frozenset({
    "OracleProxy.Future.SignedInstaller",
    "OracleProxy.Future.SystemService",
    "OracleProxy.Future.RecoveryTask",
    "OracleProxy.Future.WfpProvider",
    "OracleProxy.Future.KeyStore",
})
REQUIRED_INDEPENDENT_PROOFS = frozenset({
    "authenticode_valid_signer_windows_verified",
    "pinned_publisher_certificate_and_revocation_review",
    "build_attestation_exact_source_digest_externally_verified",
    "installer_uninstaller_codesigned_and_hash_pinned",
    "out_of_band_console_and_snapshot_rollback_tested",
    "actual_reboot_prelogin_wfp_ipv4_ipv6_dns_packets",
    "real_uu_remote_control_failure_continuity",
    "cross_host_authenticated_transport_with_key_revocation",
    "exact_owned_service_task_wfp_route_dns_file_teardown",
    "external_ga_issue_34_review",
})
# A self-declared release token, signed:true, CI variable or JSON document
# does not change source-controlled denial. This policy intentionally does NOT
# accept a signer allowlist from package metadata or CLI parameters.
APPROVED_PRODUCT_SIGNERS = frozenset()
PRODUCT_INSTALLER_ACTIVATION_ENABLED = False


class UnsafeDeliveryPlan(ValueError):
    pass


@dataclass(frozen=True)
class DeliveryReviewPlan:
    channel: str
    install_steps: tuple[str, ...]
    uninstall_steps: tuple[str, ...]
    owned_resources: frozenset[str]
    claimed_proofs: Mapping[str, bool]


def inspect_review_plan(plan: DeliveryReviewPlan) -> str:
    if not isinstance(plan, DeliveryReviewPlan) or plan.channel != "SOURCE_REVIEW_NO_INSTALL":
        raise UnsafeDeliveryPlan("not a source review channel")
    if (type(plan.install_steps) is not tuple or plan.install_steps != INSTALL_STEPS
            or type(plan.uninstall_steps) is not tuple
            or plan.uninstall_steps != SAFE_OFF_UNINSTALL_STEPS):
        raise UnsafeDeliveryPlan("unsafe lifecycle order or additional operations")
    if (type(plan.owned_resources) is not frozenset
            or plan.owned_resources != REVIEW_OWNERS):
        raise UnsafeDeliveryPlan("unowned/foreign or wildcard resource")
    if (not isinstance(plan.claimed_proofs, Mapping)
            or set(plan.claimed_proofs) != REQUIRED_INDEPENDENT_PROOFS
            or any(type(value) is not bool for value in plan.claimed_proofs.values())):
        raise UnsafeDeliveryPlan("invalid proof claim schema")
    # Even all self-declared True claims remain untrusted. There is no
    # product signing certificate, verified MSI/MSIX, production kernel,
    # hardware-protected signer or certified real reboot/WFP/UU test here.
    return "R93_SOURCE_LIFECYCLE_REVIEW_ONLY_NO_INSTALL_AUTHORIZATION"


def production_install_decision(plan: DeliveryReviewPlan) -> str:
    inspect_review_plan(plan)
    if not PRODUCT_INSTALLER_ACTIVATION_ENABLED or not APPROVED_PRODUCT_SIGNERS:
        return "R93_PRODUCT_SIGNER_AND_INSTALLER_NOT_APPROVED_DENY"
    # Future source-reviewed flow still needs an actual external cryptographic
    # verifier. Never promote caller-controlled claimed_proofs here.
    return "R93_EXTERNAL_SIGNER_AND_RELEASE_REVIEW_REQUIRED_DENY"


def default_review_plan() -> DeliveryReviewPlan:
    return DeliveryReviewPlan(
        channel="SOURCE_REVIEW_NO_INSTALL",
        install_steps=INSTALL_STEPS,
        uninstall_steps=SAFE_OFF_UNINSTALL_STEPS,
        owned_resources=REVIEW_OWNERS,
        claimed_proofs={name: False for name in REQUIRED_INDEPENDENT_PROOFS},
    )
