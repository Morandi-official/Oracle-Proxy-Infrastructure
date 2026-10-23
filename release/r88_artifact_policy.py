"""R88 CI-side artifact integrity and channel separation. NO execution/deployment.

An archive manifest is NOT a trust root. The R86 SHA-256 mapping below comes
from the independent CI log, not from the ZIP's SHA256SUMS.txt. No networking,
subprocess, driver, PowerShell or host-state modification occurs here.
"""
from __future__ import annotations

import hashlib
import pathlib
import re

R86_CI_DIGESTS = {
    "R86NoNetworkMock.exe": "cf903348275732ac1a5590d202648e432c10ab927eedd4372763f5087b6fd202",
    "R86-Common.ps1": "33ce7e151aae69c02d9a33559af4b2037f00aaa5c42ff3e99420de6e09c964f9",
    "R86-Preflight.ps1": "08824ed7c2b8624847bd99716f2faf439fa93fc5165815b3a929e325020164e5",
    "R86-Start.ps1": "7323bdfe3664476eb73024e73b716caa7db71ba78000d9ad54d1591e6955f2d",
    "R86-Verify.ps1": "765d235cc1a153f365a1ee28bdb393f16147407cbb67e1aac4331d4fe0ac3c76",
    "R86-EmergencyCleanup.ps1": "4e633fa99a34f4bf1f9ecdb44063f583f9a31d7f9f1e2e62920682ae416aacf0",
    "README-R86.txt": "131128f50e75b2f00541fddab2beaf3c494b766f74d6b8261c4414a0b718f7db",
}
R86_CI_RUN = 39044333007
R86_CI_ARTIFACT_ID = 12105571201
R86_ARTIFACT_EXPIRES_UTC = "2026-10-24T15:21:32Z"

# Explicit compile-time DENY until a reviewed publisher identity, independent
# signed release provenance, verified installer/rollback and GA signoff exist.
# Self-declared "signed":true or a companion hash manifest cannot modify this.
REVIEWED_PRODUCTION_PUBLISHER_THUMBPRINTS: frozenset[str] = frozenset()
PRODUCTION_RELEASE_ENABLED = False
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ArtifactRefused(ValueError):
    pass


def verify_exact_kit(folder: pathlib.Path, independent_hashes: dict[str, str]) -> str:
    """Return an integrity-only verdict, NEVER permission to run an artifact.

    The supplied independent_hashes MUST come from outside the untrusted kit
    (e.g. a separately authenticated CI job log). Callers must not load them
    from SHA256SUMS.txt or any other file inside the download.
    """
    root = pathlib.Path(folder)
    if root.is_symlink() or not root.is_dir():
        raise ArtifactRefused("untrusted/reparse kit root")
    if not independent_hashes or any(
        not isinstance(n, str) or not n or "/" in n or "\\" in n
        or n in (".", "..") or ":" in n
        or not isinstance(h, str) or not _SHA256.fullmatch(h)
        for n, h in independent_hashes.items()
    ):
        raise ArtifactRefused("invalid independent hash pins")
    wanted = set(independent_hashes)
    # R86 includes the in-package SHA256SUMS.txt, but it is not a trust anchor.
    allowed = wanted | {"SHA256SUMS.txt"}
    found = set()
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file() or path.name not in allowed:
            raise ArtifactRefused("foreign file, subdirectory or reparse point")
        found.add(path.name)
        if path.name == "SHA256SUMS.txt":
            continue
        if path.stat().st_size > 90_000_000 or path.stat().st_size == 0:
            raise ArtifactRefused("invalid kit file size")
        with path.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        if digest != independent_hashes[path.name]:
            raise ArtifactRefused("CI-pinned hash mismatch")
    if found != allowed:
        raise ArtifactRefused("missing kit file or manifest")
    return "R88_REVIEW_KIT_INTEGRITY_ONLY_NOT_EXECUTION_AUTHORIZATION"


def verify_r86_kit(folder: pathlib.Path) -> str:
    return verify_exact_kit(folder, R86_CI_DIGESTS)


def production_release_verdict(
    *,
    externally_authenticated_ci_provenance: bool,
    authenticode_verified_by_windows: bool,
    verified_publisher_thumbprint: str,
    independently_pinned_installer_hash: bool,
    reviewed_ga_evidence: bool,
) -> str:
    """Fail closed. No package metadata/CLI flag is an authorization source.

    Any future enabling requires a *source reviewed* publisher allowlist,
    signed installer/uninstaller rollback proof and independent GA evidence.
    Even every caller-supplied claim=True is insufficient today.
    """
    if not PRODUCTION_RELEASE_ENABLED or not REVIEWED_PRODUCTION_PUBLISHER_THUMBPRINTS:
        return "R88_PRODUCTION_RELEASE_DENIED_NO_APPROVED_SIGNER"
    fingerprint = (verified_publisher_thumbprint or "").lower()
    if not (_SHA256.fullmatch(fingerprint)
            and fingerprint in REVIEWED_PRODUCTION_PUBLISHER_THUMBPRINTS
            and externally_authenticated_ci_provenance is True
            and authenticode_verified_by_windows is True
            and independently_pinned_installer_hash is True
            and reviewed_ga_evidence is True):
        return "R88_PRODUCTION_RELEASE_DENIED_MISSING_TRUST_EVIDENCE"
    return "R88_SIGNED_CANDIDATE_REQUIRES_INDEPENDENT_RELEASE_APPROVAL"
