#!/usr/bin/env python3
"""Conservative release gate. Assertions in JSON are NOT accepted as proof.
No releases, network mutations or external API requests are performed.
"""
import argparse
import hashlib
import json
import pathlib
import re
import sys

REQUIRED = (
    "independent_cross_host_ipv4_ipv6_dns",
    "windows_service_authenticated_control",
    "durable_intent_rollback_resistance",
    "wfp_actual_failclosed_packet_capture",
    "uu_real_remote_continuity",
    "independent_rollback_test",
    "signed_installer_uninstaller",
    "supply_chain_license_review",
    "production_server_keys_and_revocation",
)
SHA = re.compile(r"^[0-9a-f]{64}$")
RELEASE = re.compile(r"^v[1-9][0-9]*\.[0-9]+\.[0-9]+$")


def validate(payload, root: pathlib.Path):
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "version", "evidence"}:
        raise ValueError("invalid manifest fields")
    if payload["schema_version"] != 1 or not isinstance(payload["version"], str) or not RELEASE.fullmatch(payload["version"]):
        raise ValueError("invalid release version")
    evidence = payload["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != set(REQUIRED):
        raise ValueError("missing or extraneous evidence gate")
    digests = set()
    for gate in REQUIRED:
        value = evidence[gate]
        if not isinstance(value, dict) or set(value) != {"sha256", "path"}:
            raise ValueError(f"{gate}: evidence item schema")
        sha, path = value["sha256"], value["path"]
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise ValueError(f"{gate}: invalid hash")
        if not isinstance(path, str) or path.startswith("/") or "\\" in path or ":" in path:
            raise ValueError(f"{gate}: unsafe path")
        rel = pathlib.PurePosixPath(path)
        if ".." in rel.parts or not path.startswith("release/evidence/") or rel.suffix not in (".json", ".pdf", ".txt"):
            raise ValueError(f"{gate}: evidence must be in scoped release/evidence directory")
        target = root.joinpath(*rel.parts)
        if target.is_symlink() or not target.is_file() or not target.resolve().is_relative_to(root.resolve()):
            raise ValueError(f"{gate}: missing/unsafe evidence file")
        data = target.read_bytes()
        if len(data) < 64 or len(data) > 10_000_000 or hashlib.sha256(data).hexdigest() != sha:
            raise ValueError(f"{gate}: mismatched evidence")
        if sha in digests:
            raise ValueError(f"{gate}: reused evidence blob")
        digests.add(sha)
    # This is an integrity/completeness gate, NOT independent attestation:
    # forged files plus hashes could pass. Human review is mandatory.
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default="release/ga-evidence.json")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = pathlib.Path(args.root).resolve()
    manifest = root / args.manifest
    if not manifest.is_file():
        print("GA_BLOCKED: no audited evidence manifest; no GA release authorized")
        return 1
    try:
        validate(json.loads(manifest.read_text("utf-8")), root)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as ex:
        print("GA_BLOCKED:", str(ex))
        return 1
    print("EVIDENCE_FILES_PRESENT_ONLY: manual external security review, signer verification and UU test signoff still mandatory")
    return 0


if __name__ == "__main__":
    sys.exit(main())
