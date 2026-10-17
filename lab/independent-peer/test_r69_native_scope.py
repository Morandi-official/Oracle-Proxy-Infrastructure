"""R69 pure negative tests; synthetic keys only, no adapter/service/network changes."""
import base64
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import r69_native_scope as scope


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def good_pair() -> dict[str, str]:
    sk = {
        "lab-peer-a": bytes(range(1, 33)),
        "lab-peer-b": bytes(range(33, 65)),
    }
    pub = {
        profile: X25519PrivateKey.from_private_bytes(key).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        for profile, key in sk.items()
    }
    result = {}
    for profile, other in (("lab-peer-a", "lab-peer-b"),
                           ("lab-peer-b", "lab-peer-a")):
        f = scope.PROFILES[profile]
        result[profile] = (
            "[Interface]\n"
            "PrivateKey = " + _b64(sk[profile]) + "\n"
            "Address = " + ", ".join(f["address"]) + "\n"
            "ListenPort = " + f["listen"] + "\n"
            "\n[Peer]\n"
            "PublicKey = " + _b64(pub[other]) + "\n"
            "AllowedIPs = " + ", ".join(f["allowed"]) + "\n"
            "Endpoint = " + f["endpoint"] + "\n"
            "PersistentKeepalive = 1\n"
        )
    return result


class R69NativeScopeTests(unittest.TestCase):
    def test_valid_two_way_narrow_lab(self):
        scope.audit_pair(good_pair())

    def test_altered_peer_identity_rejected(self):
        conf = good_pair()
        conf["lab-peer-a"] = conf["lab-peer-a"].replace(
            "PublicKey = ", "PublicKey = " + "A" * 43 + "=", 1)
        with self.assertRaises(scope.AuditError):
            scope.audit_pair(conf)

    def test_swapped_profile_rejected(self):
        conf = good_pair()
        conf["lab-peer-a"], conf["lab-peer-b"] = (
            conf["lab-peer-b"], conf["lab-peer-a"])
        with self.assertRaises(scope.AuditError):
            scope.audit_pair(conf)

    def test_missing_or_extra_profiles_rejected(self):
        for configs in ({}, {"lab-peer-a": good_pair()["lab-peer-a"]},
                        {**good_pair(), "other": "ignored"}):
            with self.subTest(configs=list(configs)):
                with self.assertRaises(scope.AuditError):
                    scope.audit_pair(configs)

    def test_both_profiles_reject_unsafe_mutations(self):
        for profile in scope.PROFILES:
            valid = good_pair()[profile]
            f = scope.PROFILES[profile]
            allowed = ", ".join(f["allowed"])
            address = ", ".join(f["address"])
            mutations = {
                "ipv4_default": valid.replace(allowed, "0.0.0.0/0"),
                "ipv6_default": valid.replace(allowed, "0.0.0.0/0, ::/0"),
                "extra_subnet": valid.replace(allowed, allowed + ", 10.0.0.0/8"),
                "too_wide_inner": valid.replace(f["allowed"][0], "10.249.129.0/24"),
                "bad_local_route": valid.replace(address, "0.0.0.0/0"),
                "extra_dns": valid.replace("ListenPort =", "DNS = 1.1.1.1\nListenPort ="),
                "pre_up": valid.replace("ListenPort =", "PreUp = echo injected\nListenPort ="),
                "post_down": valid + "PostDown = cmd.exe\n",
                "table": valid.replace("ListenPort =", "Table = auto\nListenPort ="),
                "additional_peer": valid + "\n[Peer]\nPublicKey = xyz\n",
                "duplicate_peer_key": valid.replace("Endpoint =", "PublicKey = extras\nEndpoint ="),
                "duplicate_interface": valid.replace("[Peer]", "[Interface]\n[Peer]"),
                "public_endpoint": valid.replace(f["endpoint"], "203.0.113.22:443"),
                "any_ip_endpoint": valid.replace(f["endpoint"], "0.0.0.0:51820"),
                "wrong_listen": valid.replace(f["listen"], "51820"),
                "keepalive_change": valid.replace("PersistentKeepalive = 1",
                                                   "PersistentKeepalive = 25"),
                "non_ascii": valid.replace("Endpoint =", "端点 ="),
                "windows_line_endings": valid.replace("\n", "\r\n"),
                "no_final_newline": valid.rstrip("\n"),
                "comment": valid + "# comment\n",
                "unknown": valid + "SaveConfig = true\n",
                "missing_public_key": "\n".join(
                    line for line in valid.splitlines()
                    if not line.startswith("PublicKey")) + "\n",
                "bad_private": valid.replace("PrivateKey = ", "PrivateKey = !!!"),
            }
            for label, modified in mutations.items():
                with self.subTest(profile=profile, mutation=label):
                    with self.assertRaises(scope.AuditError):
                        scope.audit_one(modified, profile)

    def test_ci_only_staging_entrypoint(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false",
                                    "RUNNER_ENVIRONMENT": "forbidden"}):
            with self.assertRaises(scope.AuditError):
                scope.audit_staged_ci_only()


if __name__ == "__main__":
    unittest.main(verbosity=2)
