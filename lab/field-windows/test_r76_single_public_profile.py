"""R76 offline negative tests: fixture keys only; never touch any network."""
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parent))
import r76_single_public_profile as render
import r72_narrow_plan as policy


NOW = datetime(2026, 10, 17, 13, 0, tzinfo=timezone.utc)
CLIENT_TEST_BYTES = bytes(range(1, 33))
SERVER_TEST_BYTES = bytes(range(33, 65))


def b64_public(private: bytes) -> str:
    raw = X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def proposal() -> dict:
    return {
        "schema_version": 1,
        "mode": "review_only_single_public_peer",
        "created_utc": "2026-10-17T12:59:00Z",
        "expires_utc": "2026-10-17T13:12:00Z",
        "client_inner_ipv4": "10.77.72.2/32",
        "server_inner_ipv4": "10.77.72.1/32",
        "allowed_ips": ["10.77.72.1/32"],
        "server_endpoint_ipv4": "8.8.8.8",
        "observed_client_public_ipv4": "9.9.9.9",
        "server_udp_port": 51828,
        "client_public_key": b64_public(CLIENT_TEST_BYTES),
        "server_public_key": b64_public(SERVER_TEST_BYTES),
        "duration_minutes": 15,
        "dns_policy": "preserve",
        "default_route_policy": "preserve",
        "ipv6_policy": "do_not_configure",
        "firewall_policy": "no_system_firewall_mutation",
        "driver_policy": "no_install_or_replace",
        "separate_operator_approval_required": True,
    }


def raw(plan):
    return json.dumps(plan, separators=(",", ":")).encode("utf-8")


class R76Tests(unittest.TestCase):
    def test_exact_profile_generated_from_reciprocal_planned_identity(self):
        plan = proposal()
        conf = render.render_in_memory(raw(plan), CLIENT_TEST_BYTES, now=NOW)
        # Never print this secret-bearing value to logs.
        self.assertTrue(render.exact_profile_grammar(conf, plan))
        self.assertEqual(conf.count("[Interface]"), 1)
        self.assertEqual(conf.count("[Peer]"), 1)
        self.assertEqual(conf.count("AllowedIPs = "), 1)
        self.assertEqual(conf.count("Endpoint = "), 1)
        self.assertNotIn("0.0.0.0/0", conf)
        self.assertNotIn("::/0", conf)
        self.assertNotIn("DNS =", conf)
        self.assertNotIn("PreUp", conf)
        self.assertNotIn("PostDown", conf)
        self.assertNotIn("ListenPort", conf)
        self.assertFalse(render.authorizes_service_or_connection(conf))

    def test_reject_unmatched_or_invalid_private_identity(self):
        plan = proposal()
        for secret in (SERVER_TEST_BYTES, bytes(32), b"short", b"", None,
                       bytearray(CLIENT_TEST_BYTES)):
            with self.subTest(kind=type(secret).__name__):
                with self.assertRaises(render.ProfileRefused):
                    render.render_in_memory(raw(plan), secret, now=NOW)

    def test_bad_proposal_mutations_rejected(self):
        base = proposal()
        malicious = {
            "global_ipv4": {"allowed_ips": ["0.0.0.0/0"]},
            "global_ipv6": {"allowed_ips": ["::/0"]},
            "wider_allowed": {"allowed_ips": ["10.77.72.0/24"]},
            "dns_override": {"dns_policy": "override"},
            "default_route": {"default_route_policy": "replace"},
            "driver_install": {"driver_policy": "install"},
            "firewall_rule": {"firewall_policy": "bypass"},
            "wrong_public_key": {"client_public_key": b64_public(SERVER_TEST_BYTES)},
            "server_same_key": {"server_public_key": base["client_public_key"]},
            "expired": {"expires_utc": "2026-10-17T12:58:00Z"},
            "public_port_changed": {"server_udp_port": 443},
            "operator_approval_removed": {"separate_operator_approval_required": False},
        }
        for label, mutation in malicious.items():
            with self.subTest(label=label):
                case = {**base, **mutation}
                with self.assertRaises(render.ProfileRefused):
                    render.render_in_memory(raw(case), CLIENT_TEST_BYTES, now=NOW)

    def test_output_grammar_refuses_injections(self):
        plan = proposal()
        legitimate = render.render_in_memory(raw(plan), CLIENT_TEST_BYTES, now=NOW)
        payloads = {
            "add_dns": legitimate + "DNS = 1.1.1.1\n",
            "add_post_up": legitimate + "PostUp = cmd.exe\n",
            "ipv4_default": legitimate.replace("AllowedIPs = 10.77.72.1/32",
                                              "AllowedIPs = 0.0.0.0/0"),
            "wider_inner": legitimate.replace("Address = 10.77.72.2/32",
                                             "Address = 10.77.72.2/24"),
            "different_endpoint": legitimate.replace(":51828", ":443"),
            "second_peer": legitimate + "[Peer]\nPublicKey = invalid\n",
            "windows_crlf": legitimate.replace("\n", "\r\n"),
            "no_last_newline": legitimate.rstrip("\n"),
            "double_key": legitimate.replace("Address =", "PrivateKey = fake\nAddress ="),
        }
        for label, changed in payloads.items():
            with self.subTest(label=label):
                self.assertFalse(render.exact_profile_grammar(changed, plan))

    def test_non_utf8_and_duplicate_properties_rejected(self):
        data = raw(proposal())
        for candidate in (b"\xff", data[:-1], b"{}", b"[]",
                          data.replace(b'"schema_version":1',
                                       b'"schema_version":1,"schema_version":1')):
            with self.subTest(prefix=candidate[:10]):
                with self.assertRaises(render.ProfileRefused):
                    render.render_in_memory(candidate, CLIENT_TEST_BYTES, now=NOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
