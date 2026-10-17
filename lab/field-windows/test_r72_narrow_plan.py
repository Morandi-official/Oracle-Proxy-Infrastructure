"""R72 negative/adversarial offline proposal scope tests; NO network calls."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import r72_narrow_plan as policy


NOW = datetime(2026, 10, 17, 13, 0, tzinfo=timezone.utc)


def example():
    return {
        "schema_version": 1,
        "mode": "review_only_single_public_peer",
        "created_utc": "2026-10-17T12:59:00Z",
        "expires_utc": "2026-10-17T13:12:00Z",
        "client_inner_ipv4": "10.77.72.2/32",
        "server_inner_ipv4": "10.77.72.1/32",
        "allowed_ips": ["10.77.72.1/32"],
        # Dummy syntactically public addresses used OFFLINE; no probe performed.
        "server_endpoint_ipv4": "8.8.8.8",
        "observed_client_public_ipv4": "9.9.9.9",
        "server_udp_port": 51828,
        "client_public_key": base64.b64encode(bytes([0x13]) * 32).decode(),
        "server_public_key": base64.b64encode(bytes([0x29]) * 32).decode(),
        "duration_minutes": 15,
        "dns_policy": "preserve",
        "default_route_policy": "preserve",
        "ipv6_policy": "do_not_configure",
        "firewall_policy": "no_system_firewall_mutation",
        "driver_policy": "no_install_or_replace",
        "separate_operator_approval_required": True,
    }


def data(obj):
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


class R72NarrowPlanTests(unittest.TestCase):
    def test_example_valid_but_never_authorizes(self):
        plan = example()
        digest = policy.validate(data(plan), now=NOW)
        self.assertEqual(len(digest), 64)
        self.assertFalse(policy.authorizes_any_connection(digest))
        self.assertFalse(policy.authorizes_any_connection(True))
        self.assertFalse(policy.authorizes_any_connection({"approved": True}))

    def test_key_order_does_not_change_review_digest(self):
        plan = example()
        a = policy.validate(data(plan), now=NOW)
        b = policy.validate(data(dict(reversed(list(plan.items())))), now=NOW)
        self.assertEqual(a, b)

    def test_reject_all_unsafe_mutations(self):
        prototype = example()
        attacks = {
            "ipv4_default": {"allowed_ips": ["0.0.0.0/0"]},
            "ipv6_default": {"allowed_ips": ["10.77.72.1/32", "::/0"]},
            "wider_private_range": {"allowed_ips": ["10.77.72.0/24"]},
            "new_target": {"allowed_ips": ["10.77.72.3/32"]},
            "two_peers": {"allowed_ips": ["10.77.72.1/32", "10.77.72.3/32"]},
            "ipv6_tunnel": {"ipv6_policy": "configure"},
            "dns_inject": {"dns_policy": "change"},
            "route_change": {"default_route_policy": "replace"},
            "wfp_enable": {"firewall_policy": "add_allow_all"},
            "driver_install": {"driver_policy": "install"},
            "old_r68_client_address": {"client_inner_ipv4": "10.77.68.2/32"},
            "old_r68_server_address": {"server_inner_ipv4": "10.77.68.1/32"},
            "new_inner": {"server_inner_ipv4": "10.0.0.1/32"},
            "wrong_port": {"server_udp_port": 51820},
            "bool_port": {"server_udp_port": True},
            "string_port": {"server_udp_port": "51828"},
            "wider_duration": {"duration_minutes": 30},
            "zero_duration": {"duration_minutes": 0},
            "string_duration": {"duration_minutes": "15"},
            "bool_duration": {"duration_minutes": True},
            "no_separate_consent": {"separate_operator_approval_required": False},
            "nonbool_consent": {"separate_operator_approval_required": 1},
            "wrong_version": {"schema_version": 2},
            "bool_version": {"schema_version": True},
            "nonreview_mode": {"mode": "connect"},
            "same_endpoint_as_client": {"observed_client_public_ipv4": "8.8.8.8"},
            "hostname_endpoint": {"server_endpoint_ipv4": "example.com"},
            "ipv6_endpoint": {"server_endpoint_ipv4": "2001:4860:4860::8888"},
            "local_endpoint": {"server_endpoint_ipv4": "127.0.0.1"},
            "private_endpoint": {"server_endpoint_ipv4": "10.0.0.6"},
            "documentation_endpoint": {"server_endpoint_ipv4": "192.0.2.12"},
            "multicast_endpoint": {"server_endpoint_ipv4": "224.0.0.1"},
            "link_local_endpoint": {"server_endpoint_ipv4": "169.254.0.1"},
            "unspecified_endpoint": {"server_endpoint_ipv4": "0.0.0.0"},
            "octal_looking_ipv4": {"server_endpoint_ipv4": "008.008.008.008"},
            "documentation_client": {"observed_client_public_ipv4": "198.51.100.6"},
            "zero_public_key": {
                "server_public_key": base64.b64encode(bytes(32)).decode()},
            "same_keys": {"server_public_key": prototype["client_public_key"]},
            "broken_key": {"client_public_key": "AAAA"},
            "bad_key_alphabet": {"server_public_key": "%" * 44},
            "already_expired": {"expires_utc": "2026-10-17T12:58:00Z"},
            "too_distant_expiry": {"expires_utc": "2026-10-17T13:45:00Z"},
            "stale_creation": {"created_utc": "2026-10-17T12:50:00Z"},
            "future_creation": {"created_utc": "2026-10-17T13:01:00Z"},
            "bad_time_format": {"created_utc": "2026-10-17 12:59:00"},
            "wrong_timezone": {"created_utc": "2026-10-17T12:59:00+00:00"},
        }
        for label, edits in attacks.items():
            with self.subTest(label=label):
                case = copy.deepcopy(prototype)
                case.update(edits)
                with self.assertRaises(policy.PlanRejected):
                    policy.validate(data(case), now=NOW)

    def test_unexpected_fields_and_missing_fields(self):
        proposal = example()
        for extra in ("PrivateKey", "ssh_password", "install_hook",
                      "approval_token", "wfp_allow_all", "route_table"):
            with self.subTest(extra=extra):
                with self.assertRaises(policy.PlanRejected):
                    policy.validate(data({**proposal, extra: "x"}), now=NOW)
        for missing in proposal:
            with self.subTest(missing=missing):
                copy_ = proposal.copy()
                del copy_[missing]
                with self.assertRaises(policy.PlanRejected):
                    policy.validate(data(copy_), now=NOW)

    def test_duplicate_json_key_and_json_constants(self):
        original = data(example()).decode("utf-8")
        duplicate = original.replace('"schema_version":1',
                                     '"schema_version":1,"schema_version":1')
        for payload in (duplicate, '{"x":NaN}', '{"x":Infinity}',
                        original + "{}",
                        "", "[]", '{"x":true}', "{" * 5000):
            with self.subTest(payload=payload[:24]):
                with self.assertRaises(policy.PlanRejected):
                    policy.validate(payload.encode(), now=NOW)

    def test_refuse_file_path_operations_and_unknown_cli(self):
        self.assertEqual(policy.main([]), 2)
        self.assertEqual(policy.main(["--connect", "any"]), 2)
        self.assertEqual(policy.main(["--review-proposal"]), 2)
        self.assertEqual(policy.main(["--review-proposal", "x", "--connect"]), 2)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "test.json"
            p.write_bytes(data(example()))
            # Even an in-scope but expiry-dead fixture cannot authorize real use.
            self.assertEqual(policy.main(["--review-proposal", str(p)]), 3)
            self.assertFalse(policy.authorizes_any_connection())

    def test_naive_timestamps_are_refused(self):
        with self.assertRaises(policy.PlanRejected):
            policy.validate(data(example()), now=NOW.replace(tzinfo=None))


if __name__ == "__main__":
    unittest.main(verbosity=2)
