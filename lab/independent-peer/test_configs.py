import base64
import os
import stat
import tempfile
import unittest
from pathlib import Path

from generate_configs import (
    CLIENT_ADDR, LAB_PORT, SERVER_ADDR, config, endpoint,
    private_key_file, safe_write,
)

KEY_A = base64.b64encode(bytes(range(32))).decode()
KEY_B = base64.b64encode(bytes(range(32, 64))).decode()


class LabConfigTests(unittest.TestCase):
    def test_safely_scoped_configs(self):
        server = config("server", KEY_A, KEY_B)
        client = config("client", KEY_B, KEY_A, "8.8.8.8")
        self.assertIn("Address = " + SERVER_ADDR, server)
        self.assertIn("Address = " + CLIENT_ADDR, client)
        self.assertIn("ListenPort = " + str(LAB_PORT), server)
        self.assertIn("Endpoint = 8.8.8.8:" + str(LAB_PORT), client)
        self.assertIn("AllowedIPs = " + SERVER_ADDR, client)
        self.assertIn("AllowedIPs = " + CLIENT_ADDR, server)
        for text in (server, client):
            self.assertNotIn("0.0.0.0/0", text)
            self.assertNotIn("::/0", text)
            self.assertNotIn("152.67.156.100", text)
            self.assertNotIn("DNS =", text)
            self.assertNotIn("PostUp", text)
            self.assertNotIn("PostDown", text)
            self.assertEqual(text.count("[Peer]"), 1)

    def test_production_private_and_invalid_endpoints_rejected(self):
        for candidate in (
            "152.67.156.100", "10.0.0.6", "127.0.0.1", "192.0.2.1",
            "198.51.100.10", "::1", "0.0.0.0", "8.8.8.8\nPostUp = echo test",
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                endpoint(candidate)
        self.assertEqual(endpoint("8.8.8.8"), "8.8.8.8")

    def test_config_rejects_key_injection_and_wrong_role(self):
        for bad in (
            "", "0" * 44, KEY_A + "\nAllowedIPs = 0.0.0.0/0",
            KEY_A.replace("A", "!"), "x",
        ):
            with self.subTest(bad=bad[:8]), self.assertRaises(ValueError):
                config("server", bad, KEY_B)
        with self.assertRaises(ValueError):
            config("client", KEY_A, KEY_B, "152.67.156.100")
        with self.assertRaises(ValueError):
            config("vpn-production", KEY_A, KEY_B)

    def test_exclusive_owner_only_files_and_overwrite_denial(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            keyfile = root / "private.txt"
            keyfile.write_text(KEY_A, encoding="ascii")
            if os.name != "nt":
                keyfile.chmod(0o600)
            self.assertEqual(private_key_file(str(keyfile)), KEY_A)
            dst = root / "lab.conf"
            safe_write(str(dst), config("server", KEY_A, KEY_B))
            self.assertTrue(dst.is_file())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o600)
            with self.assertRaises(ValueError):
                safe_write(str(dst), "overwrite")
            with self.assertRaises(ValueError):
                safe_write(str(root / "lab.ps1"), "not a config")
            if os.name != "nt":
                keyfile.chmod(0o644)
                with self.assertRaises(ValueError):
                    private_key_file(str(keyfile))

    def test_symlink_output_denial(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = root / "existing.txt"
            original.write_text("untouched")
            link = root / "link.conf"
            try:
                link.symlink_to(original)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            with self.assertRaises(ValueError):
                safe_write(str(link), "danger")
            self.assertEqual(original.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
