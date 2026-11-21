"""Synthetic source-only R104 optical prompt tests (no QEMU, no networking)."""
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest
from qmp_bounded_iso_boot_key import (
    KEY_COUNT, KEY_INTERVAL_SEC, bounded_read, key_command, owned_qmp_socket
)
from io import BytesIO


class BoundedOpticalPromptTests(unittest.TestCase):
    def test_exact_return_only(self):
        self.assertEqual(key_command(), {
            "execute": "send-key",
            "arguments": {"keys": [{"type": "qcode", "data": "ret"}],
                          "hold-time": 70}})
        self.assertLessEqual(KEY_COUNT * KEY_INTERVAL_SEC, 12)

    def test_owned_runner_socket_path_only(self):
        with TemporaryDirectory() as tmp:
            t = Path(tmp)
            name = t / "r104-isolated-install.A1b2C3d4"
            name.mkdir()
            self.assertEqual(owned_qmp_socket(str(name), tmp), name / "qmp.sock")
            for reject in (t / "else", t / "r104-isolated-install.notlong",
                           t / "r104-isolated-install.A1b2C3d4" / "sub"):
                with self.assertRaises(ValueError):
                    owned_qmp_socket(str(reject), tmp)

    def test_refuse_symlinked_runner_root(self):
        with TemporaryDirectory() as tmp:
            t = Path(tmp)
            real = t / "r104-isolated-install.A1b2C3d4"
            link = t / "r104-isolated-install.87654321"
            real.mkdir()
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                owned_qmp_socket(str(link), tmp)

    def test_bounded_qmp_json(self):
        self.assertEqual(bounded_read(BytesIO(b'{"QMP":{}}\n')), {"QMP": {}})
        with self.assertRaises(RuntimeError):
            bounded_read(BytesIO(b"[]" + b" " * 8193))
        with self.assertRaises(RuntimeError):
            bounded_read(BytesIO(b"[]\n"))
        with self.assertRaises(json.JSONDecodeError):
            bounded_read(BytesIO(b"not-json\n"))


if __name__ == "__main__":
    unittest.main()
