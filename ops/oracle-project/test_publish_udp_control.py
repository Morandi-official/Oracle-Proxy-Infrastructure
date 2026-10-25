import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('udp_control_publisher',Path(__file__).with_name('publish_udp_control.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class PinnedUdpControl(unittest.TestCase):
    def test_pinned_public_asset_is_idempotent_and_refuses_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'downloads'/'diagnostics'
            m.install(root=root);m.install(root=root)
            target=root/m.NAME
            self.assertEqual(target.read_bytes(),m.SOURCE.read_bytes())
            self.assertEqual(target.stat().st_mode&0o777,0o644)
            target.write_bytes(b'changed')
            with self.assertRaises(ValueError):m.install(root=root)
            target.unlink();target.symlink_to(m.SOURCE)
            with self.assertRaises(ValueError):m.install(root=root)
