import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import io
spec=importlib.util.spec_from_file_location('publish_diagnostic',Path(__file__).with_name('publish_port_diagnostic.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PinnedDiagnostic(unittest.TestCase):
    def test_exact_bytes_and_idempotent_publish_but_refuse_tamper_or_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'downloads'/'diagnostics'
            m.install(root=root);m.install(root=root)
            target=root/m.NAME
            self.assertEqual(target.read_bytes(),m.SOURCE.read_bytes())
            target.write_bytes(b'changed')
            with self.assertRaises(ValueError):m.install(root=root)
            target.unlink();target.symlink_to(m.SOURCE)
            with self.assertRaises(ValueError):m.install(root=root)
            bad=Path(tmp)/'bad.ps1';bad.write_bytes(b'changed')
            with self.assertRaises(ValueError):m.install(source=bad,root=root)

    def test_public_served_bytes_are_verified_not_just_local_copy(self):
        url='https://vpn-admin.morandi.dpdns.org/downloads/diagnostics/'+m.NAME
        for body,valid in ((m.SOURCE.read_bytes(),True),(b'changed',False),(b'x'*16385,False)):
            response=io.BytesIO(body);response.geturl=lambda:url
            with patch('urllib.request.urlopen',return_value=response):
                if valid:m.verify_public()
                else:
                    with self.assertRaises(ValueError):m.verify_public()
