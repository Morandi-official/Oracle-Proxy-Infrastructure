import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('publish_boot_observer',Path(__file__).with_name('publish_boot_observer.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Publication(unittest.TestCase):
    def test_exact_bytes_are_immutable_and_never_executed(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d);source=parent/'source.ps1';source.write_bytes(b'fixed harmless test source\n')
            digest=hashlib.sha256(source.read_bytes()).hexdigest();root=parent/'public'
            with patch.object(m,'SOURCE',source),patch.object(m,'DIGEST',digest),patch.object(m,'ROOT',root),patch.object(m,'NAME','observer.ps1'):
                m.install();m.install();self.assertEqual((root/'observer.ps1').read_bytes(),source.read_bytes())
                source.write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'PIN_REQUIRED'):m.install()
                self.assertNotEqual((root/'observer.ps1').read_bytes(),source.read_bytes())
    def test_foreign_links_and_changed_public_files_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d);source=parent/'source.ps1';source.write_bytes(b'test')
            root=parent/'public';root.mkdir();target=root/'observer.ps1';target.symlink_to(source)
            with patch.object(m,'SOURCE',source),patch.object(m,'DIGEST',hashlib.sha256(b'test').hexdigest()),patch.object(m,'ROOT',root),patch.object(m,'NAME','observer.ps1'):
                with self.assertRaisesRegex(ValueError,'OWNED_PATH'):m.install()
                target.unlink();target.write_bytes(b'foreign')
                with self.assertRaisesRegex(ValueError,'IMMUTABLE'):m.install()

if __name__=='__main__':unittest.main()
