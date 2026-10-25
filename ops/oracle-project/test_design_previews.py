import importlib.util
import tempfile
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('design_previews',Path(__file__).with_name('design_previews.py'))
previews=importlib.util.module_from_spec(spec);spec.loader.exec_module(previews)


class PreviewTests(unittest.TestCase):
    def test_exact_four_images_publish_and_repeat_without_touching_vpn_releases(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'public';root.mkdir();(root/'existing-vpn.zip').write_bytes(b'untouched')
            previews.install(root)
            target=root/previews.VERSION
            self.assertEqual({p.name for p in target.iterdir()},set(previews.PINS))
            previews.install(root)
            self.assertEqual((root/'existing-vpn.zip').read_bytes(),b'untouched')
            path=next(target.iterdir());path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'DIGEST'):previews.install(root)

    def test_corrupt_source_or_link_never_publishes_partial_images(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);source=base/'source';source.mkdir();root=base/'public'
            for name in previews.PINS:(source/name).write_bytes((previews.SOURCE/name).read_bytes())
            name=next(iter(previews.PINS));(source/name).write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'DIGEST'):previews.install(root,source)
            self.assertFalse(root.exists())
            (source/name).unlink();(source/name).symlink_to(previews.SOURCE/name)
            with self.assertRaisesRegex(ValueError,'REGULAR'):previews.install(root,source)
            self.assertFalse(root.exists())

    def test_public_root_link_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);root=base/'linked';root.symlink_to(base,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'LINK'):previews.install(root)
