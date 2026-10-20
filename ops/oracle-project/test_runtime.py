import hashlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime_install', Path(__file__).with_name('runtime_install.py'))
runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def test_checksum_failure_never_leaves_installable_artifact(self):
        class Response(io.BytesIO): url = 'https://release-assets.githubusercontent.com/synthetic'
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'artifact'
            with patch.object(runtime.urllib.request, 'urlopen', return_value=Response(b'wrong')):
                with self.assertRaises(ValueError): runtime.fetch_verified('https://github.com/synthetic', '0'*64, target)
            self.assertFalse(target.exists())
            with patch.object(runtime.urllib.request, 'urlopen', return_value=Response(b'correct')):
                runtime.fetch_verified('https://github.com/synthetic', hashlib.sha256(b'correct').hexdigest(), target)
            self.assertEqual(target.read_bytes(), b'correct')

    def test_tar_links_are_internal_and_cannot_redirect_member_writes(self):
        for name, link, extra, accepted in (
            ('python/bin/python3', 'python3.12', None, True),
            ('python/link', '/etc', None, False),
            ('python/link', '../../outside', None, False),
            ('python/link', 'lib', 'python/link/overwrite', False),
            ('../outside', None, None, False),
        ):
            with self.subTest(name=name, link=link), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); archive_path = root / 'archive.tgz'; stage = root / 'stage'; stage.mkdir()
                with tarfile.open(archive_path, 'w:gz') as archive:
                    item = tarfile.TarInfo(name)
                    if link: item.type = tarfile.SYMTYPE; item.linkname = link
                    archive.addfile(item)
                    if extra: archive.addfile(tarfile.TarInfo(extra))
                if accepted:
                    runtime.extract_python(archive_path, stage)
                    self.assertTrue((stage / name).is_symlink())
                else:
                    with self.assertRaises(ValueError): runtime.extract_python(archive_path, stage)
                    self.assertEqual(list(stage.iterdir()), [])


if __name__ == '__main__': unittest.main()
