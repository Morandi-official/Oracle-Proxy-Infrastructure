import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('downloads',Path(__file__).with_name('downloads.py'))
downloads = importlib.util.module_from_spec(spec); spec.loader.exec_module(downloads)


class MirrorTests(unittest.TestCase):
    def test_manifest_accepts_only_exact_versioned_public_release_paths(self):
        prefix='OracleProxy-0.3.0-rc14-win-x64-'+('a'*12)
        value={'version':'v0.3.0-rc14','source_revision':'a'*40,'assets':[
            {'name':name,'size':10,'sha256':'b'*64} for name in
            (prefix+'.zip',prefix+'-source.zip','BUILD.json','SHA256SUMS.txt')]}
        with tempfile.TemporaryDirectory() as directory,patch.object(downloads,'MANIFEST',Path(directory)/'manifest.json'):
            downloads.MANIFEST.write_text(json.dumps(value))
            self.assertEqual(downloads.manifest(),value)
            for invalid in (dict(value,version='../other'),dict(value,source_revision='main'),dict(value,assets=value['assets'][:1])):
                downloads.MANIFEST.write_text(json.dumps(invalid))
                with self.assertRaises(ValueError):downloads.manifest()

    def test_installer_mirror_requires_the_exact_versioned_setup_name(self):
        prefix='OracleProxy-0.3.0-rc21-win-x64-'+('a'*12)
        value={'version':'v0.3.0-rc21','source_revision':'a'*40,'assets':[
            {'name':name,'size':10,'sha256':'b'*64} for name in
            (prefix+'.zip',prefix+'-source.zip',prefix+'-setup.exe','BUILD.json','SHA256SUMS.txt')]}
        with tempfile.TemporaryDirectory() as directory,patch.object(downloads,'MANIFEST',Path(directory)/'manifest.json'):
            downloads.MANIFEST.write_text(json.dumps(value));self.assertEqual(downloads.manifest(),value)
            value['assets'][2]['name']='foreign.exe';downloads.MANIFEST.write_text(json.dumps(value))
            with self.assertRaises(ValueError):downloads.manifest()

    def test_download_verifies_size_hash_and_redirect_before_publication(self):
        item={'size':4,'sha256':hashlib.sha256(b'good').hexdigest()}
        class Response(io.BytesIO): url='https://release-assets.githubusercontent.com/public'
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'asset'
            for body in (b'bad!',b'oversize'):
                with self.subTest(body=body), patch.object(downloads.urllib.request,'urlopen',return_value=Response(body)):
                    with self.assertRaises(ValueError): downloads.fetch('https://github.com/public',target,item)
                    self.assertFalse(target.exists())
            with patch.object(downloads.urllib.request,'urlopen',return_value=Response(b'good')):
                downloads.fetch('https://github.com/public',target,item)
            self.assertTrue(downloads.matches(target,item))
            target.unlink()
            bad=Response(b'good');bad.url='https://untrusted.example/public'
            with patch.object(downloads.urllib.request,'urlopen',return_value=bad):
                with self.assertRaises(ValueError): downloads.fetch('https://github.com/public',target,item)
            self.assertFalse(target.exists())

    def test_failure_never_publishes_partial_version_or_leaves_staging(self):
        manifest={'version':'v0.3.0-rc14','assets':[{'name':'first'},{'name':'second'}]}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'public'
            calls=[]
            def download(url,path,item):
                calls.append(path)
                self.assertNotIn(root,path.parents)
                path.write_bytes(b'partial')
                if len(calls)==2: raise ValueError('SYNTHETIC_DOWNLOAD_FAILURE')
            with patch.object(downloads,'manifest',return_value=manifest),patch.object(downloads,'fetch',side_effect=download):
                with self.assertRaises(ValueError):downloads.install(root)
            self.assertEqual(list(root.iterdir()),[])
            self.assertEqual(list(Path(directory).iterdir()),[root])

    def test_root_symlink_and_unexpected_existing_version_are_refused(self):
        manifest={'version':'v0.3.0-rc14','assets':[]}
        with tempfile.TemporaryDirectory() as directory,patch.object(downloads,'manifest',return_value=manifest):
            parent=Path(directory);root=parent/'root';root.symlink_to(parent,target_is_directory=True)
            with self.assertRaises(ValueError):downloads.install(root)
            root.unlink();root.mkdir();version=root/manifest['version'];version.mkdir();(version/'foreign').touch()
            with self.assertRaises(ValueError):downloads.install(root)


if __name__=='__main__':unittest.main()
