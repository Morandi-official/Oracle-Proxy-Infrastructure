"""Packaging boundary tests with disposable synthetic inputs, never real credentials."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('candidate', Path(__file__).with_name('package-candidate.py'))
candidate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate)


class PackageBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.product = self.root / 'clients/windows/product'
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(candidate, 'ROOT', self.root))
        self.patches.enter_context(patch.object(candidate, 'PRODUCT', self.product))
        self.patches.enter_context(patch.dict('os.environ', {
            'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
            'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'push',
            'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1', 'RUNNER_TEMP': str(self.root / 'temp')}))
        self.put('clients/windows/product/COPYING', 'test GPL notice')
        self.put('clients/windows/product/LICENSE', 'test copyright notice')
        self.put('clients/windows/product/PORTABLE_README.zh-CN.txt', 'test instructions')
        self.put('clients/windows/product/core/go.mod', 'module example.test/core')
        self.put('clients/windows/product/core/go.sum', 'test sum')
        self.put('clients/windows/product/core/vendor/modules.txt', '# example.test v1')
        self.put('clients/windows/product/core/vendor/example.test/COPYING', 'test dependency license')
        self.put('clients/windows/product/core/vendor/example.test/core.go', 'package core')
        self.put('temp/oracle-official-wintun/LICENSE', 'test upstream distribution license')
        for name in candidate.PAYLOADS:
            self.put('dist/product/' + name, name)
        self.put('dist/product/OracleProxy.Product.Tests.exe', 'forbidden harness')
        self.put('dist/product/secret.dpapi', 'forbidden state')
        self.put('clients/windows/product/BuildPins.cs', '\n'.join(candidate.digest(self.root / 'dist/product' / name) for name in candidate.PAYLOADS))
        self.put('nuget/example/1.0/LICENSE', 'test NuGet license')
        self.put('nuget/example/1.0/example.nuspec', '<package><metadata><repository url="https://example.test/source" commit="123"/></metadata></package>')
        assets = {'packageFolders': {str(self.root / 'nuget'): {}},
                  'libraries': {'example/1.0': {'type': 'package'}},
                  'project': {'frameworks': {}}}
        self.put('clients/windows/product/obj/project.assets.json', json.dumps(assets))
        tracked = '\n'.join('clients/windows/product/' + p for p in ('COPYING', 'LICENSE', 'BuildPins.cs', 'PORTABLE_README.zh-CN.txt'))
        self.patches.enter_context(patch.object(candidate, 'run', side_effect=lambda *args, **kw: 'a' * 40 if args[1] == 'rev-parse' else tracked))

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding='utf-8')
        return path

    def invoke(self, accepted=False):
        with patch('sys.argv', ['package-candidate.py'] + (['--acceptance-passed'] if accepted else [])), contextlib.redirect_stdout(io.StringIO()):
            candidate.main()

    def test_only_product_payloads_ship_with_notices_and_actual_source(self):
        self.invoke(True)
        out = self.root / 'dist/candidate'
        bundle = next(p for p in out.glob('*.zip') if not p.name.endswith('-source.zip'))
        with zipfile.ZipFile(bundle) as archive:
            names = archive.namelist()
            self.assertEqual({p for p in names if p.endswith(('.exe', '.dll'))}, set(candidate.PAYLOADS))
            self.assertFalse(any('dpapi' in p for p in names))
            self.assertIn('licenses/nuget/example/1.0/LICENSE', names)
            self.assertTrue(json.loads(archive.read('BUILD.json'))['real_oracle_acceptance_passed'])
        with zipfile.ZipFile(next(out.glob('*-source.zip'))) as archive:
            self.assertIn('clients/windows/product/core/vendor/example.test/core.go', archive.namelist())
            self.assertFalse(any('obj/' in p or 'secret' in p for p in archive.namelist()))
        self.assertEqual(len((out / 'SHA256SUMS.txt').read_text().splitlines()), 2)

    def test_mismatched_payload_is_rejected(self):
        self.put('dist/product/OracleProxy.Core.exe', 'tampered core')
        with self.assertRaisesRegex(RuntimeError, 'compiled build pins'):
            self.invoke()

    def test_missing_license_and_untrusted_acceptance_context_are_rejected(self):
        (self.root / 'nuget/example/1.0/LICENSE').unlink()
        with self.assertRaisesRegex(RuntimeError, 'license material missing'):
            self.invoke()
        with patch.dict('os.environ', {'GITHUB_REF': 'refs/pull/1/merge'}):
            with self.assertRaisesRegex(RuntimeError, 'main push'):
                self.invoke(True)


if __name__ == '__main__':
    unittest.main()
