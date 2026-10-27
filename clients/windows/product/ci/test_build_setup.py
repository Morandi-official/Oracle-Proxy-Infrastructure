"""Meaningful archive boundary regressions for the elevated setup payload."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess
import zipfile

spec = importlib.util.spec_from_file_location('setup_build', Path(__file__).with_name('build-setup.py'))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class SetupBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.metadata = {'version': '0.3.0-rc21', 'source_revision': 'a' * 40,
                         'publisher_signed': False, 'real_oracle_acceptance_passed': True,
                         'payload_sha256': {name: hashlib.sha256(name.encode()).hexdigest() for name in build.PAYLOADS}}

    def archive(self, extra=None, changed=False):
        path = self.root / 'portable.zip'
        with zipfile.ZipFile(path, 'w') as z:
            for name in build.PAYLOADS:
                z.writestr(name, b'tampered' if changed else name.encode())
            z.writestr('BUILD.json', json.dumps(self.metadata))
            z.writestr('SHA256SUMS.txt', 'test manifest')
            z.writestr('请先阅读.txt', '用户说明'.encode('utf-8'))
            z.writestr('licenses/OracleProxy-GPL-3.0.txt', 'test license')
            if extra:
                z.writestr(extra, 'untrusted')
        return path

    def test_iscc_normal_help_exit_one_and_zero_are_identity_only(self):
        for code in (0, 1):
            with self.subTest(code=code), patch.object(build.subprocess, 'run', return_value=subprocess.CompletedProcess(['iscc', '/?'], code, 'Inno Setup 6 Command-Line Compiler\nCopyright test\n')) as run:
                self.assertEqual(build.compiler_identity(Path('ISCC.exe')), 'Inno Setup 6 Command-Line Compiler')
                self.assertFalse(run.call_args.kwargs['check'])
                self.assertEqual(run.call_args.kwargs['timeout'], 15)

    def test_iscc_failure_or_non_compiler_output_is_not_accepted(self):
        for code, output in ((2, 'Inno Setup 6 Command-Line Compiler\n'), (1, 'Error: unsupported command\n'), (0, '')):
            with self.subTest(code=code, output=output), patch.object(build.subprocess, 'run', return_value=subprocess.CompletedProcess(['iscc', '/?'], code, output)):
                with self.assertRaisesRegex(ValueError, 'IDENTITY_PROBE_FAILED'):
                    build.compiler_identity(Path('ISCC.exe'))

    def test_exact_pinned_product_payload_and_notices_only(self):
        stage = self.root / 'payload'
        build.stage_bundle(self.archive(), self.metadata, stage)
        self.assertEqual((stage / 'OracleProxy.exe').read_bytes(), b'OracleProxy.exe')
        self.assertEqual((stage / 'licenses/OracleProxy-GPL-3.0.txt').read_text(), 'test license')
        self.assertEqual((stage / '请先阅读.txt').read_text(encoding='utf-8-sig'), '用户说明')

    def test_path_traversal_extra_program_and_state_are_rejected(self):
        for index, name in enumerate(('../outside', 'licenses/../../outside', 'licenses/Bad.exe', 'state.dpapi', 'unexpected.txt')):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'ENTRY_REJECTED'):
                build.stage_bundle(self.archive(name), self.metadata, self.root / str(index))
        self.assertFalse((self.root / 'outside').exists())

    def test_changed_payload_and_metadata_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'PAYLOAD_DIGEST_MISMATCH'):
            build.stage_bundle(self.archive(changed=True), self.metadata, self.root / 'changed')
        archive = self.archive()
        with self.assertRaisesRegex(ValueError, 'METADATA_MISMATCH'):
            build.stage_bundle(archive, dict(self.metadata, source_revision='b' * 40), self.root / 'metadata')


if __name__ == '__main__':
    unittest.main()
