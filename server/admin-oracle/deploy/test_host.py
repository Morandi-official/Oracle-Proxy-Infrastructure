import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('host', Path(__file__).with_name('host.py'))
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class HostBoundaries(unittest.TestCase):
    def candidate(self, root):
        (root / 'manage.py').write_text('# synthetic application fixture\n')
        (root / 'requirements.txt').write_text('Django==5.2.18\n')

    def test_dependency_flags_urls_and_local_paths_cannot_enter_privileged_deployment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.candidate(root)
            for line in ('-e .', 'https://attacker.example.com/package.tar.gz',
                         '--index-url https://example.com', '../setup.py', 'Django>=5'):
                (root / 'requirements.txt').write_text(line)
                with self.subTest(line=line), self.assertRaises(ValueError):
                    host.source_files(root)

    def test_source_symlinks_and_missing_application_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.candidate(root)
            (root / 'malicious.py').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): host.source_files(root)
            (root / 'malicious.py').unlink(); (root / 'manage.py').unlink()
            with self.assertRaises(ValueError): host.source_files(root)

    def test_test_harnesses_and_env_credentials_are_not_installed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); self.candidate(root)
            for name in ('tests.py', 'test_settings.py', '.env'):
                (root / name).write_text('synthetic')
            paths = {str(relative) for _, relative in host.source_files(root)}
            self.assertEqual(paths, {'manage.py', 'requirements.txt'})

    def test_revision_validation_precedes_any_host_command(self):
        with patch.object(host, 'command') as command:
            for revision in ('../wg0', 'main', '', 'a'*39, 'A'*40):
                with self.subTest(revision=revision), self.assertRaises(ValueError):
                    host.install(revision)
            command.assert_not_called()


if __name__ == '__main__': unittest.main()
