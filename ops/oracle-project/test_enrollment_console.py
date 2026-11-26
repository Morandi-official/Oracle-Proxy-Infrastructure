import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import ci_request
import enrollment_console as activation


def release_host():
    source = Path(__file__).resolve().parents[2] / 'server/admin-oracle/deploy/host.py'
    spec = importlib.util.spec_from_file_location('oracle_admin_host', source)
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    return host


class ConsoleEnrollmentDeploymentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        self.host = Mock(wraps=release_host())
        self.host.ROOT = directory / 'console'
        self.host.SOURCE = directory / 'source'
        self.host.UNIT_DIR = directory / 'systemd'
        self.host.UNIT_NAMES = ('oracle-proxy-admin.service',)
        self.host.APP_USER = 'oracle-proxy-admin'
        self.host.read_environment = Mock(return_value={})
        self.host.as_user = Mock()
        self.host.command = Mock()
        self.host.seal_tree = Mock()
        self.host.require_ingress_release = Mock()
        self.host.UNIT_DIR.mkdir()
        name = self.host.UNIT_NAMES[0]
        installed_unit = self.host.UNIT_DIR / name
        installed_unit.write_text('console service to be left unchanged')
        self.host.command.return_value = SimpleNamespace(stdout=f'FragmentPath={installed_unit}\nDropInPaths=\n')
        self.previous = self.host.ROOT / 'releases' / ('c' * 40)
        self.revision = 'a' * 40
        self.target = self.previous.parent / self.revision
        for location, source in ((self.previous, b'before\n'), (self.host.SOURCE, b'after\n')):
            (location / 'console').mkdir(parents=True)
            (location / activation.CLIENT_API).write_bytes(source)
            (location / 'console/test_client_api.py').write_text('test\n')
            (location / 'manage.py').write_text('unchanged\n')
            (location / 'requirements.txt').write_text('approved==1.0\n')
            (location / 'deploy').mkdir()
            (location / 'deploy' / name).write_bytes(installed_unit.read_bytes())
        for child in ('.venv', 'staticfiles'):
            (self.previous / child).mkdir()
        current = self.host.ROOT / 'current'
        current.symlink_to(self.previous)

        def switch(release):
            current.unlink()
            current.symlink_to(release)
        self.host.switch = Mock(side_effect=switch)

        def owned(path, kind):
            if not kind(path.lstat().st_mode):
                raise ValueError('CONSOLE_DEPLOYMENT_PATH_NOT_SEALED')
            return path
        actual_lstat = Path.lstat
        def lstat(path):
            info = actual_lstat(path)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
        for stub in (patch.object(Path, 'lstat', lstat),
                     patch.object(activation, 'owned', side_effect=owned),
                     patch.object(activation, 'ready', return_value=True),
                     patch.object(activation, 'BEFORE', hashlib.sha256(b'before\n').hexdigest()),
                     patch.object(activation, 'AFTER', hashlib.sha256(b'after\n').hexdigest())):
            stub.start()
            self.addCleanup(stub.stop)

    def change(self, action=activation.APPLY):
        return activation.change(self.host, {'operation': 'deploy', 'request_id': action}, self.revision)

    def test_apply_and_rollback_only_restart_console_and_keep_predecessor_immutable(self):
        self.change()
        self.assertEqual((self.host.ROOT / 'current').resolve(), self.target)
        self.assertEqual((self.previous / activation.CLIENT_API).read_bytes(), b'before\n')
        self.assertEqual((self.target / activation.CLIENT_API).read_bytes(), b'after\n')
        for child in ('.venv', 'staticfiles'):
            self.assertEqual((self.target / child).resolve(), self.previous / child)
        self.assertEqual(json.loads((self.target / activation.RECEIPT).read_text())['previous'], self.previous.name)
        self.assertEqual(self.host.as_user.call_args.args[1][1:], ['manage.py', 'check', '--deploy', '--fail-level', 'WARNING'])
        self.change(activation.ROLLBACK)
        self.assertEqual((self.host.ROOT / 'current').resolve(), self.previous)
        commands = [call.args[0] for call in self.host.command.call_args_list]
        self.assertEqual([args for args in commands if args[1] != 'show'],
                         [['systemctl', '--job-mode=ignore-dependencies', 'restart', self.host.UNIT_NAMES[0]]] * 2)

    def test_other_repository_changes_are_never_deployed(self):
        (self.host.SOURCE / 'manage.py').write_text('different app entrypoint')
        (self.previous / 'extra.json').write_text('live release asset')
        self.change()
        self.assertEqual((self.target / 'manage.py').read_bytes(), (self.previous / 'manage.py').read_bytes())
        self.assertEqual((self.target / 'extra.json').read_text(), 'live release asset')

    def test_unknown_live_source_fails_before_staging(self):
        (self.previous / activation.CLIENT_API).write_text('different active API')
        with self.assertRaisesRegex(ValueError, 'PATCH_NOT_EXACT'):
            self.change()
        self.assertFalse(self.target.exists())
        self.host.switch.assert_not_called()

    def test_repeated_apply_uses_original_predecessor_even_if_request_revision_changed(self):
        self.change()
        self.revision = 'b' * 40
        self.change()
        self.assertEqual(self.host.switch.call_count, 1)
        self.change(activation.ROLLBACK)
        self.change(activation.ROLLBACK)
        self.assertEqual(self.host.switch.call_count, 2)

    def test_reuse_authorized_dependencies_in_shared_directory(self):
        shared = self.host.ROOT / 'shared'
        shared.mkdir()
        for name in ('.venv', 'staticfiles'):
            (self.previous / name).rename(shared / name)
            (self.previous / name).symlink_to(shared / name)
        self.change()
        for name in ('.venv', 'staticfiles'):
            self.assertEqual((self.target / name).resolve(), shared / name)

    def test_reject_dependency_outside_application_root(self):
        outside = self.host.ROOT.parent / '.venv'
        (self.previous / '.venv').rename(outside)
        (self.previous / '.venv').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'DEPENDENCY_PATH_REJECTED'):
            self.change()
        self.host.switch.assert_not_called()

    def test_interrupted_staging_can_resume_without_switching_early(self):
        self.host.as_user.side_effect = subprocess.CalledProcessError(1, ['manage.py', 'check'])
        with self.assertRaises(subprocess.CalledProcessError):
            self.change()
        self.host.as_user.side_effect = None
        self.change()
        self.assertEqual(self.host.switch.call_count, 1)

    def test_reject_foreign_preexisting_target(self):
        self.target.mkdir()
        with self.assertRaises((ValueError, OSError)):
            self.change()
        self.host.switch.assert_not_called()

    def test_failed_preflight_leaves_existing_service_link_untouched(self):
        self.host.as_user.side_effect = subprocess.CalledProcessError(1, ['manage.py', 'check'])
        with self.assertRaises(subprocess.CalledProcessError):
            self.change()
        self.host.switch.assert_not_called()
        self.assertEqual((self.host.ROOT / 'current').resolve(), self.previous)

    def test_failed_restart_restores_previous_release(self):
        def command(args, **kwargs):
            if args[1] == 'show':
                return SimpleNamespace(stdout=f'FragmentPath={self.host.UNIT_DIR / self.host.UNIT_NAMES[0]}\nDropInPaths=\n')
            if (self.host.ROOT / 'current').resolve() == self.target:
                raise subprocess.CalledProcessError(1, args)
        self.host.command.side_effect = command
        with self.assertRaises(subprocess.CalledProcessError):
            self.change()
        self.assertEqual([call.args[0] for call in self.host.switch.call_args_list], [self.target, self.previous])

    def test_review_dispatch_is_read_only_and_unknown_request_is_ignored(self):
        review = {'operation': 'preflight', 'request_id': activation.REVIEW}
        self.assertTrue(activation.dispatch(self.host, 'preflight', review, self.revision))
        self.assertFalse(activation.dispatch(self.host, 'deploy', review, self.revision))
        self.assertFalse(activation.dispatch(self.host, 'preflight', dict(review, request_id='other'), self.revision))
        self.host.switch.assert_not_called()
        self.host.as_user.assert_not_called()
        self.assertFalse(self.target.exists())

    def test_non_deploy_uses_no_patch_selector(self):
        self.assertFalse(activation.enabled('preflight', {'operation': 'deploy', 'request_id': activation.APPLY}))
        self.assertFalse(activation.enabled('deploy', {'operation': 'preflight', 'request_id': activation.APPLY}))
        self.assertFalse(activation.enabled('deploy', {'operation': 'deploy', 'request_id': activation.APPLY+'-spoofed'}))


class EnrollmentRequestSelectionTests(unittest.TestCase):
    def test_review_and_stale_apply_never_trigger_an_ordinary_deployment(self):
        request = {'operation': 'preflight', 'request_id': activation.REVIEW}
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'request.json'
            file.write_text(json.dumps(request))
            with (patch.object(ci_request, 'REQUEST', str(file)),
                  patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'push', 'BEFORE_REVISION': 'a' * 40}),
                  patch.object(subprocess, 'check_output', return_value='clients/windows/product/AccountApi.cs\n') as diff):
                self.assertEqual(ci_request.choose(), 'preflight')
                with patch.dict(os.environ, {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'REQUESTED_OPERATION': 'deploy'}):
                    self.assertEqual(ci_request.choose(), 'preflight')
                request = {'operation': 'deploy', 'request_id': activation.APPLY}
                file.write_text(json.dumps(request))
                self.assertEqual(ci_request.choose(), 'preflight')
                diff.return_value = str(file) + '\n'
                self.assertEqual(ci_request.choose(), 'deploy')
