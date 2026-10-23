import base64
import importlib.util
import io
import json
import stat
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


entry, gate, bootstrap, operations, request = [module(name) for name in
    ('ssh_entry', 'gate', 'bootstrap', 'project_operations', 'ci_request')]
REVISION = 'a' * 40
PREFIX = 'Oracle-Proxy-Infrastructure-' + REVISION + '/'
PUBLIC = 'ssh-ed25519 ' + base64.b64encode(struct.pack('>I', 11) + b'ssh-ed25519' +
                                          struct.pack('>I', 32) + bytes(range(32))).decode()


class BridgeTests(unittest.TestCase):
    def archive(self, additions=()):
        body = io.BytesIO()
        with zipfile.ZipFile(body, 'w') as archive:
            archive.writestr(PREFIX + 'ops/oracle-project/project_operations.py', '# fixture')
            for name, value in additions: archive.writestr(name, value)
        return zipfile.ZipFile(io.BytesIO(body.getvalue()))

    def test_only_fixed_operation_and_exact_revision_cross_ssh_boundary(self):
        self.assertEqual(entry.parse_command('preflight ' + REVISION), ['preflight', REVISION])
        for command in ('sh', 'sudo bash', 'scp -t /tmp/x', 'status main', 'status ' + REVISION + ';id',
                        'status ' + REVISION + '\nid', 'status ' + REVISION + ' extra',
                        'status  ' + REVISION, 'status ' + REVISION.upper()):
            with self.subTest(command=command), self.assertRaises(ValueError): entry.parse_command(command)

    def test_root_gate_rechecks_caller_and_arguments_before_network_or_source(self):
        with patch.object(gate.os, 'geteuid', return_value=1000), patch.object(gate, 'download') as download:
            with self.assertRaises(ValueError): gate.main(['preflight', REVISION])
            download.assert_not_called()
        with patch.object(gate.os, 'geteuid', return_value=0), patch.dict(gate.os.environ, {'SUDO_USER':'oracle-project-ci'}), patch.object(gate, 'download') as download:
            for arguments in (['sh', REVISION], ['status', '../../etc'], ['status', REVISION, 'exec']):
                with self.assertRaises(ValueError): gate.main(arguments)
            download.assert_not_called()

    def test_current_main_is_verified_even_if_a_previous_source_is_cached(self):
        with patch.object(gate, 'download', return_value=json.dumps({'object':{'sha':'b'*40}}).encode()):
            with self.assertRaises(ValueError): gate.verify_main(REVISION)
        with patch.object(gate, 'download', return_value=json.dumps({'object':{'sha':REVISION}}).encode()) as download:
            gate.verify_main(REVISION)
            self.assertIn('/Morandi-official/Oracle-Proxy-Infrastructure/git/ref/heads/main', download.call_args.args[0])

    def test_archive_accepts_repository_source_and_rejects_traversal_duplicates_and_links(self):
        with self.archive() as archive:
            self.assertEqual(len(gate.validated_members(archive, REVISION)), 1)
        for name in (PREFIX + '../etc/shadow', PREFIX + '/etc/shadow', PREFIX + 'config/../../etc',
                     'other-repository/ops/oracle-project/project_operations.py', PREFIX + 'config\\x.py',
                     PREFIX + 'ops/oracle-project/project_operations.py'):
            with self.subTest(name=name), self.archive([(name, 'fixture')]) as archive, self.assertRaises(ValueError):
                gate.validated_members(archive, REVISION)
        symlink = zipfile.ZipInfo(PREFIX + 'link')
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.archive([(symlink, '/etc/shadow')]) as archive, self.assertRaises(ValueError):
            gate.validated_members(archive, REVISION)

    def test_archive_size_and_required_operations_are_enforced(self):
        with self.archive() as archive:
            archive.infolist()[0].file_size = gate.MAX_EXPANDED + 1
            with self.assertRaises(ValueError): gate.validated_members(archive, REVISION)
        body = io.BytesIO()
        with zipfile.ZipFile(body, 'w') as archive: archive.writestr(PREFIX + 'README.md', 'empty')
        with zipfile.ZipFile(io.BytesIO(body.getvalue())) as archive, self.assertRaises(ValueError):
            gate.validated_members(archive, REVISION)

    def test_public_key_reuses_only_one_selected_public_identity(self):
        text = 'command="/usr/local/bin/old-gate",restrict ' + PUBLIC + ' ci-key\n'
        self.assertEqual(bootstrap.public_key(text), PUBLIC)
        for value in ('', '-----BEGIN OPENSSH PRIVATE KEY-----', PUBLIC + '\n' + PUBLIC,
                      'ssh-ed25519 not-base64', 'ssh-ed25519 YQ=='):
            with self.subTest(value=value[:40]), self.assertRaises(ValueError): bootstrap.public_key(value)

    def test_configuration_cannot_set_commands_paths_identity_or_inject_environment(self):
        good = {'client_id':'Ov23liYD7HIQdS5nDjpS', 'client_secret':'synthetic_secret_1234567890'}
        self.assertEqual(operations.parse_configuration(json.dumps(good).encode()), good)
        for value in ({**good, 'path':'/etc/shadow'}, {**good, 'command':'sudo sh'},
                      {**good, 'client_id':'id\nADMIN_GITHUB_IDS=attacker'},
                      {**good, 'client_secret':'bad\nENV=x'}, [], None):
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                operations.parse_configuration(json.dumps(value).encode())
        with self.assertRaises(ValueError): operations.parse_configuration(b'x'*4097)

    def test_gitops_manifest_cannot_include_secrets_or_arbitrary_arguments(self):
        self.assertEqual(request.parse_request(b'{"operation":"preflight","request_id":"a-1"}'), 'preflight')
        for value in ({'operation':'sh','request_id':'x'}, {'operation':'status;id','request_id':'x'},
                      {'operation':[], 'request_id':'x'}, {'operation':'status','request_id':'x','client_secret':'secret'},
                      {'operation':'status','request_id':'../../tmp'}):
            with self.assertRaises(ValueError): request.parse_request(json.dumps(value).encode())

    def test_explicit_manifest_can_request_status_with_a_diagnostics_code_change(self):
        with patch.dict(request.os.environ, {'GITHUB_EVENT_NAME':'push', 'BEFORE_REVISION':REVISION}), patch.object(request.subprocess, 'check_output', return_value=request.REQUEST + '\nops/oracle-project/project_operations.py\n'), patch.object(request.Path, 'read_bytes', return_value=b'{"operation":"status","request_id":"diagnostics-1"}'):
            self.assertEqual(request.choose(), 'status')

    def test_root_owned_file_writer_rejects_symlink_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / 'target'; target.write_text('unchanged')
            link = root / 'link'; link.symlink_to(target)
            with self.assertRaises(ValueError): bootstrap.write_owned(link, b'bad', 0o600)
            self.assertEqual(target.read_text(), 'unchanged')

    def test_failed_https_validation_restores_existing_hosts_and_owned_snippet(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); main = root / 'Caddyfile'; snippets = root / 'owned'
            snippets.mkdir(); snippet = snippets / 'admin.caddy'
            main.write_bytes(b'example.com { respond "existing site" }\n'); main.chmod(0o640)
            snippet.write_bytes(b'previous owned configuration\n')
            with patch.object(operations, 'CADDY_MAIN', main), patch.object(operations, 'CADDY_DIRECTORY', snippets), patch.object(operations, 'WEB_BACKUPS', root / 'backups'), patch.object(operations, 'run', side_effect=RuntimeError('synthetic validation failure')), patch.object(operations.subprocess, 'run'):
                with self.assertRaises(RuntimeError): operations.enable_https()
            self.assertEqual(main.read_bytes(), b'example.com { respond "existing site" }\n')
            self.assertEqual(main.stat().st_mode & 0o777, 0o640)
            self.assertEqual(snippet.read_bytes(), b'previous owned configuration\n')
            self.assertFalse((root / '.oracle-project-candidate').exists())


if __name__ == '__main__': unittest.main()
