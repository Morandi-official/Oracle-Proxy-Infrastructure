"""Disposable-only root test for actual SSH forced command and sudo isolation.

Creates ephemeral test keys; never uses or uploads a real user's key.
"""
import importlib.util
import contextlib
import io
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch


def main():
    if not (os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true' and
            os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
            os.environ.get('GITHUB_REPOSITORY') == 'Morandi-official/Oracle-Proxy-Infrastructure' and
            os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI') == '1'):
        raise SystemExit('Disposable GitHub-hosted CI required')
    root = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('bootstrap', root / 'bootstrap.py')
    bootstrap = importlib.util.module_from_spec(spec); spec.loader.exec_module(bootstrap)
    with tempfile.TemporaryDirectory(prefix='oracle-project-ssh-', dir='/tmp') as temporary:
        directory = Path(temporary)
        key, hostkey = directory / 'ci-key', directory / 'host-key'
        for target in (key, hostkey):
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(target)], check=True)
        bootstrap.install('a'*40, Path(str(key)+'.pub'), local_source=root)
        public_host = Path(str(hostkey)+'.pub').read_text().split()
        known = directory / 'known_hosts'
        known.write_text('[127.0.0.1]:22022 ' + ' '.join(public_host[:2]) + '\n')
        config = directory / 'sshd_config'
        config.write_text(f'''Port 22022
ListenAddress 127.0.0.1
HostKey {hostkey}
PidFile {directory}/sshd.pid
AuthorizedKeysFile %h/.ssh/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
StrictModes yes
AllowUsers oracle-project-ci
AllowTcpForwarding no
X11Forwarding no
''')
        Path('/run/sshd').mkdir(exist_ok=True)
        daemon = subprocess.Popen(['/usr/sbin/sshd','-D','-f',str(config),'-E',str(directory/'sshd.log')])
        try:
            for _ in range(30):
                try:
                    with socket.create_connection(('127.0.0.1',22022),timeout=1): break
                except OSError: time.sleep(.1)
            ssh = ['ssh','-T','-p','22022','-i',str(key),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                   '-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={known}',
                   'oracle-project-ci@127.0.0.1']
            result = subprocess.run(ssh + ['id'], capture_output=True, text=True, check=False)
            if result.returncode != 2:
                print(result.stderr)
                print((directory/'sshd.log').read_text())
            assert result.returncode == 2, 'SSH test identity could not authenticate or forced command failed'
            assert 'SSH_COMMAND_REJECTED' in result.stderr
            assert 'uid=0' not in result.stdout
            user = ['/usr/sbin/runuser','-u','oracle-project-ci','--']
            denied = subprocess.run(user + ['/usr/bin/sudo','-n','/usr/bin/id'], capture_output=True, check=False)
            assert denied.returncode != 0, 'CI identity unexpectedly has unrestricted sudo'
            malformed = subprocess.run(user + ['/usr/bin/sudo','-n','/usr/bin/python3','-I',
                                       '/usr/local/libexec/oracle-project/gate.py','sh','a'*40],
                                       capture_output=True, text=True, check=False)
            assert malformed.returncode == 2
            assert 'PROJECT_OPERATION_REJECTED_OR_UNAVAILABLE' in malformed.stderr
            assert bootstrap.SUDOERS.stat().st_mode & 0o777 == 0o440
            assert (bootstrap.CI_HOME/'.ssh/authorized_keys').stat().st_uid == 0
            gate_spec = importlib.util.spec_from_file_location('project_gate', root / 'gate.py')
            gate = importlib.util.module_from_spec(gate_spec); gate_spec.loader.exec_module(gate)
            # Mock only GitHub transport: the reviewed operation runs in a real
            # separate root process, through the same argument/env validation.
            with patch.dict(os.environ, {'SUDO_USER':'oracle-project-ci'}), patch.object(gate, 'ROOT', directory/'gate-state'), patch.object(gate, 'verify_main'), patch.object(gate, 'source_tree', return_value=root.parents[1]):
                assert gate.main(['preflight', 'a'*40]) == 0
            operations_spec = importlib.util.spec_from_file_location('project_operations', root / 'project_operations.py')
            operations = importlib.util.module_from_spec(operations_spec); operations_spec.loader.exec_module(operations)
            before = operations.host.read_environment()
            stream = io.StringIO(); secret = 'synthetic_ci_oauth_credential_1234567890'
            with contextlib.redirect_stdout(stream):
                operations.configure(__import__('json').dumps({'client_id':'syntheticCIClient123','client_secret':secret}).encode())
            after = operations.host.read_environment()
            assert before['ADMIN_SECRET_KEY'] == after['ADMIN_SECRET_KEY']
            assert before['ADMIN_MFA_ENCRYPTION_KEY'] == after['ADMIN_MFA_ENCRYPTION_KEY']
            assert secret not in stream.getvalue()
            assert operations.host.CONFIG.stat().st_mode & 0o777 == 0o600
            print('DISPOSABLE_ROOT_MAIN_OPERATION_DELEGATION_AND_SECRET_CONFIGURATION=PASS')
            print('DISPOSABLE_REAL_SSH_PUBLICKEY_AUTH_FORCED_COMMAND_AND_FIXED_SUDO_DENIAL=PASS')
        finally:
            daemon.terminate(); daemon.wait(timeout=5)


if __name__ == '__main__': main()
