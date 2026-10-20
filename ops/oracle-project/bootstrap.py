"""One-time root authorization of GitHub main project operations.

Reuses exactly one public key from the existing oracle-ci account by default.
Does not read a private key, modify the old account or restart sshd.
"""
import argparse
import base64
import os
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import json
import urllib.request
from pathlib import Path

REPOSITORY = 'Morandi-official/Oracle-Proxy-Infrastructure'
ACCOUNT = 'oracle-project-ci'
CI_HOME = Path('/var/lib/oracle-project-ci')
LIBEXEC = Path('/usr/local/libexec/oracle-project')
SUDOERS = Path('/etc/sudoers.d/oracle-project-ci')


def public_key(text):
    keys = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        words = shlex.split(line)
        for index, word in enumerate(words[:-1]):
            if word not in ('ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'):
                continue
            try:
                value = base64.b64decode(words[index + 1], validate=True)
                if len(value) < 32:
                    raise ValueError()
            except Exception:
                raise ValueError('Invalid SSH public key') from None
            keys.append(word + ' ' + words[index + 1]); break
    if len(keys) != 1:
        raise ValueError('Exactly one CI public key is required; select --public-key-file explicitly if needed')
    return keys[0]


def write_owned(path, body, mode):
    if path.is_symlink():
        raise ValueError('Refuse a symlink at a project authorization path')
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.oracle-project-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def install(revision, key_file=None, local_source=None):
    if os.geteuid() != 0 or not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Root administrator and exact reviewed commit required')
    if not shutil.which('visudo') or not shutil.which('sudo'):
        raise ValueError('Install the system sudo package before authorizing this bridge')
    if key_file is None:
        key_file = Path(pwd.getpwnam('oracle-ci').pw_dir) / '.ssh/authorized_keys'
    key_file = Path(key_file)
    if key_file.stat().st_size > 65536:
        raise ValueError('Unexpected CI authorized_keys size')
    key = public_key(key_file.read_text())
    sources = {}
    for name in ('ssh_entry.py', 'gate.py'):
        if local_source is not None:
            # Used only by the separately authorized disposable CI harness.
            sources[name] = (Path(local_source) / name).read_bytes()
        else:
            url = f'https://raw.githubusercontent.com/{REPOSITORY}/{revision}/ops/oracle-project/{name}'
            with urllib.request.urlopen(url, timeout=30) as response:
                sources[name] = response.read(131073)
            if len(sources[name]) > 131072:
                raise ValueError('Unexpected bridge source size')
        compile(sources[name], name, 'exec')
    rule = (f'{ACCOUNT} ALL=(root) NOPASSWD: /usr/bin/python3 -I {LIBEXEC}/gate.py *\n').encode()
    with tempfile.NamedTemporaryFile(prefix='oracle-project-sudo-', delete=False) as stream:
        stream.write(rule); candidate = stream.name
    try:
        subprocess.run(['visudo', '-cf', candidate], check=True, stdout=subprocess.DEVNULL)
    finally:
        os.unlink(candidate)
    try:
        existing = pwd.getpwnam(ACCOUNT)
        if existing.pw_dir != str(CI_HOME):
            raise ValueError('Refuse a foreign account with the project CI username')
    except KeyError:
        subprocess.run(['useradd', '--system', '--user-group', '--home-dir', str(CI_HOME),
                        '--shell', '/bin/sh', ACCOUNT], check=True)
    # '*' disables password matching without sshd treating the account as administratively locked.
    subprocess.run(['usermod', '--password', '*', ACCOUNT], check=True)
    if CI_HOME.is_symlink() or LIBEXEC.is_symlink():
        raise ValueError('Project authorization directories cannot be symlinks')
    protected = [LIBEXEC / 'ssh_entry.py', LIBEXEC / 'gate.py', SUDOERS,
                 CI_HOME / '.ssh/authorized_keys']
    snapshots = Path('/var/backups/oracle-project-authorization')
    snapshots.mkdir(mode=0o700, parents=True, exist_ok=True)
    snapshot = {}
    for path in protected:
        if path.is_symlink(): raise ValueError('Authorization file cannot be a symlink')
        snapshot[str(path)] = base64.b64encode(path.read_bytes()).decode() if path.exists() else None
    write_owned(snapshots / (str(time.time_ns()) + '.json'),
                json.dumps({'revision': revision, 'files': snapshot}).encode(), 0o600)
    CI_HOME.mkdir(mode=0o755, parents=True, exist_ok=True); CI_HOME.chmod(0o755)
    os.chown(CI_HOME, 0, 0)
    for name, body in sources.items():
        write_owned(LIBEXEC / name, body, 0o644)
    if (CI_HOME / '.ssh').is_symlink():
        raise ValueError('SSH authorization directory cannot be a symlink')
    (CI_HOME / '.ssh').mkdir(mode=0o755, exist_ok=True)
    (CI_HOME / '.ssh').chmod(0o755); os.chown(CI_HOME / '.ssh', 0, 0)
    forced = f'command="/usr/bin/python3 -I {LIBEXEC}/ssh_entry.py",restrict {key}\n'
    write_owned(CI_HOME / '.ssh/authorized_keys', forced.encode(), 0o644)
    write_owned(SUDOERS, rule, 0o440)
    subprocess.run(['visudo', '-cf', str(SUDOERS)], check=True, stdout=subprocess.DEVNULL)
    print('ORACLE_PROJECT_CI_AUTHORIZATION=READY')
    print('TRUST=Current main of ' + REPOSITORY + ' may execute project operations as root')
    print('Existing oracle-ci key authorization and SSH daemon configuration retained')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--public-key-file')
    args = parser.parse_args()
    try:
        install(args.revision, args.public_key_file)
    except Exception:
        print('PROJECT_CI_AUTHORIZATION_FAILED_CHECK_PREREQUISITES', file=sys.stderr)
        raise SystemExit(2) from None
