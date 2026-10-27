"""Compile the EXE installer from only the verified portable distribution.

No credentials, downloads, signing impersonation or arbitrary dist copying.
Run after package-candidate.py, before installer acceptance and artifact upload.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[4]
PAYLOADS = {'OracleProxy.exe', 'OracleProxy.Core.exe', 'OracleProxy.Guard.dll'}
TEXT = {'BUILD.json', 'SHA256SUMS.txt', '请先阅读.txt'}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def stage_bundle(bundle, metadata, stage):
    if stage.exists():
        raise ValueError('INSTALLER_STAGE_MUST_BE_NEW')
    stage.mkdir(parents=True)
    with zipfile.ZipFile(bundle) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or len(names) > 20000:
            raise ValueError('INSTALLER_ARCHIVE_ENTRIES_REJECTED')
        embedded = json.loads(archive.read('BUILD.json'))
        for key in ('version', 'source_revision', 'payload_sha256', 'publisher_signed', 'real_oracle_acceptance_passed'):
            if embedded.get(key) != metadata.get(key):
                raise ValueError('INSTALLER_PORTABLE_METADATA_MISMATCH')
        total = 0
        for entry in archive.infolist():
            name = entry.filename
            path = PurePosixPath(name)
            if ('\\' in name or path.is_absolute() or any(part in ('', '.', '..') for part in name.split('/')) or
                    entry.is_dir() or (entry.external_attr >> 16) & 0o170000 == 0o120000 or
                    name not in PAYLOADS | TEXT and not name.startswith('licenses/') or
                    name.lower().endswith(('.exe', '.dll')) and name not in PAYLOADS):
                raise ValueError('INSTALLER_PORTABLE_ENTRY_REJECTED')
            total += entry.file_size
            if total > 512 * 1024 * 1024:
                raise ValueError('INSTALLER_PORTABLE_TOO_LARGE')
            destination = stage.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, destination.open('xb') as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
        if not PAYLOADS | TEXT <= set(names):
            raise ValueError('INSTALLER_PORTABLE_INCOMPLETE')
        for name in PAYLOADS:
            if digest(stage / name) != metadata['payload_sha256'].get(name):
                raise ValueError('INSTALLER_PORTABLE_PAYLOAD_DIGEST_MISMATCH')
    # Inno's text reader expects a BOM for unambiguous Unicode display. Product
    # executable/DLL and license contents are otherwise kept byte-for-byte.
    readme = stage / '请先阅读.txt'
    readme.write_text(readme.read_text(encoding='utf-8-sig'), encoding='utf-8-sig')



def compiler_identity(compiler):
    # ISCC reports its ordinary command-line help with exit code 1. This is
    # only a bounded identity probe; actual compilation below remains strict.
    probe = subprocess.run([str(compiler), '/?'], text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=15, check=False)
    lines = probe.stdout.lstrip('\ufeff').splitlines()
    identity = lines[0].strip() if lines else ''
    if probe.returncode not in (0, 1) or not re.fullmatch(r'Inno Setup [0-9]+(?:\.[0-9]+)* Command-Line Compiler', identity):
        raise ValueError('INNO_COMPILER_IDENTITY_PROBE_FAILED')
    return identity


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--iscc', required=True, type=Path)
    args = parser.parse_args()
    if (os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        raise ValueError('HOSTED_WINDOWS_INSTALLER_BUILD_REQUIRED')
    compiler = args.iscc.resolve(strict=True)
    if compiler.name.lower() != 'iscc.exe':
        raise ValueError('INNO_COMPILER_REQUIRED')
    license_file = compiler.with_name('license.txt')
    if not license_file.is_file() or not 100 < license_file.stat().st_size < 65536:
        raise ValueError('INNO_RUNTIME_LICENSE_REQUIRED')
    out = ROOT / 'dist/candidate'
    metadata_file = out / 'BUILD.json'
    metadata = json.loads(metadata_file.read_text())
    version = metadata.get('version', '')
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)-rc(\d+)', version)
    revision = metadata.get('source_revision', '')
    if not match or not re.fullmatch('[a-f0-9]{40}', revision) or metadata.get('publisher_signed') is not False:
        raise ValueError('UNSIGNED_CANDIDATE_METADATA_REQUIRED')
    stem = 'OracleProxy-' + version + '-win-x64-' + revision[:12]
    portable = out / (stem + '.zip')
    sums = dict(line.split('  ', 1)[::-1] for line in (out / 'SHA256SUMS.txt').read_text().splitlines())
    if sums.get(portable.name) != digest(portable):
        raise ValueError('INSTALLER_PORTABLE_ARCHIVE_DIGEST_MISMATCH')
    target = out / (stem + '-setup.exe')
    if target.exists():
        raise ValueError('INSTALLER_OUTPUT_ALREADY_EXISTS')
    script = ROOT / 'clients/windows/product/installer/OracleProxy.iss'
    with tempfile.TemporaryDirectory(prefix='oracle-installer-') as temp:
        stage = Path(temp) / 'payload'
        stage_bundle(portable, metadata, stage)
        notices = stage / 'licenses/inno-setup'
        notices.mkdir()
        shutil.copyfile(license_file, notices / 'LICENSE.txt')
        compiler_hash = digest(compiler)
        compiler_version = compiler_identity(compiler)
        (notices / 'BUILD-TOOL.txt').write_text(
            'Inno Setup compiler/runtime: ' + compiler_version + '\n'
            'Source: https://github.com/jrsoftware/issrc\n'
            'Compiler SHA256: ' + compiler_hash + '\n', encoding='utf-8')
        subprocess.run([str(compiler), '/Qp', '/DPayloadDir=' + str(stage),
                        '/DOutputDir=' + str(out.resolve()), '/DProductVersion=' + version,
                        '/DVersionNumbers=' + '.'.join(match.groups()), '/DArtifactStem=' + stem,
                        str(script)], check=True)
    if not target.is_file() or target.stat().st_size < 100000 or target.open('rb').read(2) != b'MZ':
        raise ValueError('INSTALLER_PE_OUTPUT_REQUIRED')
    metadata['installer'] = {'filename': target.name, 'sha256': digest(target),
                             'publisher_signed': False, 'compiler_sha256': compiler_hash,
                             'compiler_version': compiler_version}
    metadata_file.write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    assets = sorted([*out.glob('*.zip'), target])
    (out / 'SHA256SUMS.txt').write_text(''.join(digest(path) + '  ' + path.name + '\n' for path in assets), encoding='utf-8')
    print('WINDOWS_SETUP_FROM_VERIFIED_PORTABLE_AND_RUNTIME_LICENSE=PASS')
    print('SETUP_SHA256=' + metadata['installer']['sha256'])


if __name__ == '__main__':
    main()
