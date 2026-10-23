"""Build explicit, auditable Windows acceptance bundles; never copy dist wholesale."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[4]
PRODUCT = ROOT / 'clients/windows/product'
PAYLOADS = ('OracleProxy.exe', 'OracleProxy.Core.exe', 'OracleProxy.Guard.dll')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(*args, cwd=ROOT):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def licenses(directory):
    return sorted(p for p in directory.rglob('*') if p.is_file() and
                  (p.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE', 'THIRD-PARTY-NOTICES'))))


def nuget_material():
    assets = json.loads((PRODUCT / 'obj/project.assets.json').read_text())
    folders = [Path(p) for p in assets['packageFolders']]
    packages = {key.lower() for key, value in assets['libraries'].items() if value['type'] == 'package'}
    # Self-contained runtime packs are downloads, not regular libraries.
    for framework in assets['project']['frameworks'].values():
        for item in framework.get('downloadDependencies', []):
            version = item['version'].strip('[]').split(',')[0].strip()
            packages.add(item['name'].lower() + '/' + version)
    material, rows = [], []
    for identity in sorted(packages):
        directory = next((folder / identity for folder in folders if (folder / identity).is_dir()), None)
        if directory is None:
            raise RuntimeError('Resolved NuGet package missing: ' + identity)
        notices = licenses(directory)
        if not notices:
            raise RuntimeError('NuGet license material missing: ' + identity)
        metadata = next(directory.glob('*.nuspec'))
        tree = ET.parse(metadata)
        repository = next((dict(e.attrib) for e in tree.iter() if e.tag.split('}')[-1] == 'repository'), {})
        rows.append({'package': identity, 'repository': repository,
                     'nuget': 'https://www.nuget.org/packages/' + identity})
        material.extend(('licenses/nuget/' + identity + '/' + p.relative_to(directory).as_posix(), p) for p in notices)
    return material, rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--acceptance-passed', action='store_true')
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise RuntimeError('Hosted build required')
    if args.acceptance_passed and (os.environ.get('GITHUB_REF') != 'refs/heads/main' or os.environ.get('GITHUB_EVENT_NAME') != 'push'):
        raise RuntimeError('Accepted distribution requires a main push')
    revision = run('git', 'rev-parse', 'HEAD')
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise RuntimeError('Invalid source revision')
    out = ROOT / 'dist/candidate'
    out.mkdir(parents=True, exist_ok=True)
    build = ROOT / 'dist/product'
    hashes = {name: digest(build / name) for name in PAYLOADS}
    pins = (PRODUCT / 'BuildPins.cs').read_text()
    if hashes['OracleProxy.Core.exe'] not in pins or hashes['OracleProxy.Guard.dll'] not in pins:
        raise RuntimeError('Payload hashes differ from compiled build pins')
    wintun = Path(os.environ['RUNNER_TEMP']) / 'oracle-official-wintun'
    wintun_licenses = licenses(wintun)
    if not wintun_licenses:
        raise RuntimeError('Official Wintun distribution license missing')
    material, packages = nuget_material()
    vendor = PRODUCT / 'core/vendor'
    if not (vendor / 'modules.txt').is_file() or not licenses(vendor):
        raise RuntimeError('Complete vendored core sources and notices required')
    metadata = {'channel': 'unsigned-acceptance-candidate', 'version': '0.3.0-rc13',
                'source_revision': revision, 'architecture': 'win-x64',
                'real_oracle_acceptance_passed': args.acceptance_passed,
                'workflow_run': os.environ['GITHUB_RUN_ID'], 'workflow_attempt': os.environ['GITHUB_RUN_ATTEMPT'],
                'publisher_signed': False, 'payload_sha256': hashes,
                'dotnet_sdk': run('dotnet', '--version'), 'go_toolchain': run('go', 'version'),
                'remaining_gates': ['live logged-in UU session continuity', 'physical Windows reboot',
                                    'Oracle IPv6 provisioning and forwarding', 'application publisher signing'],
                'nuget_packages': packages}
    tag = 'OracleProxy-0.3.0-rc13-win-x64-' + revision[:12]
    source_name = tag + '-source.zip'
    metadata['corresponding_source_archive'] = source_name
    tracked = run('git', 'ls-files', 'clients/windows/product', 'clients/windows/service-host/NativeDriverTrust.cs',
                  '.github/workflows/windows-product-candidate.yml').splitlines()
    source_files = {p: ROOT / p for p in tracked}
    for path in (PRODUCT / 'core/go.mod', PRODUCT / 'core/go.sum', PRODUCT / 'BuildPins.cs'):
        source_files[path.relative_to(ROOT).as_posix()] = path
    for path in vendor.rglob('*'):
        if path.is_file():
            source_files[path.relative_to(ROOT).as_posix()] = path
    # git-ls-files prevents DPAPI state, keys, test output, binaries and local caches entering the archive.
    with zipfile.ZipFile(out / source_name, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, path in sorted(source_files.items()):
            archive.write(path, name)
        archive.writestr('BUILD-SOURCE.json', json.dumps(metadata, indent=2))
    readme = (PRODUCT / 'PORTABLE_README.zh-CN.txt').read_text(encoding='utf-8')
    readme += '\n构建提交：' + revision + '\n配套源码包：' + source_name + '\n'
    with zipfile.ZipFile(out / (tag + '.zip'), 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name in PAYLOADS:
            archive.write(build / name, name)
        archive.writestr('请先阅读.txt', readme)
        archive.writestr('BUILD.json', json.dumps(metadata, indent=2))
        archive.write(PRODUCT / 'COPYING', 'licenses/OracleProxy-GPL-3.0.txt')
        archive.write(PRODUCT / 'LICENSE', 'licenses/OracleProxy-LICENSE.txt')
        for path in wintun_licenses:
            archive.write(path, 'licenses/wintun/' + path.relative_to(wintun).as_posix())
        for path in licenses(vendor):
            archive.write(path, 'licenses/go/' + path.relative_to(vendor).as_posix())
        archive.write(vendor / 'modules.txt', 'licenses/go/modules.txt')
        for name, path in material:
            archive.write(path, name)
        archive.writestr('SHA256SUMS.txt', ''.join(value + '  ' + name + '\n' for name, value in hashes.items()))
    # Reopen and enforce the runnable payload allowlist; no harness/bad-upgrade executable may ship.
    with zipfile.ZipFile(out / (tag + '.zip')) as archive:
        binaries = {name for name in archive.namelist() if name.lower().endswith(('.exe', '.dll'))}
        if binaries != set(PAYLOADS):
            raise RuntimeError('Unexpected runnable payload in candidate')
    sums = ''.join(digest(path) + '  ' + path.name + '\n' for path in sorted(out.glob('*.zip')))
    (out / 'SHA256SUMS.txt').write_text(sums, encoding='utf-8')
    (out / 'BUILD.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    for path in sorted(out.glob('*.zip')):
        print('CANDIDATE_ARCHIVE_BYTES=' + path.name + ':' + str(path.stat().st_size))
    print('CANDIDATE_ALLOWLIST_LICENSES_AND_CORRESPONDING_SOURCE=PASS')


if __name__ == '__main__':
    main()
