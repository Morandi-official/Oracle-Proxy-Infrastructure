"""Promote only the pinned, accepted rc17 artifacts to a draft-first prerelease.

Runs downloaded archives through hashing/metadata checks, never executes them.
No Oracle credentials are needed. Publishing is restricted to this repo's main.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = 'Morandi-official/Oracle-Proxy-Infrastructure'
MANIFEST = Path(__file__).with_name('windows-rc17.json')


def gh(*args, output=None):
    return subprocess.run(['gh', *map(str,args)], check=True, stdout=output or subprocess.PIPE,
                          stderr=subprocess.DEVNULL).stdout


def api(path): return json.loads(gh('api',f'repos/{REPO}/{path}'))


def validate_manifest(manifest):
    artifacts=manifest.get('artifacts')
    if (manifest.get('version')!='0.3.0-rc17' or
        type(manifest.get('run_id')) is not int or manifest['run_id']<=0 or
        not re.fullmatch(r'[a-f0-9]{40}',str(manifest.get('source_revision',''))) or
        not isinstance(artifacts,list) or len(artifacts)!=2):
        raise ValueError('COMPLETE_PINNED_RC17_MANIFEST_REQUIRED')
    ids=[]
    for item in artifacts:
        if (not isinstance(item,dict) or type(item.get('id')) is not int or item['id']<=0 or
            not re.fullmatch(r'[a-f0-9]{64}',str(item.get('sha256','')))):
            raise ValueError('EXACT_ARTIFACT_ID_AND_DIGEST_REQUIRED')
        ids.append(item['id'])
    if len(set(ids))!=2: raise ValueError('DISTINCT_SOURCE_AND_CLIENT_ARTIFACTS_REQUIRED')


def validate_run(run, manifest):
    if not (run.get('id')==manifest['run_id'] and run.get('head_sha')==manifest['source_revision'] and
            run.get('head_branch')=='main' and run.get('event')=='push' and
            run.get('status')=='completed' and run.get('conclusion')=='success' and
            run.get('path')=='.github/workflows/windows-product-candidate.yml' and
            run.get('head_repository',{}).get('full_name')==REPO):
        raise ValueError('ACCEPTED_MAIN_WORKFLOW_REQUIRED')


def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def read_archive(archive, output, expected_prefix):
    with zipfile.ZipFile(archive) as bundle:
        names=bundle.namelist()
        allowed={expected_prefix+'.zip',expected_prefix+'-source.zip','SHA256SUMS.txt','BUILD.json'}
        if len(set(names))!=len(names) or not set(names)<=allowed: raise ValueError('ARTIFACT_CONTENTS_REJECTED')
        for entry in bundle.infolist():
            if entry.file_size>512*1024*1024 or entry.is_dir() or (entry.external_attr>>16)&0o170000==0o120000:
                raise ValueError('ARTIFACT_ENTRY_REJECTED')
            # All entries are exact flat allowlisted names. Never extract paths.
            destination=output/entry.filename
            if destination.exists():
                if entry.file_size>32768 or destination.read_bytes()!=bundle.read(entry):
                    raise ValueError('ARTIFACT_METADATA_MISMATCH')
                continue
            with bundle.open(entry) as source, destination.open('xb') as target:
                import shutil
                shutil.copyfileobj(source,target,1024*1024)


def main():
    if sys.argv[1:] not in (['--check'],['--publish']): raise ValueError('INVALID_ARGUMENTS')
    manifest=json.loads(MANIFEST.read_text())
    validate_manifest(manifest)
    validate_run(api(f"actions/runs/{manifest['run_id']}"),manifest)
    for artifact in manifest['artifacts']:
        value=api(f"actions/artifacts/{artifact['id']}")
        if (value.get('expired') is not False or value.get('digest')!='sha256:'+artifact['sha256'] or
            value.get('workflow_run',{}).get('id')!=manifest['run_id'] or
            value.get('workflow_run',{}).get('head_sha')!=manifest['source_revision']):
            raise ValueError('PINNED_ARTIFACT_REQUIRED')
    if sys.argv[1]=='--check': print('PINNED_ACCEPTED_MAIN_ARTIFACTS=PASS');return
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_REF')!='refs/heads/main' or
        os.environ.get('GITHUB_REPOSITORY')!=REPO): raise ValueError('MAIN_PUBLICATION_REQUIRED')
    prefix='OracleProxy-'+manifest['version']+'-win-x64-'+manifest['source_revision'][:12]
    with tempfile.TemporaryDirectory(prefix='oracle-candidate-release-') as temporary:
        root=Path(temporary);assets=root/'assets';assets.mkdir()
        for index,artifact in enumerate(manifest['artifacts']):
            archive=root/f'artifact-{index}.zip'
            with archive.open('xb') as stream:
                gh('api',f"repos/{REPO}/actions/artifacts/{artifact['id']}/zip",output=stream)
            if digest(archive)!=artifact['sha256']: raise ValueError('ARTIFACT_DIGEST_MISMATCH')
            read_archive(archive,assets,prefix)
        expected={prefix+'.zip',prefix+'-source.zip','SHA256SUMS.txt','BUILD.json'}
        if {p.name for p in assets.iterdir()}!=expected: raise ValueError('COMPLETE_SOURCE_AND_PAYLOAD_REQUIRED')
        metadata=json.loads((assets/'BUILD.json').read_text())
        if not (metadata.get('version')==manifest['version'] and metadata.get('source_revision')==manifest['source_revision'] and
                metadata.get('real_oracle_acceptance_passed') is True and metadata.get('publisher_signed') is False and
                metadata.get('channel')=='unsigned-acceptance-candidate' and str(metadata.get('workflow_run'))==str(manifest['run_id'])):
            raise ValueError('CANDIDATE_ATTESTATION_REJECTED')
        sums={line.split('  ',1)[1]:line.split('  ',1)[0] for line in (assets/'SHA256SUMS.txt').read_text().splitlines()}
        if set(sums)!={prefix+'.zip',prefix+'-source.zip'}: raise ValueError('CHECKSUM_SET_REJECTED')
        for name,value in sums.items():
            if digest(assets/name)!=value: raise ValueError('PAYLOAD_OR_SOURCE_DIGEST_MISMATCH')
        notes=root/'notes.md'
        notes.write_text(Path(__file__).with_name('windows-rc17-notes.md').read_text(encoding='utf-8')+
                         f"\n构建提交：`{manifest['source_revision']}`；[完整云端验收记录](https://github.com/{REPO}/actions/runs/{manifest['run_id']})。配套源码、SHA256SUMS.txt 和 BUILD.json 随包发布。\n",encoding='utf-8')
        tag='v'+manifest['version']
        if api('git/matching-refs/tags/'+tag): raise ValueError('EXISTING_RC_TAG_REQUIRES_REVIEW')
        request=root/'draft.json'
        request.write_text(json.dumps({'tag_name':tag,'target_commitish':manifest['source_revision'],
            'name':'Oracle Proxy '+manifest['version']+' · Windows x64','draft':True,
            'prerelease':True,'body':notes.read_text()}))
        release=json.loads(gh('api','--method','POST',f'repos/{REPO}/releases','--input',request))
        release_id=release['id']
        gh('release','upload',tag,'--repo',REPO,*[assets/name for name in sorted(expected)])
        release=api(f'releases/{release_id}')
        actual={asset['name']:asset for asset in release['assets']}
        if set(actual)!=expected or release.get('draft') is not True or release.get('prerelease') is not True:
            raise ValueError('DRAFT_ASSETS_REJECTED')
        for name in expected:
            if actual[name].get('digest')!='sha256:'+digest(assets/name) or actual[name]['size']!=(assets/name).stat().st_size:
                raise ValueError('UPLOADED_ASSET_DIGEST_MISMATCH')
        request.write_text(json.dumps({'draft':False,'prerelease':True}))
        gh('api','--method','PATCH',f'repos/{REPO}/releases/{release_id}','--input',request)
        print('CANDIDATE_PRERELEASE=https://github.com/'+REPO+'/releases/tag/'+tag)


if __name__=='__main__': main()
