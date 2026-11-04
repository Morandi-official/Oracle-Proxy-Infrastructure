"""Preserve one stale failed-attempt review before freeing its reusable name."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

REPO='Morandi-official/Oracle-Proxy-Infrastructure'
ARTIFACT=13291669839
RUN=41763938124
SOURCE='02665e30839b50fa3dd7018017c0a508348b5e59'
NAME='Windows-product-build-review-only'
SIZE=240473
SHA256='10b1ac8604be4b831d8b69081d39195864b50352b093c212b71d2479fd436d9c'


def validate(value):
    run=value.get('workflow_run',{})
    if (value.get('id')!=ARTIFACT or value.get('name')!=NAME or value.get('size_in_bytes')!=SIZE or
            value.get('digest')!='sha256:'+SHA256 or value.get('expired') is not False or
            run.get('id')!=RUN or run.get('head_sha')!=SOURCE or run.get('head_branch')!='main' or
            run.get('repository_id')!=1415273545 or run.get('head_repository_id')!=1415273545):
        raise ValueError('EXACT_FAILED_ATTEMPT_REVIEW_REQUIRED')


def metadata():
    reply=subprocess.run(['gh','api',f'repos/{REPO}/actions/artifacts/{ARTIFACT}'],
                         check=False,capture_output=True,timeout=30)
    if reply.returncode:
        if b'HTTP 404' in reply.stderr:return None
        raise ValueError('ARTIFACT_METADATA_UNAVAILABLE')
    value=json.loads(reply.stdout);validate(value);return value


def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('--check','--download','--delete'):
        raise ValueError('FIXED_ACTION_REQUIRED')
    action=sys.argv[1]
    if action!='--check' and (os.environ.get('GITHUB_REPOSITORY')!=REPO or
            os.environ.get('GITHUB_REF')!='refs/heads/main' or os.environ.get('GITHUB_EVENT_NAME')!='push'):
        raise ValueError('ACCEPTED_MAIN_PUSH_ONLY')
    value=metadata()
    if action=='--check':
        print('EXACT_FAILED_REVIEW_METADATA='+('MATCH' if value else 'ALREADY_ABSENT'));return
    directory=Path(os.environ['RUNNER_TEMP'])/'rc27-preserved-failed-review'
    archive=directory/'first-attempt-review.zip'
    if action=='--download':
        with open(os.environ['GITHUB_OUTPUT'],'a') as output:
            output.write('present='+str(value is not None).lower()+'\n')
        if value is None:return
        directory.mkdir(mode=0o700)
        with archive.open('xb') as output:
            subprocess.run(['gh','api',f'repos/{REPO}/actions/artifacts/{ARTIFACT}/zip'],
                           check=True,stdout=output,stderr=subprocess.PIPE,timeout=60)
        if archive.stat().st_size!=SIZE or hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA256:
            raise ValueError('PRESERVED_REVIEW_DIGEST_MISMATCH')
        (directory/'provenance.json').write_text(json.dumps({'original_artifact_id':ARTIFACT,
            'original_run_id':RUN,'source_revision':SOURCE,'name':NAME,'size':SIZE,'sha256':SHA256},indent=2)+'\n')
        print('STALE_FAILED_REVIEW_PRESERVED_SHA256='+SHA256);return
    # This step runs only after successful upload of the opaque ZIP and provenance.
    if archive.stat().st_size!=SIZE or hashlib.sha256(archive.read_bytes()).hexdigest()!=SHA256:
        raise ValueError('PRESERVED_REVIEW_REQUIRED_BEFORE_DELETE')
    if value is not None:
        subprocess.run(['gh','api','--method','DELETE',f'repos/{REPO}/actions/artifacts/{ARTIFACT}'],
                       check=True,capture_output=True,timeout=30)
    print('EXACT_STALE_FAILED_REVIEW_NAME_FREED=PASS')


if __name__=='__main__':main()
