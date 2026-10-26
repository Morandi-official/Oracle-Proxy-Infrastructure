"""Wait for the fixed cleanup operation; never disclose the GitHub job token."""
import json
import os
import time
import urllib.request

REPO='Morandi-official/Oracle-Proxy-Infrastructure'
if os.environ.get('GITHUB_REPOSITORY')!=REPO or os.environ.get('GITHUB_REF')!='refs/heads/main':
    raise SystemExit('MAIN_ONLY')
revision=os.environ['GITHUB_SHA']

def get(path):
    request=urllib.request.Request('https://api.github.com/repos/'+REPO+'/'+path,
        headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
    with urllib.request.urlopen(request,timeout=15) as response:
        return json.loads(response.read(1048576))

started=time.monotonic()
while time.monotonic()-started<480:
    runs=get('actions/workflows/oracle-project-ops.yml/runs?head_sha='+revision+'&event=push&per_page=5')['workflow_runs']
    for run in runs:
        for job in get('actions/runs/'+str(run['id'])+'/jobs')['jobs']:
            if job['name']!='operations':continue
            steps=[s for s in job.get('steps',[]) if s['name']=='Execute the authorized project operation over pinned SSH']
            if steps and steps[0]['status']=='completed':
                if steps[0]['conclusion']!='success':raise SystemExit('OWNED_CLEANUP_SSH_FAILED')
                print('OWNED_CLEANUP_SSH_STAGE=PASS');raise SystemExit(0)
            if job['status']=='completed' and job['conclusion']!='success':raise SystemExit('OWNED_CLEANUP_JOB_FAILED')
    time.sleep(5)
raise SystemExit('OWNED_CLEANUP_WAIT_TIMEOUT')
