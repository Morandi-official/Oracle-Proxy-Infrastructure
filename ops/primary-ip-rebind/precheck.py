"""Verify both existing management entrances with the SAME pinned SSH host key.

Only the fixed root-gate preflight is permitted. No IP, IAM, route, firewall or
service mutations. Temporary SSH credentials are never included in artifacts.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

TARGETS=('152.67.156.100','141.147.78.44')
REQUEST='primary-ip-rebind-precheck-20261107'


def command(address,revision,key,known):
    if address not in TARGETS or not re.fullmatch(r'[a-f0-9]{40}',revision):raise ValueError('FIXED_PREFLIGHT_REQUIRED')
    return ['ssh','-T','-i',str(key),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
            '-o','StrictHostKeyChecking=yes','-o','HostKeyAlias=152.67.156.100',
            '-o','UserKnownHostsFile='+str(known),'-o','ConnectTimeout=12',
            '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2',
            'oracle-project-ci@'+address,'preflight '+revision]


def inspect(address,revision,key,known,run=subprocess.run):
    started=time.monotonic()
    row={'address':address,'port':22,'pinned_host_key_alias':'152.67.156.100','operation':'preflight','status':'UNAVAILABLE'}
    try:
        response=run(command(address,revision,key,known),capture_output=True,text=True,timeout=150)
        if response.returncode:
            row['status']='SSH_CONNECTION_OR_AUTH_FAILED' if response.returncode==255 else 'REMOTE_PREFLIGHT_FAILED'
            row['exit_code']=response.returncode;return row
        if len(response.stdout)>262144:raise ValueError('RESPONSE_LIMIT')
        state=json.loads(response.stdout)
        secondary=state.get('secondary_endpoint',{})
        ingress=state.get('public_ingress_readiness',{})
        row.update(status='AUTHENTICATED_PREFLIGHT_COMPLETE',host_key_verified=True,
                   application_configured=state.get('application_configured') is True,
                   primary_baseline_ready=secondary.get('primary_baseline_ready') is True,
                   secondary_alias_present=secondary.get('alias_present') is True,
                   expected_secondary_advertised=ingress.get('expected_advertised_address')=='141.147.78.44')
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):row['status']='UNAVAILABLE_OR_DEADLINE'
    finally:row['elapsed_ms']=round((time.monotonic()-started)*1000)
    return row


def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_REF')!='refs/heads/main':raise ValueError('CURRENT_MAIN_ACTION_REQUIRED')
    root=Path(__file__).resolve().parents[2]
    request=json.loads((root/'ops/oracle-project/request.json').read_text())
    if request!={'operation':'preflight','request_id':REQUEST}:
        print('PRIMARY_IP_REBIND_PRECHECK=NOT_REQUESTED');return
    revision=os.environ['GITHUB_SHA']
    if not re.fullmatch(r'[a-f0-9]{40}',revision):raise ValueError('INVALID_REVISION')
    result={'schema':1,'revision':revision,'observed_at':int(time.time()),'scope':'MANAGEMENT_PREFLIGHT_ONLY_NO_PUBLIC_IP_CHANGE','entrances':[]}
    with tempfile.TemporaryDirectory(prefix='rebind-management-') as directory:
        folder=Path(directory);folder.chmod(0o700)
        key=folder/'key';known=folder/'known_hosts'
        key.write_text(os.environ.pop('CI_KEY').replace('\r\n','\n').rstrip()+'\n');key.chmod(0o600)
        known.write_text(os.environ.pop('KNOWN_HOSTS').replace('\r\n','\n').rstrip()+'\n');known.chmod(0o600)
        for address in TARGETS:result['entrances'].append(inspect(address,revision,key,known))
    checks=('host_key_verified','application_configured','primary_baseline_ready','secondary_alias_present','expected_secondary_advertised')
    result['management_ready']=all(row.get('status')=='AUTHENTICATED_PREFLIGHT_COMPLETE' and all(row.get(k) for k in checks) for row in result['entrances'])
    result['public_mapping_change_performed']=False
    result['credential_files_removed']=not folder.exists()
    destination=root/'dist/primary-ip-rebind/precheck.json';destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_text(json.dumps(result,indent=2)+'\n')
    print('PRIMARY_IP_REBIND_PRECHECK='+json.dumps(result,sort_keys=True),flush=True)
    if not result['management_ready'] or not result['credential_files_removed']:raise SystemExit(1)


if __name__=='__main__':main()
