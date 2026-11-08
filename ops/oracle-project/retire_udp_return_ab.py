"""Retire only the owner-confirmed Nov8 third-IP host experiment; no OCI API calls."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT=Path(__file__).resolve().parent
RECEIPT=Path('/var/lib/oracle-project-ops/udp-return-ab-retired.json')


def module():
    spec=importlib.util.spec_from_file_location('owned_third_alias',ROOT/'udp_return_ab_endpoint.py')
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def exit_ipv4():
    result=subprocess.run(['curl','--fail','--silent','--show-error','--connect-timeout','8',
                           '--max-time','15','https://1.1.1.1/cdn-cgi/trace'],
                          capture_output=True,text=True,check=True,timeout=20)
    if len(result.stdout)>16384:raise ValueError('EXIT_RESPONSE_LIMIT')
    fields=dict(x.split('=',1) for x in result.stdout.splitlines() if '=' in x)
    if fields.get('ip')!='152.67.156.100':raise ValueError('RESTORED_PRIMARY_PUBLIC_IP_REQUIRED')
    return fields['ip']


def stop_unit(name):
    state=subprocess.run(['systemctl','show',name,'--property=LoadState','--value'],
                         text=True,capture_output=True,check=False,timeout=8)
    if state.returncode and state.stdout.strip()!='not-found':raise ValueError('UNIT_STATE_UNAVAILABLE')
    if state.stdout.strip()!='not-found':
        subprocess.run(['systemctl','stop',name],capture_output=True,text=True,check=True,timeout=15)
    probe=subprocess.run(['systemctl','is-active',name],capture_output=True,text=True,timeout=8)
    if probe.returncode==0 or probe.stdout.strip() not in ('inactive','unknown','failed',''):
        raise ValueError('EXACT_TIMER_STOP_NOT_VERIFIED')


def execute():
    if os.geteuid()!=0:raise ValueError('ROOT_REQUIRED')
    m=module()
    if m.STATE.is_symlink():raise ValueError('STATE_SYMLINK_REFUSED')
    fd=m.lock()
    try:
        if m.STATE.exists():
            value=m.load_state()
        else:
            m.owned_file(RECEIPT);saved=json.loads(RECEIPT.read_text())
            value=saved['original_state']
        expected={'schema':1,'device':m.DEVICE,'primary':'10.0.0.6',
                  'secondary':'10.0.0.157','public':'79.72.85.11','label':m.DEVICE+':opab'}
        if any(value.get(k)!=v for k,v in expected.items()) or not re.fullmatch(r'[a-f0-9]{32}',value.get('lease_id','')):
            raise ValueError('EXACT_THIRD_EXPERIMENT_REQUIRED')
        before,alias=m.snapshot()
        if before!=value['baseline']:raise ValueError('ORIGINAL_HOST_BASELINE_CHANGED')
        if alias and not m.owned_alias(alias):raise ValueError('FOREIGN_ALIAS_REFUSED')
        if m.SCRIPT.exists() or m.SCRIPT.is_symlink():
            m.owned_file(m.SCRIPT)
            if m.SCRIPT.read_bytes()!=(ROOT/'udp_return_ab_endpoint.py').read_bytes():
                raise ValueError('FOREIGN_STABLE_SCRIPT_REFUSED')
        verified_exit=exit_ipv4()
        receipt={'schema':1,'original_state':value,'started_at':int(time.time()),'cleaned':False}
        m.write(RECEIPT,(json.dumps(receipt,sort_keys=True)+'\n').encode())
        unit='oracle-proxy-udp-ab-'+value['lease_id']
        stop_unit(unit+'.timer');stop_unit(unit+'.service')
        if m.STATE.exists():m.rollback_locked(value['lease_id'])
        elif alias:raise ValueError('STATE_REQUIRED_TO_REMOVE_ALIAS')
        after,remaining=m.snapshot()
        if remaining or after!=before:raise ValueError('ALIAS_REMOVAL_OR_BASELINE_NOT_VERIFIED')
        exit_ipv4()
        if m.SCRIPT.exists():m.SCRIPT.unlink()
        if m.STATE.exists():m.owned_file(m.STATE);m.STATE.unlink()
        receipt.update(cleaned=True,finished_at=int(time.time()),original_baseline_unchanged=True,
                       ipv4_exit=verified_exit,alias_removed=True,timer_stopped=True,stable_script_removed=True)
        m.write(RECEIPT,(json.dumps(receipt,sort_keys=True)+'\n').encode())
        return {k:v for k,v in receipt.items() if k!='original_state'}
    finally:
        os.close(fd)
        # Keep the harmless lock inode stable for safe, idempotent retries.


if __name__=='__main__':print(json.dumps(execute(),sort_keys=True))
