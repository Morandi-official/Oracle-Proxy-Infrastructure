"""Retire exact migrated legacy aliases; protect current endpoints and routes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

SOURCE=Path(__file__).parent
REQUEST='retire-migrated-legacy-endpoints-20261109'
OLD={'10.0.0.10','10.0.0.220'}

def module(name):
    spec=importlib.util.spec_from_file_location('retirement_'+name,SOURCE/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def run(args):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=20).stdout

def normalized(rows):
    # Router advertisements naturally decrease lifetime while we observe them.
    return sorted([{k:v for k,v in r.items() if k not in ('expires','cache','lastuse')} for r in rows],key=lambda r:json.dumps(r,sort_keys=True))

def baseline():
    rows=json.loads(run(['ip','-j','address','show','dev','enp0s6']))[0]['addr_info']
    addresses=sorted([{k:r[k] for k in ('family','local','prefixlen','scope','label') if k in r} for r in rows if r['local'] not in OLD],key=lambda r:json.dumps(r,sort_keys=True))
    if not any(r.get('local')=='10.0.0.6' and r.get('label')=='enp0s6' and r.get('prefixlen')==24 for r in rows):raise ValueError('CURRENT_PRIMARY_ALIAS_REQUIRED')
    if not any(r.get('local')=='10.0.0.246' and r.get('label')=='enp0s6:opmb' and r.get('prefixlen')==32 for r in rows):raise ValueError('CURRENT_BACKUP_ALIAS_REQUIRED')
    if not any(r.get('local')=='2603:c020:c015:8100::10' for r in rows):raise ValueError('CURRENT_IPV6_REQUIRED')
    return {'addresses':addresses,'routes':[normalized(json.loads(run(['ip','-j',f,'route','show','default']))) for f in ('-4','-6')],
            'rules':[normalized(json.loads(run(['ip','-j',f,'rule','show']))) for f in ('-4','-6')]}

def verify_exit():
    body=run(['curl','--fail','--silent','--show-error','--connect-timeout','5','--max-time','12','https://1.1.1.1/cdn-cgi/trace'])
    if len(body)>16384 or dict(line.split('=',1) for line in body.splitlines() if '=' in line).get('ip')!='152.67.154.225':raise ValueError('CURRENT_PRIMARY_EGRESS_REQUIRED')

def validate_catalog(value):
    if value.get('primary')!={'public_ipv4':'152.67.154.225','private_ipv4':'10.0.0.6'} or value.get('backup')!={'public_ipv4':'150.230.113.158','private_ipv4':'10.0.0.246'} or value.get('active')!='primary' or value.get('legacy')!=[] or value.get('revision')!=3:raise ValueError('EXACT_MIGRATED_CATALOG_REQUIRED')

def retire_ci():
    cleanup=module('cleanup_webrtc_ci')
    cleanup.REQUEST=REQUEST;cleanup.OPERATION='preflight';cleanup.MARKER=cleanup.STATE/'retire-exact-failed-rc38-main-20261109.json'
    def candidates(rows,peers,now):
        matched=[r for r in rows if hashlib.sha256(r['key'].encode()).hexdigest()[:12]=='ff444e826eed']
        if any(r['machine_name']!='runnervmquqza' or r['name']!='runnervmquqza' or r['client_version']!='0.3.0-rc38+fa9292bdb3279823cf505f5097cc8c91d5ec77b6' or r['confirmed_at']!=1794229447 for r in matched):raise ValueError('COMPLETED_CI_PROFILE_CHANGED')
        chosen=[r['key'] for r in matched]
        if len(chosen)>1:raise ValueError('EXACT_COMPLETED_CI_NOT_UNIQUE')
        if any(peers.get(k,{}).get('handshake',0)>now-180 for k in chosen):raise ValueError('EXACT_COMPLETED_CI_NOT_IDLE')
        return chosen
    cleanup.candidates=candidates;cleanup.apply()

def apply():
    if os.geteuid()!=0:raise ValueError('ROOT_REQUIRED')
    request=json.loads((SOURCE/'request.json').read_text())
    if request!={'operation':'preflight','request_id':REQUEST}:raise ValueError('EXPLICIT_RETIREMENT_REQUEST_REQUIRED')
    catalog=json.loads((SOURCE.parent/'network/endpoints.json').read_text());validate_catalog(catalog)
    endpoint=module('endpoint_addresses');secondary=module('secondary_vpn');s=secondary.s
    before=baseline();verify_exit()
    # Verify every executable and unit before invoking its owned stop behavior.
    for name in ('secondary_vpn.py','secondary_endpoint.py'):
        path=endpoint.STABLE/name
        if path.exists() or path.is_symlink():
            endpoint.owned(path)
            if path.read_bytes()!=(SOURCE/name).read_bytes():raise ValueError('FOREIGN_SECONDARY_HELPER')
    allocation=endpoint.STABLE/'secondary-allocation.json'
    if allocation.exists() or allocation.is_symlink():
        endpoint.owned(allocation)
        if json.loads(allocation.read_text())!=s.EXPECTED_ALLOCATION:raise ValueError('FOREIGN_SECONDARY_ALLOCATION')
    if secondary.UNIT_PATH.exists() or secondary.UNIT_PATH.is_symlink():
        endpoint.owned(secondary.UNIT_PATH)
        if secondary.UNIT_PATH.read_text()!=secondary.unit_text():raise ValueError('FOREIGN_SECONDARY_UNIT')
    if s.STATE.exists():
        state=s.load_state()
        if state.get('mode')!='persistent' or state.get('vpn_nat_owned') is not True:raise ValueError('OWNED_PERSISTENT_SECONDARY_REQUIRED')
        secondary.rollback()
    elif any('oracle-proxy-secondary-quic' in r for r in secondary.nat_rules()):raise ValueError('SECONDARY_STATE_REQUIRED')
    if baseline()!=before:raise ValueError('PRIMARY_BACKUP_IPV6_OR_ROUTES_CHANGED')
    installed=endpoint.install() # Retires only ledger-owned .220; retains .246.
    if baseline()!=before:raise ValueError('PRIMARY_BACKUP_IPV6_OR_ROUTES_CHANGED')
    remaining={r['local'] for r in json.loads(run(['ip','-j','-4','address','show','dev','enp0s6']))[0]['addr_info']}
    if OLD & remaining:raise ValueError('OLD_ALIAS_STILL_PRESENT')
    if any('oracle-proxy-secondary-quic' in r for r in secondary.nat_rules()):raise ValueError('OLD_NAT_STILL_PRESENT')
    # Prove active production WireGuard redirect was not removed with old DNAT.
    s.run(['iptables','-w','5','-t','nat','-C','PREROUTING',*secondary.NATIVE_RULE])
    verify_exit()
    # Leave root-only evidence, but remove the obsolete helper so reboot cannot
    # recreate it. Current canonical address service and its ledger remain.
    archived=endpoint.ROOT/'legacy-endpoint-retired-20261109.json'
    endpoint.write(archived,(json.dumps({'schema':1,'complete':True,'at':int(time.time()),'removed_aliases':sorted(OLD),'preserved':before})+'\n').encode())
    for path in (secondary.UNIT_PATH,secondary.SCRIPT,s.SCRIPT,allocation,s.STATE):
        if path.exists() or path.is_symlink():endpoint.owned(path);path.unlink()
    run(['systemctl','daemon-reload'])
    retire_ci()
    return {'legacy_aliases_removed':sorted(OLD),'old_secondary_helper_removed':True,'canonical_current_endpoints_retained':True,'default_routes_and_ipv6_unchanged':True,'primary_exit':'152.67.154.225','catalog_revision':installed['revision'],'oci_resources_deleted':False}
