"""Bounded, separately owned diagnostic peer via the existing policy service."""
import base64
import json
import importlib.util
import os
from pathlib import Path
import pwd
import re
import subprocess
import sqlite3
import time

REQUEST = 'cloud-udp-third-ip-reconcile-20261108'
STATE = Path('/var/lib/oracle-proxy-control/cloud-udp-diagnostics')
ACTOR = 'github:204281968'


def validate(value):
    if not isinstance(value, dict) or set(value) != {'action', 'probe_id', 'public_key'}:
        raise ValueError('INVALID_DIAGNOSTIC_REQUEST')
    if value['action'] not in ('prepare', 'observe', 'cleanup', 'host-audit', 'endpoint-prepare', 'endpoint-observe', 'endpoint-rollback', 'reconcile-owned'):
        raise ValueError('INVALID_DIAGNOSTIC_ACTION')
    if not isinstance(value['probe_id'], str) or not re.fullmatch(r'[a-f0-9]{32}', value['probe_id']):
        raise ValueError('INVALID_DIAGNOSTIC_ID')
    key = value['public_key']
    if not isinstance(key, str) or len(key) != 44:
        raise ValueError('INVALID_DIAGNOSTIC_KEY')
    try:
        decoded = base64.b64decode(key, validate=True)
    except ValueError:
        raise ValueError('INVALID_DIAGNOSTIC_KEY') from None
    if len(decoded) != 32 or base64.b64encode(decoded).decode() != key:
        raise ValueError('INVALID_DIAGNOSTIC_KEY')
    return value


def rpc(operation, data):
    account = pwd.getpwnam('oracle-proxy-admin')
    code = "import json,re,sys;sys.path.insert(0,'/opt/oracle-proxy-admin/current');from console.control import call;v=json.load(sys.stdin)\ntry: print(json.dumps(call(v['operation'],v['actor'],v['data'])))\nexcept Exception as e:\n c=str(e);print(json.dumps({'control_error':c if re.fullmatch(r'[A-Z][A-Z0-9_]{1,80}',c) else type(e).__name__}));sys.exit(2)"
    result = subprocess.run(['/opt/oracle-proxy-admin/current/.venv/bin/python', '-I', '-c', code],
                            input=json.dumps({'operation':operation, 'actor':ACTOR, 'data':data}),
                            text=True, capture_output=True, timeout=25, user=account.pw_uid,
                            group=account.pw_gid, extra_groups=[])
    if len(result.stdout)>1024*1024:raise ValueError('DIAGNOSTIC_CONTROL_RPC_FAILED')
    if result.returncode!=0:
        try:code=json.loads(result.stdout).get('control_error','')
        except (ValueError,AttributeError):code=''
        if isinstance(code,str) and re.fullmatch(r'[A-Z][A-Z0-9_]{1,80}',code):raise ValueError(code)
        raise ValueError('DIAGNOSTIC_CONTROL_RPC_FAILED')
    return json.loads(result.stdout)


def save(path, value):
    temporary = path.with_suffix('.new')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def kernel_has_peer(key):
    result=subprocess.run(['wg','show','wg0','peers'],capture_output=True,text=True,timeout=8,check=True)
    return key in result.stdout.splitlines()


def pending_diagnostics():
    paths=list(STATE.glob('*.json'))
    if len(paths)>64:raise ValueError('DIAGNOSTIC_MARKER_LIMIT')
    pending=[]
    for path in paths:
        if path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode & 0o077 or path.stat().st_size>2048:
            raise ValueError('UNTRUSTED_DIAGNOSTIC_MARKER')
        marker=json.loads(path.read_text())
        if marker.get('name')!='Cloud UDP diagnostic '+path.stem:
            raise ValueError('DIAGNOSTIC_OWNER_MISMATCH')
        if not marker.get('cleaned'):
            pending.append({'probe_id':path.stem,'expires_at':marker['expires_at']})
    return pending


def host_audit():
    result={}
    for label,filename in (('host','udp_return_host_audit.py'),('ingress','ingress_readiness.py'),('secondary','secondary_endpoint.py'),('native','native_udp_readiness.py'),('transport','udp_transport_diagnostics.py')):
        spec=importlib.util.spec_from_file_location('cloud_readonly_'+label,Path(__file__).with_name(filename))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        result[label]=module.observe()
    return result


RECOVER_PROBES=('f196708c29374e26b72c9d35b2063f00','1f5b2e103fa64bb0804b2b77fbd3dfb6')


def reconcile_owned():
    if STATE.is_symlink() or not STATE.is_dir() or STATE.stat().st_uid!=0 or STATE.stat().st_mode&0o077:
        raise ValueError('UNTRUSTED_DIAGNOSTIC_STATE')
    result={'recovered':[],'errors':[]}
    for tag in RECOVER_PROBES:
        path=STATE/(tag+'.json')
        if not path.exists():continue
        if path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode&0o077 or path.stat().st_size>2048:
            raise ValueError('UNTRUSTED_DIAGNOSTIC_MARKER')
        marker=json.loads(path.read_text())
        if marker.get('name')!='Cloud UDP diagnostic '+tag:raise ValueError('DIAGNOSTIC_OWNER_MISMATCH')
        try:
            value=execute({'action':'cleanup','probe_id':tag,'public_key':marker['public_key']})
            result['recovered'].append({'probe_id':tag,'cleaned':value['cleaned']})
        except Exception as error:
            code=str(error)
            result['errors'].append({'probe_id':tag,'code':code if re.fullmatch(r'[A-Z][A-Z0-9_]{1,80}',code) else type(error).__name__})
    ledger=Path('/var/lib/oracle-proxy-control/ledger.sqlite3')
    if ledger.exists() and not ledger.is_symlink() and ledger.stat().st_uid==0:
        with sqlite3.connect('file:'+str(ledger)+'?mode=ro',uri=True,timeout=3) as db:
            result['ledger_counts']={label:db.execute(query).fetchone()[0] for label,query in (
                ('all_users','SELECT count(*) FROM users'),
                ('deleted_users','SELECT count(*) FROM deleted_users'),
                ('active_users','SELECT count(*) FROM users WHERE id NOT IN (SELECT user_id FROM deleted_users)'))}
    result['marker_file_count']=len(list(STATE.glob('*.json')))
    return result


def execute(value):
    validate(value)
    if value['action']=='reconcile-owned':return reconcile_owned()
    key, tag = value['public_key'], value['probe_id']
    name = 'Cloud UDP diagnostic ' + tag
    if STATE.is_symlink(): raise ValueError('UNTRUSTED_DIAGNOSTIC_STATE')
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.stat().st_uid != 0 or STATE.stat().st_mode & 0o077:
        raise ValueError('UNTRUSTED_DIAGNOSTIC_STATE')
    path = STATE / (tag + '.json')
    if path.is_symlink(): raise ValueError('UNTRUSTED_DIAGNOSTIC_MARKER')
    snapshot = rpc('state', {})
    if value['action'] != 'cleanup' and (snapshot.get('error') or snapshot['budget']['guard_blocked']):
        raise ValueError('DIAGNOSTIC_POLICY_NOT_READY')
    if path.exists():
        if path.stat().st_uid != 0 or path.stat().st_mode & 0o077 or path.stat().st_size > 2048:
            raise ValueError('UNTRUSTED_DIAGNOSTIC_MARKER')
        marker = json.loads(path.read_text())
        if marker['public_key'] != key or marker['name'] != name:
            raise ValueError('DIAGNOSTIC_OWNER_MISMATCH')
    else:
        if value['action'] != 'prepare': raise ValueError('DIAGNOSTIC_MARKER_REQUIRED')
        if any(u['name'] == name for u in snapshot['users']) or any(p['public_key'] == key for p in snapshot['peers']):
            raise ValueError('PREEXISTING_DIAGNOSTIC_IDENTITY_REFUSED')
        marker = {'public_key':key, 'name':name, 'user_id':None,
                  'created_at':int(time.time()), 'expires_at':int(time.time())+900, 'cleaned':False}
        save(path, marker)
    # Recover only this exact, pre-recorded name if a prior RPC response was lost.
    if not marker['user_id']:
        matches = [u for u in snapshot['users'] if u['name'] == name and u.get('expires') == marker['expires_at']]
        if len(matches) > 1: raise ValueError('DIAGNOSTIC_OWNER_NOT_UNIQUE')
        if matches:
            marker['user_id'] = matches[0]['id']; save(path, marker)
    if value['action'] == 'prepare':
        if marker['cleaned'] or marker['expires_at'] <= time.time():
            raise ValueError('DIAGNOSTIC_LEASE_EXPIRED')
        if not marker['user_id']:
            snapshot = rpc('user.save', {'id':None, 'name':name, 'quota_bytes':32*1024*1024,
                                        'expires_at':marker['expires_at'], 'enabled':True, 'device_limit':1})
            marker['user_id'] = snapshot['saved_user_id']; save(path, marker)
        peer = next((p for p in snapshot['peers'] if p['public_key'] == key), None)
        if peer is None:
            snapshot = rpc('peer.create', {'public_key':key, 'user_id':marker['user_id'], 'name':name})
    peer = next((p for p in snapshot['peers'] if p['public_key'] == key), None)
    if peer and (peer['user_id'] != marker['user_id'] or peer['name'] != name or not peer['owned']):
        raise ValueError('DIAGNOSTIC_PEER_OWNER_MISMATCH')
    if value['action'].startswith('endpoint-'):
        raise ValueError('THIRD_ENDPOINT_EXPERIMENT_RETIRED')
    if value['action'] == 'host-audit':
        if peer is None or marker['cleaned'] or marker['expires_at']<=time.time():
            raise ValueError('ACTIVE_DIAGNOSTIC_MARKER_REQUIRED')
        return host_audit()
    if value['action'] == 'cleanup':
        # These mutations can select only the exact identity recorded before creation.
        if marker['user_id']: rpc('peer.delete', {'public_key':key})
        if marker['user_id'] and any(u['id'] == marker['user_id'] and u['name'] == name for u in snapshot['users']):
            rpc('user.delete', {'user_id':marker['user_id']})
        final = rpc('state', {})
        if any(p['public_key'] == key and p.get('present') for p in final['peers']) or any(u['id'] == marker['user_id'] for u in final['users']) or kernel_has_peer(key):
            raise ValueError('DIAGNOSTIC_CLEANUP_NOT_VERIFIED')
        marker['cleaned'] = True; save(path, marker)
        return {'cleaned':True,'pending_diagnostics':pending_diagnostics()}
    if peer is None: raise ValueError('DIAGNOSTIC_PEER_MISSING')
    return {'server_public_key':snapshot['server_public_key'], 'allowed_ips':peer['allowed_ips'],
            'handshake':peer['handshake'], 'usage':peer['usage'], 'present':peer['present'],
            'expires_at':marker['expires_at'], 'budget_blocked':snapshot['budget']['guard_blocked']}
