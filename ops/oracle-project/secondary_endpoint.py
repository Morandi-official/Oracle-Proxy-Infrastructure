"""Owner-confirmed secondary address, bounded lease; primary networking is immutable."""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.request

DEVICE='enp0s6'
PRIMARY='10.0.0.6'
SECONDARY='10.0.0.10'
PUBLIC='141.147.78.44'
LABEL=DEVICE+':optest'
LEASE_SECONDS=86400
STATE=Path('/var/lib/oracle-project-ops/secondary-endpoint.json')
SCRIPT=Path('/usr/local/libexec/oracle-project/secondary_endpoint.py')


def run(argv):
    result=subprocess.run(argv,capture_output=True,text=True,check=True,timeout=10)
    if len(result.stdout)>262144:raise ValueError('OBSERVATION_LIMIT')
    return result


def owned_file(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('ROOT_OWNED_REGULAR_FILE_REQUIRED')


def write(path,body):
    if path.exists() or path.is_symlink():owned_file(path)
    temporary=path.with_name(path.name+'.candidate')
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(descriptor,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)


def metadata():
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request=urllib.request.Request('http://169.254.169.254/opc/v2/vnics/',headers={'Authorization':'Bearer Oracle'})
    with opener.open(request,timeout=3) as response:body=response.read(32769)
    if len(body)>32768:raise ValueError('METADATA_LIMIT')
    rows=json.loads(body)
    if not isinstance(rows,list):raise ValueError('METADATA_SHAPE')
    return rows


def allocated(rows):
    return any(isinstance(row,dict) and row.get('privateIp')==PRIMARY and
               isinstance(row.get('secondaryPrivateIps'),list) and SECONDARY in row['secondaryPrivateIps'] for row in rows)


def normalized_routes(rows):
    keys=('dst','gateway','dev','prefsrc','metric','protocol','scope','table','flags','nexthops')
    return sorted([ {k:row[k] for k in keys if k in row} for row in rows],key=lambda row:json.dumps(row,sort_keys=True))


def address_rows():
    rows=json.loads(run(['ip','-j','-4','address','show','dev',DEVICE]).stdout)
    if len(rows)!=1 or rows[0].get('ifname')!=DEVICE:raise ValueError('EXPECTED_DEVICE_REQUIRED')
    return rows[0].get('addr_info',[])


def snapshot():
    addresses=address_rows()
    primary=[row for row in addresses if row.get('local')==PRIMARY]
    if len(primary)!=1 or primary[0].get('label')!=DEVICE:raise ValueError('PRIMARY_ADDRESS_CHANGED')
    network=ipaddress.ip_network(PRIMARY+'/'+str(primary[0]['prefixlen']),strict=False)
    if ipaddress.ip_address(SECONDARY) not in network or SECONDARY in (PRIMARY,str(network.network_address),str(network.broadcast_address)):
        raise ValueError('SECONDARY_OUTSIDE_PRIMARY_SUBNET')
    alias=[row for row in addresses if row.get('local')==SECONDARY]
    baseline={
        'addresses':sorted([(row.get('local'),row.get('prefixlen'),row.get('label'),row.get('scope')) for row in addresses if row.get('local')!=SECONDARY]),
        'defaults':normalized_routes(json.loads(run(['ip','-j','-4','route','show','default']).stdout)),
        'rules':json.loads(run(['ip','-j','-4','rule','show']).stdout),
        'control_routes':[]}
    for address in ('1.1.1.1','8.8.8.8','114.114.114.114'):
        route=json.loads(run(['ip','-j','-4','route','get',address]).stdout)
        if len(route)!=1 or route[0].get('dev')!=DEVICE or route[0].get('prefsrc')!=PRIMARY:
            raise ValueError('PRIMARY_EGRESS_CHANGED')
        baseline['control_routes'].append(normalized_routes(route))
    # JSON round-trip makes tuples identical before/after persistence.
    return json.loads(json.dumps(baseline)),alias


def owned_alias(rows):
    return len(rows)==1 and rows[0].get('local')==SECONDARY and rows[0].get('prefixlen')==32 and rows[0].get('label')==LABEL


def load_state():
    owned_file(STATE)
    if STATE.stat().st_size>32768:raise ValueError('STATE_LIMIT')
    value=json.loads(STATE.read_text())
    if (value.get('schema')!=1 or value.get('device')!=DEVICE or value.get('primary')!=PRIMARY or
        value.get('secondary')!=SECONDARY or value.get('public')!=PUBLIC or value.get('label')!=LABEL or
        not isinstance(value.get('lease_id'),str) or not re.fullmatch(r'[a-f0-9]{32}',value['lease_id']) or
        value.get('phase') not in ('armed','active','rolled_back') or type(value.get('expires_at')) is not int or
        not isinstance(value.get('baseline'),dict)):
        raise ValueError('EXACT_OWNED_STATE_REQUIRED')
    return value


def persist(value):write(STATE,(json.dumps(value,sort_keys=True)+'\n').encode())


def rollback_locked(expected=None):
    value=load_state()
    if expected is not None and expected!=value['lease_id']:
        print('SECONDARY_ENDPOINT=STALE_LEASE_NOOP');return
    alias=[row for row in address_rows() if row.get('local')==SECONDARY]
    if alias:
        if not owned_alias(alias):raise ValueError('FOREIGN_ALIAS_REFUSE_ROLLBACK')
        run(['ip','-4','address','del',SECONDARY+'/32','dev',DEVICE])
    remaining=[row for row in address_rows() if row.get('local')==SECONDARY]
    if remaining:raise ValueError('ALIAS_REMOVAL_NOT_VERIFIED')
    value['phase']='rolled_back';persist(value)
    try:unchanged=snapshot()[0]==value['baseline']
    except (OSError,ValueError,subprocess.SubprocessError):unchanged=False
    print('SECONDARY_ENDPOINT=ROLLED_BACK; PRIMARY_BASELINE_UNCHANGED='+str(unchanged))


def arm_rollback(token):
    unit='oracle-proxy-secondary-'+token
    run(['systemd-run','--quiet','--collect','--unit='+unit,'--on-active='+str(LEASE_SECONDS)+'s',
         '--timer-property=AccuracySec=1s','--property=Type=oneshot',
         '/usr/bin/python3','-I',str(SCRIPT),'rollback',token])
    run(['systemctl','is-active',unit+'.timer'])


def apply_locked():
    before,alias=snapshot()
    if not allocated(metadata()):raise ValueError('IMDS_SECONDARY_ALLOCATION_NOT_VERIFIED')
    if alias:
        value=load_state()
        if not owned_alias(alias) or value['phase']!='active' or value['baseline']!=before or value['expires_at']<=int(time.time()):
            raise ValueError('EXISTING_ALIAS_REFUSE_APPLY')
        run(['systemctl','is-active','oracle-proxy-secondary-'+value['lease_id']+'.timer'])
        print('SECONDARY_ENDPOINT=ALREADY_ACTIVE; EXPIRES_AT='+str(value['expires_at']));return
    if STATE.exists() or STATE.is_symlink():load_state()
    value={'schema':1,'device':DEVICE,'primary':PRIMARY,'secondary':SECONDARY,'public':PUBLIC,'label':LABEL,
           'lease_id':secrets.token_hex(16),'phase':'armed','expires_at':int(time.time())+LEASE_SECONDS,'baseline':before}
    persist(value)
    try:
        # Schedule the independent rollback BEFORE touching the interface.
        arm_rollback(value['lease_id'])
        run(['ip','-4','address','add',SECONDARY+'/32','dev',DEVICE,'label',LABEL,'noprefixroute'])
        current,alias=snapshot()
        if current!=before or not owned_alias(alias):raise ValueError('PRIMARY_BASELINE_CHANGED_OR_ALIAS_NOT_OWNED')
        value['phase']='active';persist(value)
    except Exception:
        rollback_locked(value['lease_id']);raise
    print('SECONDARY_ENDPOINT=ACTIVE; PUBLIC='+PUBLIC+'; PRIMARY_BASELINE_UNCHANGED=True; EXPIRES_AT='+str(value['expires_at']))


def lock():
    if os.geteuid()!=0:raise ValueError('ROOT_REQUIRED')
    info=STATE.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('ROOT_PRIVATE_STATE_DIRECTORY_REQUIRED')
    fd=os.open(STATE.with_suffix('.lock'),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    fcntl.flock(fd,fcntl.LOCK_EX)
    return fd


def install():
    fd=lock()
    try:
        # A timer must invoke stable root-owned bytes, never a user's temp file.
        directory=SCRIPT.parent.lstat()
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=0 or directory.st_mode&0o022:
            raise ValueError('ROOT_SCRIPT_DIRECTORY_REQUIRED')
        write(SCRIPT,Path(__file__).read_bytes())
        apply_locked()
    finally:os.close(fd)


def rollback(expected=None):
    fd=lock()
    try:rollback_locked(expected)
    finally:os.close(fd)


def observe():
    result={'allocation_confirmed':False,'primary_baseline_ready':False,'alias_present':None,'scope':'OWNER_SECONDARY_TEST_ONLY'}
    try:
        rows=metadata()
        result['allocation_confirmed']=allocated(rows)
        matching=[row for row in rows if isinstance(row,dict) and row.get('privateIp')==PRIMARY]
        result['matching_primary_rows']=len(matching)
        result['metadata_field_names']=sorted(matching[0]) if len(matching)==1 else []
        result['secondary_field_present']=len(matching)==1 and 'secondaryPrivateIps' in matching[0]
        if result['secondary_field_present']:
            values=matching[0]['secondaryPrivateIps']
            result['secondary_field_is_list']=isinstance(values,list)
            result['secondary_field_count']=len(values) if isinstance(values,list) else None
        _,alias=snapshot();result['primary_baseline_ready']=True;result['alias_present']=bool(alias)
        if STATE.exists():
            value=load_state();result['phase']=value['phase'];result['expires_at']=value['expires_at']
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):result['observation_error']=True
    return result


if __name__=='__main__':
    try:
        if len(sys.argv)!=3 or sys.argv[1]!='rollback' or not re.fullmatch(r'[a-f0-9]{32}',sys.argv[2]):raise ValueError('FIXED_ROLLBACK_REQUIRED')
        rollback(sys.argv[2])
    except Exception:
        print('SECONDARY_ENDPOINT_OPERATION_FAILED',file=sys.stderr);raise SystemExit(2) from None
