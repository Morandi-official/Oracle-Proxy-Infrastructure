"""Apply the owner's centralized endpoint catalog without changing default routes."""
import fcntl
import importlib.util
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import time

ROOT=Path('/var/lib/oracle-project-ops')
STATE=ROOT/'endpoint-addresses.json'
STABLE=Path('/usr/local/libexec/oracle-project')
CONFIG=Path('/etc/oracle-proxy-quic/endpoints.json')
UNIT=Path('/etc/systemd/system/proxy-endpoint-addresses.service')
REPO=Path(__file__).resolve().parents[2]

def run(args):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=15).stdout

def module():
    source=Path(__file__).with_name('endpoint_config.py')
    if not source.exists():source=REPO/'server/admin-oracle/console/endpoint_config.py'
    spec=importlib.util.spec_from_file_location('owner_endpoint_catalog',source)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def owned(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('ROOT_OWNED_ENDPOINT_FILE_REQUIRED')

def write(path,body,mode=0o600):
    if path.exists() or path.is_symlink():owned(path)
    temporary=path.with_name(path.name+'.new')
    descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        os.fchmod(descriptor,mode)  # The root bridge deliberately uses umask077.
        with os.fdopen(descriptor,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    finally:temporary.unlink(missing_ok=True)

def addresses(device):return json.loads(run(['ip','-j','-4','address','show','dev',device]))[0]['addr_info']

def routes():return [json.loads(run(['ip','-j',family,'route','show','default'])) for family in ('-4','-6')]+[json.loads(run(['ip','-j','-4','rule','show']))]

def stop_timer(unit):
    stopped=subprocess.run(['systemctl','stop',unit+'.timer',unit+'.service'],capture_output=True,text=True,timeout=15)
    if stopped.returncode not in (0,5):raise ValueError('EXPERIMENT_TIMER_STOP_FAILED')
    for suffix in ('.timer','.service'):
        value=subprocess.run(['systemctl','is-active',unit+suffix],capture_output=True,text=True,timeout=10)
        if value.returncode not in (3,4) or value.stdout.strip() in ('active','activating','deactivating'):raise ValueError('EXPERIMENT_TIMER_NOT_STOPPED')

def retire_experiments(catalog,rows,record):
    adopted=[]
    for role in ('primary','backup'):
        path=ROOT/('migration-'+role+'.json')
        if not path.exists():continue
        owned(path);value=json.loads(path.read_text())
        # These two exact, owner-confirmed leases are the only leases transferred.
        expected={'primary':('10.0.0.220','152.67.154.225','enp0s6:opmp'),'backup':('10.0.0.246','150.230.113.158','enp0s6:opmb')}[role]
        if (value.get('device')!='enp0s6' or (value.get('secondary'),value.get('public'),value.get('label'))!=expected or not isinstance(value.get('lease_id'),str) or len(value['lease_id'])!=32 or any(c not in '0123456789abcdef' for c in value['lease_id'])):raise ValueError('EXACT_MIGRATION_LEASE_REQUIRED')
        target=next((r for r in rows if r['local']==expected[0]),None)
        if target and (target.get('label')!=expected[2] or target.get('prefixlen')!=32):raise ValueError('FOREIGN_MIGRATION_ALIAS')
        if target:record['owned'][expected[0]]=expected[2]
        record.setdefault('retired_leases',{})[role]=value
        write(STATE,(json.dumps(record,sort_keys=True)+'\n').encode())
        stop_timer('oracle-proxy-migrate-'+role+'-'+value['lease_id']);adopted.append((path,STABLE/('migration_'+role+'_endpoint.py')))
    return adopted

def apply_locked(catalog):
    device=catalog['interface'];before=routes();rows=addresses(device)
    primary=next((r for r in rows if r['local']=='10.0.0.6'),None)
    if primary is None or primary.get('label')!=device or catalog['subnet']!='10.0.0.0/24':raise ValueError('ORIGINAL_PRIMARY_PRIVATE_REQUIRED')
    record={'schema':1,'device':device,'owned':{}}
    if STATE.exists():
        owned(STATE);record=json.loads(STATE.read_text())
        if record.get('schema')!=1 or record.get('device')!=device or not isinstance(record.get('owned'),dict):raise ValueError('OWNED_ENDPOINT_STATE_REQUIRED')
    adopted=retire_experiments(catalog,rows,record)
    for row in rows:
        if row['local'] in record['owned'] and (row.get('label')!=record['owned'][row['local']] or row.get('prefixlen')!=32):raise ValueError('FOREIGN_MANAGED_ALIAS')
    wanted={r['private_ipv4'] for r in [catalog['primary'],catalog['backup']]+catalog['legacy']}
    # Retain every legacy address until its public IP has been retired explicitly.
    for address in sorted(wanted):
        if address=='10.0.0.6':continue
        present=next((r for r in rows if r['local']==address),None)
        if present:continue
        label=device+':op'+address.rsplit('.',1)[1]
        record['owned'][address]=label;write(STATE,(json.dumps(record,sort_keys=True)+'\n').encode())
        run(['ip','-4','address','add',address+'/32','dev',device,'label',label,'noprefixroute'])
    if routes()!=before:raise ValueError('DEFAULT_ROUTE_OR_POLICY_CHANGED')
    actual={r['local']:r for r in addresses(device)}
    if not wanted<=set(actual):raise ValueError('ENDPOINT_ADDRESS_NOT_PRESENT')
    for address,label in list(record['owned'].items()):
        if address in wanted:continue
        row=actual.get(address)
        if row and (row.get('label')!=label or row.get('prefixlen')!=32):raise ValueError('FOREIGN_RETIRED_ALIAS')
        if row:run(['ip','-4','address','del',address+'/32','dev',device])
        del record['owned'][address]
    if routes()!=before:raise ValueError('DEFAULT_ROUTE_OR_POLICY_CHANGED')
    record.update(revision=catalog['revision'],applied_at=int(time.time()))
    write(STATE,(json.dumps(record,sort_keys=True)+'\n').encode())
    for state,script in adopted:
        for path in (state,script):
            if path.exists():owned(path);path.unlink()
    return {'revision':catalog['revision'],'primary':catalog['primary']['public_ipv4'],'backup':catalog['backup']['public_ipv4'],'default_routes_unchanged':True,'temporary_migration_timers_retired':bool(adopted),'private_addresses':sorted(wanted)}

def apply():
    if os.geteuid()!=0:raise ValueError('ROOT_REQUIRED')
    fd=os.open(ROOT/'endpoint-addresses.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX);catalog=module().read()
        if catalog is None:raise ValueError('ENDPOINT_CATALOG_REQUIRED')
        return apply_locked(catalog)
    finally:os.close(fd)

def _install():
    catalog=module().validate(json.loads((REPO/'ops/network/endpoints.json').read_text()))
    if os.geteuid()!=0:raise ValueError('ROOT_REQUIRED')
    fd=os.open(ROOT/'endpoint-addresses.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        result=apply_locked(catalog)
        # Activate metadata only after the corresponding local addresses exist.
        if CONFIG.exists():owned(CONFIG);write(ROOT/'endpoint-catalog.previous.json',CONFIG.read_bytes())
        write(CONFIG,(json.dumps(catalog,sort_keys=True)+'\n').encode(),0o644)
        write(STABLE/'endpoint_config.py',(REPO/'server/admin-oracle/console/endpoint_config.py').read_bytes(),0o644)
        write(STABLE/'endpoint_addresses.py',Path(__file__).read_bytes(),0o644)
    finally:os.close(fd)
    body=b'[Unit]\nDescription=Proxy configured endpoint addresses\nAfter=network-online.target\nWants=network-online.target\nBefore=oracle-proxy-quic.service\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -I /usr/local/libexec/oracle-project/endpoint_addresses.py\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n'
    write(UNIT,body,0o644);run(['systemctl','daemon-reload']);run(['systemctl','enable','proxy-endpoint-addresses.service'])
    run(['systemctl','start','proxy-endpoint-addresses.service']);return result

def install():
    try:return _install()
    except Exception as error:
        code=str(error)
        safe=code if re.fullmatch(r'[A-Z][A-Z0-9_]{1,80}',code) else type(error).__name__
        print('ENDPOINT_CATALOG_ERROR='+safe,flush=True)
        if isinstance(error,subprocess.CalledProcessError):
            print('ENDPOINT_CATALOG_COMMAND='+str(error.cmd[0])+';RETURN_CODE='+str(error.returncode),flush=True)
        raise

if __name__=='__main__':print(json.dumps(apply(),sort_keys=True))
