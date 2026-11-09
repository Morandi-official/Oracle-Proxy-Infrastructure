"""Read-only, bounded retirement inventory; never export credentials or peer keys."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess

ROOT=Path('/var/lib/oracle-project-ops')
STABLE=Path('/usr/local/libexec/oracle-project')
SOURCE=Path(__file__).parent

def command(args):
    r=subprocess.run(args,capture_output=True,text=True,check=True,timeout=10)
    if len(r.stdout)>131072:raise ValueError('AUDIT_OUTPUT_LIMIT')
    return r.stdout

def read(path):
    if not path.exists() and not path.is_symlink():return None
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022 or s.st_size>65536:raise ValueError('UNTRUSTED_AUDIT_FILE')
    return path.read_bytes()

def metadata(path,fields):
    body=read(path)
    if body is None:return {'exists':False}
    value=json.loads(body)
    return {'exists':True,**{k:value[k] for k in fields if k in value}}

def script(name):
    body=read(STABLE/name)
    return {'exists':body is not None,'matches_repository':body==(SOURCE/name).read_bytes() if body is not None else None}

def observe():
    if os.geteuid()!=0:raise ValueError('ROOT_ONLY')
    addresses=json.loads(command(['ip','-j','address','show','dev','enp0s6']))
    rows=[{k:r[k] for k in ('family','local','prefixlen','scope','label') if k in r} for r in addresses[0]['addr_info']]
    units=json.loads(command(['systemctl','list-units','--all','--output=json','oracle-proxy-secondary-endpoint.service','oracle-proxy-udp-ab-*','oracle-proxy-migrate-*','proxy-endpoint-addresses.service']))
    unit_rows=[{k:r[k] for k in ('unit','load','active','sub') if k in r} for r in units]
    files={n:metadata(ROOT/n,fields) for n,fields in {
        'endpoint-addresses.json':('schema','device','owned','revision'),
        'secondary-endpoint.json':('schema','device','secondary','public','label','mode','phase','vpn_nat_owned','expires_at'),
        'udp-return-ab.json':('schema','device','secondary','public','label','phase','expires_at'),
        'udp-return-ab-retired.json':('schema','cleaned','alias_removed','timer_stopped','stable_script_removed'),
    }.items()}
    nat=command(['iptables','-w','5','-t','nat','-S','PREROUTING']).splitlines()
    owned_nat=[r for r in nat if 'oracle-proxy-secondary-quic' in r or 'oracle-proxy-native-udp8443' in r]
    ci=[]
    database=Path('/var/lib/oracle-proxy-control/ledger.sqlite3')
    with sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row
        for r in db.execute('SELECT d.key,e.machine_name,e.client_version,e.confirmed_at FROM devices d JOIN device_enrollments e ON e.key=d.key AND e.user_id=d.user_id WHERE d.key NOT IN (SELECT key FROM revoked_devices)'):
            fingerprint=hashlib.sha256(r['key'].encode()).hexdigest()[:12]
            if fingerprint=='ff444e826eed' or r['client_version']=='0.3.0-rc34+278f8f2c92c6095cb80b23a7b99dc2263aef436a':
                ci.append({'fingerprint':fingerprint,'machine':r['machine_name'],'version':r['client_version'],'confirmed_at':r['confirmed_at']})
    return {'scope':'READ_ONLY','addresses':rows,'units':unit_rows,'files':files,
        'scripts':{n:script(n) for n in ('secondary_vpn.py','secondary_endpoint.py','udp_return_ab_endpoint.py')},
        'secondary_unit_exists':read(Path('/etc/systemd/system/oracle-proxy-secondary-endpoint.service')) is not None,
        'owned_nat_rules':owned_nat,'ci_candidates':ci,
        'default_routes':[json.loads(command(['ip','-j',family,'route','show','default'])) for family in ('-4','-6')]}
