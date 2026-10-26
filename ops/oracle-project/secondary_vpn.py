"""Fixed owner secondary VPN ingress. No primary route, DNS or DHCP changes."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import re
import shlex
import subprocess
import sys

spec=importlib.util.spec_from_file_location('secondary_endpoint',Path(__file__).with_name('secondary_endpoint.py'))
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
SCRIPT=s.SCRIPT.with_name('secondary_vpn.py')
UNIT='oracle-proxy-secondary-endpoint.service'
UNIT_PATH=Path('/etc/systemd/system')/UNIT
COMMENT='oracle-proxy-secondary-quic'
RULE=['-d',s.SECONDARY+'/32','-p','udp','-m','udp','--dport','8443','-m','comment','--comment',COMMENT,
      '-j','DNAT','--to-destination',s.PRIMARY+':8443']
PUBLIC_STATE=Path('/etc/oracle-proxy-quic/transport.json')
PUBLIC_VALUE={'schema':1,'owner':'oracle-proxy-secondary-endpoint','transport_address':s.PUBLIC}


def nat_rules():
    return [shlex.split(line) for line in s.run(['iptables','-w','5','-t','nat','-S','PREROUTING']).stdout.splitlines()]


def inspect_nat():
    rows=nat_rules();owned=[row for row in rows if COMMENT in row]
    if owned and owned!=[['-A','PREROUTING',*RULE]]:raise ValueError('FOREIGN_SECONDARY_NAT_RULE')
    # WireGuard's typed REDIRECT must precede this catch-all QUIC destination rule.
    native=[i for i,row in enumerate(rows) if 'oracle-proxy-native-udp8443' in row and
            row[-4:]==['-j','REDIRECT','--to-ports','51820'] and '--u32' in row and
            re.sub(r'0x[0-9a-f]+',lambda match:hex(int(match[0],16)),row[row.index('--u32')+1].lower())==
            '0>>22&0x3c@8=0x1000000,0x2000000,0x3000000,0x4000000' and
            '--dport' in row and row[row.index('--dport')+1]=='8443']
    if len(native)!=1 or owned and native[0]>=rows.index(owned[0]):raise ValueError('NATIVE_REDIRECT_MUST_PRECEDE_SECONDARY_QUIC')
    return bool(owned)


def public_state(enabled):
    if PUBLIC_STATE.exists() or PUBLIC_STATE.is_symlink():
        s.owned_file(PUBLIC_STATE)
        if PUBLIC_STATE.stat().st_size>2048 or json.loads(PUBLIC_STATE.read_text())!=PUBLIC_VALUE:
            raise ValueError('FOREIGN_TRANSPORT_METADATA')
    if enabled:
        directory=PUBLIC_STATE.parent.lstat()
        if directory.st_uid!=0 or directory.st_mode&0o022 or PUBLIC_STATE.parent.is_symlink():raise ValueError('ROOT_PUBLIC_DIRECTORY_REQUIRED')
        s.write(PUBLIC_STATE,(json.dumps(PUBLIC_VALUE)+'\n').encode());PUBLIC_STATE.chmod(0o644)
    else:PUBLIC_STATE.unlink(missing_ok=True)


def ensure_locked():
    before,alias=s.snapshot()
    source=s.allocation_source(s.metadata())
    if source is None:raise ValueError('SECONDARY_ALLOCATION_NOT_VERIFIED')
    value=s.load_state()
    if before!=value['baseline'] or value['phase'] not in ('active','rolled_back') or alias and not s.owned_alias(alias):
        raise ValueError('PRIMARY_BASELINE_OR_OWNERSHIP_CHANGED')
    present=inspect_nat()
    if present and not value.get('vpn_nat_owned'):raise ValueError('UNOWNED_EXISTING_SECONDARY_NAT')
    # Rotate the old lease token before promotion. Its independent timer becomes a no-op.
    if value.get('mode')!='persistent':value['lease_id']=secrets.token_hex(16)
    value.update(mode='persistent',expires_at=0,vpn_nat_owned=True)
    s.persist(value) # Own a pending fixed rule before adding it; recoverable after a crash.
    if not alias:s.run(['ip','-4','address','add',s.SECONDARY+'/32','dev',s.DEVICE,'label',s.LABEL,'noprefixroute'])
    if not present:s.run(['iptables','-w','5','-t','nat','-A','PREROUTING',*RULE])
    if not inspect_nat() or s.snapshot()[0]!=before or not s.owned_alias(s.snapshot()[1]):raise ValueError('PERSISTENT_INGRESS_NOT_VERIFIED')
    value['phase']='active';s.persist(value)
    public_state(True)
    print('SECONDARY_VPN=PERSISTENT; PUBLIC='+s.PUBLIC+'; PRIMARY_BASELINE_UNCHANGED=True',flush=True)


def stop_locked():
    value=s.load_state()
    public_state(False) # New account state falls back to the original address first.
    rows=nat_rules();owned=[row for row in rows if COMMENT in row]
    if owned:
        if not value.get('vpn_nat_owned') or owned!=[['-A','PREROUTING',*RULE]]:raise ValueError('FOREIGN_SECONDARY_NAT_REFUSE_REMOVE')
        s.run(['iptables','-w','5','-t','nat','-D','PREROUTING',*RULE])
    if any(COMMENT in row for row in nat_rules()):raise ValueError('SECONDARY_NAT_REMOVAL_NOT_VERIFIED')
    s.rollback_locked()


def locked(action):
    fd=s.lock()
    try:action()
    finally:os.close(fd)


def unit_text():
    return ('[Unit]\nDescription=Oracle Proxy fixed secondary VPN ingress\n'
            'Wants=network-online.target\nAfter=network-online.target oracle-proxy-admin-web-firewall.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStart=/usr/bin/python3 -I '+str(SCRIPT)+' ensure\n'
            'ExecReload=/usr/bin/python3 -I '+str(SCRIPT)+' ensure\n'
            'ExecStop=/usr/bin/python3 -I '+str(SCRIPT)+' stop\n'
            'TimeoutStartSec=90\nTimeoutStopSec=45\n'
            '[Install]\nWantedBy=multi-user.target\n')


def install():
    fd=s.lock()
    try:
        # Validate the currently leased alias and exact baseline before installing anything.
        value=s.load_state();before,alias=s.snapshot()
        if value['phase']!='active' or value['baseline']!=before or not s.owned_alias(alias):raise ValueError('ACTIVE_OWNED_LEASE_REQUIRED')
        if s.allocation_source(s.metadata()) is None:raise ValueError('SECONDARY_ALLOCATION_NOT_VERIFIED')
        directory=s.SCRIPT.parent.lstat()
        if directory.st_uid!=0 or directory.st_mode&0o022 or s.SCRIPT.parent.is_symlink():raise ValueError('ROOT_SCRIPT_DIRECTORY_REQUIRED')
        s.write(s.SCRIPT,Path(__file__).with_name('secondary_endpoint.py').read_bytes())
        s.write(s.SCRIPT.with_name('secondary-allocation.json'),Path(__file__).with_name('secondary-allocation.json').read_bytes())
        s.write(SCRIPT,Path(__file__).read_bytes())
        if UNIT_PATH.exists() or UNIT_PATH.is_symlink():
            s.owned_file(UNIT_PATH)
            if UNIT_PATH.read_text()!=unit_text():raise ValueError('FOREIGN_SECONDARY_UNIT')
        s.write(UNIT_PATH,unit_text().encode());UNIT_PATH.chmod(0o644)
    finally:os.close(fd)
    # No lock held: ExecStart uses the same ownership lock.
    s.run(['systemctl','daemon-reload'])
    s.run(['systemctl','enable',UNIT])
    result=subprocess.run(['systemctl','is-active','--quiet',UNIT],check=False)
    s.run(['systemctl','reload' if result.returncode==0 else 'start',UNIT])
    s.run(['systemctl','is-active',UNIT])


def rollback():
    if UNIT_PATH.exists():
        s.owned_file(UNIT_PATH)
        if UNIT_PATH.read_text()!=unit_text():raise ValueError('FOREIGN_SECONDARY_UNIT')
        s.run(['systemctl','disable','--now',UNIT])
    locked(stop_locked)


if __name__=='__main__':
    try:
        if len(sys.argv)!=2 or sys.argv[1] not in ('ensure','stop'):raise ValueError('FIXED_SECONDARY_ACTION_REQUIRED')
        locked(ensure_locked if sys.argv[1]=='ensure' else stop_locked)
    except Exception as error:
        print('SECONDARY_VPN_OPERATION_FAILED='+type(error).__name__,file=sys.stderr);raise SystemExit(2) from None
