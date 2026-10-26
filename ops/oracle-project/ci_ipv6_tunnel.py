"""Disposable network namespace only: real NAT66 syntax and owned rollback."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

if os.geteuid()!=0 or os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')!='1' or os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):
    raise SystemExit('DISPOSABLE_NETWORK_NAMESPACE_REQUIRED')
spec=importlib.util.spec_from_file_location('ipv6_tunnel',Path(__file__).with_name('ipv6_tunnel.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True).stdout

with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    m.STATE=root/'ipv6-tunnel.json';m.PUBLIC=root/'ipv6.json'
    run('ip','link','add',m.DEVICE,'type','dummy')
    run('ip','link','set',m.DEVICE,'up')
    run('ip','link','add','wg0','type','dummy')
    run('ip','link','set','wg0','up')
    run('ip6tables','-N','OPX_FWD')
    # Physical internet proof runs separately on Oracle. Here verify only real
    # kernel rule parsing, lease-first ordering, idempotency and owned rollback.
    m.verify_physical=lambda:None
    before=m.sysctl('all/forwarding'),m.sysctl(m.DEVICE+'/accept_ra')
    m.ensure();m.ensure()
    assert json.loads(m.PUBLIC.read_text())['egress']==m.SOURCE
    rows=run('ip6tables','-S','OPX_V6_EXIT').splitlines()
    assert '-j OPX_FWD' in next(line for line in rows if line.startswith('-A'))
    assert sum('OPX_V6_EXIT' in line for line in run('ip6tables','-S','FORWARD').splitlines())==1
    assert sum(m.OWNER in line for line in run('ip6tables','-t','nat','-S','POSTROUTING').splitlines())==1
    assert m.ADDRESS.split('/')[0] in run('ip','-6','addr','show','dev','wg0')
    m.rollback()
    assert not m.PUBLIC.exists()
    assert not m.OWNER in run('ip6tables','-t','nat','-S','POSTROUTING')
    assert not 'OPX_V6_EXIT' in run('ip6tables','-S','FORWARD')
    assert before==(m.sysctl('all/forwarding'),m.sysctl(m.DEVICE+'/accept_ra'))
print('REAL_ISOLATED_IPV6_NAT_POLICY_ORDER_AND_ROLLBACK=PASS')
