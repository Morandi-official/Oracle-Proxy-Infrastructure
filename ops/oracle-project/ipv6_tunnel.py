"""Owned IPv6 tunnel egress. Outer IPv4 VPN, routes and DHCP remain untouched."""
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SOURCE = '2603:c020:c015:8100::10'
DEVICE = 'enp0s6'
PREFIX = 'fd42:6f70:78:77::/64'
ADDRESS = 'fd42:6f70:78:77::1/64'
OWNER = 'oracle-proxy-ipv6-tunnel'
SCRIPT = Path('/usr/local/libexec/oracle-project/ipv6_tunnel.py')
STATE = Path('/var/lib/oracle-proxy-control/ipv6-tunnel.json')
PUBLIC = Path('/etc/oracle-proxy-quic/ipv6.json')
UNIT = Path('/etc/systemd/system/oracle-proxy-ipv6-tunnel.service')
NAT = ['-s', PREFIX, '-o', DEVICE, '-m', 'comment', '--comment', OWNER, '-j', 'SNAT', '--to-source', SOURCE]
JUMP = ['-m', 'comment', '--comment', OWNER, '-j', 'OPX_V6_EXIT']


def run(args, accepted=(0,)):
    value = subprocess.run(args, capture_output=True, text=True, timeout=15)
    if value.returncode not in accepted or len(value.stdout) > 131072:
        raise ValueError('IPV6_FIXED_OPERATION_FAILED')
    return value


def trusted(path):
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('IPV6_ROOT_OWNERSHIP_REQUIRED')


def write(path, data, mode=0o600):
    trusted(path.parent)
    if path.exists() or path.is_symlink():
        trusted(path)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.ipv6-')
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)


def sysctl(name, value=None):
    path = Path('/proc/sys/net/ipv6/conf') / name
    if value is None:
        return path.read_text().strip()
    if value not in ('0', '1', '2'): raise ValueError('INVALID_SYSCTL')
    path.write_text(value + '\n')


def verify_physical():
    if not (Path('/sys/class/net') / DEVICE / 'device').exists():
        raise ValueError('PHYSICAL_VNIC_REQUIRED')
    rows = json.loads(run(['ip', '-j', '-6', 'address', 'show', 'dev', DEVICE]).stdout)
    if not any(a.get('local') == SOURCE and not any(f in a.get('flags', []) for f in ('tentative', 'dadfailed')) for row in rows for a in row.get('addr_info', [])):
        raise ValueError('ASSIGNED_ORACLE_IPV6_REQUIRED')
    route = json.loads(run(['ip', '-j', '-6', 'route', 'get', '2606:4700:4700::1111']).stdout)
    if len(route) != 1 or route[0].get('dev') != DEVICE:
        raise ValueError('PHYSICAL_IPV6_ROUTE_REQUIRED')
    spec = importlib.util.spec_from_file_location('ipv6_egress', Path(__file__).with_name('ipv6_egress.py'))
    probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
    if probe.observe()['status'] != 'VERIFIED':
        raise ValueError('IPV6_HTTPS_EGRESS_REQUIRED')


def state():
    trusted(STATE)
    value = json.loads(STATE.read_text())
    if set(value) != {'owner', 'forwarding', 'accept_ra'} or value['owner'] != OWNER or value['forwarding'] not in ('0', '1') or value['accept_ra'] not in ('0', '1', '2'):
        raise ValueError('FOREIGN_IPV6_STATE')
    return value


def remove_public():
    if PUBLIC.exists() or PUBLIC.is_symlink():
        trusted(PUBLIC)
        if json.loads(PUBLIC.read_text()) != {'schema': 1, 'owner': OWNER, 'egress': SOURCE, 'prefix': PREFIX}:
            raise ValueError('FOREIGN_IPV6_PUBLIC_STATE')
        PUBLIC.unlink()


def ensure():
    remove_public()
    verify_physical()
    run(['ip6tables', '-w', '5', '-S', 'OPX_FWD'])
    if not STATE.exists():
        addresses = json.loads(run(['ip', '-j', '-6', 'addr', 'show', 'dev', 'wg0']).stdout)
        if any(ipaddress.ip_interface(a['local'] + '/' + str(a['prefixlen'])).network == ipaddress.ip_network(PREFIX) for row in addresses for a in row.get('addr_info', []) if a.get('family') == 'inet6'):
            raise ValueError('UNOWNED_EXISTING_WG_IPV6')
        write(STATE, json.dumps({'owner': OWNER, 'forwarding': sysctl('all/forwarding'), 'accept_ra': sysctl(DEVICE + '/accept_ra')}).encode())
    state()
    old = run(['ip6tables', '-w', '5', '-S', 'OPX_V6_EXIT'], accepted=(0, 1))
    if old.returncode == 0 and any(OWNER not in line for line in old.stdout.splitlines() if line.startswith('-A')):
        raise ValueError('FOREIGN_IPV6_CHAIN')
    if old.returncode == 1: run(['ip6tables', '-w', '5', '-N', 'OPX_V6_EXIT'])
    # Each accept traverses the quota/expiry/kernel-lease policy first, including
    # when another installer inserts a new parent-chain rule ahead of OPX_FWD.
    rules = [
        ['-j', 'OPX_FWD'],
        ['-i', 'wg0', '-o', DEVICE, '-s', PREFIX, '-j', 'ACCEPT'],
        ['-i', DEVICE, '-o', 'wg0', '-d', PREFIX, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']]
    body = '*filter\n-F OPX_V6_EXIT\n' + ''.join('-A OPX_V6_EXIT -m comment --comment ' + OWNER + ' ' + ' '.join(rule) + '\n' for rule in rules) + 'COMMIT\n'
    result = subprocess.run(['ip6tables-restore', '-w', '5', '--noflush'], input=body, capture_output=True, text=True, timeout=15)
    if result.returncode: raise ValueError('IPV6_FILTER_INSTALL_FAILED')
    for table, chain, rule in [('filter', 'FORWARD', JUMP), ('nat', 'POSTROUTING', NAT)]:
        if run(['ip6tables', '-w', '5', '-t', table, '-C', chain, *rule], accepted=(0, 1)).returncode:
            run(['ip6tables', '-w', '5', '-t', table, '-I', chain, '1', *rule])
    sysctl(DEVICE + '/accept_ra', '2')
    sysctl('all/forwarding', '1')
    run(['ip', '-6', 'addr', 'replace', ADDRESS, 'dev', 'wg0'])
    write(PUBLIC, json.dumps({'schema': 1, 'owner': OWNER, 'egress': SOURCE, 'prefix': PREFIX}).encode(), 0o644)
    print('IPV6_TUNNEL_BASE=ACTIVE; CLIENT_ACCEPTANCE=NOT_TESTED', flush=True)


def rollback():
    remove_public()
    value = state()
    for table, chain, rule in [('filter', 'FORWARD', JUMP), ('nat', 'POSTROUTING', NAT)]:
        if run(['ip6tables', '-w', '5', '-t', table, '-C', chain, *rule], accepted=(0, 1)).returncode == 0:
            run(['ip6tables', '-w', '5', '-t', table, '-D', chain, *rule])
    run(['ip', '-6', 'addr', 'del', ADDRESS, 'dev', 'wg0'], accepted=(0, 2))
    if sysctl('all/forwarding') == '1': sysctl('all/forwarding', value['forwarding'])
    if sysctl(DEVICE + '/accept_ra') == '2': sysctl(DEVICE + '/accept_ra', value['accept_ra'])
    print('IPV6_TUNNEL_BASE=ROLLED_BACK; IPV4_UNCHANGED=True', flush=True)


def unit_text():
    return ('[Unit]\nDescription=Oracle Proxy owned IPv6 tunnel egress\n'
            'Requires=wg-quick@wg0.service oracle-proxy-control.service\n'
            'After=network-online.target wg-quick@wg0.service oracle-proxy-control.service\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStart=/usr/bin/python3 -I ' + str(SCRIPT) + ' ensure\n'
            'ExecStop=/usr/bin/python3 -I ' + str(SCRIPT) + ' rollback\n'
            'TimeoutStartSec=60\nTimeoutStopSec=45\nRestart=on-failure\nRestartSec=10\n'
            '[Install]\nWantedBy=multi-user.target\n')


def install():
    verify_physical()
    for name in ('ipv6_tunnel.py', 'ipv6_egress.py'):
        write(SCRIPT.with_name(name), Path(__file__).with_name(name).read_bytes(), 0o644)
    if UNIT.exists() and UNIT.read_text() != unit_text(): raise ValueError('FOREIGN_IPV6_UNIT')
    write(UNIT, unit_text().encode(), 0o644)
    run(['systemctl', 'daemon-reload'])
    try:
        run(['systemctl', 'enable', '--now', UNIT.name])
        run(['systemctl', 'is-active', '--quiet', UNIT.name])
    except Exception:
        subprocess.run(['systemctl', 'stop', UNIT.name], capture_output=True, timeout=45)
        if STATE.exists(): rollback()
        raise


if __name__ == '__main__':
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ('ensure', 'rollback'):
        raise SystemExit('ROOT_FIXED_OPERATION_REQUIRED')
    trusted(STATE.parent)
    with (STATE.parent / 'ipv6-tunnel.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        {'ensure': ensure, 'rollback': rollback}[sys.argv[1]]()
