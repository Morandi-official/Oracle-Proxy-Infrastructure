"""One root-owned endpoint catalog shared by API, exports and packet observations."""
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import os
import json
from pathlib import Path
import stat

PATH=Path('/etc/oracle-proxy-quic/endpoints.json')
SELECTION_DIR=Path('/var/lib/oracle-proxy-endpoints')


def version(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _read_file(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096:
        raise ValueError('ROOT_ENDPOINT_CATALOG_REQUIRED')
    return json.loads(path.read_text('ascii'))


def read_base():
    value = _read_file(PATH)
    return None if value is None else validate(value)


@contextmanager
def selection_lock(*, create=False):
    if create:
        created = False
        try:
            SELECTION_DIR.mkdir()
            created = True
        except FileExistsError:
            pass
    info = SELECTION_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('ROOT_ENDPOINT_SELECTION_DIRECTORY_REQUIRED')
    if create and created:
        SELECTION_DIR.chmod(0o755)
    fd = os.open(SELECTION_DIR / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_uid != 0:
            raise ValueError('ROOT_ENDPOINT_SELECTION_LOCK_REQUIRED')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('ENDPOINT_SELECTION_BUSY') from None
        yield
    finally:
        os.close(fd)


def public(value):
    address=ipaddress.ip_address(value)
    if address.version!=4 or not address.is_global:raise ValueError('PUBLIC_IPV4_REQUIRED')
    return str(address)

def validate(value):
    if not isinstance(value,dict) or set(value)!={'schema','revision','api_host','interface','subnet','primary','backup','active','egress_ipv4','legacy'} or type(value['schema']) is not int or value['schema']!=1:
        raise ValueError('ENDPOINT_CATALOG_SCHEMA')
    if value['api_host']!='vpn-admin.morandi.dpdns.org' or value['interface']!='enp0s6' or type(value['revision']) is not int or value['revision']<1 or value['active'] not in ('primary','backup'):
        raise ValueError('ENDPOINT_CATALOG_SCOPE')
    subnet=ipaddress.ip_network(value['subnet'],strict=True)
    if subnet.version!=4 or not subnet.is_private or subnet.prefixlen<24:raise ValueError('ENDPOINT_SUBNET_REQUIRED')
    if not isinstance(value['legacy'],list) or len(value['legacy'])>2:raise ValueError('ENDPOINT_LEGACY_LIMIT')
    rows=[value['primary'],value['backup']]+value['legacy']
    for row in rows:
        if not isinstance(row,dict) or set(row)!={'public_ipv4','private_ipv4'}:raise ValueError('ENDPOINT_ADDRESS_PAIR_REQUIRED')
        public(row['public_ipv4']);private=ipaddress.ip_address(row['private_ipv4'])
        if private not in subnet or private in (subnet.network_address,subnet.broadcast_address):raise ValueError('ENDPOINT_PRIVATE_SUBNET_REQUIRED')
    if len({r['public_ipv4'] for r in rows})!=len(rows) or len({r['private_ipv4'] for r in rows})!=len(rows):raise ValueError('DUPLICATE_ENDPOINT')
    exits=value['egress_ipv4']
    if not isinstance(exits,list) or not 1<=len(exits)<=2 or len(set(exits))!=len(exits) or any(x not in {r['public_ipv4'] for r in rows} for x in exits):raise ValueError('OWNED_EGRESS_REQUIRED')
    return value

def read():
    base = read_base()
    if base is None:
        return None
    selection = _read_file(SELECTION_DIR / 'selection.json')
    if selection is None:
        return base
    if not isinstance(selection, dict) or set(selection) != {'baseline', 'revision', 'primary', 'backup'}:
        raise ValueError('ENDPOINT_SELECTION_SCHEMA')
    if selection['baseline'] != version(base):
        return base  # An explicit GitOps address change supersedes the saved runtime roles.
    if type(selection['revision']) is not int or selection['revision'] <= base['revision']:
        raise ValueError('ENDPOINT_SELECTION_REVISION')
    proposed = propose_selection(base, selection['primary'], selection['backup'], base['revision'])
    return dict(proposed or base, revision=selection['revision'])


def propose_selection(current, primary, backup, revision):
    """Select roles among the exact address pairs already in the catalog."""
    validate(current)
    if type(revision) is not int or revision != current['revision']:
        raise ValueError('ENDPOINT_CATALOG_STALE')
    if not isinstance(primary, str) or not isinstance(backup, str) or primary == backup:
        raise ValueError('ENDPOINT_ROLES_MUST_DIFFER')
    rows = [current['primary'], current['backup'], *current['legacy']]
    candidates = {row['public_ipv4']: row for row in rows}
    if primary not in candidates or backup not in candidates:
        raise ValueError('ENDPOINT_NOT_IN_CATALOG')
    proposed = dict(current, primary=candidates[primary], backup=candidates[backup],
                    active='primary', egress_ipv4=[primary, backup],
                    legacy=[row for row in rows if row['public_ipv4'] not in (primary, backup)])
    if proposed == current:
        return None
    proposed['revision'] += 1
    return validate(proposed)


def advertised():
    config=read()
    if config is None:return None
    active=config[config['active']]['public_ipv4']
    standby=config['backup' if config['active']=='primary' else 'primary']['public_ipv4']
    return {'schema':1,'revision':config['revision'],'primary':active,'backup':standby,'egress_ipv4':config['egress_ipv4'],'private_ipv4':{row['public_ipv4']:row['private_ipv4'] for row in [config['primary'],config['backup']]+config['legacy']}}


def user_catalog(user, snapshot):
    """Public endpoint identities scoped to a root-ledger user policy."""
    config=read()
    if config is None:return None
    policy=user.get('ingress',{'access':'primary','preferred':'primary'})
    access=policy['access'];preferred=policy['preferred']
    roles=['primary','backup'] if access=='both' else [access]
    if preferred not in roles:raise ValueError('INVALID_INGRESS_POLICY')
    roles=[preferred]+[r for r in roles if r!=preferred]
    keys={'primary':snapshot['server_public_key'],**snapshot.get('endpoint_public_keys',{})}
    if any(not keys.get(role) for role in roles):raise ValueError('INGRESS_ISOLATION_NOT_READY')
    import base64
    for role in roles:
        if len(base64.b64decode(keys[role],validate=True))!=32:raise ValueError('INVALID_INGRESS_PUBLIC_KEY')
    paired=set(config['egress_ipv4'])=={config[r]['public_ipv4'] for r in ('primary','backup')}
    exits=[config[r]['public_ipv4'] for r in roles] if paired else config['egress_ipv4']
    return {'roles':roles,'addresses':[config[r]['public_ipv4'] for r in roles],
            'revision':config['revision'],'private_ipv4':{config[r]['public_ipv4']:config[r]['private_ipv4'] for r in roles},
            'server_public_keys':{config[r]['public_ipv4']:keys[r] for r in roles},'egress_ipv4':exits}
