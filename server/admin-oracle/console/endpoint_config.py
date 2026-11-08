"""One root-owned endpoint catalog shared by API, exports and packet observations."""
import ipaddress
import json
from pathlib import Path
import stat

PATH=Path('/etc/oracle-proxy-quic/endpoints.json')

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
    try:info=PATH.lstat()
    except FileNotFoundError:return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>4096:raise ValueError('ROOT_ENDPOINT_CATALOG_REQUIRED')
    return validate(json.loads(PATH.read_text('ascii')))

def advertised():
    config=read()
    if config is None:return None
    active=config[config['active']]['public_ipv4']
    standby=config['backup' if config['active']=='primary' else 'primary']['public_ipv4']
    return {'schema':1,'revision':config['revision'],'primary':active,'backup':standby,'egress_ipv4':config['egress_ipv4'],'private_ipv4':{row['public_ipv4']:row['private_ipv4'] for row in [config['primary'],config['backup']]+config['legacy']}}
