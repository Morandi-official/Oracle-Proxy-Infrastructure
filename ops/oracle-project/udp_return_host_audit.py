"""Bounded read-only host controls for the supplied failed and passing flows.

No packet generation, peer/key inventories, credential discovery, rule changes,
services or temporary listeners. Route lookups are not packet-delivery proof.
"""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import time

FLOWS=(('primary443','10.0.0.6',443,'111.55.79.240',56990),
       ('secondary8443','10.0.0.10',8443,'111.55.79.216',52306),
       ('secondary443_control','10.0.0.10',443,'111.55.79.216',51229))
SOURCES={'10.0.0.6','10.0.0.10'}


def read(command):
    result=subprocess.run(command,capture_output=True,text=True,check=True,timeout=5)
    if len(result.stdout)>65536:raise ValueError('AUDIT_OUTPUT_LIMIT')
    return result.stdout


def route_summary(text):
    rows=json.loads(text)
    if not isinstance(rows,list) or not 1<=len(rows)<=4 or any(not isinstance(r,dict) for r in rows):
        raise ValueError('INVALID_ROUTE_SHAPE')
    result=[]
    for row in rows:
        device=row.get('dev')
        result.append({'device':device if isinstance(device,str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',device) else None,
                       'type':row.get('type','unicast') if row.get('type','unicast') in ('unicast','local','unreachable','blackhole','prohibit') else 'OTHER',
                       'preferred_source':row.get('prefsrc') if row.get('prefsrc') in SOURCES else None,
                       'explicit_from':row.get('from') if row.get('from') in SOURCES else None,
                       'multipath':'multipath' in row or 'nexthops' in row})
    return result


def sysctls(file_read):
    paths={f'{scope}.{key}':f'/proc/sys/net/ipv4/conf/{scope}/{key}'
           for scope in ('all','default','enp0s6') for key in ('rp_filter','src_valid_mark','accept_local')}
    paths.update({name:'/proc/sys/net/netfilter/'+name for name in
                  ('nf_conntrack_count','nf_conntrack_max','nf_conntrack_udp_timeout','nf_conntrack_udp_timeout_stream')})
    result={}
    for name,path in paths.items():
        try:
            value=file_read(path).strip()
            result[name]=int(value) if re.fullmatch(r'[0-9]{1,20}',value) else None
        except OSError:result[name]=None
    return result


def counters(file_read):
    result={}
    for key in ('rx_packets','tx_packets','rx_errors','tx_errors','rx_dropped','tx_dropped'):
        try:
            value=file_read('/sys/class/net/enp0s6/statistics/'+key).strip()
            result[key]=int(value) if re.fullmatch(r'[0-9]{1,20}',value) else None
        except OSError:result[key]=None
    try:
        lines=file_read('/proc/net/snmp').splitlines()
        for i,line in enumerate(lines[:-1]):
            if line.startswith('Udp:') and lines[i+1].startswith('Udp:'):
                names=line.split()[1:];values=lines[i+1].split()[1:]
                if len(names)==len(values):
                    for name,value in zip(names,values):
                        if name in ('InErrors','RcvbufErrors','SndbufErrors','InCsumErrors','MemErrors') and re.fullmatch(r'[0-9]{1,20}',value):result['udp_'+name]=int(value)
    except OSError:pass
    return result


def observe(reader=read,file_read=lambda p:Path(p).read_text(),wait=time.sleep):
    result={'schema':1,'observed_at':int(time.time()),'scope':'CURRENT_HOST_ONLY_NOT_HISTORICAL_OR_OCI_EDGE_PROOF','routes':[]}
    try:
        mark=reader(['wg','show','wg0','fwmark']).strip()
        if mark=='off':mark='0'
        if not re.fullmatch(r'0x[0-9a-fA-F]{1,8}|[0-9]{1,10}',mark) or int(mark,0 if mark.startswith('0x') else 10)>2**32-1:raise ValueError('INVALID_FWMARK')
        result['wireguard_mark']=mark
    except (OSError,ValueError,subprocess.SubprocessError):mark=None;result['wireguard_mark']=None
    for label,source,public_port,destination,remote_port in FLOWS:
        for source_port in sorted({public_port,51820}):
            row={'flow':label,'explicit_source':source,'source_port':source_port,'destination':destination,'destination_port':remote_port}
            if mark is None:row['status']='MARK_UNAVAILABLE_ROUTE_NOT_EVALUATED'
            else:
                command=['ip','-j','-4','route','get',destination,'from',source,'ipproto','udp','sport',str(source_port),'dport',str(remote_port),'mark',mark]
                try:row.update(status='OBSERVED',lookup=route_summary(reader(command)))
                except (OSError,ValueError,subprocess.SubprocessError):row['status']='UNAVAILABLE'
            result['routes'].append(row)
    result['sysctls']=sysctls(file_read)
    before=counters(file_read);wait(5);after=counters(file_read)
    result['counter_delta_5s']={k:after[k]-v if v is not None and after.get(k) is not None and after[k]>=v else None for k,v in before.items()}
    result['counter_scope']='GLOBAL_INTERFACE_AND_UDP_NOT_ATTRIBUTABLE_TO_A_PARTICULAR_FLOW'
    result['oci_tools']={'cli_available':shutil.which('oci') is not None,'sdk_available':importlib.util.find_spec('oci') is not None,
                         'authentication':'NOT_TESTED_NO_CREDENTIALS_READ','platform_nat_logs':'NOT_ACCESSIBLE_FROM_HOST_COUNTERS'}
    return result
