"""Fixed read-only UDP transport summaries; no peers, addresses, keys or raw logs."""
import json
import re
import shlex
import subprocess
from pathlib import Path

PORTS=(51820,443,8443)
UNITS=('oracle-proxy-quic.service','wg-quick@wg0.service','oracle-proxy-control.service','oracle-proxy-admin-web-firewall.service')


def firewall_summary(text):
    result={str(p):{'redirect_rules':0,'redirect_packets':0,'input_accept_positions':[]} for p in PORTS}
    table='';position=0;reject=[]
    for line in text.splitlines():
        if line.startswith('*'):table=line[1:];continue
        match=re.fullmatch(r'\[(\d+):(\d+)\] (.+)',line)
        packets=int(match[1]) if match else 0
        fields=shlex.split(match[3] if match else line)
        if len(fields)<2 or fields[0]!='-A':continue
        def item(name):return fields[fields.index(name)+1] if name in fields and fields.index(name)+1<len(fields) else None
        if table=='filter' and fields[1]=='INPUT':
            position+=1
            if item('-j') in ('REJECT','DROP') and all(x not in fields for x in ('-p','-s','-d','-i','-o','-m')):reject.append(position)
            if item('-p')=='udp' and item('--dport') in result and item('-j')=='ACCEPT':result[item('--dport')]['input_accept_positions'].append(position)
        if (table=='nat' and fields[1]=='PREROUTING' and item('-p')=='udp' and item('--dport') in ('443','8443') and
                item('-j')=='REDIRECT' and item('--to-ports')=='51820' and item('--u32')=='0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000'):
            row=result[item('--dport')];row['redirect_rules']+=1;row['redirect_packets']+=packets
    return {'ports':result,'unconditional_input_reject_positions':reject,'reachability':'NOT_PROVEN'}


def read(command):
    result=subprocess.run(command,capture_output=True,text=True,check=True,timeout=5)
    if len(result.stdout)>262144:raise ValueError('OUTPUT_LIMIT')
    return result.stdout


def observe():
    result={'schema':1,'units':{},'listeners':{},'firewall':{'status':'UNAVAILABLE'},'conntrack':{}}
    for unit in UNITS:
        try:
            rows=dict(line.split('=',1) for line in read(['systemctl','show',unit,'--property=ActiveState,SubState,NRestarts,ExecMainStatus']).splitlines() if '=' in line)
            result['units'][unit]={k:v for k,v in rows.items() if k in ('ActiveState','SubState','NRestarts','ExecMainStatus') and re.fullmatch(r'[a-z0-9-]{1,32}',v)}
        except (OSError,ValueError,subprocess.SubprocessError):result['units'][unit]={'status':'UNAVAILABLE'}
    for port in PORTS:
        try:result['listeners'][str(port)]=bool(read(['ss','-H','-lun',f'sport = :{port}']).strip())
        except (OSError,ValueError,subprocess.SubprocessError):result['listeners'][str(port)]=None
    try:result['firewall']=firewall_summary(read(['iptables-save','-c']))
    except (OSError,ValueError,subprocess.SubprocessError):pass
    for name in ('nf_conntrack_count','nf_conntrack_max','nf_conntrack_udp_timeout','nf_conntrack_udp_timeout_stream'):
        try:
            value=(Path('/proc/sys/net/netfilter')/name).read_text().strip()
            if re.fullmatch(r'[0-9]{1,12}',value):result['conntrack'][name]=int(value)
        except OSError:pass
    return result


if __name__=='__main__':print(json.dumps(observe(),sort_keys=True))
