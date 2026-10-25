"""Fixed read-only UDP transport summaries; no peers, addresses, keys or raw logs."""
import json
import re
import shlex
import subprocess
from pathlib import Path

PORTS=(51820,443,8443)
UNITS=('oracle-proxy-quic.service','wg-quick@wg0.service','oracle-proxy-control.service','oracle-proxy-admin-web-firewall.service')


def normalize_u32(value):
    if not isinstance(value,str):return ''
    return re.sub(r'0[xX][0-9a-fA-F]+|[0-9]+',lambda m:str(int(m[0],16 if m[0].lower().startswith('0x') else 10)),value.replace(' ',''))


def firewall_summary(text):
    result={str(p):{'redirect_rules':0,'redirect_packets':0,'input_accept_positions':[]} for p in PORTS}
    table='';position=0;reject=[]
    egress={'filter_output_policy':None,'filter_output_rule_count':0,'filter_output_shapes':[],
            'other_tables_output_rule_count':0,'other_tables_postrouting_rule_count':0}
    for line in text.splitlines():
        if line.startswith('*'):table=line[1:];continue
        policy=re.fullmatch(r':OUTPUT (ACCEPT|DROP) \[[0-9]+:[0-9]+\]',line)
        if table=='filter' and policy:egress['filter_output_policy']=policy[1]
        match=re.fullmatch(r'\[(\d+):(\d+)\] (.+)',line)
        packets=int(match[1]) if match else 0
        fields=shlex.split(match[3] if match else line)
        if len(fields)<2 or fields[0]!='-A':continue
        def item(name):return fields[fields.index(name)+1] if name in fields and fields.index(name)+1<len(fields) else None
        if fields[1]=='OUTPUT':
            if table=='filter':
                egress['filter_output_rule_count']+=1
                if len(egress['filter_output_shapes'])<64:
                    egress['filter_output_shapes'].append({
                        'protocol':item('-p') if item('-p') in ('tcp','udp','icmp','all') else 'OTHER',
                        'target':item('-j') if item('-j') in ('ACCEPT','DROP','REJECT','RETURN','LOG') else 'CUSTOM_OR_OTHER',
                        'source_match':'-s' in fields,'destination_match':'-d' in fields,
                        'interface_match':any(x in fields for x in ('-i','-o')),
                        'port_match':any(x in fields for x in ('--sport','--dport','--sports','--dports')),
                        'packets':packets})
            else:egress['other_tables_output_rule_count']+=1
        if fields[1]=='POSTROUTING' and table not in ('filter','nat'):
            egress['other_tables_postrouting_rule_count']+=1
        if table=='filter' and fields[1]=='INPUT':
            position+=1
            if item('-j') in ('REJECT','DROP') and all(x not in fields for x in ('-p','-s','-d','-i','-o','-m')):reject.append(position)
            if item('-p')=='udp' and item('--dport') in result and item('-j')=='ACCEPT':result[item('--dport')]['input_accept_positions'].append(position)
        if (table=='nat' and fields[1]=='PREROUTING' and item('-p')=='udp' and item('--dport') in ('443','8443') and
                item('-j')=='REDIRECT' and item('--to-ports')=='51820' and normalize_u32(item('--u32'))=='0>>22&60@8=16777216,33554432,50331648,67108864'):
            row=result[item('--dport')];row['redirect_rules']+=1;row['redirect_packets']+=packets
    return {'ports':result,'unconditional_input_reject_positions':reject,'egress':egress,'reachability':'NOT_PROVEN'}


def route_summary(defaults, rules, controls):
    """No gateways, source/destination addresses or private routing-table names."""
    def device(value):
        return value if isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}',value) else None
    return {
        'default_route_count':len(defaults),
        'default_devices':sorted({device(x.get('dev')) for x in defaults if device(x.get('dev'))}),
        'default_multipath':any('multipath' in x or 'nexthops' in x for x in defaults),
        'policy_rule_count':len(rules),
        'custom_table_rule_count':sum(x.get('table') not in (None,'local','main','default',253,254,255) for x in rules),
        'source_selector_rule_count':sum(x.get('src') not in (None,'all','0.0.0.0/0') for x in rules),
        'destination_selector_rule_count':sum(x.get('dst') not in (None,'all','0.0.0.0/0') for x in rules),
        'marked_rule_count':sum('fwmark' in x for x in rules),
        'control_route_devices':[[device(x.get('dev')) for x in rows if device(x.get('dev'))] for rows in controls],
        'scope':'HOST_ONLY_NOT_OCI_SECURITY_LIST_OR_END_TO_END_PROOF',
    }


def udp_kernel_counters(text):
    allowed=('InDatagrams','OutDatagrams','NoPorts','InErrors','RcvbufErrors','SndbufErrors','InCsumErrors','IgnoredMulti','MemErrors')
    lines=text.splitlines();result={}
    for index,line in enumerate(lines[:-1]):
        if not line.startswith('Udp:') or not lines[index+1].startswith('Udp:'):continue
        names=line.split()[1:];values=lines[index+1].split()[1:]
        if len(names)!=len(values):continue
        result={k:int(v) for k,v in zip(names,values) if k in allowed and re.fullmatch(r'[0-9]{1,20}',v)}
        if result:break
    return result


def egress_observation():
    result={'status':'UNAVAILABLE'}
    try:
        defaults=json.loads(read(['ip','-j','-4','route','show','default']))
        rules=json.loads(read(['ip','-j','-4','rule','show']))
        controls=[json.loads(read(['ip','-j','-4','route','get',address])) for address in ('1.1.1.1','8.8.8.8','114.114.114.114')]
        if any(not isinstance(rows,list) or len(rows)>1024 or any(not isinstance(x,dict) for x in rows) for rows in (defaults,rules,*controls)):
            raise ValueError('INVALID_ROUTE_SHAPE')
        result=route_summary(defaults,rules,controls);result['status']='OBSERVED';result['interfaces']={}
        def number(path,maximum=10**20):
            value=path.read_text().strip()
            return int(value) if re.fullmatch(r'[0-9]{1,20}',value) and int(value)<=maximum else None
        for name in result['default_devices']:
            base=Path('/sys/class/net')/name
            values={}
            for key in ('mtu',):
                try:values[key]=number(base/key,65536)
                except OSError:values[key]=None
            for key in ('rx_dropped','tx_dropped','rx_errors','tx_errors'):
                try:values[key]=number(base/'statistics'/key)
                except OSError:values[key]=None
            for key in ('rp_filter',):
                try:values[key]=number(Path('/proc/sys/net/ipv4/conf')/name/key,2)
                except OSError:values[key]=None
            result['interfaces'][name]=values
        result['udp_kernel_counters']=udp_kernel_counters(Path('/proc/net/snmp').read_text())
    except (OSError,ValueError,TypeError,subprocess.SubprocessError):
        result['status']='UNAVAILABLE'
    return result


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
    result['egress_routes_and_counters']=egress_observation()
    return result


if __name__=='__main__':print(json.dumps(observe(),sort_keys=True))
