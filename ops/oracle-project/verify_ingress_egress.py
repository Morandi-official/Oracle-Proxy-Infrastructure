"""Read-only deployed NAT checks plus real OCI per-private-address HTTPS exits."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[2]


def run(args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=25,check=False)
    if result.returncode or len(result.stdout)>65536:raise ValueError('INGRESS_EGRESS_VERIFICATION_OPERATION_FAILED')
    return result.stdout


def read_catalog():
    spec=importlib.util.spec_from_file_location('egress_catalog',ROOT/'server/admin-oracle/console/endpoint_config.py')
    catalog=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog)
    return catalog.read()


def verify():
    value=read_catalog()
    if value is None or set(value['egress_ipv4'])!={value[r]['public_ipv4'] for r in ('primary','backup')}:
        raise ValueError('PAIRED_INGRESS_EGRESS_CATALOG_REQUIRED')
    primary=value['primary']['private_ipv4'];backup=value['backup']['private_ipv4']
    marker='-m comment --comment proxy-user-ingress-v1'
    chain='OPX_INGRESS_EGRESS'
    rules=run(['iptables','-w','5','-t','nat','-S',chain]).splitlines()
    expected=[f'-A {chain} -m connmark --mark 0x20000000/0x20000000 {marker} -j SNAT --to-source {backup}',
              f'-A {chain} {marker} -j SNAT --to-source {primary}']
    if [line for line in rules if line.startswith('-A')]!=expected:raise ValueError('INGRESS_EGRESS_RULES_MISMATCH')
    addresses=json.loads(run(['ip','-j','-4','address','show','dev','wg0']))
    for item in addresses:
        for address in item.get('addr_info',[]):
            if address.get('family')!='inet':continue
            network=str(ipaddress.ip_interface(address['local']+'/'+str(address['prefixlen'])).network)
            run(['iptables','-w','5','-t','nat','-C','POSTROUTING','-s',network,'-o',value['interface'],'-m','comment','--comment','proxy-user-ingress-v1','-j',chain])
    result={}
    for role in ('primary','backup'):
        pair=value[role]
        trace=run(['curl','--fail','--silent','--show-error','--noproxy','*','--proto','=https','--interface',pair['private_ipv4'],
                   '--connect-timeout','8','--max-time','20','https://1.1.1.1/cdn-cgi/trace'])
        ips=[line[3:] for line in trace.splitlines() if line.startswith('ip=')]
        if ips!=[pair['public_ipv4']]:raise ValueError('INGRESS_IPV4_EXIT_MISMATCH_'+role.upper())
        result[role]={'private_ipv4':pair['private_ipv4'],'verified_exit_ipv4':ips[0]}
    return result


if __name__=='__main__':print(json.dumps(verify(),sort_keys=True))
