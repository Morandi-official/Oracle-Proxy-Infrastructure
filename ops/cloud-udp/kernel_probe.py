"""Native Linux WireGuard on a disposable cloud runner, target-only routes."""
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

INTERFACE='wgcloud0'
ENDPOINTS=[(a,p) for a in ('152.67.156.100','141.147.78.44') for p in (443,8443,51820)]


def run(args):
    return subprocess.run(args,text=True,capture_output=True,check=True,timeout=20).stdout.strip()


def main(path):
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        # sudo may omit these environment flags; the caller must explicitly pass them.
        raise ValueError('DISPOSABLE_RUNNER_REQUIRED')
    info=json.loads(Path(path).read_text())
    if subprocess.run(['ip','link','show',INTERFACE],capture_output=True).returncode==0:
        raise ValueError('PREEXISTING_INTERFACE_REFUSED')
    for target in ('1.1.1.1/32','2606:4700:4700::1111/128'):
        family='-6' if ':' in target else '-4'
        if run(['ip',family,'route','show',target]):raise ValueError('PREEXISTING_TARGET_ROUTE_REFUSED')
    with tempfile.TemporaryDirectory(prefix='kernel-wg-private-') as folder:
        key=Path(folder)/'key';key.write_text(info['private_key']+'\n');key.chmod(0o600)
        for address,port in ENDPOINTS:
            created=False;row={'address':address,'port':port,'started_at':int(time.time())}
            try:
                run(['ip','link','add',INTERFACE,'type','wireguard']);created=True
                run(['wg','set',INTERFACE,'private-key',str(key),'peer',info['server_public_key'],
                     'allowed-ips','0.0.0.0/0,::/0','endpoint',address+':'+str(port),'persistent-keepalive','5'])
                for value in info['allowed_ips']:
                    run(['ip','address','add',value,'dev',INTERFACE])
                run(['ip','link','set','dev',INTERFACE,'mtu','1280','up'])
                run(['ip','route','add','1.1.1.1/32','dev',INTERFACE])
                targets=[('ipv4','https://1.1.1.1/cdn-cgi/trace','152.67.156.100')]
                if any(ipaddress.ip_interface(a).version==6 for a in info['allowed_ips']):
                    run(['ip','-6','route','add','2606:4700:4700::1111/128','dev',INTERFACE])
                    targets.append(('ipv6','https://[2606:4700:4700::1111]/cdn-cgi/trace','2603:c020:c015:8100::10'))
                for family,url,expected in targets:
                    fetched=subprocess.run(['curl','--noproxy','*','--interface',INTERFACE,'--fail','--silent','--show-error',
                                            '--connect-timeout','8','--max-time','12',url],text=True,capture_output=True,timeout=15)
                    item={'curl_exit':fetched.returncode}
                    if fetched.returncode==0:
                        values=dict(line.split('=',1) for line in fetched.stdout.splitlines() if '=' in line)
                        item['exit_ip']=str(ipaddress.ip_address(values['ip']))
                        item['expected_exit']=item['exit_ip']==expected
                    row[family]=item
                handshakes=run(['wg','show',INTERFACE,'latest-handshakes']).splitlines()
                row['handshake_fresh']=any(int(line.split()[1])>=row['started_at']-2 for line in handshakes)
                endpoints=run(['wg','show',INTERFACE,'endpoints']).splitlines()
                row['endpoint_after_handshake']=endpoints[0].split()[1] if len(endpoints)==1 else None
                row['endpoint_matches_requested']=row['endpoint_after_handshake']==address+':'+str(port)
                transfers=run(['wg','show',INTERFACE,'transfer']).splitlines()
                row['transfer']=[{'rx':int(line.split()[1]),'tx':int(line.split()[2])} for line in transfers]
                row['passed']=row['handshake_fresh'] and row['endpoint_matches_requested'] and row.get('ipv4',{}).get('expected_exit') is True
                if 'ipv6' in row:row['passed']=row['passed'] and row['ipv6'].get('expected_exit') is True
            except Exception as error:row['error_category']=type(error).__name__;row['passed']=False
            finally:
                if created:run(['ip','link','delete',INTERFACE])
            print('CLOUD_KERNEL_ENDPOINT='+json.dumps(row,sort_keys=True),flush=True)


if __name__=='__main__':main(sys.argv[1])
