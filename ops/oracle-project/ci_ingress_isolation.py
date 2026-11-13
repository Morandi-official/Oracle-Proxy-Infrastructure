"""Real WireGuard allowlists, typed UDP redirects and marked dual-stack returns.

Synthetic namespaces only. No production addresses, keys, ledger or credentials.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
NAMES=('opx-access-client','opx-access-server')


def guard():
    if not(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')=='1'):
        raise SystemExit('DISPOSABLE_CI_REQUIRED')


def run(*args,input=None,accepted=(0,)):
    result=subprocess.run(list(map(str,args)),input=input,capture_output=True,text=True,timeout=25)
    if result.returncode not in accepted:
        print('INGRESS_SYNTHETIC_FAILURE='+str(args[0])+':'+result.stderr[-1200:],flush=True)
        raise RuntimeError('INGRESS_SYNTHETIC_OPERATION_FAILED')
    return result


def child(directory):
    guard();directory=Path(directory)
    spec=importlib.util.spec_from_file_location('ingress',ROOT/'server/admin-oracle/control/ingress.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.CATALOG=directory/'catalog.json';module.READY=directory/'ready'
    def command(args,*,input=None,accepted=(0,)):return run(*args,input=input,accepted=accepted)
    controller=module.Controller(command,directory)
    controller.ensure('10.0.0.246')
    Path('/proc/sys/net/ipv4/conf/wgopbackup/rp_filter').write_text('2\n')
    module.READY.write_text(controller.public_key+'\n');module.READY.chmod(0o600)
    controller.sync(json.loads((directory/'plan.json').read_text()))
    print(controller.public_key,flush=True)


def main():
    guard();echo=None
    if any(Path('/run/netns',n).exists() for n in NAMES):raise SystemExit('PREEXISTING_NAMESPACE_REFUSED')
    with tempfile.TemporaryDirectory(prefix='opx-isolated-ingress-') as directory:
        directory=Path(directory)
        try:
            for n in NAMES:run('ip','netns','add',n)
            run('ip','link','add','opx-ac','type','veth','peer','name','opx-as')
            for name,interface,address in ((NAMES[0],'opx-ac','10.0.0.2/24'),(NAMES[1],'opx-as','10.0.0.6/24')):
                run('ip','link','set',interface,'netns',name)
                run('ip','-n',name,'address','add',address,'dev',interface)
                run('ip','-n',name,'link','set',interface,'up');run('ip','-n',name,'link','set','lo','up')
            run('ip','-n',NAMES[1],'address','add','10.0.0.246/32','dev','opx-as')
            server_private=run('wg','genkey').stdout;client_private=run('wg','genkey').stdout
            server_public=run('wg','pubkey',input=server_private).stdout.strip();client_public=run('wg','pubkey',input=client_private).stdout.strip()
            for label,value in (('server.key',server_private),('client.key',client_private)):
                path=directory/label;path.write_text(value);path.chmod(0o600)
            run('ip','-n',NAMES[1],'link','add','wg0','type','wireguard')
            run('ip','netns','exec',NAMES[1],'wg','set','wg0','private-key',directory/'server.key','listen-port','51820')
            run('ip','-n',NAMES[1],'address','add','10.77.0.1/24','dev','wg0')
            run('ip','-n',NAMES[1],'-6','address','add','fd42:6f70:78:77::1/64','dev','wg0','nodad')
            run('ip','-n',NAMES[1],'link','set','wg0','up')
            run('ip','-n',NAMES[0],'link','add','wgc','type','wireguard')
            run('ip','netns','exec',NAMES[0],'wg','set','wgc','private-key',directory/'client.key')
            run('ip','-n',NAMES[0],'address','add','10.77.0.2/24','dev','wgc')
            run('ip','-n',NAMES[0],'-6','address','add','fd42:6f70:78:77::2/64','dev','wgc','nodad')
            run('ip','-n',NAMES[0],'link','set','wgc','up')
            (directory/'catalog.json').write_text(json.dumps({'primary':{'private_ipv4':'10.0.0.6'},'backup':{'private_ipv4':'10.0.0.246'}}));(directory/'catalog.json').chmod(0o600)
            plan=[{'public_key':client_public,'addresses':['10.77.0.2/32','fd42:6f70:78:77::2/128'],'roles':['primary'],'active':True}]
            def sync(roles):
                plan[0]['roles']=roles;(directory/'plan.json').write_text(json.dumps(plan))
                return run('ip','netns','exec',NAMES[1],sys.executable,__file__,'--child',directory).stdout.strip()
            backup_public=sync(['primary'])
            # Primary native UDP443/8443 rules mirror the real pre-existing path.
            from web_firewall import UDP443_RULE,UDP8443_RULE
            for rule in (UDP443_RULE,UDP8443_RULE):run('ip','netns','exec',NAMES[1],'iptables','-t','nat','-A','PREROUTING',*rule)
            server='''import socket,threading,time
for family,address in ((socket.AF_INET,'10.77.0.1'),(socket.AF_INET6,'fd42:6f70:78:77::1')):
 s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((address,18080));s.listen()
 def loop(s=s):
  while True:
   c,_=s.accept()
   try:c.recv(8);c.sendall(b'OK')
   finally:c.close()
 threading.Thread(target=loop,daemon=True).start()
print('READY',flush=True)
while True:time.sleep(1)
'''
            echo=subprocess.Popen(['ip','netns','exec',NAMES[1],sys.executable,'-u','-c',server],stdout=subprocess.PIPE,text=True)
            assert echo.stdout.readline().strip()=='READY'
            previous=[None]
            def probe(role,port,expected,server_key=None):
                key=server_key or (server_public if role=='primary' else backup_public)
                if previous[0]:run('ip','netns','exec',NAMES[0],'wg','set','wgc','peer',previous[0],'remove')
                previous[0]=key;address='10.0.0.6' if role=='primary' else '10.0.0.246'
                run('ip','netns','exec',NAMES[0],'wg','set','wgc','peer',key,'allowed-ips','10.77.0.0/24,fd42:6f70:78:77::/64','endpoint',address+':'+str(port))
                code='''import socket,sys
for family,host in ((socket.AF_INET,'10.77.0.1'),(socket.AF_INET6,'fd42:6f70:78:77::1')):
 s=socket.socket(family);s.settimeout(4 if sys.argv[1]=='True' else 1)
 try:s.connect((host,18080));s.sendall(b'probe');ok=s.recv(2)==b'OK'
 except OSError:ok=False
 finally:s.close()
 assert ok==(sys.argv[1]=='True'), 'unexpected ingress authorization result'
'''
                run('ip','netns','exec',NAMES[0],sys.executable,'-c',code,str(expected))
            for port in (443,8443,51820):probe('primary',port,True);probe('backup',port,False);probe('backup',port,False,server_public)
            print('REAL_PRIMARY_ONLY_DENIES_BACKUP_ALL_NATIVE_PORTS_AND_MANUAL_SERVER_KEY=PASS',flush=True)
            sync(['primary','backup'])
            for port in (443,8443,51820):probe('backup',port,True)
            probe('primary',51821,False,backup_public)
            print('REAL_BACKUP_ALLOWLIST_DUALSTACK_RETURN_ROUTING_AND_INTERNAL_PORT_BYPASS_DENIED=PASS',flush=True)
            sync(['backup']);probe('primary',443,False);probe('backup',443,True)
            sync(['primary']);probe('backup',443,False);probe('primary',443,True)
            print('REAL_PERMISSION_SWITCH_REVOKES_WRONG_INGRESS_WITH_SAME_CLIENT_KEY=PASS',flush=True)
        finally:
            if echo:echo.terminate();echo.wait(timeout=5)
            for n in reversed(NAMES):run('ip','netns','delete',n,accepted=(0,1))


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--child':child(sys.argv[2])
    else:main()
