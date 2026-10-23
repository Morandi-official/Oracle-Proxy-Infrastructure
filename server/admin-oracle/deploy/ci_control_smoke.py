"""Synthetic private namespaces only; never receives production keys or Peer data."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]


def run(args,**kwargs):
 result=subprocess.run(list(map(str,args)),check=False,capture_output=True,text=True,**kwargs)
 if result.returncode:
  print('SYNTHETIC_CI_COMMAND_FAILURE='+str(args[0])+'\n'+result.stderr[-4000:],flush=True)
  result.check_returncode()
 return result


def worker(path):
 spec=importlib.util.spec_from_file_location('agent',ROOT/'control/agent.py');agent=importlib.util.module_from_spec(spec);spec.loader.exec_module(agent)
 info=json.loads(Path(path).read_text());agent.LEASE=2
 class NamespaceDriver(agent.Driver):
  def observe(self):
   peers={}
   for line in self.command(['wg','show','wg0','allowed-ips']).stdout.splitlines():
    key,ips=line.split('\t',1);peers[key]={'allowed_ips':ips.replace(',',' ').split(),'rx':0,'tx':0,'handshake':0}
   for line in self.command(['wg','show','wg0','transfer']).stdout.splitlines():
    key,rx,tx=line.split();peers[key].update(rx=int(rx),tx=int(tx))
   for line in self.command(['wg','show','wg0','latest-handshakes']).stdout.splitlines():
    key,at=line.split();peers[key]['handshake']=int(at)
   nics={}
   for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
    name,fields=line.split(':',1)
    if name.strip()=='egress0':
     values=fields.split();nics['egress0']={'rx':int(values[0]),'tx':int(values[8])}
   return {'peers':peers,'nics':nics,'boot':'synthetic-ci-boot','networks':['10.250.0.1/24','fd42:250::1/64'],
           'server_public_key':info['server_public'],'listen_port':51820}
 driver=NamespaceDriver();clock=[time.time()];engine=agent.Engine(Path(path).parent/'ledger.sqlite3',driver,lambda:clock[0]);engine.tick()
 def request(op,data):return engine.dispatch({'operation':op,'actor':'github:204281968','data':data})
 def ping(expected):
  for address in ('10.200.0.2','fd42:200::2'):
   result=subprocess.run(['ip','netns','exec','opx-client','ping','-c','1','-W','1',address],capture_output=True)
   if (result.returncode==0)!=expected:
    print('SYNTHETIC_PACKET_TARGET='+address+'\n'+result.stdout.decode()+result.stderr.decode(),file=sys.stderr,flush=True)
    for args in (['ip','netns','exec','opx-client','ip','route','get',address],['wg','show','wg0','latest-handshakes'],['ip','route','show'],['ip','-6','route','show'],['iptables','-S','FORWARD'],['ip6tables','-S','FORWARD']):
     diagnostic=subprocess.run(args,capture_output=True,text=True,check=False)
     print('SYNTHETIC_NAMESPACE_DIAGNOSTIC='+args[0]+' '+diagnostic.stdout+diagnostic.stderr,file=sys.stderr,flush=True)
   assert (result.returncode==0)==expected,'Synthetic forwarded IPv4/IPv6 packet disposition mismatch'
  for address in ('10.200.0.2','fd42:200::2'):
   code='import socket,sys\ns=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(1)\ns.sendto(bytes.fromhex("123401000001000000000000076578616d706c6504746573740000010001"),(sys.argv[1],53))\ntry:\n r=s.recv(512);sys.exit(0 if r[:4]==bytes.fromhex("12348183") else 2)\nexcept OSError:sys.exit(1)\n'
   result=subprocess.run(['ip','netns','exec','opx-client',sys.executable,'-c',code,address],capture_output=True)
   assert (result.returncode==0)==expected,'Synthetic UDP DNS/53 disposition mismatch'
 def user(**kwargs):
  data={'id':None,'name':'CI synthetic user','quota_bytes':1000000,'expires_at':None,'enabled':True};data.update(kwargs)
  return request('user.put',data)['users'][0]
 # The unadopted preexisting peer must retain its original connectivity.
 ping(True)
 u=user();request('peer.assign',{'public_key':info['client_public'],'user_id':u['id'],'name':'CI synthetic Windows peer'})
 ping(True)
 user(id=u['id'],enabled=False);ping(False)
 user(id=u['id']);ping(True)
 user(id=u['id'],expires_at=int(clock[0])+1);clock[0]+=2;engine.tick();ping(False)
 user(id=u['id']);ping(True)
 # A real TCP connection is established before exceeding the quota.
 server_code='import socket\ns=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("10.200.0.2",5050));s.listen();c,_=s.accept()\nwhile True:\n d=c.recv(65536)\n if not d:break\n c.sendall(d)\n'
 server=subprocess.Popen(['ip','netns','exec','opx-exit',sys.executable,'-u','-c',server_code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 client=None
 try:
  time.sleep(.15)
  client_code='import socket,sys\ns=socket.create_connection(("10.200.0.2",5050),3);s.settimeout(1);print("READY",flush=True)\nfor line in sys.stdin:\n try:\n  s.sendall(b"synthetic");print("PASS" if s.recv(9)==b"synthetic" else "FAIL",flush=True)\n except OSError:print("BLOCKED",flush=True)\n'
  client=subprocess.Popen(['ip','netns','exec','opx-client',sys.executable,'-u','-c',client_code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
  assert client.stdout.readline().strip()=='READY'
  client.stdin.write('send\n');client.stdin.flush();assert client.stdout.readline().strip()=='PASS'
  engine.tick();used=engine.used('user',u['id']);assert used['rx']+used['tx']>0
  # Save a quota already exceeded by the observed real encrypted traffic.
  user(id=u['id'],quota_bytes=1)
  client.stdin.write('send\n');client.stdin.flush();assert client.stdout.readline().strip()=='BLOCKED'
  assert engine.snapshot()['users'][0]['status']=='quota'
 finally:
  if client:client.kill();client.wait()
  server.kill();server.wait()
 user(id=u['id']);ping(True)
 # No more application/controller renewals: the kernel alone expires the lease.
 time.sleep(2.3);ping(False);engine.tick();ping(True)
 # Budget stop is global, including the WireGuard interface's established traffic.
 request('budget.set',{'limit_bytes':10000,'reserve_bytes':1000,'guard_enabled':True,'prior_usage_bytes':9500,'confirm_current_period':True});ping(False)
 request('budget.set',{'limit_bytes':10000,'reserve_bytes':1000,'guard_enabled':False,'prior_usage_bytes':None,'confirm_current_period':False});ping(True)
 # Ledger must survive a controller restart and must not charge an unchanged sample twice.
 before=engine.used('user',u['id']);engine.db.close()
 engine=agent.Engine(Path(path).parent/'ledger.sqlite3',driver,lambda:clock[0]);engine.tick()
 after=engine.used('user',u['id']);assert after['rx']>=before['rx'] and after['tx']>=before['tx']
 request('user.delete',{'user_id':u['id']});ping(False)
 assert engine.snapshot()['users']==[]
 request('peer.revoke',{'public_key':info['client_public']});ping(False)
 assert engine.device_count(u['id'])==0
 before=engine.used('user',u['id']);engine.db.close()
 engine=agent.Engine(Path(path).parent/'ledger.sqlite3',driver,lambda:clock[0]);engine.tick();ping(False)
 assert engine.used('user',u['id'])['tx']>=before['tx']
 engine.db.close()
 print('DISPOSABLE_REAL_USER_DELETE_ALL_DEVICES_DENIED_WITH_ACCOUNTING_RETAINED_AFTER_RESTART=PASS')
 print('DISPOSABLE_REAL_DEVICE_REVOKE_KERNEL_DENIAL_SURVIVES_CONTROL_RESTART=PASS')
 print('DISPOSABLE_REAL_WIREGUARD_DUALSTACK_UDP_DNS_USER_DISABLE_EXPIRY_QUOTA_ESTABLISHED_TCP_KERNEL_LEASE_GLOBAL_BUDGET_LEDGER=PASS')


def main():
 if len(sys.argv)==3 and sys.argv[1]=='worker':worker(sys.argv[2]);return
 if not(os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')=='1'):
  raise SystemExit('Explicit disposable GitHub CI required')
 # Real production unit hardening + Unix peer-credential checks, on this disposable host only.
 operations_path=ROOT.parents[1]/'ops/oracle-project/project_operations.py'
 spec=importlib.util.spec_from_file_location('operations',operations_path);operations=importlib.util.module_from_spec(spec);spec.loader.exec_module(operations)
 operations.install_control()
 socket_test='''import json,socket,struct
s=socket.socket(socket.AF_UNIX);s.connect('/run/oracle-proxy-control/control.sock')
assert struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]==0
s.sendall(b'{"operation":"state","actor":"github:204281968","data":{}}\\n')
body=b''
try:
 while b'\\n' not in body:
  chunk=s.recv(65536)
  if not chunk:break
  body+=chunk
except ConnectionResetError:pass
'''
 run(['runuser','-u','oracle-proxy-admin','--',sys.executable,'-c',socket_test+"\nassert json.loads(body)['ok']\n"])
 run(['runuser','-u','nobody','-g','oracle-proxy-admin','--',sys.executable,'-c',socket_test+"\nassert not body\n"])
 run(['runuser','-u','oracle-proxy-admin','--','test','!','-r','/var/lib/oracle-proxy-control/ledger.sqlite3'])
 run(['systemctl','stop','oracle-proxy-control.service'])
 print('DISPOSABLE_REAL_ROOT_CONTROL_UNIT_WEB_UID_ONLY_SOCKET_AND_ROOT_LEDGER_ACL=PASS')
 namespaces=('opx-router','opx-client','opx-exit')
 dns_server=None
 if any(name in run(['ip','netns','list']).stdout for name in namespaces):raise SystemExit('Namespace already exists')
 try:
  for name in namespaces:run(['ip','netns','add',name]);run(['ip','-n',name,'link','set','lo','up'])
  for left,right,left_ns,right_ns,left_addr,right_addr in (
   ('underlay0','underlay1','opx-router','opx-client','192.0.2.1/24','192.0.2.2/24'),
   ('egress0','egress1','opx-router','opx-exit','10.200.0.1/24','10.200.0.2/24')):
   run(['ip','link','add',left,'type','veth','peer','name',right]);run(['ip','link','set',left,'netns',left_ns]);run(['ip','link','set',right,'netns',right_ns])
   for name,ns,address in ((left,left_ns,left_addr),(right,right_ns,right_addr)):
    run(['ip','-n',ns,'addr','add',address,'dev',name]);run(['ip','-n',ns,'link','set',name,'up'])
  run(['ip','-n','opx-router','addr','add','fd42:200::1/64','dev','egress0','nodad'])
  run(['ip','-n','opx-exit','addr','add','fd42:200::2/64','dev','egress1','nodad'])
  # Deterministic neighbours avoid first-packet NDP/DAD timing in the private fixture.
  router_mac=json.loads(run(['ip','-j','-n','opx-router','link','show','dev','egress0']).stdout)[0]['address']
  exit_mac=json.loads(run(['ip','-j','-n','opx-exit','link','show','dev','egress1']).stdout)[0]['address']
  run(['ip','-n','opx-router','-6','neigh','replace','fd42:200::2','lladdr',exit_mac,'dev','egress0','nud','permanent'])
  run(['ip','-n','opx-exit','-6','neigh','replace','fd42:200::1','lladdr',router_mac,'dev','egress1','nud','permanent'])
  with tempfile.TemporaryDirectory(prefix='oracle-policy-disposable-') as temporary:
   root=Path(temporary);public={}
   for role,ns,address in (('server','opx-router','10.250.0.1/24'),('client','opx-client','10.250.0.2/32')):
    private=run(['wg','genkey']).stdout;key=root/(role+'.key');key.write_text(private);key.chmod(0o600)
    public[role]=run(['wg','pubkey'],input=private).stdout.strip()
    run(['ip','-n',ns,'link','add','wg0','type','wireguard']);run(['ip','netns','exec',ns,'wg','set','wg0','private-key',key,'listen-port','51820'])
    run(['ip','-n',ns,'addr','add',address,'dev','wg0']);run(['ip','-n',ns,'link','set','wg0','up'])
   run(['ip','-n','opx-router','addr','add','fd42:250::1/64','dev','wg0','nodad'])
   run(['ip','-n','opx-client','addr','add','fd42:250::2/128','dev','wg0','nodad'])
   run(['ip','netns','exec','opx-router','wg','set','wg0','peer',public['client'],'allowed-ips','10.250.0.2/32,fd42:250::2/128'])
   run(['ip','netns','exec','opx-client','wg','set','wg0','peer',public['server'],'allowed-ips','10.250.0.0/24,10.200.0.0/24,fd42:250::/64,fd42:200::/64','endpoint','192.0.2.1:51820'])
   run(['ip','-n','opx-client','route','add','10.200.0.0/24','dev','wg0'])
   run(['ip','-n','opx-exit','route','add','10.250.0.0/24','via','10.200.0.1'])
   run(['ip','-n','opx-client','-6','route','add','fd42:200::/64','dev','wg0'])
   run(['ip','-n','opx-exit','-6','route','add','fd42:250::/64','via','fd42:200::1'])
   run(['ip','netns','exec','opx-router','sysctl','-w','net.ipv4.ip_forward=1'])
   run(['ip','netns','exec','opx-router','sysctl','-w','net.ipv6.conf.all.forwarding=1'])
   dns_code='import socket,select\nsockets=[]\nfor family,address in ((socket.AF_INET,"10.200.0.2"),(socket.AF_INET6,"fd42:200::2")):\n s=socket.socket(family,socket.SOCK_DGRAM)\n if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)\n s.bind((address,53));sockets.append(s)\nwhile True:\n ready,_,_=select.select(sockets,[],[])\n for s in ready:\n  q,a=s.recvfrom(512);s.sendto(q[:2]+bytes.fromhex("8183")+q[4:6]+b"\\0"*6+q[12:],a)\n'
   dns_server=subprocess.Popen(['ip','netns','exec','opx-exit',sys.executable,'-u','-c',dns_code],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   time.sleep(.2)
   fixture=root/'fixture.json';fixture.write_text(json.dumps({'client_public':public['client'],'server_public':public['server']}))
   result=run(['ip','netns','exec','opx-router',sys.executable,Path(__file__).resolve(),'worker',fixture])
   print(result.stdout.strip())
 finally:
  if dns_server:dns_server.kill();dns_server.wait()
  for name in namespaces:subprocess.run(['ip','netns','del',name],capture_output=True,check=False)


if __name__=='__main__':main()
