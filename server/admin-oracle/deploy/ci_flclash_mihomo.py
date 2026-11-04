"""Pinned Mihomo + kernel WireGuard in an empty network namespace; synthetic keys only."""
import ast
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[1]

def run(*args,input=None):return subprocess.run(args,input=input,text=True,capture_output=True,check=True).stdout.strip()

def main(binary):
 if os.geteuid()!=0 or os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')!='1':raise ValueError('DISPOSABLE_NAMESPACE_REQUIRED')
 # Caller starts unshare -n: loopback down, no physical network/default route.
 if len(json.loads(run('ip','-j','link','show')))!=1:raise ValueError('EMPTY_NAMESPACE_REQUIRED')
 run('ip','link','set','lo','up')
 run('ip','link','add','wg0','type','wireguard')
 private=run('wg','genkey');public=run('wg','pubkey',input=private+'\n')
 client_private=run('wg','genkey');client_public=run('wg','pubkey',input=client_private+'\n')
 tree=ast.parse((ROOT/'console/flclash.py').read_text())
 function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='configuration')
 env={'ipaddress':ipaddress,'transport_address':lambda:'127.0.0.1','ipv6_info':lambda:{'prefix':'fd42:6f70:78:77::/64'}}
 exec(compile(ast.Module(body=[function],type_ignores=[]),'actual-profile-renderer','exec'),env)
 config=env['configuration'](None,{'server_public_key':public},{'allowed_ips':['10.77.0.2/32','fd42:6f70:78:77::2/128']},client_private)
 assert len(config['proxies'])==1 and config['rules']==['MATCH,Proxy UDP'] and not config['proxy-groups']
 request_count=[0]
 class Handler(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
   request_count[0]+=1;body=b'SYNTHETIC_WG_ONLY_RESPONSE';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def log_message(self,*args):pass
 class V6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
 with tempfile.TemporaryDirectory() as directory:
  folder=Path(directory);keyfile=folder/'server.key';keyfile.write_text(private+'\n');keyfile.chmod(0o600)
  run('wg','set','wg0','private-key',str(keyfile),'listen-port','443','peer',client_public,'allowed-ips','10.77.0.2/32,fd42:6f70:78:77::2/128')
  run('ip','addr','add','10.77.0.1/24','dev','wg0')
  run('ip','-6','addr','add','fd42:6f70:78:77::1/64','dev','wg0','nodad')
  run('ip','link','set','wg0','up')
  for server in (http.server.ThreadingHTTPServer(('10.77.0.1',18080),Handler),V6(('fd42:6f70:78:77::1',18080),Handler)):
   threading.Thread(target=server.serve_forever,daemon=True).start()
  profile=folder/'profile.yaml';profile.write_text(json.dumps(config));profile.chmod(0o600)
  run(binary,'-t','-d',directory,'-f',str(profile))
  print('ACTUAL_FLCLASH_EXPORT_ACCEPTED_BY_PINNED_MIHOMO=PASS',flush=True)
  # FlClash controls TUN privileges. This fixture exercises its SAME outbound
  # through HTTP proxy, with no OS route changes or production network access.
  config['tun']['enable']=False;config['dns']['enable']=False
  profile.write_text(json.dumps(config))
  process=subprocess.Popen([binary,'-d',directory,'-f',str(profile)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  try:
   for _ in range(100):
    try:
     with socket.create_connection(('127.0.0.1',7890),timeout=.1):break
    except OSError:time.sleep(.05)
   def fetch(url,timeout=8):
    client=http.client.HTTPConnection('127.0.0.1',7890,timeout=timeout)
    try:client.request('GET',url,headers={'Connection':'close'});return client.getresponse().read()
    finally:client.close()
   for host in ('10.77.0.1','[fd42:6f70:78:77::1]'):
    assert fetch('http://'+host+':18080/test')==b'SYNTHETIC_WG_ONLY_RESPONSE'
   rows=run('wg','show','wg0','transfer').splitlines();assert any(int(r.split()[1])>0 and int(r.split()[2])>0 for r in rows)
   assert any(int(r.split()[1])>0 for r in run('wg','show','wg0','latest-handshakes').splitlines())
   print('MIHOMO_EXPORT_REAL_WIREGUARD_UDP443_IPV4_AND_IPV6=PASS',flush=True)
   run('wg','set','wg0','peer',client_public,'remove');before=request_count[0]
   try:answer=fetch('http://10.77.0.1:18080/after-revoke',timeout=4)
   except (OSError,TimeoutError,http.client.HTTPException):answer=b''
   assert answer!=b'SYNTHETIC_WG_ONLY_RESPONSE' and request_count[0]==before
   print('MIHOMO_UDP_FAILURE_HAS_NO_DIRECT_OR_TLS_FALLBACK=PASS',flush=True)
  finally:
   process.terminate()
   try:process.wait(timeout=5)
   except subprocess.TimeoutExpired:process.kill();process.wait()

if __name__=='__main__':main(str(Path(sys.argv[1]).resolve()))
