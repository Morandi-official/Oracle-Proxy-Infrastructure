"""Pinned Mihomo + kernel WireGuard in an empty network namespace; synthetic keys only."""
import ast
import base64
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

ROOT=Path(__file__).resolve().parents[1]

def run(*args,input=None):return subprocess.run(args,input=input,text=True,capture_output=True,check=True).stdout.strip()

def expect_tunnel(fetch,url,alive,clock=time.monotonic,pause=time.sleep):
 # A listening mixed proxy does not establish that its WireGuard outbound has
 # finished cold startup. Require the same exact response within a bounded wait.
 deadline=clock()+12;last='NO_RESPONSE'
 while True:
  if not alive():raise AssertionError('MIHOMO_EXITED_BEFORE_WG_READY')
  try:
   status,body=fetch(url)
   if status==200 and body==b'SYNTHETIC_WG_ONLY_RESPONSE':return
   last='HTTP_'+str(status)+'_BYTES_'+str(len(body))
  except (OSError,TimeoutError,http.client.HTTPException) as error:last=type(error).__name__
  if clock()>=deadline:raise AssertionError('MIHOMO_COLD_START_WG_NOT_READY_'+last)
  pause(.25)

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
 assert config['proxies'][0]['dns']==['https://1.1.1.1/dns-query']
 request_count=[0];dns_sources=[]
 class Handler(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
   request_count[0]+=1;body=b'SYNTHETIC_WG_ONLY_RESPONSE';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def log_message(self,*args):pass
 class DoHHandler(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
   encoded=parse_qs(urlsplit(self.path).query).get('dns',[''])[0]
   if not encoded or len(encoded)>5500:self.send_error(400);return
   try:body=base64.urlsafe_b64decode(encoded+'='*((-len(encoded))%4))
   except ValueError:self.send_error(400);return
   self.answer(body)
  def do_POST(self):
   length=int(self.headers.get('Content-Length','0'))
   if not 12<=length<=4096:self.send_error(400);return
   self.answer(self.rfile.read(length))
  def answer(self,body):
   dns_sources.append(self.client_address[0])
   if not 12<=len(body)<=4096:self.send_error(400);return
   end=12
   while end<len(body) and body[end]:end+=1+body[end]
   end+=1
   if end+4>len(body):self.send_error(400);return
   kind,cls=struct.unpack('!HH',body[end:end+4]);question=body[12:end+4]
   address=ipaddress.ip_address('10.77.0.1' if kind==1 else 'fd42:6f70:78:77::1').packed if kind in (1,28) else None
   reply=body[:2]+struct.pack('!HHHHH',0x8180,1,1 if address else 0,0,0)+question
   if address:reply+=b'\xc0\x0c'+struct.pack('!HHIH',kind,cls,60,len(address))+address
   self.send_response(200);self.send_header('Content-Type','application/dns-message');self.send_header('Content-Length',str(len(reply)));self.end_headers();self.wfile.write(reply)
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
  # Private CA exists only in this disposable namespace. Keep TLS checking on;
  # trust it in the test child using Go's standard certificate-file mechanism.
  cert=folder/'resolver.crt';tlskey=folder/'resolver.key'
  run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(tlskey),'-out',str(cert),'-subj','/CN=WireGuard DoH fixture','-addext','subjectAltName=IP:10.77.0.1')
  tlskey.chmod(0o600)
  resolver=http.server.ThreadingHTTPServer(('10.77.0.1',18443),DoHHandler)
  tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,tlskey)
  resolver.socket=tls.wrap_socket(resolver.socket,server_side=True)
  threading.Thread(target=resolver.serve_forever,daemon=True).start()
  profile=folder/'profile.yaml';profile.write_text(json.dumps(config));profile.chmod(0o600)
  run(binary,'-t','-d',directory,'-f',str(profile))
  print('ACTUAL_FLCLASH_EXPORT_ACCEPTED_BY_PINNED_MIHOMO=PASS',flush=True)
  # FlClash controls TUN privileges. This fixture exercises its SAME outbound
  # through HTTP proxy, with no OS route changes or production network access.
  config['tun']['enable']=False;config['dns']['enable']=False
  config['proxies'][0]['dns']=['https://10.77.0.1:18443/dns-query']
  profile.write_text(json.dumps(config))
  child_env=os.environ.copy();child_env['SSL_CERT_FILE']=str(cert)
  process=subprocess.Popen([binary,'-d',directory,'-f',str(profile)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=child_env)
  try:
   for _ in range(100):
    try:
     with socket.create_connection(('127.0.0.1',7890),timeout=.1):break
    except OSError:time.sleep(.05)
   def response(url,timeout=4):
    client=http.client.HTTPConnection('127.0.0.1',7890,timeout=timeout)
    try:
     client.request('GET',url,headers={'Connection':'close'});reply=client.getresponse()
     return reply.status,reply.read()
    finally:client.close()
   def fetch(url,timeout=8):return response(url,timeout)[1]
   for host in ('10.77.0.1','[fd42:6f70:78:77::1]'):
    expect_tunnel(response,'http://'+host+':18080/test',lambda:process.poll() is None)
   expect_tunnel(response,'http://doh-wireguard-test.invalid:18080/test',lambda:process.poll() is None)
   assert dns_sources and all(ipaddress.ip_address(a)==ipaddress.ip_address('10.77.0.2') for a in dns_sources)
   print('MIHOMO_REMOTE_DOH_REAL_TLS_DNS_THROUGH_WIREGUARD_NO_DIRECT_RESOLVER=PASS',flush=True)
   rows=run('wg','show','wg0','transfer').splitlines();assert any(int(r.split()[1])>0 and int(r.split()[2])>0 for r in rows)
   assert any(int(r.split()[1])>0 for r in run('wg','show','wg0','latest-handshakes').splitlines())
   print('MIHOMO_EXPORT_REAL_WIREGUARD_UDP443_IPV4_AND_IPV6=PASS',flush=True)
   run('wg','set','wg0','peer',client_public,'remove');before=request_count[0]
   try:answer=fetch('http://10.77.0.1:18080/after-revoke',timeout=4)
   except (OSError,TimeoutError,http.client.HTTPException):answer=b''
   assert answer!=b'SYNTHETIC_WG_ONLY_RESPONSE' and request_count[0]==before
   before_dns=len(dns_sources)
   try:fetch('http://after-revoke-doh.invalid:18080/test',timeout=4)
   except (OSError,TimeoutError,http.client.HTTPException):pass
   assert len(dns_sources)==before_dns
   print('MIHOMO_UDP_FAILURE_HAS_NO_DIRECT_OR_TLS_FALLBACK=PASS',flush=True)
  finally:
   process.terminate()
   try:process.wait(timeout=5)
   except subprocess.TimeoutExpired:process.kill();process.wait()

if __name__=='__main__':main(str(Path(sys.argv[1]).resolve()))
