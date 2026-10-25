"""Disposable Linux namespaces: real native UDP443 demux and admin hairpin."""
import os
import subprocess
import tempfile
import time
from pathlib import Path
import web_firewall as rules

def run(*args):return subprocess.run(list(args),check=True,stdout=subprocess.DEVNULL)

def main():
    if not (os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')=='1'):
        raise SystemExit('DISPOSABLE_CI_REQUIRED')
    names=['opx-route-client','opx-route-server'];proc=None;front=None;back=None;directory=None
    if any(Path('/run/netns',name).exists() for name in names):raise SystemExit('PREEXISTING_NAMESPACE_REFUSED')
    try:
        for name in names:run('ip','netns','add',name)
        run('ip','link','add','opx-ra','type','veth','peer','name','opx-rb')
        for interface,name,address in [('opx-ra',names[0],'192.0.2.1/30'),('opx-rb',names[1],'192.0.2.2/30')]:
            run('ip','link','set',interface,'netns',name)
            if name==names[1]:run('ip','-n',name,'link','set',interface,'name','wg0');interface='wg0'
            run('ip','-n',name,'address','add',address,'dev',interface)
            run('ip','-n',name,'link','set',interface,'up');run('ip','-n',name,'link','set','lo','up')
        run('ip','-n',names[0],'route','add','152.67.156.100/32','via','192.0.2.2')
        for rule in (rules.UDP443_RULE,rules.UDP8443_RULE,rules.ADMIN_TUN_RULE,rules.ADMIN_H3_TUN_RULE):run('ip','netns','exec',names[1],'iptables','-t','nat','-A','PREROUTING',*rule)
        run('ip','netns','exec',names[1],'iptables','-P','INPUT','DROP')
        for rule in (rules.RULE,rules.QUIC_RULE,rules.HTTP3_RULE,['-p','udp','--dport','51820','-j','ACCEPT']):run('ip','netns','exec',names[1],'iptables','-A','INPUT',*rule)
        server="""import socket,threading
for port in (443,8443,51820):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',port))
 def echo(s=s,port=port):
  while True:
   b,a=s.recvfrom(4096);s.sendto(str(port).encode(),a)
 threading.Thread(target=echo,daemon=True).start()
s=socket.socket();s.bind(('0.0.0.0',443));s.listen();print('READY',flush=True)
while True:
 c,a=s.accept();c.sendall(b'admin-tunnel');c.close()
"""
        proc=subprocess.Popen(['ip','netns','exec',names[1],'python3','-u','-c',server],stdout=subprocess.PIPE,text=True)
        assert proc.stdout.readline().strip()=='READY'
        client="""import socket
for port in (443,8443):
 for packet,expected in [(b'\\x01\\0\\0\\0'+bytes(144),b'51820'),(b'\\xc3HTTP3',str(port).encode())]:
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.connect(('192.0.2.2',port));s.send(packet);assert s.recv(100)==expected;s.close()
s=socket.create_connection(('152.67.156.100',443),3);assert s.recv(100)==b'admin-tunnel';s.close()
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.connect(('152.67.156.100',443));s.send(b'\\xc3HTTP3');assert s.recv(100)==b'443';s.close()
"""
        run('ip','netns','exec',names[0],'python3','-c',client)
        print('REAL_UDP443_8443_NATIVE_DEMUX_PRESERVES_QUIC_AND_ADMIN_TUNNEL_HAIRPIN=PASS')
        # Exercise the actual Caddy template's deferred Alt-Svc policy with
        # distinct real socket source addresses, not an adapted-JSON assertion.
        run('ip','-n',names[0],'address','add','10.77.0.2/30','dev','opx-ra')
        run('ip','-n',names[1],'address','add','10.77.0.1/30','dev','wg0')
        run('ip','netns','exec',names[1],'iptables','-I','INPUT','1','-i','lo','-j','ACCEPT')
        backend="""from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.send_header('Alt-Svc','h3=":443"');self.end_headers();self.wfile.write(b'OK')
 def log_message(self,*args):pass
HTTPServer(('127.0.0.1',8787),Handler).serve_forever()
"""
        back=subprocess.Popen(['ip','netns','exec',names[1],'python3','-c',backend],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        directory=tempfile.TemporaryDirectory(prefix='opx-caddy-path-')
        template=(Path(__file__).resolve().parents[2]/'server/admin-oracle/deploy/Caddyfile').read_text()
        config=Path(directory.name)/'Caddyfile'
        config.write_text('{\n admin off\n auto_https off\n}\n'+template.replace('vpn-admin.morandi.dpdns.org {',':80 {',1))
        env=dict(os.environ,XDG_DATA_HOME=directory.name+'/data',XDG_CONFIG_HOME=directory.name+'/config')
        front=subprocess.Popen(['ip','netns','exec',names[1],'caddy','run','--config',str(config),'--adapter','caddyfile'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        header_client="""import http.client
for source,expected in [(None,'h3=":443"'),(('10.77.0.2',0),'clear')]:
 c=http.client.HTTPConnection('192.0.2.2',80,timeout=2,source_address=source)
 c.request('GET','/privacy-check/',headers={'Host':'vpn-admin.morandi.dpdns.org'})
 r=c.getresponse();assert r.status==200;assert r.getheader('Alt-Svc')==expected;r.read();c.close()
"""
        for _ in range(30):
            result=subprocess.run(['ip','netns','exec',names[0],'python3','-c',header_client],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if result.returncode==0:break
            if front.poll() is not None:raise RuntimeError('ISOLATED_CADDY_START_FAILED')
            time.sleep(.2)
        else:raise RuntimeError('ISOLATED_CADDY_SOURCE_HEADER_POLICY_FAILED')
        print('REAL_ADMIN_VPN_ALT_SVC_CLEAR_PUBLIC_HTTP3_ADVERTISEMENT_PRESERVED=PASS')

    finally:
        for process in (front,back,proc):
            if process is not None:process.terminate();process.wait(timeout=5)
        if directory is not None:directory.cleanup()
        for name in reversed(names):subprocess.run(['ip','netns','delete',name],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':main()
