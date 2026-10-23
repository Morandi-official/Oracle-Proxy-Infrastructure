"""Disposable Linux namespaces: real native UDP443 demux and admin hairpin."""
import os
import subprocess
from pathlib import Path
import web_firewall as rules

def run(*args):return subprocess.run(list(args),check=True,stdout=subprocess.DEVNULL)

def main():
    if not (os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')=='1'):
        raise SystemExit('DISPOSABLE_CI_REQUIRED')
    names=['opx-route-client','opx-route-server'];proc=None
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
        for rule in (rules.UDP443_RULE,rules.UDP8443_RULE,rules.ADMIN_TUN_RULE):run('ip','netns','exec',names[1],'iptables','-t','nat','-A','PREROUTING',*rule)
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
"""
        run('ip','netns','exec',names[0],'python3','-c',client)
        print('REAL_UDP443_8443_NATIVE_DEMUX_PRESERVES_QUIC_AND_ADMIN_TUNNEL_HAIRPIN=PASS')
    finally:
        if proc is not None:proc.terminate();proc.wait(timeout=5)
        for name in reversed(names):subprocess.run(['ip','netns','delete',name],check=False,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':main()
