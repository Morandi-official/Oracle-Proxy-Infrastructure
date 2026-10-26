"""Hosted-runner namespaces: real alias invariants and independent systemd expiry."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def run(*argv):return subprocess.run(list(argv),check=True,capture_output=True,text=True,timeout=10)


def main():
    if not (os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('ORACLE_ADMIN_DISPOSABLE_CI')=='1'):
        raise SystemExit('DISPOSABLE_CI_REQUIRED')
    server='opx-secondary-server';client='opx-secondary-client';units=[];process=None
    if any(Path('/run/netns',name).exists() for name in (server,client)):raise SystemExit('PREEXISTING_NAMESPACE_REFUSED')
    with tempfile.TemporaryDirectory(prefix='opx-secondary-ci-') as directory:
        root=Path(directory);source=Path(__file__).with_name('secondary_endpoint.py').read_text()
        script=root/'secondary_endpoint.py';state=root/'state.json'
        source=source.replace("STATE=Path('/var/lib/oracle-project-ops/secondary-endpoint.json')",'STATE=Path('+repr(str(state))+')')
        source=source.replace("SCRIPT=Path('/usr/local/libexec/oracle-project/secondary_endpoint.py')",'SCRIPT=Path('+repr(str(script))+')')
        source=source.replace('LEASE_SECONDS=86400','LEASE_SECONDS=12')
        script.write_text(source);script.chmod(0o600)
        spec=importlib.util.spec_from_file_location('secondary_ci',script)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        (root/'secondary-allocation.json').write_text(json.dumps(module.EXPECTED_ALLOCATION))
        original_run=module.run
        def isolated(argv):
            if argv[0]=='ip':argv=['ip','netns','exec',server,*argv]
            if argv[0]=='systemd-run':
                index=argv.index('/usr/bin/python3')
                argv=argv[:index]+['--property=NetworkNamespacePath=/run/netns/'+server]+argv[index:]
            return original_run(argv)
        module.run=isolated
        module.metadata=lambda:[{'privateIp':module.PRIMARY,'secondaryPrivateIps':[module.SECONDARY]}]
        try:
            for name in (server,client):run('ip','netns','add',name);run('ip','-n',name,'link','set','lo','up')
            run('ip','link','add','opx-sa','type','veth','peer','name','opx-sb')
            run('ip','link','set','opx-sa','netns',server);run('ip','link','set','opx-sb','netns',client)
            run('ip','-n',server,'link','set','opx-sa','name','enp0s6')
            run('ip','-n',server,'address','add','10.0.0.6/24','dev','enp0s6')
            run('ip','-n',server,'link','set','enp0s6','up')
            run('ip','-n',client,'address','add','10.0.0.1/24','dev','opx-sb')
            run('ip','-n',client,'link','set','opx-sb','up')
            run('ip','-n',server,'route','add','default','via','10.0.0.1')
            baseline=module.snapshot()[0]
            module.install();first=module.load_state();units.append('oracle-proxy-secondary-'+first['lease_id'])
            assert module.snapshot()[0]==baseline and module.owned_alias(module.snapshot()[1])
            module.install();assert module.load_state()['expires_at']==first['expires_at']
            listener="""import socket
s=socket.socket();s.bind(('0.0.0.0',443));s.listen();print('READY',flush=True)
while True:
 c,a=s.accept();c.sendall(b'OK');c.close()
"""
            process=subprocess.Popen(['ip','netns','exec',server,'python3','-u','-c',listener],stdout=subprocess.PIPE,text=True)
            assert process.stdout.readline().strip()=='READY'
            client_code="""import socket
for host in ('10.0.0.6','10.0.0.10'):
 with socket.create_connection((host,443),2) as s:assert s.recv(10)==b'OK'
"""
            run('ip','netns','exec',client,'python3','-c',client_code)
            print('REAL_SECONDARY_ALIAS_PRIMARY_ROUTES_AND_BOTH_TCP_ENDPOINTS=PASS',flush=True)
            for _ in range(30):
                if module.load_state()['phase']=='rolled_back':break
                time.sleep(.5)
            assert module.load_state()['phase']=='rolled_back' and not module.snapshot()[1] and module.snapshot()[0]==baseline
            print('REAL_INDEPENDENT_SYSTEMD_LEASE_EXPIRY_REMOVES_ONLY_ALIAS=PASS',flush=True)
            actual_mac=json.loads(run('ip','-n',server,'-j','link','show','dev','enp0s6').stdout)[0]['address']
            module.kernel_mac=lambda:json.loads(run('ip','-n',server,'-j','link','show','dev','enp0s6').stdout)[0]['address']
            module.metadata=lambda:[{'privateIp':module.PRIMARY,'macAddr':actual_mac,'subnetCidrBlock':'10.0.0.0/24'}]
            module.install();second=module.load_state();units.append('oracle-proxy-secondary-'+second['lease_id'])
            assert module.allocation_source(module.metadata())=='OWNER_CONSOLE_AND_PRIMARY_IMDS'
            print('REAL_KERNEL_MAC_AND_ROOT_OWNED_OWNER_RECORD_WITHOUT_IMDS_SECONDARY_LIST=PASS',flush=True)
            module.rollback(first['lease_id']);assert module.owned_alias(module.snapshot()[1])
            module.rollback(second['lease_id']);assert not module.snapshot()[1] and module.snapshot()[0]==baseline
            print('REAL_STALE_LEASE_NOOP_AND_EXPLICIT_OWNED_ROLLBACK=PASS',flush=True)
            # Exercise the production persistent service and actual conntrack reverse NAT.
            import web_firewall
            run('ip','netns','exec',server,'iptables','-t','nat','-A','PREROUTING',*web_firewall.UDP8443_RULE)
            metadata_fixture="\nmetadata=lambda:[{'privateIp':PRIMARY,'secondaryPrivateIps':[SECONDARY]}]\n"
            script.write_text(script.read_text().replace("if __name__=='__main__':",metadata_fixture+"\nif __name__=='__main__':"))
            module.install();third=module.load_state();units.append('oracle-proxy-secondary-'+third['lease_id'])
            persistent=root/'secondary_vpn.py';public=root/'transport.json'
            persistent_source=Path(__file__).with_name('secondary_vpn.py').read_text()
            persistent_source=persistent_source.replace("UNIT='oracle-proxy-secondary-endpoint.service'","UNIT='opx-secondary-persistent-ci.service'")
            persistent_source=persistent_source.replace("PUBLIC_STATE=Path('/etc/oracle-proxy-quic/transport.json')",'PUBLIC_STATE=Path('+repr(str(public))+')')
            persistent_source=persistent_source.replace("[Service]\\nType=oneshot", "[Service]\\nNetworkNamespacePath=/run/netns/"+server+"\\nType=oneshot")
            persistent.write_text(persistent_source);persistent.chmod(0o600)
            vpn_spec=importlib.util.spec_from_file_location('secondary_vpn_ci',persistent)
            vpn=importlib.util.module_from_spec(vpn_spec);vpn_spec.loader.exec_module(vpn)
            def vpn_isolated(argv):
                if argv[0] in ('ip','iptables'):argv=['ip','netns','exec',server,*argv]
                return original_run(argv)
            vpn.s.run=vpn_isolated
            try:vpn.install()
            except Exception:
                print(run('journalctl','-u',vpn.UNIT,'-n','30','--no-pager').stdout,flush=True)
                print('CI_UNIT='+vpn.unit_text(),flush=True)
                raise
            promoted=vpn.s.load_state();assert promoted['mode']=='persistent' and promoted['lease_id']!=third['lease_id']
            module.rollback(third['lease_id']);assert module.owned_alias(module.snapshot()[1])
            echo="""import socket,threading,time
for port in (51820,8443):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',port))
 def echo(s=s,port=port):
  while True:
   b,a=s.recvfrom(4096);s.sendto(str(port).encode(),a)
 threading.Thread(target=echo,daemon=True).start()
print('READY',flush=True);time.sleep(120)
"""
            udp=subprocess.Popen(['ip','netns','exec',server,'python3','-u','-c',echo],stdout=subprocess.PIPE,text=True)
            try:
                assert udp.stdout.readline().strip()=='READY'
                probe="""import socket
for address in ('10.0.0.6','10.0.0.10'):
 for packet,expected in [(bytes([1,0,0,0])+bytes(144),b'51820'),(b'\\xc3QUIC',b'8443')]:
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
   sock.settimeout(3);sock.connect((address,8443));sock.send(packet)
   assert sock.recv(100)==expected
"""
                run('ip','netns','exec',client,'python3','-c',probe)
                print('REAL_SECONDARY_NATIVE_DEMUX_AND_QUIC_REVERSE_NAT_PRESERVES_SOURCE=PASS',flush=True)
                run('systemctl','stop',vpn.UNIT)
                assert not module.snapshot()[1] and not public.exists()
                run('systemctl','start',vpn.UNIT)
                assert module.owned_alias(module.snapshot()[1]) and public.exists()
                run('ip','netns','exec',client,'python3','-c',probe)
                assert module.snapshot()[0]==baseline
                print('REAL_PERSISTENT_SYSTEMD_STOP_START_RESTORES_ONLY_OWNED_INGRESS=PASS',flush=True)
                vpn.rollback();assert not module.snapshot()[1] and not public.exists() and module.snapshot()[0]==baseline
                assert not any(vpn.COMMENT in row for row in vpn.nat_rules())
                print('REAL_PERSISTENT_ROLLBACK_REMOVES_ONLY_OWNED_NAT_ALIAS_AND_METADATA=PASS',flush=True)
            finally:
                udp.terminate();udp.wait(timeout=5)
                subprocess.run(['systemctl','disable','--now',vpn.UNIT],check=False,capture_output=True)
                vpn.UNIT_PATH.unlink(missing_ok=True)
                subprocess.run(['systemctl','daemon-reload'],check=False,capture_output=True)

        finally:
            if process is not None:process.terminate();process.wait(timeout=5)
            for unit in units:
                subprocess.run(['systemctl','stop',unit+'.timer',unit+'.service'],check=False,capture_output=True)
                subprocess.run(['systemctl','reset-failed',unit+'.timer',unit+'.service'],check=False,capture_output=True)
            for name in (client,server):subprocess.run(['ip','netns','delete',name],check=False,capture_output=True)


if __name__=='__main__':main()
