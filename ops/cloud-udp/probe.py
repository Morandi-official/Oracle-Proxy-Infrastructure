"""Real cloud WireGuard tests; explicit localhost proxy, no default-route changes."""
import ast
import base64
import gzip
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import uuid
import zipfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
ENDPOINTS = [(address, port) for address in ('152.67.154.225', '150.230.113.158') for port in (443,8443,51820)]
PINS = {
    'Linux':('mihomo-linux-amd64-v1-v1.19.33.gz','8ec92e7b2fdc6b853ba00156bab7e4e965c8b0d843b8c4ac8ab98795f02ad524'),
    'Windows':('mihomo-windows-amd64-v1-v1.19.33.zip','fb0b960eff568459502d4ebe53e9cca203053d86ec9024fe935f19615d74d9aa'),
}


def run(args, timeout=30, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=True, **kwargs).stdout.strip()


def binary(folder):
    asset, digest = PINS[platform.system()]
    request = urllib.request.Request('https://github.com/MetaCubeX/mihomo/releases/download/v1.19.33/'+asset)
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(40*1024*1024+1)
    if len(data)>40*1024*1024 or hashlib.sha256(data).hexdigest()!=digest:
        raise ValueError('MIHOMO_PIN_FAILED')
    path = folder / ('mihomo.exe' if platform.system()=='Windows' else 'mihomo')
    if asset.endswith('.gz'): path.write_bytes(gzip.decompress(data))
    else:
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names=[n for n in archive.namelist() if n.endswith('.exe') and '/' not in n and '\\' not in n]
            if len(names)!=1:raise ValueError('MIHOMO_ARCHIVE_REJECTED')
            path.write_bytes(archive.read(names[0]))
    path.chmod(0o700)
    return str(path)


def configuration(info, private, address, port, local_port):
    tree=ast.parse((ROOT/'server/admin-oracle/console/flclash.py').read_text())
    function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='configuration')
    env={'ipaddress':ipaddress,'transport_address':lambda:address,
         'ipv6_info':lambda:{'prefix':'fd42:6f70:78:77::/64'}}
    exec(compile(ast.Module(body=[function],type_ignores=[]),'actual-profile-renderer','exec'),env)
    config=env['configuration'](None,{'server_public_key':info['server_public_key']},info,private)
    config['tun']['enable']=False
    config['mixed-port']=local_port
    config['proxies'][0]['port']=port
    if len(config['proxies'])!=1 or config['rules']!=['MATCH,Proxy UDP'] or config['proxy-groups']:
        raise ValueError('UDP_ONLY_CONFIGURATION_REQUIRED')
    return config


def fetch(port, target, tls=False):
    # http.client always connects to the explicitly supplied proxy. Environment
    # NO_PROXY and system proxy settings cannot send test traffic directly.
    if tls:
        client=http.client.HTTPSConnection('127.0.0.1',port,timeout=12,context=ssl.create_default_context())
        client.set_tunnel(target,443)
        path='/cdn-cgi/trace'
    else:
        client=http.client.HTTPConnection('127.0.0.1',port,timeout=12)
        path='http://1.1.1.1/'
    try:
        client.request('GET',path,headers={'Connection':'close'})
        response=client.getresponse();body=response.read(16385)
        if len(body)>16384:raise ValueError('PROBE_RESPONSE_TOO_LARGE')
        result={'http_status':response.status}
        if tls and response.status==200:
            fields=dict(line.split('=',1) for line in body.decode().splitlines() if '=' in line)
            result['exit_ip']=str(ipaddress.ip_address(fields['ip']))
            result['expected_exit']=result['exit_ip'] in ('152.67.156.100','2603:c020:c015:8100::10')
        return result
    except Exception as error:
        return {'error_category':type(error).__name__}
    finally:client.close()


def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_REF')!='refs/heads/main' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('MAIN_HOSTED_RUNNER_ONLY')
    revision=os.environ['GITHUB_SHA']
    if len(revision)!=40 or any(c not in '0123456789abcdef' for c in revision):raise ValueError('REVISION_REQUIRED')
    result_path=ROOT/'dist/cloud-udp'/('result-'+platform.system().lower()+'.json')
    result_path.parent.mkdir(parents=True,exist_ok=True)
    results={'platform':platform.system(),'revision':revision,'started_at':int(time.time()),'endpoints':[],'cleaned':False}
    key=X25519PrivateKey.generate()
    private=base64.b64encode(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode()
    public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
    tag=uuid.uuid4().hex
    results['probe_id']=tag
    with tempfile.TemporaryDirectory(prefix='cloud-udp-private-') as directory:
        folder=Path(directory);folder.chmod(0o700)
        # Never log a command containing credentials or upload this directory.
        keyfile=folder/'ssh-key';keyfile.write_text(os.environ.pop('CI_KEY').replace('\r\n','\n').rstrip()+'\n',newline='\n');keyfile.chmod(0o600)
        known=folder/'known_hosts';known.write_text(os.environ.pop('KNOWN_HOSTS').replace('\r\n','\n').rstrip()+'\n',newline='\n');known.chmod(0o600)
        if platform.system()=='Windows':
            run(['icacls',str(keyfile),'/inheritance:r','/grant:r',os.environ['USERNAME']+':(R)'])
        command=['ssh','-T','-i',str(keyfile),'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
                 '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),'-o','ConnectTimeout=15',
                 'oracle-project-ci@152.67.156.100','preflight '+revision]
        def rpc(action):
            body=json.dumps({'action':action,'probe_id':tag,'public_key':public})+'\n'
            if platform.system()=='Windows':
                import paramiko
                client=paramiko.SSHClient()
                client.load_host_keys(str(known))
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                try:
                    client.connect('152.67.156.100',username='oracle-project-ci',key_filename=str(keyfile),
                                   look_for_keys=False,allow_agent=False,timeout=15,banner_timeout=15,auth_timeout=15)
                    incoming,outgoing,errors=client.exec_command('preflight '+revision,timeout=120)
                    incoming.write(body);incoming.flush();incoming.channel.shutdown_write()
                    received=outgoing.read(2*1024*1024+1)
                    status=outgoing.channel.recv_exit_status()
                    output=received.decode('utf-8')
                    if len(received)>2*1024*1024 or status!=0:
                        safe=[x for x in output.splitlines() if x.startswith('CLOUD_UDP_ERROR=')]
                        if len(safe)==1:print(safe[0],flush=True)
                        raise ValueError('DIAGNOSTIC_REMOTE_COMMAND_FAILED')
                finally:client.close()
            else:
                try:output=run(command,input=body,timeout=120)
                except subprocess.CalledProcessError as error:
                    safe=[x for x in error.stdout.splitlines() if x.startswith('CLOUD_UDP_ERROR=')]
                    if len(safe)==1:print(safe[0],flush=True)
                    raise ValueError('DIAGNOSTIC_REMOTE_COMMAND_FAILED') from None
            lines=[line.split('=',1)[1] for line in output.splitlines() if line.startswith('CLOUD_UDP_IDENTITY=')]
            if len(lines)!=1:raise ValueError('DIAGNOSTIC_RPC_PROTOCOL_FAILED')
            return json.loads(lines[0])
        attempted=False
        tests_completed=False
        try:
            executable=binary(folder)
            results['reconciliation']=rpc('reconcile-owned')
            print('CLOUD_UDP_RECONCILIATION='+json.dumps(results['reconciliation'],sort_keys=True),flush=True)
            if results['reconciliation']['errors']:raise ValueError('OWNED_DIAGNOSTIC_RECONCILIATION_FAILED')
            attempted=True
            info=rpc('prepare')
            results['host_return_before']=rpc('host-audit')
            if platform.system()=='Linux':
                native=folder/'native.json';native.write_text(json.dumps({**info,'private_key':private}));native.chmod(0o600)
                native_result=subprocess.run(['sudo','-n','env','GITHUB_ACTIONS=true','RUNNER_ENVIRONMENT=github-hosted',sys.executable,str(Path(__file__).with_name('kernel_probe.py')),str(native)],text=True,capture_output=True,timeout=240)
                for line in native_result.stdout.splitlines():
                    if line.startswith('CLOUD_KERNEL_ENDPOINT='):print(line,flush=True)
                if native_result.returncode!=0:results['kernel_error']='KERNEL_PROBE_FAILED'
                else:results['kernel']=[json.loads(line.split('=',1)[1]) for line in native_result.stdout.splitlines() if line.startswith('CLOUD_KERNEL_ENDPOINT=')]
                sticky_result=subprocess.run(['sudo','-n','env','GITHUB_ACTIONS=true','RUNNER_ENVIRONMENT=github-hosted',sys.executable,str(Path(__file__).with_name('kernel_probe.py')),str(native),'--sticky-source'],text=True,capture_output=True,timeout=240)
                for line in sticky_result.stdout.splitlines():
                    if line.startswith('CLOUD_KERNEL_STICKY_ENDPOINT='):print(line,flush=True)
                if sticky_result.returncode!=0:results['kernel_sticky_error']='KERNEL_STICKY_PROBE_FAILED'
                else:results['kernel_sticky']=[json.loads(line.split('=',1)[1]) for line in sticky_result.stdout.splitlines() if line.startswith('CLOUD_KERNEL_STICKY_ENDPOINT=')]
                native.unlink(missing_ok=True)
            for address,port in ENDPOINTS:
                with socket.socket() as pick:
                    pick.bind(('127.0.0.1',0));local_port=pick.getsockname()[1]
                row={'address':address,'port':port,'started_at':int(time.time())}
                work=folder/(address+'-'+str(port));work.mkdir(mode=0o700)
                profile=work/'profile.json';profile.write_text(json.dumps(configuration(info,private,address,port,local_port)));profile.chmod(0o600)
                process=subprocess.Popen([executable,'-d',str(work),'-f',str(profile)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        try:
                            with socket.create_connection(('127.0.0.1',local_port),timeout=.1):break
                        except OSError:
                            if process.poll() is not None:raise ValueError('MIHOMO_START_FAILED')
                            time.sleep(.1)
                    else:raise ValueError('MIHOMO_LISTENER_MISSING')
                    before=rpc('observe')
                    row['numeric_http']=fetch(local_port,'1.1.1.1')
                    row['numeric_tls']=fetch(local_port,'1.1.1.1',True)
                    row['domain_doh_tls']=fetch(local_port,'www.cloudflare.com',True)
                    if any(ipaddress.ip_interface(a).version==6 for a in info['allowed_ips']):
                        row['ipv6_tls']=fetch(local_port,'2606:4700:4700::1111',True)
                    after=rpc('observe')
                    for _ in range(8):
                        if after['handshake']>=row['started_at']-2 and any(after['usage'][k]>before['usage'][k] for k in ('rx','tx')):break
                        time.sleep(1);after=rpc('observe')
                    row['server_handshake_fresh']=after['handshake']>=row['started_at']-2
                    row['server_usage_delta']={k:after['usage'][k]-before['usage'][k] for k in ('rx','tx')}
                    row['udp_only']=True;row['direct_fallback']=False
                    row['passed']=row['numeric_http'].get('http_status') in (200,301,302,308) and row['numeric_tls'].get('expected_exit') is True and row['domain_doh_tls'].get('expected_exit') is True and row['server_handshake_fresh']
                    if 'ipv6_tls' in row:row['passed']=row['passed'] and row['ipv6_tls'].get('expected_exit') is True
                except Exception as error:row['error_category']=type(error).__name__;row['passed']=False
                finally:
                    process.terminate()
                    try:process.wait(timeout=8)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                results['endpoints'].append(row)
                print('CLOUD_UDP_ENDPOINT='+json.dumps(row,sort_keys=True),flush=True)
            tests_completed=True
        finally:
            if attempted:
                try:results['host_return_after']=rpc('host-audit')
                except Exception as error:results['host_return_audit_error']=type(error).__name__
                for attempt in range(3):
                    try:
                        cleanup=rpc('cleanup')
                        results['cleaned']=cleanup.get('cleaned') is True
                        results['pending_diagnostics']=cleanup.get('pending_diagnostics',[])
                        break
                    except Exception:
                        if attempt==2:results['cleanup_error']='CLEANUP_NOT_VERIFIED'
                        else:time.sleep(5)
            results['finished_at']=int(time.time())
            result_path.write_text(json.dumps(results,indent=2)+'\n')
            print('CLOUD_UDP_IDENTITY_CLEANED='+str(results['cleaned']),flush=True)
            print('CLOUD_UDP_PENDING_DIAGNOSTICS='+str(len(results.get('pending_diagnostics',[]))),flush=True)
    missing_kernel_rows=platform.system()=='Linux' and (len(results.get('kernel',[]))!=len(ENDPOINTS) or len(results.get('kernel_sticky',[]))!=len(ENDPOINTS))
    if missing_kernel_rows or not results['cleaned'] or len(results['endpoints'])!=len(ENDPOINTS) or not all(r.get('passed') for r in results['endpoints']) or results.get('kernel_error') or results.get('kernel_sticky_error') or any(not row.get('passed') for row in results.get('kernel',[])+results.get('kernel_sticky',[])):
        raise SystemExit(1)


if __name__=='__main__':main()
