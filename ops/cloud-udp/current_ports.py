"""Compare current UDP paths with the kernel on a disposable Linux runner."""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
INTERFACE = 'wgcloud0'
HOST_ID = '152.67.156.100'  # Pinned SSH host identity, not the chosen transport IP.
PORTS = (443, 8443, 51820)


def run(command, *, input=None, timeout=12):
    result = subprocess.run(command, input=input, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('COMMAND_FAILED_'+Path(command[0]).name.upper())
    return result.stdout.strip()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def handshake_counts(sock, parser, address, port):
    sock.setblocking(False)
    indices, responses = set(), set()
    while True:
        try:
            header, metadata = sock.recvfrom(80)
        except BlockingIOError:
            break
        packet = parser(header, metadata[2] != 4)
        if packet is None or (packet['address'], packet['port']) != (address, port):
            continue
        if packet['kind'] == 'initiation':
            indices.add(packet['client_index'])
        elif packet['kind'] == 'response':
            responses.add(packet['client_index'])
    return sorted(indices)[:16], len(indices & responses)


SPEED_HOST = 'speed.cloudflare.com'
SPEED_BYTES = 2 * 1024 * 1024


def speed_targets():
    addresses = {}
    try:
        resolved = socket.getaddrinfo(SPEED_HOST, 443, type=socket.SOCK_STREAM)
    except OSError:
        return addresses
    for _, _, _, _, (address, *_) in resolved:
        ip = ipaddress.ip_address(address)
        if ip.is_global:
            addresses.setdefault(ip.version, ip)
    return addresses


def download(ip, route):
    options = ['--interface', INTERFACE] if route == 'wireguard' else []
    literal = f'[{ip}]' if ip.version == 6 else str(ip)
    result = subprocess.run(
        ['curl', '--noproxy', '*', '--http1.1', '--silent', '--show-error', '--fail',
         '--connect-timeout', '5', '--max-time', '12', '--output', '/dev/null',
         '--write-out', '%{json}', '--resolve', f'{SPEED_HOST}:443:{literal}', *options,
         '-H', 'Accept-Encoding: identity', f'https://{SPEED_HOST}/__down?bytes={SPEED_BYTES}'],
        capture_output=True, text=True, timeout=14)
    metrics = json.loads(result.stdout)
    print('CLOUD_BULK_DOWNLOAD=' + json.dumps({
        'route': route, 'family': ip.version, 'curl_exit': result.returncode,
        'http': metrics['http_code'], 'bytes': metrics['size_download'],
        'first_byte_ms': round(metrics['time_starttransfer'] * 1000),
        'total_ms': round(metrics['time_total'] * 1000),
    }, sort_keys=True), flush=True)


def trial(row, info, secret, wire_headers):
    address, port = row['address'], row['port']
    nic = json.loads(run(['ip','-j','-4','route','get',address]))[0]['dev']
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',nic) or nic in ('lo',INTERFACE):
        raise ValueError('PHYSICAL_ROUTE_NOT_VERIFIED')
    speeds = speed_targets() if row['role'] == 'primary' and port == 443 else {}
    for ip in speeds.values():
        if not run(['ip', f'-{ip.version}', 'route', 'show', 'exact', f'{ip}/{ip.max_prefixlen}']):
            download(ip, 'direct')
        else:
            raise ValueError('PREEXISTING_SPEED_TARGET_ROUTE_REFUSED')
    with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,0) as sniffer:
        sniffer.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,262144)
        wire_headers.attach(sniffer)
        sniffer.bind((nic,0x0003))
        run(['ip','link','add',INTERFACE,'type','wireguard'])
        try:
            families = {ipaddress.ip_interface(v).version for v in info['allowed_ips']}
            speed_ips = [ip for version, ip in speeds.items() if version in families]
            allowed = ['1.1.1.1/32', '2606:4700:4700::1111/128']
            allowed.extend(f'{ip}/{ip.max_prefixlen}' for ip in speed_ips)
            run(['wg','set',INTERFACE,'private-key',str(secret),'peer',info['endpoint_public_keys'][row['role']],
                 'allowed-ips',','.join(allowed),'endpoint',f'{address}:{port}'])
            for value in info['allowed_ips']:
                run(['ip','address','add',value,'dev',INTERFACE])
            run(['ip','link','set','dev',INTERFACE,'mtu','1280','up'])
            run(['ip','-4','route','add','1.1.1.1/32','dev',INTERFACE])
            targets = [('ipv4','https://1.1.1.1/cdn-cgi/trace',address)]
            if 6 in families:
                run(['ip','-6','route','add','2606:4700:4700::1111/128','dev',INTERFACE])
                targets.append(('ipv6','https://[2606:4700:4700::1111]/cdn-cgi/trace','2603:c020:c015:8100::10'))
            for family,url,expected in targets:
                result=subprocess.run(['curl','--noproxy','*','--interface',INTERFACE,'--fail','--silent','--show-error',
                                       '--connect-timeout','7','--max-time','9',url],capture_output=True,text=True,timeout=11)
                observed = next((line[3:] for line in result.stdout.splitlines() if line.startswith('ip=')), '')
                row[family] = {'curl_exit':result.returncode,'expected_exit':observed==expected}
                if family == 'ipv4' and result.returncode and not any(line.split()[-1]!='0' for line in run(['wg','show',INTERFACE,'latest-handshakes']).splitlines()):
                    break
            row['kernel_handshake']=any(line.split()[-1]!='0' for line in run(['wg','show',INTERFACE,'latest-handshakes']).splitlines())
            observed=run(['wg','show',INTERFACE,'endpoints']).split()
            row['requested_endpoint_retained']=len(observed)==2 and observed[1]==f'{address}:{port}'
            indices,responses=handshake_counts(sniffer,wire_headers.parse,address,port)
            row.update(client_tx_initiations=len(indices),client_rx_responses=responses)
            row['passed']=row['kernel_handshake'] and row['requested_endpoint_retained'] and all(row.get(family,{}).get('expected_exit',False) for family,_,_ in targets)
            for ip in speed_ips:
                run(['ip', f'-{ip.version}', 'route', 'add', f'{ip}/{ip.max_prefixlen}', 'dev', INTERFACE])
                download(ip, 'wireguard')
            return indices
        finally:
            run(['ip','link','delete',INTERFACE])


def main():
    if os.geteuid()!=0 or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_REF')!='refs/heads/main' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
        raise ValueError('MAIN_HOSTED_RUNNER_ONLY')
    sha=os.environ['GITHUB_SHA']
    if not re.fullmatch(r'[a-f0-9]{40}',sha):
        raise ValueError('REVISION_REQUIRED')
    if subprocess.run(['ip','link','show',INTERFACE],capture_output=True).returncode==0:
        raise ValueError('PREEXISTING_INTERFACE_REFUSED')
    # Refuse to replace existing target routes, even on the disposable runner.
    for family,target in (('-4','1.1.1.1/32'),('-6','2606:4700:4700::1111/128')):
        if run(['ip',family,'route','show','exact',target]):
            raise ValueError('PREEXISTING_TARGET_ROUTE_REFUSED')

    config=load('catalog',Path('ops/network/endpoint_catalog.py')).load()
    roles = tuple(role for role in ('primary', 'backup') if config[role]['public_ipv4'] is not None)
    targets={role:str(ipaddress.IPv4Address(config[role]['public_ipv4'])) for role in roles}
    headers=load('wire_headers',Path('server/admin-oracle/control/udp_capture.py'))
    os.umask(0o077)
    probe=uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='proxy-udp-probe-') as folder:
        folder=Path(folder)
        credential=folder/'ssh-key'
        credential.write_text(os.environ.pop('CI_KEY').strip()+'\n')
        hosts=folder/'known-hosts'
        hosts.write_text(os.environ.pop('KNOWN_HOSTS').strip()+'\n')
        key=folder/'wireguard-key'
        private=run(['wg','genkey'])
        key.write_text(private+'\n')
        public=run(['wg','pubkey'],input=private+'\n')
        del private
        ssh=['ssh','-T','-i',str(credential),'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes',
             '-o','UserKnownHostsFile='+str(hosts),'-o','HostKeyAlias='+HOST_ID,'-o','ConnectTimeout=4']
        host=None
        for address in [*targets.values(),*(v['public_ipv4'] for v in config['legacy'])]:
            candidate='oracle-project-ci@'+address
            try:
                run(ssh+[candidate,'logs '+sha],input='',timeout=9)
                host=candidate
                break
            except (RuntimeError,subprocess.TimeoutExpired):
                continue
        if host is None:
            raise ValueError('PINNED_MANAGEMENT_ENDPOINT_UNREACHABLE')

        def rpc(action, **extra):
            payload=json.dumps({'action':action,'probe_id':probe,'public_key':public,**extra})+'\n'
            operation=subprocess.run(ssh+[host,'preflight '+sha],input=payload,text=True,capture_output=True,timeout=28)
            lines=[line for line in operation.stdout.splitlines() if line.startswith('CLOUD_UDP_IDENTITY=')]
            if operation.returncode or len(lines)!=1:
                code=next((line for line in operation.stdout.splitlines() if re.fullmatch(r'CLOUD_UDP_ERROR=[A-Za-z0-9_]{1,90}',line)),'CLOUD_UDP_ERROR=REMOTE_FAILED')
                raise RuntimeError(action+' '+code)
            return json.loads(lines[0].split('=',1)[1])

        status = rpc('overview')
        print('CLOUD_UDP_ACTIVE_CATALOG='+json.dumps(status,sort_keys=True),flush=True)
        membership = [config['primary'], config['backup'], *config['legacy']]
        runtime_roles = tuple(role for role in ('primary', 'backup') if status[role]['public_ipv4'] is not None)
        if runtime_roles != roles or any(status[role] not in membership for role in roles) or status['primary'] == status['backup']:
            raise ValueError('RUNTIME_ENDPOINT_OUTSIDE_REGISTERED_CATALOG')
        targets = {role: status[role]['public_ipv4'] for role in roles}
        headers.ADDRESSES = {address: socket.inet_aton(address) for address in targets.values()}
        capture_open=False
        rows=[]
        try:
            info=rpc('prepare')
            if not info.get('present') or not all(info.get('endpoint_public_keys',{}).get(role) for role in roles):
                raise ValueError('INGRESS_PROBE_IDENTITY_NOT_READY')
            rpc('capture-start')
            capture_open=True
            # One known control, followed by the previously failing backup ports.
            ordered=[('primary',443),('backup',443),('backup',8443),('backup',51820),('primary',8443),('primary',51820)]
            for role,port in (target for target in ordered if target[0] in roles):
                row={'role':role,'address':targets[role],'port':port,'started_at':int(time.time())}
                rpc('capture-begin',address=row['address'],port=port)
                try:
                    indices=trial(row,info,key,headers)
                except (ValueError,RuntimeError,subprocess.TimeoutExpired,OSError) as error:
                    row['error_category']=type(error).__name__
                    row['passed']=False
                    indices=[]
                row['server']=rpc('capture-sample',sender_indices=indices)
                rows.append(row)
                print('CLOUD_NATIVE_UDP_TRIAL='+json.dumps(row,sort_keys=True),flush=True)
            finished=rpc('capture-finish')
            capture_open=False
            for row,server in zip(rows,finished['trials'],strict=True):
                row['server']=server
                print('CLOUD_NATIVE_UDP_FINAL='+json.dumps(row,sort_keys=True),flush=True)
        finally:
            if capture_open:
                try:
                    rpc('capture-finish')
                except RuntimeError:
                    print('CLOUD_NATIVE_CAPTURE_FINISH_UNCONFIRMED',flush=True)
            for attempt in range(3):
                try:
                    if rpc('cleanup').get('cleaned') is True:
                        print('CLOUD_NATIVE_PROBE_IDENTITY_REMOVED=PASS',flush=True)
                        break
                except (RuntimeError,subprocess.TimeoutExpired):
                    pass
                if attempt==2:
                    raise RuntimeError('CLOUD_NATIVE_PROBE_CLEANUP_UNCONFIRMED')
                time.sleep(2)
        if len(rows) != len(roles) * len(PORTS) or not all(row.get('passed') for row in rows):
            raise RuntimeError('CLOUD_NATIVE_UDP_PORT_MATRIX_NOT_ALL_PASSED')


if __name__=='__main__':
    main()
