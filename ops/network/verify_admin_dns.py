"""Read-only public DNS cutover and end-to-end origin TLS; no authentication or mutations."""
import http.client
import json
import socket
import ssl
import time
from pathlib import Path
import importlib.util

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('public_endpoints',ROOT/'ops/network/endpoint_catalog.py')
endpoints=importlib.util.module_from_spec(spec);spec.loader.exec_module(endpoints)


def main():
    config=endpoints.load();host=config['api_host'];expected=config[config['active']]['public_ipv4']
    resolved=set()
    for attempt in range(7):
        resolved={row[4][0] for row in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)}
        print('ADMIN_DNS_A='+json.dumps(sorted(resolved)),flush=True)
        if resolved=={expected}:break
        if attempt<6:time.sleep(10)
    if resolved!={expected}:raise RuntimeError('ADMIN_DNS_ACTIVE_ADDRESS_MISMATCH')
    print('ADMIN_DNS_CURRENT_ACTIVE_ADDRESS=PASS',flush=True)
    context=ssl.create_default_context()
    for address in endpoints.targets(config):
        with socket.create_connection((address,443),timeout=15) as raw:
            with context.wrap_socket(raw,server_hostname=host) as tls:
                peer=tls.getpeername()[0]
                connection=http.client.HTTPConnection(host,443,timeout=15);connection.sock=tls
                try:
                    connection.request('GET','/login/',headers={'Host':host,'Connection':'close'})
                    response=connection.getresponse();body=response.read(65537)
                    if response.status!=200 or len(body)>65536 or b'name="password"' not in body or b'name="username"' not in body:
                        raise RuntimeError('ADMIN_ORIGIN_LOGIN_FORM_NOT_VERIFIED')
                    if peer!=address:raise RuntimeError('ADMIN_ORIGIN_PEER_MISMATCH')
                    print('ADMIN_ORIGIN_TLS='+json.dumps({'address':address,'peer':peer,'http':response.status,'hostname_verified':True,'login_form':True}),flush=True)
                finally:connection.close()
    print('ADMIN_DNS_AND_BOTH_CONFIGURED_HTTPS_ORIGINS=PASS')

if __name__=='__main__':main()
