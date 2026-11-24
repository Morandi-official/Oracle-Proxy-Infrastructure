"""Read the current Oracle bindings before reducing the known London inventory."""
import json
import socket
import subprocess

import oci

VNIC = 'ocid1.vnic.oc1.uk-london-1.abwgiljtvinh2xd5rknwxycmpniiwzaekj6fub5y27lmefjmfieikxmzauxq'
ADDRESSES = {'152.67.156.100', '152.67.154.225', '150.230.113.158',
             '141.147.78.44', '141.147.106.2', '143.47.230.219'}
HOSTNAME = 'vpn-admin.morandi.dpdns.org'


def collect():
    result = {}
    try:
        result['admin_a'] = sorted({ip[4][0] for ip in socket.getaddrinfo(HOSTNAME, 443, socket.AF_INET)})
    except OSError:
        result['admin_a'] = []
    for address in ('10.0.0.6', '10.0.0.220'):
        probe = subprocess.run(
            ['curl', '--fail', '--silent', '--noproxy', '*', '--connect-timeout', '3', '--max-time', '5',
             '--interface', address, 'https://1.1.1.1/cdn-cgi/trace'],
            text=True, capture_output=True, timeout=7)
        result.setdefault('source_exit', {})[address] = next(
            (line[3:] for line in probe.stdout.splitlines() if line.startswith('ip=') and line[3:] in ADDRESSES),
            None) if probe.returncode == 0 else None
    retry = oci.retry.NoneRetryStrategy()
    try:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner(
            retry_strategy=retry, federation_client_retry_strategy=retry)
        network = oci.core.VirtualNetworkClient(
            {'region': 'uk-london-1'}, signer=signer, timeout=(3, 8), retry_strategy=retry)
    except Exception:
        result['instance_principal'] = 'UNAVAILABLE'
        return result
    try:
        response = network.list_private_ips(vnic_id=VNIC, limit=20)
        private = {p.id: p.ip_address for p in response.data}
        result['vnic_primary'] = next((p.ip_address for p in response.data if p.is_primary), None)
        result['vnic_list_complete'] = not bool(response.headers.get('opc-next-page'))
    except oci.exceptions.ServiceError as error:
        result['vnic_read_error'] = error.status
        private = {}
    try:
        response = network.list_public_ips('REGION', signer.tenancy_id, lifetime='RESERVED', limit=20)
        result['root_list_complete'] = not bool(response.headers.get('opc-next-page'))
        result['root_reserved_count'] = len(response.data)
        result['known_addresses'] = sorted(
            (dict(public=p.ip_address, private=private.get(p.private_ip_id), state=p.lifecycle_state)
             for p in response.data if p.ip_address in ADDRESSES),
            key=lambda row: row['public'])
    except oci.exceptions.ServiceError as error:
        result['public_list_error'] = error.status
    return result


if __name__ == '__main__':
    print(json.dumps(collect(), sort_keys=True))
