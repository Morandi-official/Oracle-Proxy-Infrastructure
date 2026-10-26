"""Bounded, read-only IPv6 HTTPS probe. No routes, firewall or sysctls changed."""
import ipaddress
import subprocess
import time

SOURCE = '2603:c020:c015:8100::10'
TARGET = 'https://www.cloudflare.com/cdn-cgi/trace'


def observe():
    started = time.monotonic()
    result = {'status': 'UNAVAILABLE', 'family': 6, 'tls_verified': True,
              'tunnel_forwarding_tested': False}
    try:
        response = subprocess.run(
            ['curl', '-6', '--noproxy', '*', '--interface', SOURCE,
             '--proto', '=https', '--fail', '--silent', '--show-error',
             '--connect-timeout', '5', '--max-time', '10',
             '--max-filesize', '8192', TARGET],
            check=False, capture_output=True, text=True, timeout=12)
        result['curl_exit'] = response.returncode
        if response.returncode == 0 and len(response.stdout) <= 8192:
            fields = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
            peer = ipaddress.ip_address(fields.get('ip', ''))
            if peer.version == 6 and str(peer) == SOURCE:
                result.update(status='VERIFIED', observed_egress=str(peer))
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000)
    return result
