"""Measure bounded origin egress and count configured rate caps without user data."""
import importlib.util
import json
from pathlib import Path
import subprocess


def command(args, timeout=12):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


def sample(address):
    result = command(['curl', '-6' if ':' in address else '-4', '--noproxy', '*', '--interface', address, '--http1.1',
                      '--connect-timeout', '5', '--max-time', '10', '--silent', '--show-error',
                      '--output', '/dev/null', '--write-out', '%{json}',
                      'https://speed.cloudflare.com/__down?bytes=2097152'])
    row = json.loads(result.stdout) if result.stdout else {}
    return {'family': 6 if ':' in address else 4, 'curl_exit': result.returncode,
            'http': row.get('http_code'), 'bytes': row.get('size_download'),
            'first_byte_ms': round(row.get('time_starttransfer', 0) * 1000),
            'total_ms': round(row.get('time_total', 0) * 1000)}


def main():
    path = Path(__file__).with_name('cloud_udp_identity.py')
    spec = importlib.util.spec_from_file_location('cloud_speed_policy_readback', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state = module.rpc('state', {})
    active = [row for row in state['users'] if row['status'] == 'active']
    limits = {key: sum(isinstance((row.get('rate') or {}).get(key), int) for row in active)
              for key in ('download_bps', 'upload_bps')}
    qdisc = command(['tc', '-j', 'qdisc', 'show', 'dev', 'enp0s6'])
    kinds = sorted({value['kind'] for value in json.loads(qdisc.stdout)}) if qdisc.returncode == 0 else []
    print(json.dumps({'active_account_count': len(active), 'configured_rate_counts': limits,
                      'quota_guard_blocked': bool(state['budget']['guard_blocked']),
                      'physical_qdisc': kinds,
                      'origin_downloads': [sample(address) for address in ('10.0.0.6', '2603:c020:c015:8100::10')]},
                     sort_keys=True))


if __name__ == '__main__':
    main()
