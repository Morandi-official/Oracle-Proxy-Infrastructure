"""Idempotent boot-time allowance for this host's public HTTP/HTTPS only."""
import os
import shutil
import subprocess

RULE = ['-p', 'tcp', '-m', 'multiport', '--dports', '80,443', '-m', 'comment',
        '--comment', 'oracle-proxy-admin-https', '-j', 'ACCEPT']


def main():
    if os.geteuid() != 0: raise ValueError('ROOT_REQUIRED')
    if not shutil.which('iptables'): raise ValueError('IPTABLES_REQUIRED')
    for name in ('iptables', 'ip6tables'):
        binary = shutil.which(name)
        if not binary: continue
        result = subprocess.run([binary, '-w', '5', '-C', 'INPUT', *RULE], check=False,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 1:
            subprocess.run([binary, '-w', '5', '-I', 'INPUT', '1', *RULE], check=True)
        elif result.returncode != 0: raise ValueError('FIREWALL_INSPECTION_FAILED')
    print('PROJECT_WEB_FIREWALL=TCP_80_443_ALLOWED')


if __name__ == '__main__': main()
