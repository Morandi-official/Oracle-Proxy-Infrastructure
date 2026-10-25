"""Idempotent boot-time allowance for this host's public HTTP/HTTPS and fixed QUIC port."""
import os
import shutil
import subprocess

RULE = ['-p', 'tcp', '-m', 'multiport', '--dports', '80,443', '-m', 'comment',
        '--comment', 'oracle-proxy-admin-https', '-j', 'ACCEPT']

QUIC_RULE = ['-p', 'udp', '--dport', '8443', '-m', 'comment',
             '--comment', 'oracle-proxy-wireguard-quic', '-j', 'ACCEPT']


HTTP3_RULE=['-p','udp','--dport','443','-m','comment',
            '--comment','oracle-proxy-admin-http3','-j','ACCEPT']

# Only WireGuard message types are redirected; genuine QUIC / HTTP/3 on
# UDP443 keeps its existing destination. No generic port-forwarding interface.
UDP443_RULE=['-p','udp','--dport','443','-m','addrtype','--dst-type','LOCAL',
             '-m','u32','--u32','0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000',
             '-m','comment','--comment','oracle-proxy-native-udp443','-j','REDIRECT','--to-ports','51820']
UDP8443_RULE=['8443' if x=='443' else 'oracle-proxy-native-udp8443' if x=='oracle-proxy-native-udp443' else x for x in UDP443_RULE]
ADMIN_TUN_RULE=['-i','wg0','-d','152.67.156.100','-p','tcp','--dport','443',
                '-m','comment','--comment','oracle-proxy-admin-through-tunnel','-j','REDIRECT','--to-ports','443']
ADMIN_H3_TUN_RULE=['udp' if x=='tcp' else 'oracle-proxy-admin-h3-through-tunnel' if x=='oracle-proxy-admin-through-tunnel' else x for x in ADMIN_TUN_RULE]


def allow(binary, rule, table='filter', chain='INPUT'):
    result = subprocess.run([binary, '-w', '5', '-t', table, '-C', chain, *rule], check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 1:
        subprocess.run([binary, '-w', '5', '-t', table, '-I', chain, '1', *rule], check=True)
    elif result.returncode != 0: raise ValueError('FIREWALL_INSPECTION_FAILED')


def main():
    if os.geteuid() != 0: raise ValueError('ROOT_REQUIRED')
    if not shutil.which('iptables'): raise ValueError('IPTABLES_REQUIRED')
    for name in ('iptables', 'ip6tables'):
        binary = shutil.which(name)
        if not binary: continue
        allow(binary, RULE)
        allow(binary, HTTP3_RULE)
        if name == 'iptables':
            allow(binary, QUIC_RULE)
            allow(binary, UDP443_RULE, 'nat', 'PREROUTING')
            allow(binary, UDP8443_RULE, 'nat', 'PREROUTING')
            allow(binary, ADMIN_TUN_RULE, 'nat', 'PREROUTING')
            allow(binary, ADMIN_H3_TUN_RULE, 'nat', 'PREROUTING')
    print('PROJECT_WEB_FIREWALL=TCP_80_443_UDP_443_8443_ALLOWED')


if __name__ == '__main__': main()
