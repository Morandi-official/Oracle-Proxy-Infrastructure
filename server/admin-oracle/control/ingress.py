"""Separate kernel WireGuard identity and peer allowlist for the backup entrance.

No private key is returned to RPC, logs or the web process. Default routing is
untouched; only marked return traffic to the existing inner networks uses table 196.
"""
import ipaddress
import json
import os
from pathlib import Path
import stat
import shlex
import re

INTERFACE='wgopbackup'
PORT=51821
MARK='0x20000000/0x20000000'
TABLE='196'
PRIORITY='19600'
CATALOG=Path('/etc/oracle-proxy-quic/endpoints.json')
READY=Path('/run/oracle-proxy-control/ingress-ready')
COMMENT='proxy-user-ingress-v1'


def protected(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        raise ValueError('INGRESS_PRIVATE_FILE_PERMISSIONS')


class Controller:
    def __init__(self,command,state):
        self.command=command;self.state=state;self.ready=False;self.cache=None
        self.key=state/'backup-ingress.key';self.receipt=state/'backup-ingress.json'

    def call(self,args,**kwargs):return self.command(args,**kwargs)

    def config(self):
        try:info=CATALOG.lstat()
        except FileNotFoundError:return None
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('INGRESS_CATALOG_UNTRUSTED')
        value=json.loads(CATALOG.read_text())
        device=value.get('interface')
        if not isinstance(device,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',device) or device in ('lo','wg0',INTERFACE):raise ValueError('INGRESS_EGRESS_INTERFACE_INVALID')
        self.egress_interface=device
        addresses=[str(ipaddress.IPv4Address(value[role]['private_ipv4'])) for role in ('primary','backup')]
        if addresses[0]==addresses[1] or not all(ipaddress.ip_address(a).is_private for a in addresses):raise ValueError('INGRESS_CATALOG_INVALID')
        self.primary_address=addresses[0]
        return addresses

    def ensure_rule(self,tool,table,chain,rule):
        result=self.call([tool,'-w','5','-t',table,'-C',chain,*rule],accepted=(0,1))
        if result.returncode==1:self.call([tool,'-w','5','-t',table,'-I',chain,'1',*rule])

    def ensure(self,backup):
        addresses=json.loads(self.call(['ip','-j','address','show','dev','wg0']).stdout)
        signature=sorted((a.get('family'),a.get('local'),a.get('prefixlen'),a.get('scope')) for item in addresses for a in item.get('addr_info',[]) if a.get('scope')!='link')
        if self.ready and self.backup==backup and self.address_signature==signature:return
        if not self.key.exists():
            key=self.call(['wg','genkey']).stdout.strip()
            fd=os.open(self.key,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as stream:stream.write(key+'\n');stream.flush();os.fsync(stream.fileno())
        protected(self.key)
        public=self.call(['wg','pubkey'],input=self.key.read_text()).stdout.strip()
        if len(public)!=44:raise ValueError('INGRESS_PUBLIC_KEY_INVALID')
        exists=self.call(['ip','-j','link','show','dev',INTERFACE],accepted=(0,1))
        expected={'schema':1,'owner':COMMENT,'interface':INTERFACE,'public_key':public}
        if self.receipt.exists():
            protected(self.receipt)
            if json.loads(self.receipt.read_text())!=expected:raise ValueError('INGRESS_RECEIPT_MISMATCH')
        elif exists.returncode==0:raise ValueError('INGRESS_FOREIGN_INTERFACE')
        else:
            fd=os.open(self.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'w') as stream:json.dump(expected,stream);stream.flush();os.fsync(stream.fileno())
        if exists.returncode!=0:self.call(['ip','link','add',INTERFACE,'type','wireguard'])
        self.call(['wg','set',INTERFACE,'private-key',str(self.key),'listen-port',str(PORT)])
        self.call(['ip','link','set','dev',INTERFACE,'up'])
        for item in addresses:
            for addr in item.get('addr_info',[]):
                if addr.get('family') not in ('inet','inet6') or addr.get('scope')=='link':continue
                host=ipaddress.ip_interface(str(addr['local'])+'/'+str(addr['prefixlen']))
                if not host.ip.is_private:raise ValueError('INGRESS_INNER_PRIVATE_REQUIRED')
                family='-4' if host.version==4 else '-6';tool='iptables' if host.version==4 else 'ip6tables'
                self.call(['ip',family,'address','replace',str(host.ip)+('/32' if host.version==4 else '/128'),'dev',INTERFACE,'noprefixroute'])
                current=json.loads(self.call(['ip','-j',family,'rule','show']).stdout)
                matching=[r for r in current if r.get('priority')==int(PRIORITY)]
                if matching and any(str(r.get('table'))!=TABLE or r.get('fwmark') not in ('0x20000000',536870912) or r.get('fwmask') not in ('0x20000000',536870912) for r in matching):raise ValueError('INGRESS_FOREIGN_POLICY_RULE')
                if not matching:self.call(['ip',family,'rule','add','priority',PRIORITY,'fwmark',MARK,'lookup',TABLE])
                routes=self.call(['ip','-j',family,'route','show','table',TABLE],accepted=(0,2))
                if routes.returncode==0 and any(r.get('dev')!=INTERFACE for r in json.loads(routes.stdout)):raise ValueError('INGRESS_FOREIGN_ROUTE_TABLE')
                self.call(['ip',family,'route','replace',str(host.network),'dev',INTERFACE,'table',TABLE])
                device=getattr(self,'egress_interface',None)
                if device:
                    flag='/proc/sys/net/ipv4/ip_forward' if host.version==4 else '/proc/sys/net/ipv6/conf/all/forwarding'
                    if Path(flag).read_text().strip()!='1':raise ValueError('INGRESS_FORWARDING_NOT_READY')
                    chain='OPX_INGRESS_FORWARD'
                    result=self.call([tool,'-w','5','-S',chain],accepted=(0,1))
                    if result.returncode==1:self.call([tool,'-w','5','-N',chain])
                    elif any(COMMENT not in line for line in result.stdout.splitlines() if line.startswith('-A')):raise ValueError('INGRESS_FOREIGN_FIREWALL_CHAIN')
                    body=['*filter','-F '+chain,f'-A {chain} -m comment --comment {COMMENT} -j OPX_FWD',
                          f'-A {chain} -i {INTERFACE} -o {device} -s {host.network} -m comment --comment {COMMENT} -j ACCEPT',
                          f'-A {chain} -i {device} -o {INTERFACE} -d {host.network} -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment {COMMENT} -j ACCEPT',
                          f'-A {chain} -m comment --comment {COMMENT} -j DROP','COMMIT','']
                    self.call([tool+'-restore','-w','5','--noflush'],input='\n'.join(body))
                    for direction in ('-i','-o'):
                        self.ensure_rule(tool,'filter','FORWARD',[direction,INTERFACE,'-m','comment','--comment',COMMENT,'-j',chain])
                    rule=['-s',str(host.network),'-o',device,'-m','connmark','--mark',MARK,'-m','comment','--comment',COMMENT]
                    if host.version==4:rule+=['-j','MASQUERADE']
                    else:
                        external=json.loads(self.call(['ip','-j','-6','address','show','dev',device]).stdout)
                        exits=[a['local'] for item in external for a in item.get('addr_info',[]) if a.get('family')=='inet6' and ipaddress.ip_address(a['local']).is_global]
                        metadata=Path('/etc/oracle-proxy-quic/ipv6.json')
                        selected=None
                        if metadata.exists():
                            info=metadata.lstat()
                            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('INGRESS_IPV6_METADATA_UNTRUSTED')
                            selected=json.loads(metadata.read_text()).get('egress')
                            if selected not in exits:raise ValueError('INGRESS_IPV6_EGRESS_NOT_LOCAL')
                        if selected is None and len(exits)==1:selected=exits[0]
                        if selected is None:raise ValueError('INGRESS_IPV6_EGRESS_AMBIGUOUS')
                        rule+=['-j','SNAT','--to-source',selected]
                    self.ensure_rule(tool,'nat','POSTROUTING',rule)
                # Preserve only our bit; foreign marks and default route remain intact.
                self.ensure_rule(tool,'mangle','PREROUTING',['-i',INTERFACE,'-m','comment','--comment',COMMENT,'-j','CONNMARK','--set-xmark',MARK])
                for chain in ('PREROUTING','OUTPUT'):
                    self.ensure_rule(tool,'mangle',chain,['-m','connmark','--mark',MARK,'-m','comment','--comment',COMMENT,'-j','CONNMARK','--restore-mark','--nfmask','0x20000000','--ctmask','0x20000000'])
        # Encrypted backup traffic is sent to its separate identity before legacy
        # generic native-port redirects. Genuine QUIC remains on its own listener.
        existing=self.call(['iptables','-w','5','-t','nat','-S','PREROUTING']).stdout
        for line in existing.splitlines():
            rule=shlex.split(line)
            if COMMENT not in rule:continue
            if rule[:3]!=['-A','PREROUTING','-d'] or rule[-4:]!=['-j','REDIRECT','--to-ports',str(PORT)]:raise ValueError('INGRESS_FOREIGN_NAT_RULE')
            old=ipaddress.ip_network(rule[3],strict=True)
            if old.version!=4 or old.prefixlen!=32 or not old.network_address.is_private:raise ValueError('INGRESS_FOREIGN_NAT_RULE')
            if str(old.network_address)!=backup:self.call(['iptables','-w','5','-t','nat','-D','PREROUTING',*rule[2:]])
        for port in ('443','8443','51820'):
            self.ensure_rule('iptables','nat','PREROUTING',['-d',backup+'/32','-p','udp','--dport',port,'-m','u32','--u32','0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000','-m','comment','--comment',COMMENT,'-j','REDIRECT','--to-ports',str(PORT)])
        # Port 51821 is internal implementation, never an alternate public entrance.
        # Each permitted public port has an exact conntrack original destination.
        chain='OPX_INGRESS_PORT'
        result=self.call(['iptables','-w','5','-S',chain],accepted=(0,1))
        if result.returncode==1:self.call(['iptables','-w','5','-N',chain])
        elif any(COMMENT not in line for line in result.stdout.splitlines() if line.startswith('-A')):raise ValueError('INGRESS_FOREIGN_FIREWALL_CHAIN')
        body=['*filter','-F '+chain]
        body.append(f'-A {chain} -i lo -m comment --comment {COMMENT} -j ACCEPT')
        for port in ('443','8443','51820'):
            body.append(f'-A {chain} -p udp -m conntrack --ctstate DNAT --ctorigdst {backup} --ctorigdstport {port} -m comment --comment {COMMENT} -j ACCEPT')
        body.extend([f'-A {chain} -m comment --comment {COMMENT} -j DROP','COMMIT',''])
        self.call(['iptables-restore','-w','5','--noflush'],input='\n'.join(body))
        self.ensure_rule('iptables','filter','INPUT',['-p','udp','--dport',str(PORT),'-m','comment','--comment',COMMENT,'-j',chain])
        primary=getattr(self,'primary_address',None)
        if primary:
            if self.call(['wg','show','wg0','listen-port']).stdout.strip()!='51820':raise ValueError('INGRESS_PRIMARY_PORT_REQUIRED')
            chain='OPX_PRIMARY_PORT'
            result=self.call(['iptables','-w','5','-S',chain],accepted=(0,1))
            if result.returncode==1:self.call(['iptables','-w','5','-N',chain])
            elif any(COMMENT not in line for line in result.stdout.splitlines() if line.startswith('-A')):raise ValueError('INGRESS_FOREIGN_FIREWALL_CHAIN')
            body=['*filter','-F '+chain,f'-A {chain} -i lo -m comment --comment {COMMENT} -j ACCEPT']
            for port in ('443','8443','51820'):
                body.append(f'-A {chain} -p udp -m conntrack --ctorigdst {primary} --ctorigdstport {port} -m comment --comment {COMMENT} -j ACCEPT')
            body.extend([f'-A {chain} -m comment --comment {COMMENT} -j DROP','COMMIT',''])
            self.call(['iptables-restore','-w','5','--noflush'],input='\n'.join(body))
            self.ensure_rule('iptables','filter','INPUT',['-p','udp','--dport','51820','-m','comment','--comment',COMMENT,'-j',chain])
            # Public permissions currently cover the two numeric IPv4 entrances.
            # IPv6 payload remains tunneled, but raw IPv6 must not bypass these
            # entrance selectors by addressing a wildcard WireGuard listener.
            chain='OPX_INGRESS_V6PORT'
            result=self.call(['ip6tables','-w','5','-S',chain],accepted=(0,1))
            if result.returncode==1:self.call(['ip6tables','-w','5','-N',chain])
            elif any(COMMENT not in line for line in result.stdout.splitlines() if line.startswith('-A')):raise ValueError('INGRESS_FOREIGN_FIREWALL_CHAIN')
            body=['*filter','-F '+chain,f'-A {chain} -i lo -m comment --comment {COMMENT} -j ACCEPT',f'-A {chain} -m comment --comment {COMMENT} -j DROP','COMMIT','']
            self.call(['ip6tables-restore','-w','5','--noflush'],input='\n'.join(body))
            self.ensure_rule('ip6tables','filter','INPUT',['-p','udp','-m','multiport','--dports','51820,51821','-m','comment','--comment',COMMENT,'-j',chain])
        self.public_key=public;self.backup=backup;self.address_signature=signature;self.ready=True

    def peers(self,interface):
        return {line.split('\t',1)[0]:line.split('\t',1)[1].replace(' ',',').split(',') for line in self.call(['wg','show',interface,'allowed-ips']).stdout.splitlines()}

    def sync(self,plan):
        config=self.config()
        if config is None:
            if self.receipt.exists():raise ValueError('INGRESS_CATALOG_REQUIRED')
            return False
        marker=READY
        if not marker.exists():raise ValueError('INGRESS_ROUTING_NOT_READY')
        protected(marker)
        self.ensure(config[1])
        if marker.read_text().strip()!=self.public_key:raise ValueError('INGRESS_ROUTING_IDENTITY_MISMATCH')
        # Ownership is durable in the root ledger; revoke before adding any grant.
        for interface,role in (('wg0','primary'),(INTERFACE,'backup')):
            actual=self.peers(interface)
            known={p['public_key'] for p in plan}
            if role=='backup':
                for key in set(actual)-known:self.call(['wg','set',interface,'peer',key,'remove'])
            for peer in plan:
                key=peer['public_key'];wanted=role in peer['roles'] and peer['active']
                if not wanted and key in actual:self.call(['wg','set',interface,'peer',key,'remove'])
            for peer in plan:
                if role in peer['roles'] and peer['active'] and set(actual.get(peer['public_key'],[]))!=set(peer['addresses']):
                    self.call(['wg','set',interface,'peer',peer['public_key'],'allowed-ips',','.join(peer['addresses'])])
        return True


def network_start():
    """Fixed boot helper; the sandboxed policy service cannot change sysctls."""
    import subprocess
    if os.geteuid()!=0:raise ValueError('ROOT_REQUIRED')
    state=Path('/var/lib/oracle-proxy-control')
    def command(args,*,input=None,accepted=(0,)):
        result=subprocess.run(args,input=input,capture_output=True,text=True,timeout=8)
        if result.returncode not in accepted:raise ValueError('INGRESS_NETWORK_OPERATION_FAILED')
        return result
    controller=Controller(command,state);config=controller.config()
    if config is None:return
    controller.ensure(config[1])
    # Only the new backup interface needs loose reverse-path validation: its
    # inner prefix is also routed via wg0 in the unchanged main routing table.
    Path('/proc/sys/net/ipv4/conf/'+INTERFACE+'/rp_filter').write_text('2\n')
    marker=READY
    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:stream.write(controller.public_key+'\n')


if __name__=='__main__':network_start()
