"""Own only inner wg0 traffic control; never replace another application's qdisc."""
import ipaddress
import json
import os

ROOT='7a10:'

def action_rows(value):
    """iproute2 emits either actions directly or inside total-acts wrappers."""
    if isinstance(value,list):return [row for item in value for row in action_rows(item)]
    if not isinstance(value,dict):return []
    if type(value.get('index')) is int:return [value]
    return [row for item in value.values() if isinstance(item,(dict,list)) for row in action_rows(item)]

class Controller:
    def __init__(self,command,state,revoke):
        self.command=command;self.path=state/'bandwidth-owned.json';self.revoke=revoke;self.cached=None

    def apply(self,plan):
        # Plan contains only validated integer rates and single-host tunnel addresses.
        plan=sorted(plan,key=lambda p:p['slot'])
        qdiscs=json.loads(self.command(['tc','-j','qdisc','show','dev','wg0']).stdout)
        root=next((q for q in qdiscs if q.get('root')),None)
        ingress=next((q for q in qdiscs if q.get('kind')=='ingress'),None)
        receipt=None
        if self.path.is_symlink():raise ValueError('BANDWIDTH_UNTRUSTED_RECEIPT')
        if self.path.exists():
            receipt=json.loads(self.path.read_text())
            if receipt.get('schema')!=1:raise ValueError('BANDWIDTH_UNTRUSTED_RECEIPT')
        owned_root=bool(receipt and root and root.get('handle')==ROOT and root.get('kind')=='htb')
        owned_ingress=bool(receipt and ingress and ingress.get('handle')=='ffff:')
        if root and not owned_root and (root.get('handle')!='0:' or root.get('kind') not in ('noqueue',)):
            if plan or receipt:raise ValueError('BANDWIDTH_FOREIGN_QDISC')
        if ingress and not owned_ingress and (plan or receipt):raise ValueError('BANDWIDTH_FOREIGN_INGRESS')
        if not plan and not receipt:return
        if self.cached==plan and owned_root and (not any(p['upload_bps'] for p in plan) or owned_ingress):return
        self.revoke()
        # Persist ownership before commands, so partial application can be recovered.
        previous=receipt.get('actions',[]) if receipt else []
        if any(type(i)is not int or not 731001<=i<=731256 for i in previous):raise ValueError('BANDWIDTH_UNTRUSTED_RECEIPT')
        actions=[731000+p['slot'] for p in plan if p['upload_bps']]
        existing=json.loads(self.command(['tc','-j','actions','list','action','police']).stdout)
        indices={a['index'] for a in action_rows(existing)}
        if any(i in indices and i not in previous for i in actions):raise ValueError('BANDWIDTH_FOREIGN_ACTION')
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        temp=self.path.with_suffix('.new')
        if temp.is_symlink():raise ValueError('BANDWIDTH_UNTRUSTED_RECEIPT')
        temp.write_text(json.dumps({'schema':1,'actions':sorted(set(previous+actions))}));temp.chmod(0o600);os.replace(temp,self.path)
        if owned_root:self.command(['tc','qdisc','del','dev','wg0','root'])
        if owned_ingress:self.command(['tc','qdisc','del','dev','wg0','ingress'])
        for index in previous:self.command(['tc','actions','del','action','police','index',str(index)],accepted=(0,2,255))
        if not plan:
            self.path.unlink();self.cached=[];return
        lines=['qdisc add dev wg0 root handle '+ROOT+' htb default fff',
               'class add dev wg0 parent '+ROOT+' classid 7a10:1 htb rate 100gbit ceil 100gbit',
               'class add dev wg0 parent 7a10:1 classid 7a10:fff htb rate 100gbit ceil 100gbit']
        if actions:lines.append('qdisc add dev wg0 handle ffff: ingress')
        pref=100
        for p in plan:
            slot=p['slot'];down=p['download_bps'];up=p['upload_bps'];classid=f'7a10:{256+slot:x}';index=731000+slot
            if down:lines.append(f'class add dev wg0 parent 7a10:1 classid {classid} htb rate {down}bit ceil {down}bit burst {max(65536,down//80)} cburst {max(65536,down//80)}')
            if up:lines.append(f'actions add action police index {index} rate {up}bit burst {max(65536,up//80)} conform-exceed drop/ok')
            for address in sorted(p['addresses']):
                ip=ipaddress.ip_address(address);proto='ip' if ip.version==4 else 'ipv6';host=str(ip)+('/32' if ip.version==4 else '/128')
                if not ip.is_private or ip.is_unspecified or ip.is_multicast:raise ValueError('BANDWIDTH_INVALID_ADDRESS')
                if down:lines.append(f'filter add dev wg0 parent {ROOT} protocol {proto} pref {pref} flower dst_ip {host} classid {classid}')
                if up:lines.append(f'filter add dev wg0 parent ffff: protocol {proto} pref {pref} flower src_ip {host} action police index {index}')
                pref+=1
        try:self.command(['tc','-batch','-'],input='\n'.join(lines)+'\n')
        except Exception:raise ValueError('BANDWIDTH_APPLY_FAILED') from None
        temp.write_text(json.dumps({'schema':1,'actions':actions}));temp.chmod(0o600);os.replace(temp,self.path)
        self.cached=plan


class SharedIngressController:
    """Shared kernel policers across both WireGuard interfaces and IP families."""
    def __init__(self,command,state,revoke):
        self.command=command;self.state=state;self.revoke=revoke;self.path=state/'bandwidth-shared.json';self.cached=None

    def apply(self,plan):
        plan=sorted(plan,key=lambda p:p['slot'])
        if not plan and not (self.path.exists() or self.path.is_symlink() or (self.state/'bandwidth-owned.json').exists()):
            # No configured cap and no owned qdisc to remove: never interrupt
            # active leases merely because the periodic policy tick ran.
            self.cached=[];return
        if self.cached==plan:
            valid=not plan or all(any(q.get('kind')=='clsact' for q in json.loads(self.command(['tc','-j','qdisc','show','dev',i]).stdout)) for i in ('wg0','wgopbackup'))
            if valid:return
        self.revoke()
        # Only migrate the original, explicitly owned root/ingress qdiscs.
        if (self.state/'bandwidth-owned.json').exists():Controller(self.command,self.state,self.revoke).apply([])
        receipt=None
        if self.path.is_symlink():raise ValueError('BANDWIDTH_UNTRUSTED_RECEIPT')
        if self.path.exists():
            receipt=json.loads(self.path.read_text())
            if receipt.get('schema')!=2:raise ValueError('BANDWIDTH_UNTRUSTED_RECEIPT')
        previous=receipt.get('actions',[]) if receipt else []
        if any(type(i)is not int or not (741001<=i<=741256 or 742001<=i<=742256) for i in previous):raise ValueError('BANDWIDTH_UNTRUSTED_RECEIPT')
        actions=[base+p['slot'] for p in plan for direction,base in (('upload_bps',741000),('download_bps',742000)) if p[direction]]
        listing=self.command(['tc','-j','actions','list','action','police']).stdout
        listing=action_rows(json.loads(listing))
        if any(a.get('index') in actions and a.get('index') not in previous for a in listing):raise ValueError('BANDWIDTH_FOREIGN_ACTION')
        if not plan and not receipt:return
        for interface in ('wg0','wgopbackup'):
            rows=json.loads(self.command(['tc','-j','qdisc','show','dev',interface]).stdout)
            if any(q.get('kind') not in ('noqueue','clsact') for q in rows):raise ValueError('BANDWIDTH_FOREIGN_QDISC')
            if any(q.get('kind')=='clsact' for q in rows) and not receipt:raise ValueError('BANDWIDTH_FOREIGN_INGRESS')
        pending={'schema':2,'actions':sorted(set(previous+actions))}
        temporary=self.path.with_suffix('.new')
        if temporary.is_symlink():raise ValueError('BANDWIDTH_UNTRUSTED_RECEIPT')
        temporary.write_text(json.dumps(pending));temporary.chmod(0o600);os.replace(temporary,self.path)
        for interface in ('wg0','wgopbackup'):
            self.command(['tc','qdisc','del','dev',interface,'clsact'],accepted=(0,2))
        for index in previous:self.command(['tc','actions','del','action','police','index',str(index)],accepted=(0,2,255))
        if not plan:self.path.unlink();self.cached=[];return
        lines=['qdisc add dev '+i+' clsact' for i in ('wg0','wgopbackup')]
        pref=100
        for p in plan:
            for direction,base,hook,column in (('upload_bps',741000,'ingress','src_ip'),('download_bps',742000,'egress','dst_ip')):
                rate=p[direction]
                if not rate:continue
                index=base+p['slot']
                lines.append(f'actions add action police index {index} rate {rate}bit burst {max(65536,rate//80)} conform-exceed drop/ok')
                for address in sorted(p['addresses']):
                    ip=ipaddress.ip_address(address)
                    if not ip.is_private or ip.is_unspecified or ip.is_multicast:raise ValueError('BANDWIDTH_INVALID_ADDRESS')
                    protocol='ip' if ip.version==4 else 'ipv6';host=str(ip)+('/32' if ip.version==4 else '/128')
                    for interface in ('wg0','wgopbackup'):
                        lines.append(f'filter add dev {interface} {hook} protocol {protocol} pref {pref} flower {column} {host} action police index {index}')
                    pref+=1
        self.command(['tc','-batch','-'],input='\n'.join(lines)+'\n')
        temporary.write_text(json.dumps({'schema':2,'actions':actions}));temporary.chmod(0o600);os.replace(temporary,self.path);self.cached=plan
