"""Own only inner wg0 traffic control; never replace another application's qdisc."""
import ipaddress
import json
import os

ROOT='7a10:'

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
        indices={a.get('index') for a in existing.get('actions',[])} if isinstance(existing,dict) else {a.get('index') for a in existing}
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
