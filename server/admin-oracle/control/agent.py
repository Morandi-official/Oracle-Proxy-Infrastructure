"""Root-owned policy/accounting service. Fixed RPC; no shell, private keys or web DB access."""
import base64
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pwd
import re
import select
import socket
import sqlite3
import struct
import subprocess
import time
import uuid
from pathlib import Path

STATE = Path('/var/lib/oracle-proxy-control')
SOCKET = '/run/oracle-proxy-control/control.sock'
TICK = 5
LEASE = 20
MAX_BYTES = 10**16


def integer(value, maximum=MAX_BYTES):
    if type(value) is not int or not 0 <= value <= maximum: raise ValueError('INVALID_INTEGER')
    return value


def public_key(value):
    if not isinstance(value, str) or len(value) != 44: raise ValueError('INVALID_PUBLIC_KEY')
    try: raw = base64.b64decode(value, validate=True)
    except ValueError: raise ValueError('INVALID_PUBLIC_KEY') from None
    if len(raw) != 32 or base64.b64encode(raw).decode() != value: raise ValueError('INVALID_PUBLIC_KEY')
    return value


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value: raise ValueError('INVALID_ID')
    return value


def period(now):
    return dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime('%Y-%m')


def host_ips(values):
    result = []
    for value in values:
        network = ipaddress.ip_network(value, strict=True)
        if network.prefixlen != network.max_prefixlen: raise ValueError('HOST_ADDRESS_REQUIRED')
        if not network.network_address.is_private or network.network_address.is_unspecified or network.network_address.is_multicast:
            raise ValueError('PRIVATE_TUNNEL_ADDRESS_REQUIRED')
        result.append(str(network.network_address))
    if not 1 <= len(result) <= 2: raise ValueError('ONE_OR_TWO_HOST_ADDRESSES_REQUIRED')
    return sorted(result)


class Driver:
    def revoke(self):
        # Best effort across all families even if one set is unavailable. Never renew on errors.
        for name in ('OPXOK4','OPXOK6','OPXALL4','OPXALL6'):
            try: self.command(['ipset','flush',name])
            except Exception: pass

    def command(self, args, *, input=None, accepted=(0,)):
        result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=8, check=False)
        if result.returncode not in accepted or len(result.stdout) > 1024 * 1024:
            raise RuntimeError('FIXED_SYSTEM_OPERATION_FAILED')
        return result

    def observe(self):
        # Never use `wg show dump` or read wg0.conf: both can disclose private/PSK keys.
        peers = {}
        for line in self.command(['wg', 'show', 'wg0', 'allowed-ips']).stdout.splitlines():
            key, addresses = line.split('\t', 1); public_key(key)
            peers[key] = {'allowed_ips': [a for a in addresses.replace(',', ' ').split() if a!='(none)'], 'rx': 0, 'tx': 0, 'handshake': 0}
        if len(peers) > 512: raise ValueError('TOO_MANY_PEERS')
        for field, command in (('transfer', 'transfer'), ('handshake', 'latest-handshakes')):
            for line in self.command(['wg', 'show', 'wg0', command]).stdout.splitlines():
                parts = line.split(); key = public_key(parts[0])
                if key not in peers: continue
                if field == 'transfer':
                    peers[key]['rx'], peers[key]['tx'] = integer(int(parts[1]), 2**63-1), integer(int(parts[2]), 2**63-1)
                else: peers[key]['handshake'] = integer(int(parts[1]), 2**63-1)
        interfaces = set()
        for version, target in (('-4', '1.1.1.1'), ('-6', '2606:4700:4700::1111')):
            result = self.command(['ip', '-j', version, 'route', 'get', target], accepted=(0, 2))
            if result.returncode == 0:
                for item in json.loads(result.stdout):
                    name = item.get('dev', '')
                    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}', name) or name in ('lo', 'wg0'):
                        raise ValueError('INVALID_EGRESS_INTERFACE')
                    if not (Path('/sys/class/net') / name / 'device').exists():
                        raise ValueError('PHYSICAL_VNIC_REQUIRED')
                    interfaces.add(name)
        if not interfaces: raise ValueError('NO_EGRESS_INTERFACE')
        nics = {name: {field: integer(int((Path('/sys/class/net') / name / 'statistics' /
                      (field + '_bytes')).read_text()), 2**63-1) for field in ('rx', 'tx')} for name in interfaces}
        addresses = json.loads(self.command(['ip', '-j', 'addr', 'show', 'dev', 'wg0']).stdout)
        networks = [str(ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}"))
                    for item in addresses for a in item.get('addr_info', []) if a['family'] in ('inet', 'inet6')]
        return {'peers': peers, 'nics': nics, 'boot': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'server_public_key': self.command(['wg', 'show', 'wg0', 'public-key']).stdout.strip(),
                'listen_port': int(self.command(['wg', 'show', 'wg0', 'listen-port']).stdout.strip()),
                'networks': networks}

    def add_peer(self, key, addresses):
        public_key(key); host_ips(addresses)
        self.command(['wg', 'set', 'wg0', 'peer', key, 'allowed-ips', ','.join(addresses)])

    def initialize(self, guarded):
        for family in (4, 6):
            suffix = str(family); tool = 'iptables' if family == 4 else 'ip6tables'
            for short, kind, timeout in (('MAN', 'hash:ip', False), ('OK', 'hash:ip', True), ('ALL', 'hash:net', True)):
                args = ['ipset', 'create', 'OPX' + short + suffix, kind, 'family', 'inet' if family == 4 else 'inet6', 'maxelem', '2048']
                if timeout: args += ['timeout', str(LEASE)]
                self.command([*args, '-exist'])
            for chain in ('OPX_IN', 'OPX_FWD'):
                old = self.command([tool, '-w', '5', '-S', chain], accepted=(0, 1))
                if old.returncode == 0 and any('oracle-proxy-control' not in line for line in old.stdout.splitlines() if line.startswith('-A')):
                    raise ValueError('FOREIGN_FIREWALL_CHAIN')
                if old.returncode == 1: self.command([tool, '-w', '5', '-N', chain])
            lines = ['*filter', '-F OPX_IN', '-F OPX_FWD']
            for chain, direction, column in (('OPX_IN', '-i', 'src'), ('OPX_FWD', '-i', 'src'), ('OPX_FWD', '-o', 'dst')):
                prefix = f'-A {chain} {direction} wg0 '
                comment = '-m comment --comment oracle-proxy-control -j DROP'
                if guarded:
                    lines.append(prefix + f'-m set ! --match-set OPXALL{suffix} {column} ' + comment)
                lines.append(prefix + f'-m set --match-set OPXMAN{suffix} {column} -m set ! --match-set OPXOK{suffix} {column} ' + comment)
            self.command([tool + '-restore', '-w', '5', '--noflush'], input='\n'.join([*lines, 'COMMIT', '']))
            for parent, direction, chain in (('INPUT', '-i', 'OPX_IN'), ('FORWARD', '-i', 'OPX_FWD'), ('FORWARD', '-o', 'OPX_FWD')):
                rule = [direction, 'wg0', '-m', 'comment', '--comment', 'oracle-proxy-control', '-j', chain]
                check = self.command([tool, '-w', '5', '-C', parent, *rule], accepted=(0, 1))
                if check.returncode == 1: self.command([tool, '-w', '5', '-I', parent, '1', *rule])

    def leases(self, managed, allowed, global_allowed):
        # Managed addresses never disappear on crashes; allow leases expire in the kernel.
        lines = []
        for family in (4, 6):
            suffix = str(family)
            for address in sorted(managed):
                if ipaddress.ip_address(address).version != family: continue
                lines.append('add OPXMAN' + suffix + ' ' + address)
                if address in allowed:
                    timeout = allowed[address] if isinstance(allowed,dict) else LEASE
                    lines.append('add OPXOK' + suffix + ' ' + address + ' timeout ' + str(timeout))
                else: lines.append('del OPXOK' + suffix + ' ' + address)
            for network in (('0.0.0.0/1', '128.0.0.0/1') if family == 4 else ('::/1', '8000::/1')):
                lines.append(('add OPXALL' + suffix + ' ' + network + ' timeout ' + str(LEASE)) if global_allowed else
                             ('del OPXALL' + suffix + ' ' + network))
        self.command(['ipset', '-exist', 'restore'], input='\n'.join(lines)+'\n')


class Engine:
    def __init__(self, database, driver, now=time.time):
        self.db = sqlite3.connect(database, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, quota INTEGER,
            expires INTEGER, enabled INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS devices (key TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
            addresses TEXT NOT NULL, owned INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS device_limits (user_id TEXT PRIMARY KEY, maximum INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS revoked_devices (key TEXT PRIMARY KEY);
          CREATE TABLE IF NOT EXISTS counters (key TEXT PRIMARY KEY, rx INTEGER, tx INTEGER, boot TEXT);
          CREATE TABLE IF NOT EXISTS usage (month TEXT, kind TEXT, key TEXT, rx INTEGER, tx INTEGER,
            PRIMARY KEY(month,kind,key));
          CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at INTEGER, actor TEXT, action TEXT, resource TEXT);
        ''')
        self.driver = driver; self.now = now; self.observation = None; self.error = None
        self.last_sample = None; self.last_enforced = None
        self.set_default('started_at', int(now())); self.set_default('nic_total', 0)
        self.set_default('accounting_gaps', 0)
        self.set_default('user_states', {})
        self.set_default('budget', {'limit_bytes': 10_000_000_000_000, 'reserve_bytes': 1_000_000_000_000,
            'guard_enabled': False, 'period': period(now()), 'prior_usage_bytes': None, 'anchor_total': 0,
            'baseline_at': None, 'baseline_gaps': 0})
        self.driver.initialize(self.get('budget')['guard_enabled'])
        managed = {address for row in self.db.execute('SELECT addresses FROM devices') for address in host_ips(json.loads(row[0]))}
        self.driver.leases(managed,set(),False)

    def get(self, key):
        return json.loads(self.db.execute('SELECT value FROM kv WHERE key=?', (key,)).fetchone()[0])

    def set(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO kv VALUES (?,?)', (key, json.dumps(value, separators=(',', ':'))))

    def set_default(self, key, value):
        if self.db.execute('SELECT 1 FROM kv WHERE key=?', (key,)).fetchone() is None: self.set(key, value)

    def add_usage(self, kind, key, rx, tx):
        self.db.execute('INSERT INTO usage VALUES (?,?,?,?,?) ON CONFLICT(month,kind,key) DO UPDATE SET rx=rx+excluded.rx,tx=tx+excluded.tx',
                        (period(self.now()), kind, key, rx, tx))

    def used(self, kind, key):
        row = self.db.execute('SELECT rx,tx FROM usage WHERE month=? AND kind=? AND key=?', (period(self.now()), kind, key)).fetchone()
        return {'rx': row['rx'], 'tx': row['tx']} if row else {'rx': 0, 'tx': 0}

    def device_limit(self, user_id):
        row = self.db.execute('SELECT maximum FROM device_limits WHERE user_id=?', (user_id,)).fetchone()
        return row[0] if row else 3

    def device_count(self, user_id):
        return self.db.execute('SELECT count(*) FROM devices WHERE user_id=? AND key NOT IN (SELECT key FROM revoked_devices)', (user_id,)).fetchone()[0]

    def revoked(self, key):
        return self.db.execute('SELECT 1 FROM revoked_devices WHERE key=?', (key,)).fetchone() is not None

    def reason(self, user):
        if not user['enabled']: return 'disabled'
        if user['expires'] is not None and user['expires'] <= self.now(): return 'expired'
        usage = self.used('user', user['id'])
        if user['quota'] is not None and usage['rx'] + usage['tx'] >= user['quota']: return 'quota'
        return 'active'

    def budget_state(self):
        value = self.get('budget').copy(); month = period(self.now())
        measured = self.used('server', 'all')['tx']
        valid = (value['period'] == month and value['prior_usage_bytes'] is not None and
                 value.get('baseline_gaps',0) == self.get('accounting_gaps'))
        estimated = value['prior_usage_bytes'] + max(0, self.get('nic_total') - value['anchor_total']) if valid else None
        remaining = max(0, value['limit_bytes'] - estimated) if estimated is not None else None
        available = max(0, remaining - value['reserve_bytes']) if remaining is not None else None
        return {**value, 'current_period': month, 'measured_outbound_bytes': measured,
                'estimated_used_bytes': estimated, 'remaining_bytes': remaining, 'vpn_available_bytes': available,
                'history_complete': valid, 'official_api_connected': False, 'basis': 'manual-baseline-plus-local-vnic' if valid else 'local-since-observation-only',
                'guard_blocked': bool(value['guard_enabled'] and (available is None or available <= 0)),
                'accounting_gaps': self.get('accounting_gaps'), 'started_at': self.get('started_at')}

    def tick(self):
        try:
            observation = self.driver.observe()
            # New product-owned peers are restored after wg-quick/reboot, without reading/writing wg0.conf.
            for device in self.db.execute('SELECT * FROM devices WHERE owned=1 AND key NOT IN (SELECT key FROM revoked_devices)'):
                addresses = json.loads(device['addresses'])
                if device['key'] not in observation['peers']:
                    occupied = [ipaddress.ip_network(ip) for peer in observation['peers'].values() for ip in peer['allowed_ips']]
                    if any(ipaddress.ip_network(ip).overlaps(other) for ip in addresses for other in occupied if ipaddress.ip_network(ip).version==other.version):
                        raise ValueError('OWNED_PEER_ADDRESS_CONFLICT')
                    self.driver.add_peer(device['key'], addresses)
            now = int(self.now()); month = period(now)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                old_sample = self.get('last_sample') if self.db.execute("SELECT 1 FROM kv WHERE key='last_sample'").fetchone() else now
                if now - old_sample > LEASE: self.set('accounting_gaps', self.get('accounting_gaps') + 1)
                budget = self.get('budget')
                if budget['period'] != month:
                    # Only a fully observed UTC month can start automatically with a zero baseline.
                    start = int(dt.datetime.fromtimestamp(now, dt.timezone.utc).replace(day=1,hour=0,minute=0,second=0,microsecond=0).timestamp())
                    if now - old_sample <= LEASE and old_sample <= start <= now:
                        budget.update(period=month, prior_usage_bytes=0, anchor_total=self.get('nic_total'), baseline_at=start,
                                      baseline_gaps=self.get('accounting_gaps'))
                        self.set('budget', budget)
                for kind, entries in (('peer', observation['peers']), ('nic', observation['nics'])):
                    for key, counter in entries.items():
                        old = self.db.execute('SELECT * FROM counters WHERE key=?', (kind+':'+key,)).fetchone()
                        delta = {}
                        for field in ('rx', 'tx'):
                            delta[field] = (counter[field] - old[field] if old and old['boot'] == observation['boot'] and
                                            counter[field] >= old[field] else counter[field] if old else 0)
                        if old and (old['boot'] != observation['boot'] or any(counter[f] < old[f] for f in ('rx','tx'))):
                            self.set('accounting_gaps', self.get('accounting_gaps') + 1)
                        self.db.execute('INSERT OR REPLACE INTO counters VALUES (?,?,?,?)',
                                        (kind+':'+key, counter['rx'], counter['tx'], observation['boot']))
                        if kind == 'nic':
                            self.set('nic_total', self.get('nic_total') + delta['tx'])
                            self.add_usage('server', 'all', delta['rx'], delta['tx'])
                        else:
                            self.add_usage('peer', key, delta['rx'], delta['tx'])
                            device = self.db.execute('SELECT user_id FROM devices WHERE key=?', (key,)).fetchone()
                            if device: self.add_usage('user', device['user_id'], delta['rx'], delta['tx'])
                self.set('last_sample', now); self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK'); raise
            self.observation = observation; self.last_sample = now
            self.enforce(); self.error = None
        except Exception as error:
            # Do not renew kernel leases on incomplete observation or accounting failure.
            self.driver.revoke()
            message=str(error)
            self.error = message if re.fullmatch(r'[A-Z_]{1,80}',message) else 'OBSERVATION_OR_ENFORCEMENT_FAILED'
            raise

    def enforce(self):
        managed = set(); allowed = {}
        users = {row['id']: dict(row) for row in self.db.execute('SELECT * FROM users')}
        for device in self.db.execute('SELECT * FROM devices'):
            saved = host_ips(json.loads(device['addresses'])); managed.update(saved)
            current = (self.observation or {}).get('peers', {}).get(device['key'])
            if current:
                addresses = host_ips(current['allowed_ips']); managed.update(addresses)
                if sorted(addresses) != sorted(saved): continue
                user = users[device['user_id']]
                if self.reason(user) == 'active' and not self.revoked(device['key']):
                    timeout = LEASE if user['expires'] is None else min(LEASE,max(1,int(user['expires']-self.now())))
                    allowed.update({address:timeout for address in addresses})
        try: self.driver.leases(managed, allowed, not self.budget_state()['guard_blocked'])
        except Exception:
            self.error='ENFORCEMENT_FAILED';self.driver.revoke();raise
        states={user_id:self.reason(user) for user_id,user in users.items()}
        previous=self.get('user_states')
        for user_id,state in states.items():
            if previous.get(user_id)!=state:self.audit('system:policy','access.'+state,user_id)
        if states!=previous:self.set('user_states',states)
        self.last_enforced = int(self.now())

    def audit(self, actor, action, resource):
        self.db.execute('INSERT INTO audit(at,actor,action,resource) VALUES (?,?,?,?)',
                        (int(self.now()), actor, action, resource))

    def snapshot(self):
        observation = self.observation or {'peers':{}, 'nics':{}, 'networks':[], 'server_public_key':None, 'listen_port':None}
        users = []
        for user in self.db.execute('SELECT * FROM users ORDER BY name,id'):
            usage = self.used('user', user['id'])
            users.append({**dict(user), 'enabled': bool(user['enabled']), 'usage': usage,
                          'remaining_bytes': max(0, user['quota']-usage['rx']-usage['tx']) if user['quota'] is not None else None,
                          'status': self.reason(user), 'device_limit':self.device_limit(user['id']), 'device_count':self.device_count(user['id'])})
        bindings = {row['key']:dict(row) for row in self.db.execute('SELECT * FROM devices')}
        peers = []
        for key in sorted(set(observation['peers']) | set(bindings)):
            peer = observation['peers'].get(key); device = bindings.get(key)
            peers.append({'public_key':key, 'fingerprint':hashlib.sha256(key.encode()).hexdigest()[:12],
                'user_id':device['user_id'] if device else None, 'name':device['name'] if device else '',
                'allowed_ips': peer['allowed_ips'] if peer else json.loads(device['addresses']),
                'handshake':peer['handshake'] if peer else 0, 'present':peer is not None,
                'revoked':self.revoked(key), 'managed':device is not None, 'owned':bool(device and device['owned']), 'usage': self.used('peer',key)})
        return {'schema':1, 'observed_at':self.last_sample, 'enforced_at':self.last_enforced, 'error':self.error,
            'period': period(self.now()), 'sample_interval_seconds':TICK, 'lease_seconds':LEASE,
            'users':users, 'peers':peers, 'budget':self.budget_state(), 'nics':sorted(observation['nics']),
            'server_public_key':observation['server_public_key'], 'listen_port':observation['listen_port'],
            'audit':[dict(row) for row in self.db.execute('SELECT at,actor,action,resource FROM audit ORDER BY id DESC LIMIT 50')]}

    def dispatch(self, request):
        if not isinstance(request, dict) or set(request) != {'operation','actor','data'}: raise ValueError('INVALID_REQUEST')
        operation, actor, data = request['operation'], request['actor'], request['data']
        if not isinstance(actor, str) or not re.fullmatch(r'github:[0-9]{1,20}', actor): raise ValueError('INVALID_ACTOR')
        if not isinstance(data, dict): raise ValueError('INVALID_DATA')
        if operation == 'state' and not data: return self.snapshot()
        # Account all current counters under the old ownership before any binding/config mutation.
        self.tick()
        if operation == 'user.put':
            if set(data) != {'id','name','quota_bytes','expires_at','enabled'}: raise ValueError('INVALID_FIELDS')
            user_id = identifier(data['id']) if data['id'] else str(uuid.uuid4())
            if data['id'] and not self.db.execute('SELECT 1 FROM users WHERE id=?',(user_id,)).fetchone(): raise ValueError('USER_NOT_FOUND')
            if not isinstance(data['name'],str) or not 1 <= len(data['name'].strip()) <= 80 or any(ord(c)<32 for c in data['name']): raise ValueError('INVALID_NAME')
            if type(data['enabled']) is not bool: raise ValueError('INVALID_ENABLED')
            quota = integer(data['quota_bytes']) if data['quota_bytes'] is not None else None
            expires = integer(data['expires_at'], 4102444800) if data['expires_at'] is not None else None
            if self.db.execute('SELECT count(*) FROM users').fetchone()[0] >= 256 and not data['id']: raise ValueError('USER_LIMIT')
            self.db.execute('INSERT OR REPLACE INTO users VALUES (?,?,?,?,?)', (user_id,data['name'].strip(),quota,expires,data['enabled']))
            self.audit(actor,'user.updated',user_id)
        elif operation == 'user.limit':
            if set(data) != {'user_id','device_limit'}: raise ValueError('INVALID_FIELDS')
            user_id = identifier(data['user_id']); maximum = integer(data['device_limit'], 32)
            if maximum < 1: raise ValueError('INVALID_DEVICE_LIMIT')
            if not self.db.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone(): raise ValueError('USER_NOT_FOUND')
            if self.device_count(user_id) > maximum: raise ValueError('REVOKE_DEVICES_BEFORE_LOWERING_LIMIT')
            self.db.execute('INSERT OR REPLACE INTO device_limits VALUES (?,?)', (user_id,maximum))
            self.audit(actor,operation,user_id)
        elif operation == 'peer.revoke':
            if set(data) != {'public_key'}: raise ValueError('INVALID_FIELDS')
            key = public_key(data['public_key'])
            if not self.db.execute('SELECT 1 FROM devices WHERE key=?', (key,)).fetchone(): raise ValueError('PEER_NOT_FOUND')
            # Keep the address tombstone and accounting history. Never free an old
            # address while an old wg configuration might still contain this key.
            self.db.execute('INSERT OR IGNORE INTO revoked_devices VALUES (?)', (key,))
            self.audit(actor,operation,hashlib.sha256(key.encode()).hexdigest()[:12])
        elif operation in ('peer.assign','peer.create'):
            expected = {'public_key','user_id','name'}
            if set(data) != expected: raise ValueError('INVALID_FIELDS')
            key = public_key(data['public_key']); user_id = identifier(data['user_id'])
            if not self.db.execute('SELECT 1 FROM users WHERE id=?',(user_id,)).fetchone(): raise ValueError('USER_NOT_FOUND')
            if not isinstance(data['name'],str) or not 1 <= len(data['name'].strip()) <= 80 or any(ord(c)<32 for c in data['name']): raise ValueError('INVALID_NAME')
            peer = self.observation['peers'].get(key)
            existing = self.db.execute('SELECT * FROM devices WHERE key=?',(key,)).fetchone()
            if self.revoked(key): raise ValueError('DEVICE_REVOKED')
            if (not existing or existing['user_id'] != user_id) and self.device_count(user_id) >= self.device_limit(user_id):
                raise ValueError('DEVICE_LIMIT_REACHED')
            if operation == 'peer.create':
                if len(self.observation['peers'])>=512: raise ValueError('PEER_LIMIT')
                if key == self.observation['server_public_key']: raise ValueError('CLIENT_PUBLIC_KEY_EQUALS_SERVER')
                if peer or existing: raise ValueError('PEER_ALREADY_EXISTS')
                occupied = [ipaddress.ip_network(a) for p in self.observation['peers'].values() for a in p['allowed_ips']]
                occupied.extend(ipaddress.ip_network(a) for row in self.db.execute('SELECT addresses FROM devices') for a in json.loads(row[0]))
                selected = None
                for value in self.observation['networks']:
                    interface = ipaddress.ip_interface(value)
                    if interface.version != 4 or not interface.is_private or not 16 <= interface.network.prefixlen <= 30: continue
                    for address in interface.network.hosts():
                        if address != interface.ip and not any(address in network for network in occupied if network.version==4):
                            selected = str(address)+'/32'; break
                    if selected: break
                if not selected: raise ValueError('NO_FREE_IPV4_TUNNEL_ADDRESS')
                addresses = [selected]
                self.driver.leases(set(host_ips(addresses)),set(),not self.budget_state()['guard_blocked'])
                # Durable ownership precedes the kernel mutation. If interrupted or the
                # netlink reply is lost, reconciliation retries only this owned peer.
                self.db.execute('INSERT INTO devices VALUES (?,?,?,?,1)',
                                (key,user_id,data['name'].strip(),json.dumps(addresses)))
                self.driver.add_peer(key, addresses)
            else:
                if not peer: raise ValueError('PEER_NOT_FOUND')
                host_ips(peer['allowed_ips']); addresses = peer['allowed_ips']
            self.db.execute('INSERT OR REPLACE INTO devices VALUES (?,?,?,?,?)',
                            (key,user_id,data['name'].strip(),json.dumps(addresses),int(operation=='peer.create' or bool(existing and existing['owned']))))
            self.audit(actor,operation,hashlib.sha256(key.encode()).hexdigest()[:12])
            self.tick()
        elif operation == 'budget.set':
            if set(data) != {'limit_bytes','reserve_bytes','guard_enabled','prior_usage_bytes','confirm_current_period'}: raise ValueError('INVALID_FIELDS')
            limit = integer(data['limit_bytes']); reserve = integer(data['reserve_bytes'])
            if not 0 < limit or reserve >= limit or type(data['guard_enabled']) is not bool or type(data['confirm_current_period']) is not bool: raise ValueError('INVALID_BUDGET')
            prior = integer(data['prior_usage_bytes']) if data['prior_usage_bytes'] is not None else None
            if prior is not None and not data['confirm_current_period']: raise ValueError('BASELINE_CONFIRMATION_REQUIRED')
            old = self.get('budget')
            value = {'limit_bytes':limit, 'reserve_bytes':reserve, 'guard_enabled':data['guard_enabled'],
                'prior_usage_bytes':prior, 'anchor_total':self.get('nic_total'), 'period':period(self.now()),
                'baseline_at':int(self.now()) if prior is not None else None, 'baseline_gaps':self.get('accounting_gaps')}
            if prior is None and not data['confirm_current_period']:
                for field in ('prior_usage_bytes','anchor_total','period','baseline_at','baseline_gaps'):
                    value[field] = old[field]
            if prior is None and data['confirm_current_period']: raise ValueError('BASELINE_VALUE_REQUIRED')
            self.set('budget',value)
            try: self.driver.initialize(value['guard_enabled']); self.enforce()
            except Exception:
                self.set('budget',old); self.driver.initialize(old['guard_enabled']); raise
            self.audit(actor,'budget.updated',period(self.now()))
        else: raise ValueError('UNKNOWN_OPERATION')
        self.enforce()
        return self.snapshot()


def main():
    if os.geteuid() != 0: raise SystemExit('Root service required')
    os.umask(0o077); STATE.mkdir(mode=0o700, exist_ok=True)
    engine = Engine(STATE/'ledger.sqlite3', Driver())
    allowed_uid = pwd.getpwnam('oracle-proxy-admin').pw_uid
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if Path(SOCKET).exists(): Path(SOCKET).unlink()
    server.bind(SOCKET); os.chmod(SOCKET,0o660); server.listen(16)
    notify = os.environ.get('NOTIFY_SOCKET')
    if notify:
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as ready:
            ready.connect('\0'+notify[1:] if notify.startswith('@') else notify)
            ready.sendall(b'READY=1')
    due = 0
    while True:
        if time.monotonic() >= due:
            try: engine.tick()
            except Exception: pass  # Kernel allow leases expire; no raw system output in journal.
            due = time.monotonic()+TICK
        readable, _, _ = select.select([server],[],[], max(0,due-time.monotonic()))
        if not readable: continue
        connection, _ = server.accept()
        with connection:
            connection.settimeout(3)
            _, uid, _ = struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if uid != allowed_uid: continue
            try:
                body = bytearray()
                while b'\n' not in body and len(body) <= 16384:
                    chunk = connection.recv(4096)
                    if not chunk: break
                    body.extend(chunk)
                if len(body)>16384 or not body.endswith(b'\n') or body.count(b'\n')!=1: raise ValueError('INVALID_FRAME')
                value = engine.dispatch(json.loads(body))
                result = {'ok':True,'data':value}
            except ValueError as error:
                code = str(error)
                result = {'ok':False,'error':code if re.fullmatch(r'[A-Z_]{1,80}',code) else 'INVALID_REQUEST'}
            except Exception: result = {'ok':False,'error':'CONTROL_UNAVAILABLE'}
            try: connection.sendall(json.dumps(result,separators=(',',':')).encode()+b'\n')
            except OSError: pass


if __name__ == '__main__': main()
