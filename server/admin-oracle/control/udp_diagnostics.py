"""Short-lived, account-bound diagnostic observations; no policy mutations."""
import importlib.util
from pathlib import Path
import time
import uuid

spec=importlib.util.spec_from_file_location('udp_capture',Path(__file__).with_name('udp_capture.py'))
capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)
TARGETS={(address,port) for address in capture.ADDRESSES for port in capture.PORTS}


def identifier(value):
    if not isinstance(value,str) or str(uuid.UUID(value))!=value:raise ValueError('INVALID_DIAGNOSTIC_ID')
    return value


class Manager:
    def __init__(self,clock=time.monotonic,factory=capture.Capture):
        self.clock=clock;self.factory=factory;self.sessions={}

    def expire(self):
        for key,row in list(self.sessions.items()):
            if self.clock()-row['created']>180:
                row['capture'].close();del self.sessions[key]

    def call(self,operation,data,peer):
        self.expire()
        identifier(data.get('diagnostic_id'))
        key=data['diagnostic_id']
        if operation=='udp-diagnostic.start':
            if set(data)!={'diagnostic_id','public_key'}:raise ValueError('INVALID_DIAGNOSTIC_FIELDS')
            if key in self.sessions:raise ValueError('DIAGNOSTIC_ALREADY_EXISTS')
            if len(self.sessions)>=3 or any(s['public_key']==data['public_key'] for s in self.sessions.values()):
                raise ValueError('DIAGNOSTIC_BUSY')
            self.sessions[key]={'public_key':data['public_key'],'created':self.clock(),'capture':self.factory(),'trials':[],'active':None}
            return {'diagnostic_id':key,'capture_status':'starting','expires_in_seconds':180}
        row=self.sessions.get(key)
        if row is None:raise ValueError('DIAGNOSTIC_EXPIRED_OR_RESTARTED')
        if row['public_key']!=data['public_key']:raise ValueError('DIAGNOSTIC_OWNER_MISMATCH')
        if operation=='udp-diagnostic.begin':
            if set(data)!={'diagnostic_id','public_key','address','port'}:raise ValueError('INVALID_DIAGNOSTIC_FIELDS')
            if (data['address'],data['port']) not in TARGETS or type(data['port'])!=int:raise ValueError('INVALID_DIAGNOSTIC_TARGET')
            if row['capture'].status=='starting' and not row['capture'].ready.wait(.75):
                raise ValueError('DIAGNOSTIC_CAPTURE_STARTING')
            if row['active'] is not None or len(row['trials'])>=6 or any(t['address']==data['address'] and t['port']==data['port'] for t in row['trials']):
                raise ValueError('DIAGNOSTIC_STEP_CONFLICT')
            trial={'address':data['address'],'port':data['port'],'since':self.clock(),'started_at':int(time.time()),
                   'indices':[],'before_handshake':peer['handshake'],'before_usage':dict(peer['usage'])}
            row['trials'].append(trial);row['active']=trial
            return {'trial':len(row['trials'])-1,'capture_status':row['capture'].status,'server_started_at':trial['started_at']}
        if operation=='udp-diagnostic.sample':
            if set(data)!={'diagnostic_id','public_key','sender_indices','complete'} or type(data['complete'])!=bool:
                raise ValueError('INVALID_DIAGNOSTIC_FIELDS')
            trial=row['active']
            if trial is None:raise ValueError('DIAGNOSTIC_NO_ACTIVE_STEP')
            indices=data['sender_indices']
            # Validate before storing; the capture layer does the same check.
            capture.summarize([],trial['address'],trial['port'],indices,trial['since'])
            trial['indices']=list(dict.fromkeys(trial['indices']+indices))[:16]
            trial['after_handshake']=peer['handshake'];trial['after_usage']=dict(peer['usage'])
            result=self.report(row,trial)
            if data['complete']:row['active']=None
            return result
        if operation=='udp-diagnostic.finish':
            if set(data)!={'diagnostic_id','public_key'}:raise ValueError('INVALID_DIAGNOSTIC_FIELDS')
            row['capture'].close()
            result={'diagnostic_id':key,'trials':[self.report(row,t) for t in row['trials']]}
            del self.sessions[key]
            return result
        raise ValueError('INVALID_DIAGNOSTIC_OPERATION')

    def report(self,row,trial):
        observed=row['capture'].report(trial['address'],trial['port'],trial['indices'],trial['since'])
        usage=trial.get('after_usage',trial['before_usage'])
        return {'address':trial['address'],'port':trial['port'],'server_started_at':trial['started_at'],
                'capture':observed,'index_correlation_available':bool(trial['indices']),
                'kernel_handshake_at':trial.get('after_handshake',trial['before_handshake']),
                'kernel_handshake_advanced':trial.get('after_handshake',0)>trial['before_handshake'],
                'peer_usage_delta':{k:max(0,usage[k]-trial['before_usage'][k]) for k in ('rx','tx')}}
