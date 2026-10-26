"""Bearer-only native accounts; explicit, session-bound device confirmation."""
import base64
import fcntl
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import re
import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction, DatabaseError
from django.db.models import F
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .transports import quic_info, transport_address, ipv6_info
from . import control
from .models import Audit, ClientAccount, ClientSession, ClientLoginThrottle

DUMMY_PASSWORD = make_password(secrets.token_urlsafe(32))


def actor(request=None):
    if settings.ADMIN_AUTH_MODE == 'local':
        if request is not None and getattr(request,'user',None) is not None and request.user.is_authenticated:
            from .views import audit_actor
            return audit_actor(request)
        return 'system:client-api'
    return f'github:{next(iter(settings.ADMIN_GITHUB_IDS))}'


def response(data, status=200):
    result=JsonResponse(data,status=status);result['Cache-Control']='no-store';return result


def native_only(request):
    return not request.META.get('HTTP_ORIGIN') and not request.META.get('HTTP_COOKIE')


def payload(request, fields):
    if request.content_type!='application/json' or len(request.body)>4096:raise ValueError('INVALID_REQUEST')
    value=json.loads(request.body)
    if not isinstance(value,dict) or set(value)!=fields:raise ValueError('INVALID_REQUEST')
    return value


def failed(error):
    code=str(error)
    return response({'error':code if re.fullmatch(r'[A-Z_]{1,80}',code) else 'INVALID_REQUEST'},400)


def valid_name(value):
    if not isinstance(value,str) or not 1<=len(value.strip())<=80 or any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError('INVALID_NAME')
    return value.strip()


def throttle(username):
    now=timezone.now();minute=int(now.timestamp())//60
    with transaction.atomic():
        ClientLoginThrottle.objects.filter(expires_at__lt=now).delete()
        for key,maximum in [('global',30),('user:'+hashlib.sha256(username.encode()).hexdigest(),5)]:
            bucket=f'{minute}:{key}'
            ClientLoginThrottle.objects.get_or_create(bucket=bucket,defaults={'expires_at':now+timedelta(minutes=2)})
            ClientLoginThrottle.objects.filter(bucket=bucket).update(attempts=F('attempts')+1)
            if ClientLoginThrottle.objects.get(bucket=bucket).attempts>maximum:return False
    return True


def fingerprint(key):return hashlib.sha256(key.encode()).hexdigest()[:12]


def confirmed(peer):
    receipt=peer.get('enrollment') if peer else None
    return isinstance(receipt,dict) and type(receipt.get('confirmed_at')) is int and receipt['confirmed_at']>0


def client_state(snapshot,account,key,allow_legacy=False,proposed_name='',dual_stack=False):
    if key in snapshot.get('deleted_public_keys',[]):raise ValueError('DEVICE_REVOKED')
    user=next((u for u in snapshot['users'] if u['id']==str(account.user_id)),None)
    peer=next((p for p in snapshot['peers'] if p['public_key']==key),None)
    if not user:raise ValueError('ACCOUNT_UNAVAILABLE')
    if peer and (peer['user_id']!=str(account.user_id) or peer.get('revoked')):raise ValueError('DEVICE_REVOKED')
    receipt=peer.get('enrollment') if peer else None
    is_confirmed=confirmed(peer);registered=bool(peer and (is_confirmed or allow_legacy))
    used=user['usage']['rx']+user['usage']['tx']
    stale=not snapshot['observed_at'] or timezone.now().timestamp()-snapshot['observed_at']>20
    status='unavailable' if snapshot['error'] or stale else 'server_budget' if snapshot['budget']['guard_blocked'] else user['status']
    owned=[p for p in snapshot['peers'] if p['user_id']==str(account.user_id)]
    active=[p for p in owned if not p.get('revoked')]
    retired=sorted((p for p in owned if p.get('revoked')),key=lambda p:(p.get('enrollment') or {}).get('confirmed_at',0),reverse=True)
    devices=[{'id':fingerprint(p['public_key']),'name':p['name'],'current':p['public_key']==key,'revoked':p['revoked'],'confirmed_at':(p.get('enrollment') or {}).get('confirmed_at')} for p in active+retired[:8]]
    data={'schema':1,'observed_at':snapshot['observed_at'],'period':snapshot['period'],
        'account':{'username':account.username,'status':status,'used_bytes':used,'limit_bytes':user['quota'],'remaining_bytes':user['remaining_bytes'],'expires_at':user['expires'],'device_limit':user['device_limit'],'device_count':user['device_count']},
        'registration':{'status':'registered' if is_confirmed else 'legacy' if peer else 'pending','device_id':fingerprint(key),'device_name':peer['name'] if peer else proposed_name,'confirmed_at':receipt['confirmed_at'] if is_confirmed else None,'requires_confirmation':not is_confirmed,'requires_slot':not bool(peer)},
        'devices':devices,'devices_history_truncated':len(retired)>8,
        'device':{'public_key':key,'registered':registered,'handshake_at':peer['handshake'] if peer else 0,'usage':peer['usage'] if peer else {'rx':0,'tx':0}},'tunnel':None}
    if registered:
        ipv6 = ipv6_info() if dual_stack else None
        dual = bool(ipv6 and any(ipaddress.ip_interface(a).version == 6 and ipaddress.ip_interface(a).ip in ipaddress.ip_network(ipv6['prefix']) for a in peer['allowed_ips']))
        addresses = [a for a in peer['allowed_ips'] if dual or ipaddress.ip_interface(a).version == 4]
        data['tunnel']={'transport_address':transport_address(),'endpoint':f"152.67.156.100:{snapshot['listen_port']}",'server_public_key':snapshot['server_public_key'],'addresses':addresses,'allowed_ips':['0.0.0.0/0','::/0'] if dual else ['0.0.0.0/0'],'dns':['1.1.1.1'],'ipv6_policy':'tunnel' if dual else 'block','ipv6_egress':ipv6['egress'] if dual else None,'native_udp_ports':[51820,443,8443] if snapshot['listen_port']==51820 else [snapshot['listen_port']],'https_relay':snapshot['listen_port']==51820,'quic':quic_info() if snapshot['listen_port']==51820 else None}
    return data


def credentials(value):
    username,password=value['username'],value['password']
    if not isinstance(username,str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,63}',username):raise ValueError('INVALID_CREDENTIALS')
    if not isinstance(password,str) or not 1<=len(password)<=128:raise ValueError('INVALID_CREDENTIALS')
    if not throttle(username):return None,response({'error':'RATE_LIMITED'},429)
    account=ClientAccount.objects.filter(username=username).first()
    if not check_password(password,account.password if account else DUMMY_PASSWORD) or not account:return None,response({'error':'INVALID_CREDENTIALS'},401)
    key=value['public_key']
    if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9+/]{43}=',key):raise ValueError('INVALID_PUBLIC_KEY')
    raw=base64.b64decode(key,validate=True)
    if len(raw)!=32 or not any(raw) or base64.b64encode(raw).decode()!=key:raise ValueError('INVALID_PUBLIC_KEY')
    valid_name(value['device_name'])
    return account,None


def issue_session(request,value,explicit):
    account,rejected=credentials(value)
    if rejected is not None:return rejected
    key=value['public_key'];name=valid_name(value['device_name'])
    version=value.get('client_version','')
    if explicit and (not isinstance(version,str) or not re.fullmatch(r'[A-Za-z0-9.+-]{1,100}',version)):raise ValueError('INVALID_CLIENT_VERSION')
    with management_lock():
        current=ClientAccount.objects.filter(user_id=account.user_id).first()
        if not current or current.password!=account.password or current.username!=account.username:raise ValueError('INVALID_CREDENTIALS')
        snapshot=control.call('state',actor(request),{})
        peer=next((p for p in snapshot['peers'] if p['public_key']==key),None)
        if not explicit and not confirmed(peer):return response({'error':'CLIENT_UPDATE_REQUIRED'},409)
        data=client_state(snapshot,current,key,proposed_name=name,dual_stack=request.META.get('HTTP_X_ORACLE_CLIENT_CAPABILITIES')=='dual-stack-v1')
        token=secrets.token_urlsafe(32);now=timezone.now()
        expiry=now+timedelta(days=30) if data['device']['registered'] else now+timedelta(minutes=15)
        with transaction.atomic():
            ClientSession.objects.filter(expires_at__lte=now).delete()
            if ClientSession.objects.filter(account=current,enrollment_flow=True,reported_mode='pending').exclude(public_key=key).count()>=32:raise ValueError('PENDING_SESSION_LIMIT')
            ClientSession.objects.filter(account=current,public_key=key).delete()
            ClientSession.objects.create(account=current,public_key=key,token_hash=hashlib.sha256(token.encode()).hexdigest(),expires_at=expiry,enrollment_flow=explicit,proposed_name=name,client_version=version,last_seen_at=now,reported_mode='disconnected' if data['device']['registered'] else 'pending')
            Audit.objects.create(actor=f'client:{current.user_id}',action='device.login' if data['device']['registered'] else 'device.confirmation.requested',resource=fingerprint(key))
        data.update(token=token,token_expires_at=int(expiry.timestamp()));return response(data)


@csrf_exempt
@require_POST
def authenticate(request):
    if not native_only(request):return response({'error':'NATIVE_CLIENT_REQUIRED'},403)
    try:return issue_session(request,payload(request,{'username','password','public_key','device_name','client_version'}),True)
    except (ValueError,TypeError,KeyError) as error:return failed(error)
    except (OSError,TimeoutError,DatabaseError):return response({'error':'CONTROL_SERVICE_UNAVAILABLE'},503)


@csrf_exempt
@require_POST
def login(request):
    """Compatibility only: never creates a Peer or bypasses confirmation."""
    if not native_only(request):return response({'error':'NATIVE_CLIENT_REQUIRED'},403)
    try:return issue_session(request,payload(request,{'username','password','public_key','device_name'}),False)
    except (ValueError,TypeError,KeyError) as error:return failed(error)
    except (OSError,TimeoutError,DatabaseError):return response({'error':'CONTROL_SERVICE_UNAVAILABLE'},503)


def session(request):
    if not native_only(request):return None
    authorization=request.META.get('HTTP_AUTHORIZATION','')
    if not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}',authorization):return None
    return ClientSession.objects.select_related('account').filter(token_hash=hashlib.sha256(authorization[7:].encode()).hexdigest(),expires_at__gt=timezone.now()).first()


def state_for(credential,snapshot,dual_stack=False):
    return client_state(snapshot,credential.account,credential.public_key,allow_legacy=not credential.enrollment_flow,proposed_name=credential.proposed_name,dual_stack=dual_stack)


@require_GET
def state(request):
    credential=session(request)
    if not credential:return response({'error':'LOGIN_REQUIRED'},401)
    try:
        result=state_for(credential,control.call('state',actor(request),{}),request.META.get('HTTP_X_ORACLE_CLIENT_CAPABILITIES')=='dual-stack-v1')
        ClientSession.objects.filter(pk=credential.pk).update(last_seen_at=timezone.now())
        return response(result)
    except ValueError as error:return failed(error)
    except (OSError,TimeoutError,KeyError,DatabaseError):return response({'error':'CONTROL_SERVICE_UNAVAILABLE'},503)


@csrf_exempt
@require_POST
def enroll(request):
    credential=session(request)
    if not credential:return response({'error':'LOGIN_REQUIRED'},401)
    try:
        value=payload(request,{'device_name','confirm'})
        if value['confirm'] is not True:raise ValueError('DEVICE_CONFIRMATION_REQUIRED')
        name=valid_name(value['device_name'])
        with management_lock():
            credential=session(request)
            if not credential:return response({'error':'LOGIN_REQUIRED'},401)
            # Sessions created before this flow have no version/name metadata.
            version=credential.client_version or 'legacy-upgrade'
            machine=credential.proposed_name or name
            Audit.objects.create(actor=f'client:{credential.account.user_id}',action='device.confirmation.submitted',resource=fingerprint(credential.public_key))
            snapshot=control.call('peer.enroll',actor(request),{'public_key':credential.public_key,'user_id':str(credential.account.user_id),'name':name,'machine_name':machine,'client_version':version,'confirm':True})
            result=client_state(snapshot,credential.account,credential.public_key,dual_stack=request.META.get('HTTP_X_ORACLE_CLIENT_CAPABILITIES')=='dual-stack-v1')
            if result['registration']['status']!='registered':raise ValueError('DEVICE_CONFIRMATION_REQUIRED')
            ClientSession.objects.filter(pk=credential.pk).update(enrollment_flow=True,expires_at=timezone.now()+timedelta(days=30),last_seen_at=timezone.now(),reported_mode='disconnected')
            return response(result)
    except (ValueError,TypeError,KeyError) as error:return failed(error)
    except (OSError,TimeoutError,DatabaseError):return response({'error':'CONTROL_SERVICE_UNAVAILABLE'},503)


@csrf_exempt
@require_POST
def presence(request):
    credential=session(request)
    if not credential:return response({'error':'LOGIN_REQUIRED'},401)
    try:
        value=payload(request,{'mode','transport'})
        if value['mode'] not in ('unknown','pending','disconnected','protected','connected','recovery'):raise ValueError('INVALID_CLIENT_STATUS')
        if value['transport'] not in (None,'wireguard-udp','wireguard-quic','wireguard-https'):raise ValueError('INVALID_CLIENT_STATUS')
        result=state_for(credential,control.call('state',actor(request),{}),request.META.get('HTTP_X_ORACLE_CLIENT_CAPABILITIES')=='dual-stack-v1')
        mode=value['mode'] if result['registration']['status']=='registered' else 'pending'
        transport=value['transport'] if mode=='connected' else ''
        changed=ClientSession.objects.filter(pk=credential.pk).exclude(reported_mode=mode).update(reported_mode=mode)
        if changed and mode in ('connected','disconnected','protected','recovery'):
            Audit.objects.create(actor=f'client:{credential.account.user_id}',action='client.reported.'+mode,resource=fingerprint(credential.public_key))
        ClientSession.objects.filter(pk=credential.pk).update(last_seen_at=timezone.now(),reported_transport=transport or '')
        return response(result)
    except (ValueError,TypeError,KeyError) as error:return failed(error)
    except (OSError,TimeoutError,DatabaseError):return response({'error':'CONTROL_SERVICE_UNAVAILABLE'},503)


@csrf_exempt
@require_POST
def logout(request):
    credential=session(request)
    if not credential:return response({'error':'LOGIN_REQUIRED'},401)
    Audit.objects.create(actor=f'client:{credential.account.user_id}',action='device.logout',resource=fingerprint(credential.public_key))
    credential.delete();return response({'ok':True})


def annotate_devices(snapshot):
    """Administrator-only view. Presence is advisory, never policy authority."""
    now=timezone.now();peers={p['public_key']:p for p in snapshot.get('peers',[])}
    sessions={row.public_key:row for row in ClientSession.objects.select_related('account').filter(expires_at__gt=now)}
    for peer in snapshot.get('peers',[]):
        row=sessions.get(peer['public_key'])
        if row is not None and str(row.account.user_id)!=peer['user_id']:row=None
        age=(now-row.last_seen_at).total_seconds() if row and row.last_seen_at else None
        peer['client_status']={'last_seen_at':int(row.last_seen_at.timestamp()) if row and row.last_seen_at else None,'online':age is not None and 0<=age<=30,'reported_mode':row.reported_mode if row else 'unknown','transport':row.reported_transport if row else ''}
    users={u['id'] for u in snapshot.get('users',[])}
    snapshot['pending_devices']=[{'id':fingerprint(row.public_key),'public_key':row.public_key,'name':row.proposed_name,'user_id':str(row.account.user_id),'created_at':int(row.created_at.timestamp()),'last_seen_at':int(row.last_seen_at.timestamp()) if row.last_seen_at else None} for row in sessions.values() if row.enrollment_flow and row.public_key not in peers and row.public_key not in snapshot.get('deleted_public_keys',[]) and str(row.account.user_id) in users]
    return snapshot


def set_account(request, value):
    """Called only after the existing administrator GitHub + MFA + CSRF gate."""
    if set(value) != {'user_id','username','password','device_limit'}: raise ValueError('INVALID_FIELDS')
    user_id = str(uuid.UUID(value['user_id'])); username=value['username']; password=value['password']
    if not isinstance(username,str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,63}',username): raise ValueError('INVALID_USERNAME')
    if not isinstance(password,str) or not 12 <= len(password) <= 128: raise ValueError('PASSWORD_LENGTH_12_TO_128_REQUIRED')
    if ClientAccount.objects.filter(username=username).exclude(user_id=user_id).exists(): raise ValueError('USERNAME_ALREADY_EXISTS')
    encoded = make_password(password)
    snapshot = control.call('user.limit',actor(request),{'user_id':user_id,'device_limit':value['device_limit']})
    with transaction.atomic():
        account,_ = ClientAccount.objects.update_or_create(user_id=user_id, defaults={'username':username,'password':encoded})
        ClientSession.objects.filter(account=account).delete()
    Audit.objects.create(actor=actor(request),action='account.credentials.reset',resource=user_id)
    return snapshot


@contextmanager
def management_lock():
    # Serialize multi-worker credential/ledger transitions; lock contains no secret.
    settings.STATE_DIR.mkdir(parents=True, exist_ok=True)
    with (settings.STATE_DIR/'account-management.lock').open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def save_account(request, value):
    fields = {'id','name','username','password','device_limit','quota_bytes','expires_at','enabled'}
    if set(value) != fields: raise ValueError('INVALID_FIELDS')
    username, password = value['username'], value['password']
    if not isinstance(username,str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,63}',username): raise ValueError('INVALID_USERNAME')
    if not isinstance(password,str) or (password and not 12 <= len(password) <= 128): raise ValueError('PASSWORD_LENGTH_12_TO_128_REQUIRED')
    with management_lock():
        if value['id'] is not None and not isinstance(value['id'],str): raise ValueError('INVALID_USER_ID')
        user_id = str(uuid.UUID(value['id'])) if value['id'] else None
        account = ClientAccount.objects.filter(user_id=user_id).first() if user_id else None
        if not account and not password: raise ValueError('PASSWORD_LENGTH_12_TO_128_REQUIRED')
        if ClientAccount.objects.filter(username=username).exclude(user_id=user_id).exists(): raise ValueError('USERNAME_ALREADY_EXISTS')
        encoded = make_password(password) if password else account.password
        policy = {k:value[k] for k in ('id','name','device_limit','quota_bytes','expires_at','enabled')}
        # Across the separate root and web databases, stage access disabled first.
        # A partial write leaves the account blocked, never with mismatched access.
        staged = control.call('user.save',actor(request),{**policy,'enabled':False})
        user_id = staged['saved_user_id']; policy['id'] = user_id
        with transaction.atomic():
            current,_ = ClientAccount.objects.update_or_create(user_id=user_id,defaults={'username':username,'password':encoded})
            if password or (account and account.username != username):
                ClientSession.objects.filter(account=current).delete()
            Audit.objects.create(actor=actor(request),action='account.saved',resource=user_id)
        return control.call('user.save',actor(request),policy)


def delete_account(request, value):
    if set(value) != {'user_id'}: raise ValueError('INVALID_FIELDS')
    if not isinstance(value['user_id'],str): raise ValueError('INVALID_USER_ID')
    user_id = str(uuid.UUID(value['user_id']))
    with management_lock():
        # Root tombstones/revokes every device before deleting bearer credentials.
        # Retrying is idempotent if the web database write was interrupted.
        snapshot = control.call('user.delete',actor(request),{'user_id':user_id})
        with transaction.atomic():
            ClientAccount.objects.filter(user_id=user_id).delete()
            Audit.objects.create(actor=actor(request),action='account.deleted',resource=user_id)
        return snapshot


def delete_device(request,value):
    if set(value)!={'public_key'}:raise ValueError('INVALID_FIELDS')
    key=value['public_key']
    with management_lock():
        snapshot=control.call('peer.delete',actor(request),{'public_key':key})
        with transaction.atomic():
            ClientSession.objects.filter(public_key=key).delete()
            Audit.objects.create(actor=actor(request),action='device.deleted',resource=fingerprint(key))
        return snapshot
