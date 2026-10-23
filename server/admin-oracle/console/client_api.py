"""Native-client API. No browser session, signup, admin identity or arbitrary RPC."""
import fcntl
from contextlib import contextmanager
import hashlib
import json
import re
import secrets
import uuid
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import transaction
from django.db.models import F
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .transports import quic_info
from . import control
from .models import Audit, ClientAccount, ClientSession, ClientLoginThrottle

# One cost-matched dummy hash prevents fast username enumeration.
DUMMY_PASSWORD = make_password(secrets.token_urlsafe(32))


def actor():
    return f'github:{next(iter(settings.ADMIN_GITHUB_IDS))}'


def response(data, status=200):
    result = JsonResponse(data, status=status)
    result['Cache-Control'] = 'no-store'
    return result


def native_only(request):
    # Bearer endpoints deliberately do not accept ambient browser credentials.
    return not request.META.get('HTTP_ORIGIN') and not request.META.get('HTTP_COOKIE')


def payload(request, fields):
    if request.content_type != 'application/json' or len(request.body) > 4096:
        raise ValueError('INVALID_REQUEST')
    value = json.loads(request.body)
    if not isinstance(value, dict) or set(value) != fields: raise ValueError('INVALID_REQUEST')
    return value


def throttle(username):
    now = timezone.now(); minute = int(now.timestamp()) // 60
    # Persistent, atomic counters shared by all Gunicorn workers. Do not rely
    # on a client-controlled IP header for password-guessing protection.
    with transaction.atomic():
        ClientLoginThrottle.objects.filter(expires_at__lt=now).delete()
        for key, maximum in [('global', 30), ('user:' + hashlib.sha256(username.encode()).hexdigest(), 5)]:
            bucket = f'{minute}:{key}'
            ClientLoginThrottle.objects.get_or_create(bucket=bucket, defaults={'expires_at':now+timedelta(minutes=2)})
            ClientLoginThrottle.objects.filter(bucket=bucket).update(attempts=F('attempts')+1)
            if ClientLoginThrottle.objects.get(bucket=bucket).attempts > maximum: return False
    return True


def client_state(snapshot, account, key):
    user = next((u for u in snapshot['users'] if u['id'] == str(account.user_id)), None)
    peer = next((p for p in snapshot['peers'] if p['public_key'] == key and p['user_id'] == str(account.user_id)), None)
    if not user or not peer or peer.get('revoked'): raise ValueError('DEVICE_REVOKED')
    used = user['usage']['rx'] + user['usage']['tx']
    stale = not snapshot['observed_at'] or timezone.now().timestamp()-snapshot['observed_at'] > 20
    status = ('unavailable' if snapshot['error'] or stale else 'server_budget' if snapshot['budget']['guard_blocked'] else user['status'])
    return {'schema':1, 'observed_at':snapshot['observed_at'], 'period':snapshot['period'],
            'account':{'username':account.username, 'status':status, 'used_bytes':used,
                       'limit_bytes':user['quota'], 'remaining_bytes':user['remaining_bytes'],
                       'expires_at':user['expires'], 'device_limit':user['device_limit'], 'device_count':user['device_count']},
            'device':{'public_key':key, 'handshake_at':peer['handshake'], 'usage':peer['usage']},
            'tunnel':{'endpoint':f"152.67.156.100:{snapshot['listen_port']}",
                      'server_public_key':snapshot['server_public_key'], 'addresses':peer['allowed_ips'],
                      'allowed_ips':['0.0.0.0/0'], 'dns':['1.1.1.1'], 'ipv6_policy':'block',
                      'native_udp_ports':[51820,443,8443] if snapshot['listen_port']==51820 else [snapshot['listen_port']],
                      'https_relay':snapshot['listen_port']==51820,
                      'quic':quic_info() if snapshot['listen_port']==51820 else None}}


@csrf_exempt
@require_POST
def login(request):
    if not native_only(request): return response({'error':'NATIVE_CLIENT_REQUIRED'},403)
    try:
        value = payload(request, {'username','password','public_key','device_name'})
        username, password = value['username'], value['password']
        if not isinstance(username,str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,63}',username): raise ValueError('INVALID_CREDENTIALS')
        if not isinstance(password,str) or not 1 <= len(password) <= 128: raise ValueError('INVALID_CREDENTIALS')
        if not throttle(username): return response({'error':'RATE_LIMITED'},429)
        account = ClientAccount.objects.filter(username=username).first()
        if not check_password(password, account.password if account else DUMMY_PASSWORD) or not account:
            return response({'error':'INVALID_CREDENTIALS'},401)
        key, name = value['public_key'], value['device_name']
        if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9+/]{43}=',key): raise ValueError('INVALID_PUBLIC_KEY')
        if not isinstance(name,str) or not 1 <= len(name.strip()) <= 80 or any(ord(c)<32 for c in name): raise ValueError('INVALID_NAME')
        snapshot = control.call('state',actor(),{})
        user = next((u for u in snapshot['users'] if u['id']==str(account.user_id)),None)
        if not user or user['status'] != 'active': return response({'error':'ACCOUNT_UNAVAILABLE'},403)
        peer = next((p for p in snapshot['peers'] if p['public_key']==key),None)
        if peer:
            if peer['user_id'] != str(account.user_id) or peer.get('revoked'): raise ValueError('DEVICE_REVOKED')
        else:
            # Root controller serializes cap check + durable registration; concurrent
            # logins from multiple web workers cannot exceed the device allowance.
            snapshot = control.call('peer.create',actor(),{'public_key':key,'user_id':str(account.user_id),'name':name.strip()})
            Audit.objects.create(actor=f'client:{account.user_id}',action='device.enroll',resource=hashlib.sha256(key.encode()).hexdigest()[:12])
        data = client_state(snapshot,account,key)
        token = secrets.token_urlsafe(32); expiry = timezone.now()+timedelta(days=30)
        with transaction.atomic():
            # Lock the credential version logically as well as the DB transaction:
            # a password reset racing an in-flight login cannot revive old access.
            current = ClientAccount.objects.filter(user_id=account.user_id).first()
            if current is None: raise ValueError('INVALID_CREDENTIALS')
            if current.password != account.password: raise ValueError('INVALID_CREDENTIALS')
            ClientSession.objects.filter(account=account,public_key=key).delete()
            ClientSession.objects.filter(expires_at__lte=timezone.now()).delete()
            ClientSession.objects.create(account=account,public_key=key,token_hash=hashlib.sha256(token.encode()).hexdigest(),expires_at=expiry)
        data.update(token=token,token_expires_at=int(expiry.timestamp()))
        return response(data)
    except (ValueError,TypeError,KeyError) as error:
        code = str(error)
        return response({'error':code if re.fullmatch(r'[A-Z_]{1,80}',code) else 'INVALID_REQUEST'},400)
    except (OSError,TimeoutError): return response({'error':'CONTROL_SERVICE_UNAVAILABLE'},503)


def session(request):
    if not native_only(request): return None
    authorization = request.META.get('HTTP_AUTHORIZATION','')
    if not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}',authorization): return None
    return ClientSession.objects.select_related('account').filter(
        token_hash=hashlib.sha256(authorization[7:].encode()).hexdigest(),expires_at__gt=timezone.now()).first()


@require_GET
def state(request):
    credential = session(request)
    if not credential: return response({'error':'LOGIN_REQUIRED'},401)
    try:
        return response(client_state(control.call('state',actor(),{}),credential.account,credential.public_key))
    except ValueError: return response({'error':'DEVICE_REVOKED'},403)
    except (OSError,TimeoutError,KeyError): return response({'error':'CONTROL_SERVICE_UNAVAILABLE'},503)


@csrf_exempt
@require_POST
def logout(request):
    credential = session(request)
    if not credential: return response({'error':'LOGIN_REQUIRED'},401)
    credential.delete()
    return response({'ok':True})


def set_account(request, value):
    """Called only after the existing administrator GitHub + MFA + CSRF gate."""
    if set(value) != {'user_id','username','password','device_limit'}: raise ValueError('INVALID_FIELDS')
    user_id = str(uuid.UUID(value['user_id'])); username=value['username']; password=value['password']
    if not isinstance(username,str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,63}',username): raise ValueError('INVALID_USERNAME')
    if not isinstance(password,str) or not 12 <= len(password) <= 128: raise ValueError('PASSWORD_LENGTH_12_TO_128_REQUIRED')
    if ClientAccount.objects.filter(username=username).exclude(user_id=user_id).exists(): raise ValueError('USERNAME_ALREADY_EXISTS')
    encoded = make_password(password)
    snapshot = control.call('user.limit',actor(),{'user_id':user_id,'device_limit':value['device_limit']})
    with transaction.atomic():
        account,_ = ClientAccount.objects.update_or_create(user_id=user_id, defaults={'username':username,'password':encoded})
        ClientSession.objects.filter(account=account).delete()
    Audit.objects.create(actor=actor(),action='account.credentials.reset',resource=user_id)
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
        staged = control.call('user.save',actor(),{**policy,'enabled':False})
        user_id = staged['saved_user_id']; policy['id'] = user_id
        with transaction.atomic():
            current,_ = ClientAccount.objects.update_or_create(user_id=user_id,defaults={'username':username,'password':encoded})
            if password or (account and account.username != username):
                ClientSession.objects.filter(account=current).delete()
            Audit.objects.create(actor=actor(),action='account.saved',resource=user_id)
        return control.call('user.save',actor(),policy)


def delete_account(request, value):
    if set(value) != {'user_id'}: raise ValueError('INVALID_FIELDS')
    if not isinstance(value['user_id'],str): raise ValueError('INVALID_USER_ID')
    user_id = str(uuid.UUID(value['user_id']))
    with management_lock():
        # Root tombstones/revokes every device before deleting bearer credentials.
        # Retrying is idempotent if the web database write was interrupted.
        snapshot = control.call('user.delete',actor(),{'user_id':user_id})
        with transaction.atomic():
            ClientAccount.objects.filter(user_id=user_id).delete()
            Audit.objects.create(actor=actor(),action='account.deleted',resource=user_id)
        return snapshot
