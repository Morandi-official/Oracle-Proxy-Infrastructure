"""Administrator-issued, independently revocable WireGuard-only Mihomo profiles."""
import base64
import hashlib
import ipaddress
import json
import secrets
import uuid
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from django.conf import settings
from django.db import DatabaseError
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST
from . import client_api, control
from .models import Audit, ClientAccount, FlClashProfile
from .transports import transport_address, ipv6_info


def cipher():
    # Domain separation; existing SECRET_KEY backup/rotation policy also protects
    # profiles. Neither private key nor bearer URL is kept in the policy ledger.
    key=hashlib.sha256(('proxy/flclash/profile/v1\0'+settings.SECRET_KEY).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def summary(row):
    return {'id':str(row.pk),'user_id':str(row.account_id),'name':row.name,
            'device_id':client_api.fingerprint(row.public_key),'status':row.phase,
            'created_at':int(row.created_at.timestamp()),'last_used_at':int(row.last_used_at.timestamp()) if row.last_used_at else None}


def purge_revoked(state):
    """Erase profile material only after an authoritative revocation/deletion."""
    revoked=set(state.get('deleted_public_keys',[]))|{p['public_key'] for p in state.get('peers',[]) if p.get('revoked')}
    FlClashProfile.objects.filter(phase='revoked').delete()
    if revoked:FlClashProfile.objects.filter(public_key__in=revoked).delete()


def observe_usage(state):
    """A handshake proves key use, never physical-device identity."""
    from datetime import datetime, timezone as utc
    purge_revoked(state)
    now=timezone.now().timestamp()
    peers={p['public_key']:p for p in state.get('peers',[])}
    rows=FlClashProfile.objects.exclude(phase='revoked')
    for row in rows:
        peer=peers.get(row.public_key)
        if not peer or peer.get('user_id')!=str(row.account_id):continue
        handshake=peer.get('handshake')
        if type(handshake) is int and 0<handshake<=now+5 and (not row.last_used_at or handshake>row.last_used_at.timestamp()):
            row.last_used_at=datetime.fromtimestamp(handshake,utc.utc);row.save(update_fields=['last_used_at'])
        peer['client_kind']='flclash'
        peer['flclash_used']=bool(row.last_used_at)
        peer['flclash_last_used_at']=int(row.last_used_at.timestamp()) if row.last_used_at else None


def available_user(state,user_id):
    at=state.get('observed_at',0);now=timezone.now().timestamp()
    if state.get('error') or not at or not 0<=now-at<=20:raise ValueError('CONTROL_SERVICE_UNAVAILABLE')
    user=next((u for u in state['users'] if u['id']==str(user_id)),None)
    if not user or user['status']!='active':raise ValueError('ACCOUNT_UNAVAILABLE')
    if state['budget']['guard_blocked']:raise ValueError('SERVER_BUDGET_BLOCKED')
    if user['device_count']>=user['device_limit']:raise ValueError('DEVICE_LIMIT_REACHED')
    return user


def active_state(row, actor):
    state=control.call('state',actor,{})
    peer=next((p for p in state['peers'] if p['public_key']==row.public_key and p['user_id']==str(row.account_id)),None)
    user=next((u for u in state['users'] if u['id']==str(row.account_id)),None)
    now=timezone.now().timestamp();at=state.get('observed_at',0)
    if (row.phase!='active' or not peer or peer.get('revoked') or not user or
        user['status']!='active' or state.get('error') or not at or not 0<=now-at<=20 or
        state['budget']['guard_blocked']):raise ValueError('PROFILE_UNAVAILABLE')
    return state,peer


def material(row):
    try:return json.loads(cipher().decrypt(row.encrypted_material.encode()))
    except (InvalidToken,ValueError,UnicodeError):raise ValueError('PROFILE_KEY_UNAVAILABLE') from None


def configuration(row,state,peer,private_key):
    v4=next(str(ipaddress.ip_interface(a).ip) for a in peer['allowed_ips'] if ipaddress.ip_interface(a).version==4)
    v6info=ipv6_info()
    v6=next((str(ipaddress.ip_interface(a).ip) for a in peer['allowed_ips'] if ipaddress.ip_interface(a).version==6 and v6info and ipaddress.ip_interface(a).ip in ipaddress.ip_network(v6info['prefix'])),None)
    node={'name':'Proxy UDP','type':'wireguard','server':transport_address(),'port':443,
          'ip':v4,'private-key':private_key,'public-key':state['server_public_key'],
          'udp':True,'mtu':1280,'persistent-keepalive':25,'remote-dns-resolve':True,
          'dns':['https://1.1.1.1/dns-query'],'allowed-ips':['0.0.0.0/0']+(['::/0'] if v6 else [])}
    if v6:node['ipv6']=v6
    # JSON is a strict YAML subset accepted by Mihomo and FlClash. A single
    # outbound and MATCH policy: no DIRECT, selectors, providers or fallback.
    # Resolver packets use the same WireGuard outbound; numeric endpoint avoids
    # a bootstrap DNS lookup. FlClash owns enabling its OS TUN / kill switch.
    return {'mixed-port':7890,'allow-lan':False,'bind-address':'127.0.0.1',
            'tun':{'enable':True,'stack':'mixed','auto-route':True,'strict-route':True,'auto-detect-interface':True,'dns-hijack':['any:53','tcp://any:53']},
            'mode':'rule','log-level':'warning','ipv6':bool(v6),
            'dns':{'enable':True,'ipv6':bool(v6),'enhanced-mode':'fake-ip',
                   'respect-rules':True,'nameserver':['https://1.1.1.1/dns-query'],
                   'proxy-server-nameserver':['https://1.1.1.1/dns-query']},
            'proxies':[node],'proxy-groups':[], 'rules':['MATCH,Proxy UDP']}


@require_GET
def profiles(request):
    from .views import deny
    rejected=deny(request)
    if rejected is not None:return rejected
    try:
        state=control.call('state','system:health',{});observe_usage(state)
        rows=[]
        for row in FlClashProfile.objects.select_related('account').order_by('-created_at')[:2048]:
            item=summary(row)
            peer=next((p for p in state['peers'] if p['public_key']==row.public_key and p['user_id']==str(row.account_id)),None)
            user=next((u for u in state['users'] if u['id']==str(row.account_id)),None)
            if item['status']=='active' and (not peer or peer.get('revoked')):item['status']='revoked'
            elif item['status']=='active' and (not user or user['status']!='active' or state.get('error') or state['budget']['guard_blocked'] or not 0<=timezone.now().timestamp()-state.get('observed_at',0)<=20):item['status']='blocked'
            rows.append(item)
        return JsonResponse({'profiles':rows})
    except (OSError,TimeoutError,ValueError,DatabaseError):return JsonResponse({'error':'CONTROL_SERVICE_UNAVAILABLE'},status=503)


@require_POST
def create(request):
    from .views import deny,audit_actor
    rejected=deny(request)
    if rejected is not None:return rejected
    try:
        # Accept the previous admin form during rolling deployment. New form
        # has no device-name / confirmation / separate enrollment step.
        value=json.loads(request.body) if request.content_type=='application/json' and len(request.body)<=4096 else None
        if not isinstance(value,dict) or set(value) not in ({'user_id'},{'user_id','name','confirm'}):raise ValueError('INVALID_REQUEST')
        if 'confirm' in value and value['confirm'] is not True:raise ValueError('DEVICE_CONFIRMATION_REQUIRED')
        with client_api.management_lock():
            account=ClientAccount.objects.get(user_id=uuid.UUID(value['user_id']))
            state=control.call('state',audit_actor(request),{})
            available_user(state,account.user_id)
            if FlClashProfile.objects.filter(account=account).exclude(phase='revoked').count()>=32:raise ValueError('DEVICE_LIMIT_REACHED')
            ordinal=FlClashProfile.objects.filter(account=account).count()+1
            name=f'{account.username[:48]}的第{ordinal}个FlClash设备'
            key=X25519PrivateKey.generate()
            private=base64.b64encode(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode()
            public=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
            token=secrets.token_urlsafe(32)
            row=FlClashProfile.objects.create(account=account,name=name,public_key=public,
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                encrypted_material=cipher().encrypt(json.dumps({'private_key':private,'token':token}).encode()).decode())
            # Persist pending first: if RPC/response is interrupted, the exact
            # public key remains visible and revocable. Never allocate on GET.
            try:
                control.call('peer.enroll',audit_actor(request),{'public_key':public,'user_id':str(account.user_id),'name':name,'machine_name':name,'client_version':'FlClash-UDP-v1','confirm':True})
            except ValueError as error:
                # Explicit quota/account rejection occurs before binding in
                # the root engine. Unknown I/O outcomes remain revocable.
                if str(error) in ('DEVICE_LIMIT_REACHED','ACCOUNT_UNAVAILABLE','SERVER_BUDGET_BLOCKED'):row.delete()
                raise
            row.phase='active';row.save(update_fields=['phase'])
            Audit.objects.create(actor=audit_actor(request),action='flclash.created',resource=client_api.fingerprint(public))
            return JsonResponse({'profile':summary(row)},status=201)
    except ClientAccount.DoesNotExist:return JsonResponse({'error':'ACCOUNT_UNAVAILABLE'},status=400)
    except (ValueError,TypeError,KeyError,AttributeError) as error:
        code=str(error)
        return JsonResponse({'error':code if code in ('DEVICE_LIMIT_REACHED','ACCOUNT_UNAVAILABLE','SERVER_BUDGET_BLOCKED','DEVICE_CONFIRMATION_REQUIRED','CONTROL_SERVICE_UNAVAILABLE') else 'PROFILE_CREATE_REJECTED'},status=400)
    except (OSError,TimeoutError,DatabaseError):return JsonResponse({'error':'CONTROL_SERVICE_UNAVAILABLE'},status=503)


@require_POST
def action(request,profile_id):
    from .views import deny,audit_actor
    rejected=deny(request)
    if rejected is not None:return rejected
    try:
        value=client_api.payload(request,{'action'})
        with client_api.management_lock():
            row=FlClashProfile.objects.select_related('account').get(pk=profile_id)
            if value['action']=='revoke':
                state=control.call('state',audit_actor(request),{})
                if any(p['public_key']==row.public_key for p in state['peers']):
                    control.call('peer.delete',audit_actor(request),{'public_key':row.public_key})
                row.delete()
                Audit.objects.create(actor=audit_actor(request),action='flclash.revoked',resource=client_api.fingerprint(row.public_key))
                return JsonResponse({'deleted':True})
            if value['action']!='link':raise ValueError('INVALID_ACTION')
            active_state(row,audit_actor(request));secret=material(row)
            link=request.build_absolute_uri(f'/api/flclash/import/{row.pk}/{secret["token"]}/profile.yaml')
            return JsonResponse({'url':link})
    except FlClashProfile.DoesNotExist:return JsonResponse({'error':'PROFILE_NOT_FOUND'},status=404)
    except (ValueError,TypeError,KeyError):return JsonResponse({'error':'PROFILE_UNAVAILABLE'},status=400)
    except (OSError,TimeoutError,DatabaseError):return JsonResponse({'error':'CONTROL_SERVICE_UNAVAILABLE'},status=503)


@require_GET
def download(request,profile_id,token):
    # Secret subscription URL, independent of administrator cookies. Request
    # paths, tokens and config contents must never enter Audit or stdout.
    if len(token)!=43:return HttpResponse(status=404)
    row=FlClashProfile.objects.select_related('account').filter(pk=profile_id,phase='active').first()
    if not row or not secrets.compare_digest(row.token_hash,hashlib.sha256(token.encode()).hexdigest()):return HttpResponse(status=404)
    try:
        state,peer=active_state(row,'system:client-api')
        data=configuration(row,state,peer,material(row)['private_key'])
        result=HttpResponse(json.dumps(data,ensure_ascii=False,indent=2)+'\n',content_type='application/yaml; charset=utf-8')
        result['Content-Disposition']='attachment; filename="Proxy-UDP.yaml"'
        result['Cache-Control']='no-store, private';result['Referrer-Policy']='no-referrer'
        return result
    except (ValueError,KeyError,StopIteration,TypeError,OSError,TimeoutError,DatabaseError):return HttpResponse(status=503)
