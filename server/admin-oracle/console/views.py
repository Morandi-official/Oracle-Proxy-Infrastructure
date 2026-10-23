from time import time

from allauth.account.authentication import get_authentication_records
from allauth.mfa.models import Authenticator
from allauth.socialaccount.models import SocialAccount
from django.conf import settings
from django.http import FileResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods
import json
from . import control, client_api

from .models import Audit, Snapshot, ClientAccount


def github_identity(request):
    if not request.user.is_authenticated or not request.user.is_active:
        return None
    account = SocialAccount.objects.filter(user=request.user, provider='github',
                                            uid__in=settings.ADMIN_GITHUB_IDS).first()
    return account.uid if account else None


def assurance(request):
    uid = github_identity(request)
    if not uid:
        return None, 'LOGIN_REQUIRED'
    enrolled = Authenticator.objects.filter(user=request.user, type=Authenticator.Type.TOTP).exists()
    if not enrolled:
        return uid, 'MFA_ENROLLMENT_REQUIRED'
    records = get_authentication_records(request)
    valid = any(r.get('method') == 'mfa' and r.get('type') in ('totp', 'recovery_codes') and
                isinstance(r.get('at'), (int, float)) and 0 <= time() - r['at'] < 3600
                for r in records)
    # A linked SocialAccount alone must never grant access to a password/session bypass.
    social = any(r.get('method') == 'socialaccount' and r.get('provider') == 'github' and
                 r.get('uid') == uid and isinstance(r.get('at'), (int, float)) and
                 0 <= time() - r['at'] < 3600 for r in records)
    return uid, None if valid and social else 'MFA_LOGIN_REQUIRED'


def deny(request):
    uid, reason = assurance(request)
    if reason:
        return JsonResponse({'error': reason}, status=401 if not uid else 403)
    return None


@require_GET
def login_page(request):
    return render(request, 'login.html')


@require_GET
def dashboard(request):
    uid, reason = assurance(request)
    if reason == 'LOGIN_REQUIRED':
        return redirect('login')
    if reason == 'MFA_ENROLLMENT_REQUIRED':
        return redirect('mfa_activate_totp')
    if reason:
        return render(request, 'finish_mfa.html', status=403)
    return render(request, 'dashboard.html')


@require_GET
def status(request):
    rejected = deny(request)
    if rejected is not None:
        return rejected
    row = Snapshot.objects.order_by('-observed_at').first()
    age = max(0, int((timezone.now() - row.observed_at).total_seconds())) if row else None
    uid = github_identity(request)
    Audit.objects.create(actor=f'github:{uid}', action='status.read')
    return JsonResponse({'node_id': settings.NODE_ID, 'actor': request.user.username,
                         'snapshot': row.payload if row else None, 'age_seconds': age,
                         'freshness': 'unknown' if row is None else ('fresh' if age <= 180 else 'stale'),
                         'capabilities': {'status': True, 'peers': True, 'usage': True, 'configuration': False},
                         'vpn_release': 'experimental-unverified'})


@require_GET
def audit(request):
    rejected = deny(request)
    if rejected is not None:
        return rejected
    entries = [{'occurred_at': int(row.occurred_at.timestamp()), 'actor': row.actor,
                'action': row.action, 'resource': row.resource}
               for row in Audit.objects.order_by('-occurred_at', '-id')[:100]]
    return JsonResponse({'entries': entries})


@require_http_methods(['GET','POST'])
def management(request):
    rejected = deny(request)
    if rejected is not None: return rejected
    operation, data = 'state', {}
    if request.method == 'POST':
        if request.content_type != 'application/json' or len(request.body)>8192:
            return JsonResponse({'error':'INVALID_REQUEST'},status=400)
        try:
            value = json.loads(request.body)
            if not isinstance(value,dict) or set(value)!={'operation','data'} or value['operation'] not in (
                    'peer.assign','peer.create','peer.revoke','account.save','account.delete','budget.set') or not isinstance(value['data'],dict):
                raise ValueError()
            operation, data = value['operation'], value['data']
        except (ValueError,TypeError): return JsonResponse({'error':'INVALID_REQUEST'},status=400)
    try:
        if operation == 'account.save': result = client_api.save_account(request,data)
        elif operation == 'account.delete': result = client_api.delete_account(request,data)
        else: result = control.call(operation, f'github:{github_identity(request)}', data)
    except (OSError,TimeoutError,json.JSONDecodeError):
        return JsonResponse({'error':'CONTROL_SERVICE_UNAVAILABLE'},status=503)
    except ValueError as error:
        return JsonResponse({'error':str(error)},status=400)
    if operation!='state':
        Audit.objects.create(actor=f'github:{github_identity(request)}',action=operation,resource='policy-control')
    accounts = {str(a.user_id):a.username for a in ClientAccount.objects.all()}
    for user in result.get('users',[]): user['username'] = accounts.get(user['id'])
    return JsonResponse(result)


@require_GET
def asset(request, name):
    rejected = deny(request)
    if rejected is not None:
        return rejected
    path = settings.BASE_DIR / 'static' / 'console' / name
    return FileResponse(path.open('rb'), content_type='text/javascript' if name.endswith('.js') else 'text/css')


@require_GET
def health(request):
    # Reverse proxy exposes this only to the local deployment health checker.
    if request.META.get('REMOTE_ADDR') not in ('127.0.0.1', '::1'):
        return JsonResponse({'error': 'NOT_FOUND'}, status=404)
    Snapshot.objects.exists()  # Include database/migration readiness.
    summary = {'ready':False}
    try:
        data=control.call('state',f'github:{next(iter(settings.ADMIN_GITHUB_IDS))}',{})
        summary={'ready':bool(data.get('observed_at') and not data.get('error')),
                 'observed_at':data.get('observed_at'),'error':data.get('error'),
                 'user_count':len(data['users']),'peer_count':len(data['peers']),
                 'managed_peer_count':sum(p['managed'] for p in data['peers']),
                 'guard_enabled':data['budget']['guard_enabled'],
                 'balance_known':data['budget']['remaining_bytes'] is not None}
    except (OSError,ValueError,TimeoutError,KeyError): pass
    return JsonResponse({'ready': True,'control':summary})
