"""Authenticated, bounded endpoint diagnostics. No secret or packet-body uploads."""
from datetime import timedelta
import json
import uuid
from django.db import DatabaseError
from django.db import transaction
from django.db.models import F
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST,require_GET
from . import client_api,control
from .models import UdpDiagnostic,ClientLoginThrottle

TARGETS={(a,p) for a in ('152.67.156.100','141.147.78.44') for p in (443,8443,51820)}
COUNTERS={'tx_initiations','rx_responses','rx_cookies','rx_invalid','rx_obsolete','read_errors','write_errors',
          'last_read_error','last_write_error','rcvbuf_before','sndbuf_before','rcvbuf_after','sndbuf_after','socket_buffer_error'}
ERRORS={'','CORE_START_FAILED','CORE_READY_TIMEOUT','ORACLE_PROBE_TIMEOUT','ORACLE_PROBE_HTTP_FAILED',
        'ORACLE_EGRESS_NOT_VERIFIED','EGRESS_PROBE_TIMEOUT','EGRESS_PROBE_HTTP_FAILED','EGRESS_NOT_VERIFIED',
        'CANCELLED','LOCAL_DIAGNOSTIC_FAILED'}


def client_evidence(value):
    if not isinstance(value,dict) or set(value)!={'counters','egress_verified','error','elapsed_ms'}:
        raise ValueError('INVALID_DIAGNOSTIC_EVIDENCE')
    counters=value['counters']
    if not isinstance(counters,dict) or not set(counters)<=COUNTERS:
        raise ValueError('INVALID_DIAGNOSTIC_COUNTERS')
    if any(type(v)!=int or not 0<=v<=2**32-1 for v in counters.values()):
        raise ValueError('INVALID_DIAGNOSTIC_COUNTERS')
    if type(value['egress_verified'])!=bool or value['error'] not in ERRORS or type(value['elapsed_ms'])!=int or not 0<=value['elapsed_ms']<=180000:
        raise ValueError('INVALID_DIAGNOSTIC_EVIDENCE')
    return value


def verdict(client,server):
    if client['egress_verified']:return 'PASSED'
    counters=client['counters']
    if counters.get('write_errors',0):return 'LOCAL_WRITE_ERROR'
    if not counters.get('tx_initiations',0):return 'NO_INITIATION_SENT'
    captured=server.get('capture',{})
    if not server.get('index_correlation_available') or captured.get('capture_status')=='unavailable':
        return 'SERVER_OBSERVATION_UNAVAILABLE'
    if captured.get('tx_responses',0) and not counters.get('rx_responses',0):return 'RETURN_OR_LOCAL_RECEIVE_PATH'
    if counters.get('rx_responses',0):return 'REPLY_WITHOUT_VERIFIED_EGRESS'
    if not captured.get('complete_observation'):return 'INSUFFICIENT_OBSERVATION'
    if not captured.get('rx_initiations',0):return 'FORWARD_PATH_NOT_OBSERVED'
    return 'SERVER_RESPONSE_NOT_OBSERVED'


def cleanup():
    now=timezone.now()
    UdpDiagnostic.objects.filter(phase='running',updated_at__lt=now-timedelta(minutes=4)).update(phase='interrupted')
    UdpDiagnostic.objects.filter(started_at__lt=now-timedelta(days=7)).delete()
    excess=list(UdpDiagnostic.objects.order_by('-started_at').values_list('pk',flat=True)[2048:2548])
    if excess:UdpDiagnostic.objects.filter(pk__in=excess).delete()


def rate_limit(credential):
    now=timezone.now();minute=int(now.timestamp())//60
    with transaction.atomic():
        ClientLoginThrottle.objects.filter(expires_at__lt=now).delete()
        for scope,maximum in [('global',90),(str(credential.account_id),45)]:
            bucket='udp-diag:'+str(minute)+':'+scope
            ClientLoginThrottle.objects.get_or_create(bucket=bucket,defaults={'expires_at':now+timedelta(minutes=2)})
            ClientLoginThrottle.objects.filter(bucket=bucket).update(attempts=F('attempts')+1)
            if ClientLoginThrottle.objects.get(bucket=bucket).attempts>maximum:raise ValueError('DIAGNOSTIC_RATE_LIMITED')


@csrf_exempt
@require_POST
def native(request):
    credential=client_api.session(request)
    if not credential:return client_api.response({'error':'LOGIN_REQUIRED'},401)
    try:
        rate_limit(credential)
        if request.content_type!='application/json' or len(request.body)>16384:raise ValueError('INVALID_REQUEST')
        value=json.loads(request.body)
        if not isinstance(value,dict):raise ValueError('INVALID_REQUEST')
        action=value.get('action')
        fields={'start':{'action','diagnostic_id'},'begin':{'action','diagnostic_id','address','port'},
                'sample':{'action','diagnostic_id','sender_indices','client','complete'},
                'finish':{'action','diagnostic_id','cancelled'}}
        if action not in fields or set(value)!=fields[action]:raise ValueError('INVALID_DIAGNOSTIC_FIELDS')
        with client_api.management_lock():
            device=client_api.fingerprint(credential.public_key)
            if action=='start':
                initial_id=value['diagnostic_id']
                if not isinstance(initial_id,str) or str(uuid.UUID(initial_id))!=initial_id:raise ValueError('INVALID_DIAGNOSTIC_ID')
                state=client_api.state_for(credential,control.call('state',client_api.actor(request),{}),True)
                if not state['device']['registered'] or state['account']['status']!='active':raise ValueError('DIAGNOSTIC_ACCOUNT_NOT_ACTIVE')
                cleanup()
                if UdpDiagnostic.objects.filter(account=credential.account,device_id=device,phase='running').exists():raise ValueError('DIAGNOSTIC_BUSY')
                if UdpDiagnostic.objects.filter(account=credential.account,started_at__gte=timezone.now()-timedelta(hours=1)).count()>=12:
                    raise ValueError('DIAGNOSTIC_RATE_LIMITED')
                row=UdpDiagnostic.objects.create(id=initial_id,account=credential.account,device_id=device,report={'schema':1,'trials':[]})
                try:server=control.call('udp-diagnostic.start',client_api.actor(request),{'diagnostic_id':str(row.pk),'public_key':credential.public_key})
                except Exception:
                    row.phase='unavailable';row.save(update_fields=['phase','updated_at']);raise
                return client_api.response(server)
            identity=value['diagnostic_id']
            if not isinstance(identity,str) or str(uuid.UUID(identity))!=identity:raise ValueError('INVALID_DIAGNOSTIC_ID')
            row=UdpDiagnostic.objects.filter(pk=identity,account=credential.account,device_id=device).first()
            if row is None:raise ValueError('DIAGNOSTIC_NOT_FOUND')
            data={'diagnostic_id':identity,'public_key':credential.public_key}
            if action=='begin':
                if row.phase!='running':raise ValueError('DIAGNOSTIC_NOT_RUNNING')
                if type(value['port'])!=int or (value['address'],value['port']) not in TARGETS:raise ValueError('INVALID_DIAGNOSTIC_TARGET')
                server=control.call('udp-diagnostic.begin',client_api.actor(request),{**data,'address':value['address'],'port':value['port']})
                row.report['trials'].append({'address':value['address'],'port':value['port'],'server':server})
            elif action=='sample':
                if row.phase!='running' or not row.report['trials'] or type(value['complete'])!=bool:raise ValueError('DIAGNOSTIC_STEP_CONFLICT')
                evidence=client_evidence(value['client'])
                indices=value['sender_indices']
                if not isinstance(indices,list) or len(indices)>16 or any(type(i)!=int or not 0<=i<2**32 for i in indices):raise ValueError('INVALID_DIAGNOSTIC_CORRELATION')
                server=control.call('udp-diagnostic.sample',client_api.actor(request),{**data,'sender_indices':indices,'complete':value['complete']})
                row.report['trials'][-1].update({'client':evidence,'server':server,'verdict':verdict(evidence,server)})
                server={**server,'verdict':row.report['trials'][-1]['verdict']}
            else:
                if type(value['cancelled'])!=bool:raise ValueError('INVALID_DIAGNOSTIC_FIELDS')
                if row.phase!='running':return client_api.response({'diagnostic_id':identity,'report':row.report,'phase':row.phase,'server_capture_closed':bool(row.report.get('server_capture_closed'))})
                closed=False
                try:
                    server=control.call('udp-diagnostic.finish',client_api.actor(request),data)
                    closed=True
                    for trial,observed in zip(row.report['trials'],server['trials']):
                        trial['server']=observed
                        if 'client' in trial:trial['verdict']=verdict(trial['client'],observed)
                except (ValueError,OSError,TimeoutError):
                    row.report['server_finish']='UNAVAILABLE_OR_RESTARTED'
                row.phase='cancelled' if value['cancelled'] else 'complete'
                row.report['client_receive_layer']='connected_udp_socket'
                row.report['physical_nic_observation']='not_collected'
                row.report['limitation']='Paired endpoint observations do not identify a specific intermediate network hop.'
                row.report['server_capture_closed']=closed
                server={'diagnostic_id':identity,'report':row.report,'phase':row.phase,'server_capture_closed':closed}
            row.save(update_fields=['report','phase','updated_at'])
            return client_api.response(server)
    except (ValueError,TypeError,KeyError) as error:return client_api.failed(error)
    except (OSError,TimeoutError,DatabaseError):return client_api.response({'error':'CONTROL_SERVICE_UNAVAILABLE'},503)


@require_GET
def administrator(request):
    from .views import deny
    rejected=deny(request)
    if rejected is not None:return rejected
    cleanup()
    return JsonResponse({'diagnostics':[{'id':str(row.pk),'username':row.account.username,'device_id':row.device_id,
        'started_at':int(row.started_at.timestamp()),'phase':row.phase,'report':row.report}
        for row in UdpDiagnostic.objects.select_related('account').order_by('-started_at')[:32]]})
