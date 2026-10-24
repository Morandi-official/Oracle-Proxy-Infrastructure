#!/usr/bin/env python3
"""Bounded, read-only OCI API probe. Independent of the firewall lease loop.

Never reads API-key files or exports IMDS certificates, session tokens or raw errors.
The SDK uses short-lived instance-principal credentials held in this process only.
"""
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import signal
import tempfile
import time
import urllib.request
from decimal import Decimal

CACHE=Path('/var/lib/oracle-proxy-control/oci-usage.json')
# Oracle public USD catalog, checked 2026-10-23: these exact networking SKUs
# have metric "Gigabyte Outbound Data Transfer Per Month", zero price from
# rangeMin=0 through rangeMax=10240, then a positive per-GB rate. Keep the
# original API GB unit; never silently equate this with local VNIC bytes.
TRANSFER_SKUS={'B88327','B93455','B93456'}
PRICE_REFERENCE='https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?currencyCode=USD'


def free_tier(rows,complete):
    result={'free_tier_status':'REVIEW_REQUIRED','free_tier_limit_gb':None,
            'free_tier_used_gb':None,'free_tier_remaining_gb':None,
            'free_tier_policy_checked':'2026-10-23','free_tier_price_reference':PRICE_REFERENCE,
            'free_tier_basis':'official-usage-plus-public-price-tier-not-live-balance-api'}
    if not complete:
        result['free_tier_status']='PAGINATED_INCOMPLETE'; return result
    if not rows:
        result['free_tier_status']='NO_EGRESS_ROWS'; return result
    selected=[]
    for row in rows:
        part=row.get('part_number','')
        if part not in TRANSFER_SKUS or row['unit'] not in ('GB Months','GB','Gigabyte Months'):
            return result
        selected.append(part)
    if len(set(selected))!=1:
        result['free_tier_status']='MULTIPLE_ZONES_REQUIRE_REVIEW'; return result
    used=sum((Decimal(str(row['quantity'])) for row in rows),Decimal(0))
    result.update(free_tier_status='VERIFIED_USAGE_AND_PRICE_TIER',free_tier_limit_gb=10240,
                  free_tier_used_gb=float(used),free_tier_remaining_gb=float(max(Decimal(0),Decimal(10240)-used)))
    return result


def metadata(resource):
    if resource not in ('instance/','vnics/'): raise ValueError('INVALID_METADATA_RESOURCE')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request=urllib.request.Request('http://169.254.169.254/opc/v2/'+resource,headers={'Authorization':'Bearer Oracle'})
    with opener.open(request,timeout=3) as response:
        body=response.read(65537)
        if len(body)>65536: raise ValueError('METADATA_TOO_LARGE')
        return json.loads(body)


def error_code(error):
    status=getattr(error,'status',None)
    if status in (401,403,404): return 'IAM_OR_RESOURCE_ACCESS_DENIED'
    if status==429: return 'API_RATE_LIMITED'
    return 'API_UNAVAILABLE'


def error_details(error):
    """Classify bounded diagnostics without logging exception text or credentials."""
    status=getattr(error,'status',None)
    code=getattr(error,'code',None)
    allowed={'InvalidParameter','InvalidParameterValue','InvalidRequest','InvalidTimeInterval',
             'NotAuthenticated','NotAuthorizedOrNotFound','NotAuthorized','InternalError',
             'TooManyRequests','NotSupported','LimitExceeded','BadRequest'}
    category=('HTTP_ERROR' if type(status) is int else
              'SDK_RESPONSE_ERROR' if isinstance(error,AttributeError) else
              'SDK_VALIDATION_ERROR' if isinstance(error,(ValueError,TypeError)) else
              'TIMEOUT' if isinstance(error,TimeoutError) else 'TRANSPORT_OR_SDK_ERROR')
    return {'http_status':status if type(status) is int and 100<=status<=599 else None,
            'category':category,'service_code':code if isinstance(code,str) and code in allowed else 'OTHER'}


def billing_range(now):
    # Query completed UTC hours, including today; this does not remove Oracle ingestion delay.
    end=now.astimezone(dt.timezone.utc).replace(minute=0,second=0,microsecond=0)
    return end.replace(day=1,hour=0),end


def finite(value):
    value=float(value)
    if not math.isfinite(value) or value<0: raise ValueError('INVALID_METRIC')
    return value


def collect():
    now=dt.datetime.now(dt.timezone.utc)
    result={'schema':1,'checked_at':int(now.timestamp()),'period':now.strftime('%Y-%m'),
            'status':'METADATA_UNAVAILABLE','monitoring_status':'NOT_QUERIED','billing_status':'NOT_QUERIED',
            'vnic_outbound_bytes':None,'metric_through':None,'billing_rows':[],
            'remaining_bytes':None,'basis':'official-observation-not-verified-billing-balance'}
    try:
        instance=metadata('instance/');vnics=metadata('vnics/')
        region=instance.get('canonicalRegionName') or instance['region'];compartment=instance['compartmentId']
        if not re.fullmatch(r'[a-z]{2,4}-[a-z]+-[0-9]+',region): raise ValueError('INVALID_REGION')
        ids=[v['vnicId'] for v in vnics]
        if not ids or len(ids)>16 or any(not re.fullmatch(r'ocid1.vnic.[A-Za-z0-9_.-]+',v) for v in ids): raise ValueError('INVALID_VNICS')
        # Only non-secret resource identifiers, visible to the sole administrator,
        # are retained to make an exact-instance dynamic-group rule reviewable.
        result.update(region=region,instance_id=instance['id'],compartment_id=compartment,vnic_count=len(ids))
        created=instance.get('timeCreated')
        if type(created) is int and 0<created//1000<=int(now.timestamp()):
            result['instance_created_at']=created//1000
    except Exception: return result
    os.environ['OCI_PYTHON_SDK_NO_SERVICE_IMPORTS']='true'
    from oci.auth.signers import InstancePrincipalsSecurityTokenSigner
    from oci.retry import NoneRetryStrategy
    from oci.monitoring import MonitoringClient
    from oci.monitoring.models import SummarizeMetricsDataDetails
    from oci.usage_api import UsageapiClient
    from oci.usage_api.models import RequestSummarizedUsagesDetails
    retry=NoneRetryStrategy()
    try:
        signer=InstancePrincipalsSecurityTokenSigner(retry_strategy=retry,federation_client_retry_strategy=retry)
        result['status']='INSTANCE_PRINCIPAL_READY'
    except Exception as error:
        result.update(status='INSTANCE_PRINCIPAL_UNAVAILABLE',monitoring_status=error_code(error),billing_status='AUTHENTICATION_UNAVAILABLE')
        return result
    start=now.replace(day=1,hour=0,minute=0,second=0,microsecond=0)
    # Completed UTC hours only. Fresh local counters remain a separate measure;
    # missing/retained metric history must never be silently treated as zero.
    end=now.replace(minute=0,second=0,microsecond=0)
    try:
        client=MonitoringClient({'region':region},signer=signer,timeout=(3,8),retry_strategy=retry)
        total=0;latest=None;earliest=None;points=0
        for identity in ids:
            details=SummarizeMetricsDataDetails(namespace='oci_vcn',query='VnicToNetworkBytes[1h]{resourceId="'+identity+'"}.sum()',start_time=start,end_time=end,resolution='1h')
            data=client.summarize_metrics_data(compartment,details,retry_strategy=retry).data
            for stream in data:
                if stream.name!='VnicToNetworkBytes' or stream.dimensions.get('resourceId')!=identity: raise ValueError('UNEXPECTED_METRIC')
                for point in stream.aggregated_datapoints:
                    total+=finite(point.value);points+=1
                    latest=max(latest or point.timestamp,point.timestamp)
                    earliest=min(earliest or point.timestamp,point.timestamp)
        result.update(monitoring_status='OBSERVED_WITH_UNVERIFIED_COVERAGE' if points else 'NO_DATA',vnic_outbound_bytes=int(total) if points else None,
                      metric_through=int(latest.timestamp()) if latest else None,metric_from=int(earliest.timestamp()) if earliest else None,
                      metric_query_from=int(start.timestamp()),metric_query_to=int(end.timestamp()),metric_points=points)
    except Exception as error: result['monitoring_status']=error_code(error)
    try:
        client=UsageapiClient({'region':region},signer=signer,timeout=(3,8),retry_strategy=retry)
        billing_start,billing_end=billing_range(now)
        result['billing_through']=int(billing_end.timestamp())
        result['billing_granularity']='HOURLY'
        if billing_end<=billing_start:
            result['billing_status']='NO_COMPLETED_HOURS'
            return result
        midnight=billing_end.replace(hour=0)
        windows=[]
        if midnight>billing_start:windows.append((billing_start,midnight,'DAILY'))
        if billing_end>midnight:windows.append((midnight,billing_end,'HOURLY'))
        result['billing_granularity']='DAILY_HISTORY_HOURLY_TODAY'
        rows=[];complete=True
        for window_start,window_end,granularity in windows:
            details=RequestSummarizedUsagesDetails(tenant_id=signer.tenancy_id,time_usage_started=window_start,time_usage_ended=window_end,
                granularity=granularity,query_type='USAGE',group_by=['service','skuName','skuPartNumber','unit'],is_aggregate_by_time=True)
            before=len(rows);page=None;seen=set();window_complete=False
            try:
                for _ in range(4):
                    response=client.request_summarized_usages(details,page=page,limit=1000,retry_strategy=retry)
                    for row in response.data.items:
                        label=row.sku_name or ''
                        if re.search(r'outbound|outgoing|data transfer',label,re.I):
                            part=getattr(row,'sku_part_number','') or ''
                            if part and not re.fullmatch(r'B[0-9]{5,8}',part):raise ValueError('INVALID_TRANSFER_SKU')
                            rows.append({'sku':label[:160],'part_number':part,'unit':(row.unit or '')[:40],'quantity':finite(row.computed_quantity)})
                    page=response.headers.get('opc-next-page')
                    if not page:window_complete=True;break
                    if page in seen:break
                    seen.add(page)
            except Exception as error:
                # Preserve a complete historical result if today's hourly query is
                # rejected; never claim that a partial current day was included.
                if granularity!='HOURLY' or getattr(error,'status',None)!=400:raise
                rows=rows[:before];result['billing_granularity']='DAILY_FALLBACK'
                result['billing_through']=int(midnight.timestamp())
                result['billing_hourly_status']='HOURLY_QUERY_REJECTED'
                window_complete=True
            if not window_complete:complete=False;break
        if len(rows)>32:complete=False
        result.update(billing_status='PAGINATED_INCOMPLETE' if not complete else 'ROWS_REQUIRE_SKU_REVIEW' if rows else 'NO_EGRESS_ROWS',billing_rows=rows[:32])
        result.update(free_tier(rows,complete))
        if result['free_tier_status']=='VERIFIED_USAGE_AND_PRICE_TIER':result['billing_status']='VERIFIED_USAGE_AND_PRICE_TIER'
    except Exception as error:
        result['billing_status']=error_code(error)
        for key,value in error_details(error).items():result['billing_error_'+key]=value
    return result


def write_cache(value):
    previous={}
    try:
        if not CACHE.is_symlink() and CACHE.stat().st_size<=32768: previous=json.loads(CACHE.read_text())
    except (OSError,ValueError): pass
    signature=lambda v:(v.get('period'),v.get('billing_rows'),v.get('billing_status'))
    value['billing_changed_at']=previous.get('billing_changed_at') if signature(value)==signature(previous) else value['checked_at']
    value['next_check_at']=value['checked_at']+600
    CACHE.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.oci-usage-',dir=CACHE.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(value,stream,separators=(',',':'));stream.flush();os.fsync(stream.fileno())
        os.replace(name,CACHE)
    finally:
        if os.path.exists(name):os.unlink(name)


def main():
    if os.geteuid()!=0: raise SystemExit('ROOT_ONLY')
    os.umask(0o077)
    def timeout(*_): raise TimeoutError('BOUNDED_PROBE_TIMEOUT')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(75)
    try: value=collect()
    except Exception: value={'schema':1,'checked_at':int(time.time()),'period':dt.datetime.now(dt.timezone.utc).strftime('%Y-%m'),'status':'PROBE_UNAVAILABLE','remaining_bytes':None}
    write_cache(value)
    # Only fixed categorical statuses leave the host in CI logs.
    print('OCI_READ_ONLY_API_PROBE='+json.dumps({k:value.get(k) for k in ('status','monitoring_status','billing_status','vnic_count','vnic_outbound_bytes','metric_through')},sort_keys=True))


if __name__=='__main__':main()
