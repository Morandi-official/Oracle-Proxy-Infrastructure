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

CACHE=Path('/var/lib/oracle-proxy-control/oci-usage.json')


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
        total=0;latest=None;points=0
        for identity in ids:
            details=SummarizeMetricsDataDetails(namespace='oci_vcn',query='VnicToNetworkBytes[1h]{resourceId="'+identity+'"}.sum()',start_time=start,end_time=end,resolution='1h')
            data=client.summarize_metrics_data(compartment,details,retry_strategy=retry).data
            for stream in data:
                if stream.name!='VnicToNetworkBytes' or stream.dimensions.get('resourceId')!=identity: raise ValueError('UNEXPECTED_METRIC')
                for point in stream.aggregated_datapoints:
                    total+=finite(point.value);points+=1
                    latest=max(latest or point.timestamp,point.timestamp)
        result.update(monitoring_status='OBSERVED_WITH_UNVERIFIED_COVERAGE' if points else 'NO_DATA',vnic_outbound_bytes=int(total) if points else None,
                      metric_through=int(latest.timestamp()) if latest else None,metric_points=points)
    except Exception as error: result['monitoring_status']=error_code(error)
    try:
        client=UsageapiClient({'region':region},signer=signer,timeout=(3,8),retry_strategy=retry)
        details=RequestSummarizedUsagesDetails(tenant_id=signer.tenancy_id,time_usage_started=start,time_usage_ended=end,
                    granularity='DAILY',query_type='USAGE',group_by=['service','skuName','unit'],is_aggregate_by_time=True)
        response=client.request_summarized_usages(details,retry_strategy=retry)
        rows=[]
        for row in response.data.items:
            # Do not infer billable internet egress from arbitrary quantities or a
            # zero-cost/free-tier row. Preserve the official SKU/unit for review.
            label=row.sku_name or ''
            if re.search(r'outbound|outgoing|data transfer',label,re.I):
                rows.append({'sku':label[:160],'unit':(row.unit or '')[:40],'quantity':finite(row.computed_quantity or 0)})
        result.update(billing_status='PAGINATED_INCOMPLETE' if response.headers.get('opc-next-page') else 'ROWS_REQUIRE_SKU_REVIEW' if rows else 'NO_EGRESS_ROWS',billing_rows=rows[:32])
    except Exception as error: result['billing_status']=error_code(error)
    return result


def write_cache(value):
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
