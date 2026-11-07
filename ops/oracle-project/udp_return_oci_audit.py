"""Use the existing instance principal for fixed read-only OCI controls.

Never load API-key/config files, print SDK objects/errors, or mutate IAM/network.
"""
import datetime as dt
import importlib.util
import ipaddress
import json
from pathlib import Path
import signal
import time

VNIC='ocid1.vnic.oc1.uk-london-1.abwgiljtvinh2xd5rknwxycmpniiwzaekj6fub5y27lmefjmfieikxmzauxq'
GROUP='ocid1.loggroup.oc1.uk-london-1.amaaaaaaiqqyrzia6rtmdlprq5i6m6zoj7e6lxkausrct3otalalz7zajlfq'
LOG='ocid1.log.oc1.uk-london-1.amaaaaaaiqqyrziag6tnmkfoxsns7bshwj5xiod6tnzsgw5ebuihlozzlrmq'
CLIENTS={'111.55.79.216','111.55.79.240'}
LOCAL={'10.0.0.6','10.0.0.10'}


def flow(record):
    if not isinstance(record,dict):return None
    event=record.get('logContent',record)
    if not isinstance(event,dict):return None
    data=event.get('data',{})
    if not isinstance(data,dict):return None
    if data.get('status')=='SKIPDATA':
        return {'status':'SKIPDATA',**{k:data[k] for k in ('startTime','endTime') if type(data.get(k)) is int}}
    source=data.get('sourceAddress');destination=data.get('destinationAddress')
    if not ((source in CLIENTS and destination in LOCAL) or (source in LOCAL and destination in CLIENTS)):return None
    if data.get('protocol') not in (17,'17') or not any(data.get(k) in (443,8443,51820) for k in ('sourcePort','destinationPort')):return None
    if data.get('action') not in ('ACCEPT','REJECT'):return None
    row={'sourceAddress':source,'destinationAddress':destination,'action':data['action'],'protocol':17}
    for key in ('sourcePort','destinationPort','packets','bytesOut','startTime','endTime'):
        value=data.get(key)
        if type(value) is int and 0<=value<2**63:row[key]=value
    return row


def collect():
    base=Path(__file__).resolve().parents[2]
    spec=importlib.util.spec_from_file_location('existing_oci_usage',base/'server/admin-oracle/control/oci_usage.py')
    usage=importlib.util.module_from_spec(spec);spec.loader.exec_module(usage)
    result={'schema':1,'observed_at':int(time.time()),'authentication':'NOT_READY','scope':'FIXED_READ_ONLY_NETWORK_AND_HISTORICAL_LOG_QUERIES','support_case_submitted':False}
    try:
        import oci
        retry=oci.retry.NoneRetryStrategy()
        signer=oci.auth.signers.InstancePrincipalsSecurityTokenSigner(retry_strategy=retry,federation_client_retry_strategy=retry)
        result['authentication']='INSTANCE_PRINCIPAL_READY'
    except Exception as error:
        result['authentication_error']=usage.error_details(error);return result
    config={'region':'uk-london-1'}
    try:
        network=oci.core.VirtualNetworkClient(config,signer=signer,timeout=(3,8),retry_strategy=retry)
        vnic=network.get_vnic(VNIC).data
        result['vnic']={'status':'OBSERVED','nsg_count':len(vnic.nsg_ids or []),'skip_source_dest_check':vnic.skip_source_dest_check}
        private=network.list_private_ips(vnic_id=VNIC,limit=16)
        result['ip_mappings']=[]
        result['ip_mapping_list_complete']=not bool(private.headers.get('opc-next-page'))
        for item in private.data:
            if item.ip_address not in LOCAL:continue
            row={'private':item.ip_address,'primary':item.is_primary}
            try:
                public=network.get_public_ip_by_private_ip_id(oci.core.models.GetPublicIpByPrivateIpIdDetails(private_ip_id=item.id)).data
                row['public']=str(ipaddress.ip_address(public.ip_address))
            except Exception as error:row['error']=usage.error_details(error)
            result['ip_mappings'].append(row)
    except Exception as error:result['network_read_error']=usage.error_details(error)
    try:
        logging=oci.loggingsearch.LogSearchClient(config,signer=signer,timeout=(3,10),retry_strategy=retry)
        details=oci.loggingsearch.models.SearchLogsDetails(
            time_start=dt.datetime(2026,11,7,5,35,tzinfo=dt.timezone.utc),time_end=dt.datetime(2026,11,7,5,41,tzinfo=dt.timezone.utc),
            search_query='search "'+signer.tenancy_id+'/'+GROUP+'/'+LOG+'" | sort by datetime asc',is_return_field_info=False)
        response=logging.search_logs(details,limit=1000)
        result['flow_log_query']={'status':'OBSERVED','window_utc':'2026-11-07 05:35–05:41','query_complete':not bool(response.headers.get('opc-next-page')),
                                  'records':[safe for entry in response.data.results or [] if (safe:=flow(entry.data)) is not None]}
    except Exception as error:result['flow_log_read_error']=usage.error_details(error)
    return result


if __name__=='__main__':
    def deadline(*_):raise TimeoutError()
    signal.signal(signal.SIGALRM,deadline);signal.alarm(50)
    try:value=collect()
    except Exception:value={'schema':1,'status':'UNAVAILABLE_OR_DEADLINE','support_case_submitted':False}
    finally:signal.alarm(0)
    print(json.dumps(value,sort_keys=True))
