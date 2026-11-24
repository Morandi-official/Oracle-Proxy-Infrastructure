"""Read the existing OCI flow log as the instance principal. Export counts only."""
from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import re
import signal
import sys

GROUP = 'ocid1.loggroup.oc1.uk-london-1.amaaaaaaiqqyrzia6rtmdlprq5i6m6zoj7e6lxkausrct3otalalz7zajlfq'
LOG = 'ocid1.log.oc1.uk-london-1.amaaaaaaiqqyrziag6tnmkfoxsns7bshwj5xiod6tnzsgw5ebuihlozzlrmq'
START = datetime(2026, 11, 21, 6, 19, 37, tzinfo=timezone.utc)
END = datetime(2026, 11, 21, 6, 22, tzinfo=timezone.utc)
LEGACY = {'10.0.0.6': 'legacy_primary_private', '152.67.154.225': 'legacy_primary_public',
          '10.0.0.10': 'legacy_backup_private', '141.147.78.44': 'legacy_backup_public'}
LOCAL = {'10.0.0.220': 'primary', '152.67.156.100': 'primary',
         '10.0.0.246': 'backup', '150.230.113.158': 'backup'}
PORTS = (443, 8443, 51820)


def count_flow(value, actions, capture, coverage=None):
    if not isinstance(value, dict):
        return
    event = value.get('logContent', value)
    data = event.get('data') if isinstance(event, dict) else None
    if not isinstance(data, dict):
        return
    start, end = data.get('startTime'), data.get('endTime')
    if type(start) is not int or type(end) is not int or start > end or start > END.timestamp() or end < START.timestamp():
        return
    status = data.get('status')
    if status in ('OK', 'SKIPDATA', 'NODATA'):
        capture[status] += 1
    if coverage is not None:
        for direction, field in (('source', 'sourceAddress'), ('destination', 'destinationAddress')):
            address = data.get(field)
            address_label = LEGACY.get(address, address if address in LOCAL else None)
            if address_label:
                protocol = data.get('protocol')
                protocol_label = {'17': 'UDP', '6': 'TCP', '1': 'ICMP'}.get(str(protocol), 'other')
                coverage[address_label, direction, protocol_label] += 1
    if data.get('protocol') not in (17, '17') or data.get('action') not in ('ACCEPT', 'REJECT'):
        return
    source, destination = data.get('sourceAddress'), data.get('destinationAddress')
    packets = data.get('packets')
    if type(packets) is not int or packets < 0:
        return
    if source in LOCAL and destination not in LOCAL and data.get('sourcePort') in PORTS:
        actions[LOCAL[source], data['sourcePort'], 'out', data['action']] += packets
    elif destination in LOCAL and source not in LOCAL and data.get('destinationPort') in PORTS:
        actions[LOCAL[destination], data['destinationPort'], 'in', data['action']] += packets


def audit(coverage_only=False):
    import oci

    result = {'authentication': 'PENDING', 'capture_window_utc': [START.isoformat(), END.isoformat()]}
    try:
        retry = oci.retry.NoneRetryStrategy()
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner(retry_strategy=retry, federation_client_retry_strategy=retry)
        result['authentication'] = 'INSTANCE_PRINCIPAL_READY'
        client = oci.loggingsearch.LogSearchClient({'region': 'uk-london-1'}, signer=signer, timeout=(3, 8), retry_strategy=retry)
        details = oci.loggingsearch.models.SearchLogsDetails(
            time_start=START-timedelta(minutes=1), time_end=min(END+timedelta(minutes=15), datetime.now(timezone.utc)),
            search_query=f'search "{signer.tenancy_id}/{GROUP}/{LOG}" | sort by datetime asc',
            is_return_field_info=False)
        actions, capture, coverage = Counter(), Counter(), Counter()
        filter_ids = set()
        page, pages, scanned = None, 0, 0
        for _ in range(8):
            options = {'limit': 1000}
            if page:
                options['page'] = page
            response = client.search_logs(details, **options)
            pages += 1
            for entry in response.data.results or []:
                scanned += 1
                value=entry.data
                count_flow(value, actions, capture, coverage if coverage_only else None)
                if coverage_only and isinstance(value,dict):
                    event=value.get('logContent',value)
                    metadata=event.get('oracle') if isinstance(event,dict) else None
                    if isinstance(metadata,dict):
                        candidate=next((v for k,v in metadata.items() if k.lower()=='filterocid'),None)
                        if isinstance(candidate,str) and re.fullmatch(r'ocid1\.capturefilter\.oc1\.[a-z0-9.-]{6,130}',candidate):
                            filter_ids.add(candidate)
            page = response.headers.get('opc-next-page')
            if not page:
                break
        result.update(status='OBSERVED', pages=pages, scanned_records=scanned, query_complete=not page, capture_counts=dict(capture),
                      flow_packets=[dict(role=k[0], port=k[1], direction=k[2], action=k[3], packets=n) for k,n in sorted(actions.items())])
        if coverage_only:
            result['filter_metadata']={'referenced_filters':len(filter_ids)}
            if len(filter_ids)==1:
                try:
                    network=oci.core.VirtualNetworkClient({'region':'uk-london-1'},signer=signer,timeout=(3,8),retry_strategy=retry)
                    observed=network.get_capture_filter(next(iter(filter_ids))).data
                    rules=observed.flow_log_capture_filter_rules or []
                    result['filter_metadata'].update(status='OBSERVED',
                        is_historical_focused_filter=observed.display_name=='udp-path-focused', rule_count=len(rules),
                        sampling_intervals=sorted({rule.sampling_rate for rule in rules if type(rule.sampling_rate) is int}))
                except oci.exceptions.ServiceError as error:
                    result['filter_metadata'].update(status='OCI_ERROR',http_status=error.status)
                except (OSError,TypeError,AttributeError) as error:
                    result['filter_metadata'].update(status='UNAVAILABLE',error_type=type(error).__name__)
            result['observed_address_coverage']=[dict(address=k[0],direction=k[1],protocol=k[2],records=n) for k,n in sorted(coverage.items())]
            try:
                management=oci.logging.LoggingManagementClient({'region':'uk-london-1'},signer=signer,timeout=(3,8),retry_strategy=retry)
                log=management.get_log(GROUP,LOG).data
                source=log.configuration.source
                resource=source.resource
                kind=resource.split('.')[1] if isinstance(resource,str) and resource.startswith('ocid1.') else None
                result['log_metadata']={'status':'OBSERVED','enabled':log.is_enabled,'scope_kind':kind if kind in ('subnet','vcn','instance','vnic') else None,
                                        'matches_target_vnic':resource=='ocid1.vnic.oc1.uk-london-1.abwgiljtvinh2xd5rknwxycmpniiwzaekj6fub5y27lmefjmfieikxmzauxq'}
            except oci.exceptions.ServiceError as error:
                result['log_metadata']={'status':'OCI_ERROR','http_status':error.status}
            except (AttributeError,TypeError,OSError) as error:
                result['log_metadata']={'status':'UNAVAILABLE','error_type':type(error).__name__}
    except oci.exceptions.ServiceError as error:
        code = error.code if isinstance(error.code, str) and re.fullmatch(r'[A-Za-z0-9_]{1,80}', error.code) else 'OCI_SERVICE_ERROR'
        result.update(status='OCI_ERROR', http_status=error.status, code=code)
    except Exception as error:
        result.update(status='QUERY_FAILED', category=type(error).__name__)
    return result


if __name__ == '__main__':
    if sys.argv[1:] == ['--incident-20261124']:
        START = datetime(2026, 11, 24, 4, 27, 30, tzinfo=timezone.utc)
        END = datetime(2026, 11, 24, 4, 47, tzinfo=timezone.utc)
        LOCAL = {'10.0.0.6': 'endpoint_152_67_154_225', '10.0.0.10': 'endpoint_141_147_78_44'}
        LEGACY = {}
    elif sys.argv[1:] == ['--incident-1532']:
        START = datetime(2026, 11, 21, 7, 32, 16, tzinfo=timezone.utc)
        END = datetime(2026, 11, 21, 7, 35, tzinfo=timezone.utc)
    elif sys.argv[1:] == ['--incident-1544']:
        START = datetime(2026, 11, 21, 7, 43, 45, tzinfo=timezone.utc)
        END = datetime(2026, 11, 21, 7, 44, 16, tzinfo=timezone.utc)
    elif sys.argv[1:] == ['--incident-1833']:
        START = datetime(2026, 11, 21, 10, 33, 40, tzinfo=timezone.utc)
        END = datetime(2026, 11, 21, 10, 36, 0, tzinfo=timezone.utc)
        PORTS = (443,)
    elif sys.argv[1:] != ['--coverage'] and sys.argv[1:]:
        raise ValueError('FIXED_CAPTURE_WINDOW_REQUIRED')
    def deadline(*_):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(58)
    try:
        if sys.argv[1:] == ['--coverage']:
            windows = [('successful_cloud', (6,58,48), (7,0,0)),
                       ('windows_failure', (7,43,45), (7,44,16))]
            records = {}
            for label,begin,end in windows:
                START = datetime(2026,11,21,*begin,tzinfo=timezone.utc)
                END = datetime(2026,11,21,*end,tzinfo=timezone.utc)
                records[label] = audit(coverage_only=True)
            print(json.dumps(records,sort_keys=True))
        else:
            print(json.dumps(audit(coverage_only=sys.argv[1:] == ['--incident-20261124']), sort_keys=True))
    finally:
        signal.alarm(0)
