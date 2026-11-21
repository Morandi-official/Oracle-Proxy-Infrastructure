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
LOCAL = {'10.0.0.220': 'primary', '152.67.156.100': 'primary',
         '10.0.0.246': 'backup', '150.230.113.158': 'backup'}
PORTS = (443, 8443, 51820)


def count_flow(value, actions, capture):
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


def audit():
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
        actions, capture = Counter(), Counter()
        page, pages, scanned = None, 0, 0
        for _ in range(8):
            options = {'limit': 1000}
            if page:
                options['page'] = page
            response = client.search_logs(details, **options)
            pages += 1
            for entry in response.data.results or []:
                scanned += 1
                count_flow(entry.data, actions, capture)
            page = response.headers.get('opc-next-page')
            if not page:
                break
        result.update(status='OBSERVED', pages=pages, scanned_records=scanned, query_complete=not page, capture_counts=dict(capture),
                      flow_packets=[dict(role=k[0], port=k[1], direction=k[2], action=k[3], packets=n) for k,n in sorted(actions.items())])
    except oci.exceptions.ServiceError as error:
        code = error.code if isinstance(error.code, str) and re.fullmatch(r'[A-Za-z0-9_]{1,80}', error.code) else 'OCI_SERVICE_ERROR'
        result.update(status='OCI_ERROR', http_status=error.status, code=code)
    except Exception as error:
        result.update(status='QUERY_FAILED', category=type(error).__name__)
    return result


if __name__ == '__main__':
    if sys.argv[1:] == ['--incident-1532']:
        START = datetime(2026, 11, 21, 7, 32, 16, tzinfo=timezone.utc)
        END = datetime(2026, 11, 21, 7, 35, tzinfo=timezone.utc)
    elif sys.argv[1:]:
        raise ValueError('FIXED_CAPTURE_WINDOW_REQUIRED')
    def deadline(*_):
        raise TimeoutError()
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(58)
    try:
        print(json.dumps(audit(), sort_keys=True))
    finally:
        signal.alarm(0)
