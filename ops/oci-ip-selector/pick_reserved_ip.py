#!/usr/bin/env python3
"""Bounded OCI Cloud Shell address selection. Default is read-only; --apply changes resources."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid

REGION = 'uk-london-1'
LIMIT = 7
PROTECTED_IPS = {'152.67.156.100', '141.147.78.44', '79.72.85.11', '130.162.169.253'}


class Stop(Exception):
    pass


class CliError(Stop):
    def __init__(self, code, status=None):
        self.code, self.status = code, status
        super().__init__('OCI_CLI_' + code)


def cli(args, request_id=None):
    command = ['oci', '--region', REGION, '--output', 'json', '--no-retry']
    if request_id:command += ['--opc-client-request-id', request_id]
    p = subprocess.run([*command, 'network', 'public-ip', *args], text=True, capture_output=True, timeout=120)
    if p.returncode:
        try:
            error = json.loads(p.stderr[p.stderr.index('{'):])
            code = error.get('code', 'FAILED')
            status = error.get('status')
        except (ValueError, KeyError):
            code, status = 'FAILED', None
        if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,80}', code):
            code = 'FAILED'
        raise CliError(code, status)
    return json.loads(p.stdout) if p.stdout.strip() else {}


def binding(row):
    return row.get('private-ip-id') or row.get('assigned-entity-id')


def inventory(compartment):
    response = cli(['list', '--scope', 'REGION', '--lifetime', 'RESERVED',
                    '--compartment-id', compartment, '--all'])
    rows = response.get('data')
    if not isinstance(rows, list) or response.get('opc-next-page'):
        raise Stop('COMPLETE_INVENTORY_REQUIRED')
    if any(x.get('compartment-id') != compartment or x.get('lifetime') != 'RESERVED' for x in rows):
        raise Stop('INVENTORY_SCOPE_MISMATCH')
    return rows


def snapshot(rows):
    return {r['id']: {'ip': r['ip-address'], 'binding': binding(r),
                       'state': r.get('lifecycle-state')} for r in rows}


def matches(address):
    a, b, c, d = map(int, str(ipaddress.IPv4Address(address)).split('.'))
    return 100 <= a <= 199 and 10 <= b <= 99 and 100 <= d <= 250 and d % 10 == 0


def save(path, data):
    if path.is_symlink():
        raise Stop('JOURNAL_SYMLINK_REFUSED')
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n'); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def owned_new(row, record, compartment, original_ids):
    return (isinstance(row, dict) and row.get('id') == record.get('id') and
            row.get('id') not in original_ids and
            str(row.get('id', '')).startswith('ocid1.publicip.oc1.uk-london-1.') and
            row.get('ip-address') == record.get('ip') and row.get('ip-address') not in PROTECTED_IPS and
            row.get('display-name') == record.get('name') and
            row.get('compartment-id') == compartment and row.get('lifetime') == 'RESERVED' and
            row.get('lifecycle-state') == 'AVAILABLE' and not binding(row) and
            row.get('freeform-tags', {}).get('selector-run') == record.get('run'))


def select(compartment, journal):
    fd = os.open(journal.with_name("run.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:raise Stop("RUN_ALREADY_ACTIVE") from None
        return select_locked(compartment, journal)
    finally:
        os.close(fd)


def select_locked(compartment, journal):
    # Never restart a spent budget or overwrite an unresolved creation response.
    if journal.exists() or journal.is_symlink():
        raise Stop('JOURNAL_EXISTS_USE_STATUS_DO_NOT_RESTART')
    rows = inventory(compartment)
    if {r['ip-address'] for r in rows} != PROTECTED_IPS or len(rows) != len(PROTECTED_IPS):
        raise Stop('EXPECTED_FOUR_EXISTING_IPS_REQUIRED')
    baseline = snapshot(rows)
    run_id = uuid.uuid4().hex
    state = {'schema': 1, 'region': REGION, 'compartment': compartment, 'limit': LIMIT,
             'run': run_id, 'original': baseline, 'attempts': [], 'status': 'running'}
    save(journal, state)
    try:
        for number in range(1, LIMIT + 1):
            # Each successful creation and each uncertain creation consumes a slot.
            entry = {'number': number, 'run': run_id,
                     'name': 'udp-primary-shell-' + run_id[:8] + '-' + str(number + 13),
                     'client_request_id': str(uuid.uuid4()), 'status': 'creation_intent'}
            state['attempts'].append(entry); save(journal, state)
            response = cli(['create', '--compartment-id', compartment, '--lifetime', 'RESERVED',
                            '--display-name', entry['name'],
                            '--freeform-tags', json.dumps({'selector-run': run_id})],
                           request_id=entry['client_request_id'])
            # Save the actual unmodified CLI response BEFORE parsing or deleting.
            raw = journal.with_name('create-' + str(number) + '.json')
            save(raw, response)
            row = response.get('data', {})
            entry.update(id=row.get('id'), ip=row.get('ip-address'),
                         created_at=row.get('time-created'), raw_response=raw.name,
                         request_id=response.get('opc-request-id'), status='created')
            save(journal, state)
            print(json.dumps(entry, ensure_ascii=False), flush=True)
            if not owned_new(row, entry, compartment, baseline):
                raise Stop('CREATED_OBJECT_NOT_VERIFIED_NO_DELETE')
            current = cli(['get', '--public-ip-id', entry['id']]).get('data')
            if not owned_new(current, entry, compartment, baseline):
                raise Stop('LIVE_OBJECT_NOT_OWNED_OR_UNBOUND_NO_DELETE')
            if matches(entry['ip']):
                entry['status'] = 'MATCH_RETAINED_UNBOUND'; state['status'] = 'matched'
                save(journal, state)
                print('MATCH_RETAINED_UNBOUND=' + entry['ip'], flush=True)
                break
            entry['status'] = 'delete_intent'; save(journal, state)
            try:
                cli(['delete', '--public-ip-id', entry['id'], '--force'])
                entry['delete_cli_result'] = 'success'
            except CliError as e:
                entry['delete_cli_result'] = e.code
                if e.status != 404:
                    raise
            try:
                cli(['get', '--public-ip-id', entry['id']])
            except CliError as e:
                if e.status != 404:
                    raise
            else:
                raise Stop('DELETION_NOT_VERIFIED_OBJECT_STILL_READABLE')
            after = inventory(compartment)
            if any(r['id'] == entry['id'] or r['ip-address'] == entry['ip'] for r in after):
                raise Stop('DELETION_NOT_VERIFIED_INVENTORY')
            if snapshot(after) != baseline:
                raise Stop('ORIGINAL_INVENTORY_CHANGED_STOP')
            entry['status'] = 'ABSENCE_VERIFIED'
            save(journal, state)
            print('ABSENCE_VERIFIED=' + entry['id'], flush=True)
        else:
            state['status'] = 'no_match_budget_exhausted'
        final = snapshot(inventory(compartment))
        if state['status'] == 'matched':
            match = state['attempts'][-1]
            if final.pop(match['id'], None) is None:
                raise Stop('RETAINED_MATCH_MISSING')
        if final != baseline:
            raise Stop('ORIGINAL_INVENTORY_CHANGED_STOP')
        save(journal, state)
        return state
    except BaseException as e:
        state['status'] = 'STOPPED_REVIEW_JOURNAL_NO_RESTART'
        state['error'] = str(e) if isinstance(e, Stop) else type(e).__name__
        save(journal, state)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compartment-id', required=True)
    parser.add_argument('--apply', action='store_true', help='Actually create up to7 new IPs and delete only own nonmatches.')
    args = parser.parse_args()
    if not re.fullmatch(r'ocid1\.(?:tenancy|compartment)\.oc1\.[A-Za-z0-9.]+', args.compartment_id):
        raise Stop('EXPLICIT_COMPARTMENT_OCID_REQUIRED')
    directory = Path.home() / '.proxy-ip-selection-20261108'
    if not args.apply:
        print(json.dumps({'scope': 'READ_ONLY', 'region': REGION,
                         'inventory': snapshot(inventory(args.compartment_id)),
                         'journal_exists': (directory / 'state.json').exists()}, indent=2))
        return
    if directory.is_symlink():
        raise Stop('JOURNAL_DIRECTORY_SYMLINK_REFUSED')
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise Stop('PRIVATE_OWNED_JOURNAL_DIRECTORY_REQUIRED')
    state = select(args.compartment_id, directory / 'state.json')
    print('FINAL_STATUS=' + state['status'])
    print('JOURNAL=' + str(directory / 'state.json'))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('STOPPED=' + (str(e) if isinstance(e, Stop) else type(e).__name__), file=sys.stderr)
        print('Review ~/.proxy-ip-selection-20261108/state.json; do not rerun --apply or erase the journal.', file=sys.stderr)
        sys.exit(2)
