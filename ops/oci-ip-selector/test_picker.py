import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('picker', Path(__file__).with_name('pick_reserved_ip.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
COMP = 'ocid1.tenancy.oc1..test'


class PickerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.journal = Path(self.tmp.name) / 'state.json'
        self.rows = {}
        for n, ip in enumerate(sorted(m.PROTECTED_IPS)):
            key = 'ocid1.publicip.oc1.uk-london-1.existing' + str(n)
            self.rows[key] = {'id': key, 'ip-address': ip, 'compartment-id': COMP,
                              'lifetime': 'RESERVED', 'lifecycle-state': 'ASSIGNED',
                              'private-ip-id': 'protected-' + str(n)}
        self.initial = copy.deepcopy(self.rows)
        self.addresses = ['79.72.82.' + str(n) for n in range(100, 107)]
        self.created = []; self.deleted = []; self.bad_owner = False; self.fail_delete = False
        self.lose_creation = False
        self.addCleanup(patch.stopall)
        self.real_cli = m.cli
        patch.object(m, 'cli', side_effect=self.cli).start()

    def cli(self, args, request_id=None):
        op = args[0]
        if op == 'list':
            self.assertIn('--all', args)
            return {'data': copy.deepcopy(list(self.rows.values()))}
        if op == 'create':
            self.assertTrue(self.journal.exists())
            saved = json.loads(self.journal.read_text())
            self.assertEqual(saved['attempts'][-1]['status'], 'creation_intent')
            self.assertIsNotNone(request_id)
            n = len(self.created)
            key = 'ocid1.publicip.oc1.uk-london-1.new' + str(n)
            row = {'id': key, 'ip-address': self.addresses[n], 'compartment-id': COMP,
                   'lifetime': 'RESERVED', 'lifecycle-state': 'AVAILABLE',
                   'display-name': args[args.index('--display-name') + 1],
                   'freeform-tags': json.loads(args[args.index('--freeform-tags') + 1]),
                   'time-created': '2026-11-08T10:00:00Z'}
            self.rows[key] = row; self.created.append(key)
            if self.lose_creation:raise TimeoutError('response lost')
            return {'data': copy.deepcopy(row)}
        key = args[args.index('--public-ip-id') + 1]
        self.assertNotIn(key, self.initial)  # No GET/delete selection of a protected object.
        if op == 'get':
            if key not in self.rows:raise m.CliError('NotAuthorizedOrNotFound', 404)
            row = copy.deepcopy(self.rows[key])
            if self.bad_owner:row['private-ip-id'] = 'foreign-binding'
            return {'data': row}
        if op == 'delete':
            self.assertIn('--force', args)
            saved = json.loads(self.journal.read_text())
            raw = Path(self.tmp.name) / saved['attempts'][-1]['raw_response']
            self.assertEqual(json.loads(raw.read_text())['data']['id'], key)
            if self.fail_delete:raise m.CliError('NotAuthorizedOrNotFound', 404)
            self.deleted.append(key); self.rows.pop(key)
            return {}
        raise AssertionError(op)

    def test_budget7_only_owned_nonmatches_removed_preserves_all_originals(self):
        result = m.select(COMP, self.journal)
        self.assertEqual(result['status'], 'no_match_budget_exhausted')
        self.assertEqual(len(self.created), 7); self.assertEqual(len(self.deleted), 7)
        self.assertEqual(self.rows, self.initial)
        with self.assertRaisesRegex(m.Stop, 'JOURNAL_EXISTS'):m.select(COMP, self.journal)
        self.assertEqual(len(self.created), 7)

    def test_first_match_is_retained_unbound_no_further_creations(self):
        self.addresses[0] = '144.21.55.100'
        result = m.select(COMP, self.journal)
        self.assertEqual(result['status'], 'matched')
        self.assertEqual(len(self.created), 1); self.assertEqual(self.deleted, [])
        match = self.rows[self.created[0]]
        self.assertIsNone(m.binding(match)); self.assertEqual(match['lifecycle-state'], 'AVAILABLE')
        self.assertTrue(all(self.rows[k] == v for k, v in self.initial.items()))

    def test_live_binding_change_prevents_any_delete_or_next_create(self):
        self.bad_owner = True
        with self.assertRaisesRegex(m.Stop, 'LIVE_OBJECT'):m.select(COMP, self.journal)
        self.assertEqual(len(self.created), 1); self.assertEqual(self.deleted, [])
        self.assertEqual(json.loads(self.journal.read_text())['status'], 'STOPPED_REVIEW_JOURNAL_NO_RESTART')

    def test_delete404_but_get_still_present_does_not_claim_cleanup(self):
        self.fail_delete = True
        with self.assertRaisesRegex(m.Stop, 'STILL_READABLE'):m.select(COMP, self.journal)
        self.assertEqual(len(self.created), 1); self.assertEqual(self.deleted, [])

    def test_lost_create_response_records_intent_stops_and_refuses_restart(self):
        self.lose_creation = True
        with self.assertRaises(TimeoutError):m.select(COMP, self.journal)
        self.assertEqual(len(self.created), 1)
        self.assertEqual(json.loads(self.journal.read_text())['attempts'][0]['status'], 'creation_intent')
        with self.assertRaisesRegex(m.Stop, 'JOURNAL_EXISTS'):m.select(COMP, self.journal)
        self.assertEqual(len(self.created), 1)

    def test_unexpected_existing_inventory_refuses_creation(self):
        self.rows['foreign'] = {**next(iter(self.rows.values())), 'id': 'foreign', 'ip-address': '145.1.1.1'}
        with self.assertRaisesRegex(m.Stop, 'EXPECTED_FOUR'):m.select(COMP, self.journal)
        self.assertEqual(self.created, [])

    def test_pattern_uses_actual_requested_second_two_digits_and_last_three_digits(self):
        self.assertTrue(m.matches('144.21.55.100'))
        self.assertTrue(m.matches('144.21.255.250'))
        for ip in ['141.147.65.110', '79.72.85.100', '144.21.55.90', '144.21.55.255']:
            self.assertFalse(m.matches(ip), ip)

    def test_cli_disables_retries_and_attaches_client_request_id(self):
        from types import SimpleNamespace
        with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(returncode=0,stdout='{}')) as proc:
            self.real_cli(['list', '--scope', 'REGION', '--all'], request_id='test-correlation')
        args = proc.call_args.args[0]
        self.assertIn('--no-retry', args)
        self.assertEqual(args[args.index('--region') + 1], 'uk-london-1')
        self.assertEqual(args[args.index('--opc-client-request-id') + 1], 'test-correlation')
        self.assertNotIn('--debug', args)

    def test_parallel_invocation_is_refused_without_cloud_calls(self):
        import os,fcntl
        fd=os.open(self.journal.with_name('run.lock'), os.O_CREAT|os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.Stop,'RUN_ALREADY_ACTIVE'):m.select(COMP,self.journal)
        finally:os.close(fd)
        self.assertEqual(self.created,[])

if __name__ == '__main__':unittest.main()
