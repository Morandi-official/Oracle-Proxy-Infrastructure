import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('choice',Path(__file__).with_name('choose_reserved_ips.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
COMP='ocid1.tenancy.oc1..test'


class ChoiceTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'state.json';self.now=1800000000;self.created=[];self.deleted=[]
        self.rows={}
        for n,ip in enumerate(sorted(c.ORIGINAL_IPS)):
            key='ocid1.publicip.oc1.uk-london-1.original'+str(n)
            self.rows[key]={'id':key,'ip-address':ip,'compartment-id':COMP,'lifetime':'RESERVED',
                            'lifecycle-state':'ASSIGNED','private-ip-id':'protected'+str(n)}
        self.original=copy.deepcopy(self.rows);self.fail_at=None;self.foreign=False;self.lose=False
        self.addCleanup(patch.stopall)
        patch.object(c.api,'cli',side_effect=self.cli).start()
        patch.object(c.api,'quota',side_effect=lambda comp:{'available':max(0,6-len(self.rows)),'used':len(self.rows)}).start()
        patch.object(c.time,'time',side_effect=lambda:self.now).start()
        patch.object(c.time,'sleep',side_effect=self.sleep).start()

    def sleep(self,seconds):self.now+=seconds

    def cli(self,args,request_id=None):
        if args[0]=='list':
            self.assertIn('--all',args);return {'data':copy.deepcopy(list(self.rows.values()))}
        if args[0]=='create':
            intent=json.loads(self.path.read_text())['attempts'][-1]
            self.assertEqual(intent['status'],'creation_intent');self.assertIsNotNone(request_id)
            if self.fail_at==len(self.created):raise c.api.CliError('TooManyRequests',429,{'message':'test rate limit'})
            n=len(self.created);key='ocid1.publicip.oc1.uk-london-1.choice'+str(n)
            row={'id':key,'ip-address':'144.21.55.'+str(100+n),'display-name':args[args.index('--display-name')+1],
                 'freeform-tags':json.loads(args[args.index('--freeform-tags')+1]),'compartment-id':COMP,
                 'lifetime':'RESERVED','lifecycle-state':'AVAILABLE','time-created':'2026-11-08T12:00:00Z'}
            self.rows[key]=row;self.created.append(key)
            if self.lose:raise TimeoutError()
            return {'data':copy.deepcopy(row)}
        key=args[args.index('--public-ip-id')+1];self.assertNotIn(key,self.original)
        if args[0]=='get':
            if key not in self.rows:raise c.api.CliError('NotAuthorizedOrNotFound',404)
            row=copy.deepcopy(self.rows[key])
            if self.foreign:row['private-ip-id']='foreign-binding'
            return {'data':row}
        if args[0]=='delete':
            state=json.loads(self.path.read_text());record=next(x for x in state['attempts'] if x.get('id')==key)
            self.assertEqual(json.loads(self.path.with_name(record['raw_response']).read_text())['data']['id'],key)
            self.deleted.append(key);self.rows.pop(key);return {}
        raise AssertionError(args)

    def test_first_batch_holds4_and_does_not_autodelete_any_candidate(self):
        s=c.process(COMP,self.path,create=True)
        self.assertEqual(len(c.held(s)),4);self.assertEqual(len(self.created),4);self.assertEqual(self.deleted,[])
        self.assertEqual(len(self.rows),6)
        c.process(COMP,self.path,create=True)
        self.assertEqual(len(self.created),4)

    def test_delete_only_user_selected_candidates_then_refill_free_slots(self):
        c.process(COMP,self.path,create=True)
        s=c.process(COMP,self.path,discard=(2,4))
        self.assertEqual([x['number'] for x in c.held(s)],[1,3])
        s=c.process(COMP,self.path,create=True)
        self.assertEqual(len(c.held(s)),4);self.assertEqual(len(self.created),6)
        self.assertTrue(all(self.rows[k]==v for k,v in self.original.items()))

    def test_cap10_survives_multiple_batches_and_restart(self):
        s=c.process(COMP,self.path,create=True)
        c.process(COMP,self.path,discard=tuple(x['number'] for x in c.held(s)))
        s=c.process(COMP,self.path,create=True)
        c.process(COMP,self.path,discard=tuple(x['number'] for x in c.held(s)))
        s=c.process(COMP,self.path,create=True)
        self.assertEqual(len(self.created),10);self.assertEqual(len(s['attempts']),10)
        c.process(COMP,self.path,create=True);self.assertEqual(len(self.created),10)

    def test_refuses_extra_old_resources_before_new_round(self):
        row=copy.deepcopy(next(iter(self.rows.values())));row.update(id='extra',**{'ip-address':'79.72.85.11'})
        self.rows['extra']=row
        with self.assertRaisesRegex(c.api.Stop,'REMOVE_EXTRA'):c.process(COMP,self.path,create=True)
        self.assertEqual(self.created,[])

    def test_binding_changed_after_journal_prevents_delete(self):
        c.process(COMP,self.path,create=True);self.foreign=True
        with self.assertRaises(c.api.Stop):c.process(COMP,self.path,discard=(1,))
        self.assertEqual(self.deleted,[])

    def test_rejected_create_keeps_prior_candidates_and_does_not_reset_budget(self):
        self.fail_at=1
        with self.assertRaises(c.api.CliError):c.process(COMP,self.path,create=True)
        state=json.loads(self.path.read_text())
        self.assertEqual(len(state['attempts']),2);self.assertEqual(state['attempts'][-1]['status'],'REJECTED')
        self.assertEqual(len(c.held(state)),1)
        self.assertGreaterEqual(state['next_create_at'],self.now+900)
        self.fail_at=None
        state=c.process(COMP,self.path,create=True)
        self.assertEqual(len(state['attempts']),5);self.assertEqual(len(c.held(state)),4)

    def test_lost_creation_response_is_not_retried_or_deleted_without_identity(self):
        self.lose=True
        with self.assertRaises(TimeoutError):c.process(COMP,self.path,create=True)
        with self.assertRaises(c.api.Stop):c.process(COMP,self.path,create=True)
        self.assertEqual(len(self.created),1);self.assertEqual(self.deleted,[])

    def test_original_binding_change_stops_before_creation(self):
        c.process(COMP,self.path,create=True)
        self.rows[next(iter(self.original))]['private-ip-id']='different'
        with self.assertRaisesRegex(c.api.Stop,'ORIGINAL_IP'):c.process(COMP,self.path,create=True)
        self.assertEqual(len(self.created),4)

if __name__=='__main__':unittest.main()
