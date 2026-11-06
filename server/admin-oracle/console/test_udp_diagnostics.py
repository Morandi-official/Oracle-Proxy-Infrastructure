import importlib.util
import json
from pathlib import Path
import time
import uuid
from django.test import TestCase
from . import test_client_api as fixtures
from .models import UdpDiagnostic

spec=importlib.util.spec_from_file_location('diagnostics',Path(__file__).resolve().parents[1]/'control/udp_diagnostics.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class FakeCapture:
    def __init__(self):self.status='observing';self.records=[];self.closed=False
    def close(self):self.closed=True;self.status='complete'
    def report(self,address,port,indices,since):
        return {**module.capture.summarize(self.records,address,port,indices,since),
                'capture_status':self.status,'complete_observation':self.closed,
                'socket_drops':0,'ring_evictions':0}


class UdpApiTests(TestCase):
    login=fixtures.ClientApiTests.login
    enroll=fixtures.ClientApiTests.enroll
    def setUp(self):
        fixtures.ClientApiTests.setUp(self)
        self.manager=module.Manager(factory=FakeCapture)
        self.engine.udp_diagnostics=self.manager
        self.token=self.login().json()['token']
        self.identity=str(uuid.uuid4())

    def post(self,value,token=None,**headers):
        return self.client.post('/api/client/udp-diagnostics',json.dumps(value),content_type='application/json',
                                secure=True,HTTP_AUTHORIZATION='Bearer '+(token or self.token),**headers)

    def start(self):
        response=self.post({'action':'start','diagnostic_id':self.identity})
        self.assertEqual(response.status_code,200,response.content)
        return response

    def begin(self,address='152.67.156.100',port=443):
        return self.post({'action':'begin','diagnostic_id':self.identity,'address':address,'port':port})

    def evidence(self,**values):
        client={'counters':{'tx_initiations':2,'rx_responses':0},'egress_verified':False,'error':'ORACLE_PROBE_TIMEOUT','elapsed_ms':12000}
        client.update(values)
        return {'action':'sample','diagnostic_id':self.identity,'sender_indices':[123],'complete':True,'client':client}

    def test_paired_evidence_saved_and_existing_device_slot_unchanged(self):
        before=self.engine.snapshot()['users'][0]['device_count']
        self.start();self.assertEqual(self.begin().status_code,200)
        row=self.manager.sessions[self.identity]
        for kind in ('initiation','response'):
            row['capture'].records.append({'at':time.monotonic(),'address':'152.67.156.100','port':443,
                'kind':kind,'client_index':123,'server_index':456,'outgoing':kind=='response','udp_bytes':156 if kind=='initiation' else 100})
        sampled=self.post(self.evidence());self.assertEqual(sampled.status_code,200,sampled.content)
        self.assertEqual(sampled.json()['verdict'],'RETURN_OR_LOCAL_RECEIVE_PATH')
        finished=self.post({'action':'finish','diagnostic_id':self.identity,'cancelled':False})
        self.assertEqual(finished.status_code,200,finished.content)
        self.assertTrue(finished.json()['server_capture_closed'])
        self.assertNotIn(self.identity,self.manager.sessions)
        saved=UdpDiagnostic.objects.get(pk=self.identity)
        self.assertEqual(saved.report['trials'][0]['server']['capture']['tx_responses'],1)
        self.assertEqual(saved.report['physical_nic_observation'],'not_collected')
        self.assertNotIn('private_key',json.dumps(saved.report))
        self.assertEqual(self.engine.snapshot()['users'][0]['device_count'],before)

    def test_other_device_cannot_read_or_finish_session(self):
        self.start();other=self.login(index=13).json()['token']
        response=self.post({'action':'finish','diagnostic_id':self.identity,'cancelled':True},token=other)
        self.assertEqual(response.status_code,400)
        self.assertEqual(response.json()['error'],'DIAGNOSTIC_NOT_FOUND')
        self.assertIn(self.identity,self.manager.sessions)

    def test_origin_bearer_and_admin_boundary(self):
        value={'action':'start','diagnostic_id':self.identity}
        self.assertEqual(self.post(value,HTTP_ORIGIN='https://foreign.invalid').status_code,401)
        self.assertEqual(self.post(value,token='x'*43).status_code,401)
        self.assertIn(self.client.get('/api/udp-diagnostics',secure=True).status_code,(401,403))
        self.assertEqual(UdpDiagnostic.objects.count(),0)

    def test_no_arbitrary_hosts_ports_or_secret_uploads(self):
        self.start()
        self.assertEqual(self.begin('127.0.0.1',22).status_code,400)
        self.assertEqual(self.begin(port=443).status_code,200)
        value=self.evidence();value['client']['private_key']='SYNTHETIC_SECRET'
        self.assertEqual(self.post(value).status_code,400)
        value=self.evidence();value['sender_indices']=[True]
        self.assertEqual(self.post(value).status_code,400)
        self.assertNotIn('SYNTHETIC_SECRET',json.dumps(UdpDiagnostic.objects.get(pk=self.identity).report))

    def test_cancel_closes_capture_and_never_resumes_or_connects(self):
        self.start();captured=self.manager.sessions[self.identity]['capture']
        finished=self.post({'action':'finish','diagnostic_id':self.identity,'cancelled':True})
        self.assertEqual(finished.status_code,200)
        self.assertTrue(captured.closed)
        self.assertEqual(UdpDiagnostic.objects.get(pk=self.identity).phase,'cancelled')

    def test_capture_incompleteness_cannot_be_called_forward_path_loss(self):
        self.start();self.begin()
        response=self.post(self.evidence())
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['verdict'],'INSUFFICIENT_OBSERVATION')

    def test_only_six_unique_endpoints_and_no_step_overlap(self):
        self.start();self.assertEqual(self.begin().status_code,200)
        self.assertEqual(self.begin(port=8443).status_code,400)
        self.post(self.evidence())
        self.assertEqual(self.begin().status_code,400)

    def test_second_active_diagnostic_on_same_device_refused(self):
        self.start()
        response=self.post({'action':'start','diagnostic_id':str(uuid.uuid4())})
        self.assertEqual(response.status_code,400)
        self.assertEqual(response.json()['error'],'DIAGNOSTIC_BUSY')
