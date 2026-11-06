import importlib.util
from pathlib import Path
import socket
import struct
import unittest
import uuid
import threading

spec=importlib.util.spec_from_file_location('udp_capture',Path(__file__).with_name('udp_capture.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def packet(kind=1,index=123,receiver=456,outgoing=False,port=443,udp_length=None):
    size=20+(20 if kind==2 else 16)
    value=bytearray(size);value[0]=0x45;value[9]=17
    value[12:16]=socket.inet_aton('10.0.0.6' if outgoing else '192.0.2.7')
    value[16:20]=socket.inet_aton('192.0.2.7' if outgoing else '10.0.0.6')
    struct.pack_into('!HHH',value,20,port if outgoing else 40000,40000 if outgoing else port,udp_length or {1:156,2:100,3:72,4:40}[kind])
    struct.pack_into('<II',value,28,kind,index)
    if kind==2:struct.pack_into('<I',value,36,receiver)
    return value


class CaptureTest(unittest.TestCase):
    def test_sender_and_receiver_are_correlated_not_unrelated_clients(self):
        rows=[]
        for value,out in [(packet(index=123),False),(packet(index=999),False),
                          (packet(kind=2,index=345,receiver=123,outgoing=True),True),
                          (packet(kind=2,index=345,receiver=999,outgoing=True),True)]:
            rows.append({**module.parse(value,out),'at':10})
        result=module.summarize(rows,'152.67.156.100',443,[123],9)
        self.assertEqual(result['rx_initiations'],1)
        self.assertEqual(result['tx_responses'],1)
        self.assertFalse(result['authentication_proof'])
        self.assertNotIn('192.0.2.7',str(rows))

    def test_address_port_and_window_scope(self):
        row={**module.parse(packet(index=123),False),'at':10}
        for address,port,since in [('141.147.78.44',443,9),('152.67.156.100',8443,9),('152.67.156.100',443,11)]:
            self.assertEqual(module.summarize([row],address,port,[123],since)['rx_initiations'],0)

    def test_data_or_unfamiliar_packet_never_records_payload(self):
        self.assertIsNone(module.parse(packet(kind=4),False))
        self.assertIsNone(module.parse(packet(udp_length=155),False))
        for length in range(36):self.assertIsNone(module.parse(packet()[:length],False))
        malformed=packet();malformed[6:8]=b'\0\1';self.assertIsNone(module.parse(malformed,False))
        malformed=packet();malformed[9]=6;self.assertIsNone(module.parse(malformed,False))

    def test_cookie_and_unsigned_index_boundaries(self):
        row=module.parse(packet(kind=3,index=2**32-1,outgoing=True),True)
        self.assertEqual(row['client_index'],2**32-1)
        self.assertEqual(row['kind'],'cookie')
        for indices in ([True],[-1],[2**32],[1]*17,'123'):
            with self.assertRaises(ValueError):module.summarize([],'152.67.156.100',443,indices,0)


class ManagerTest(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('manager',Path(__file__).with_name('udp_diagnostics.py'))
        manager=importlib.util.module_from_spec(spec);spec.loader.exec_module(manager)
        class FakeCapture:
            status='observing'
            def __init__(self):self.closed=False;self.ready=threading.Event();self.ready.set()
            def close(self):self.closed=True
            def report(self,*args):return {'rx_initiations':0,'tx_responses':0,'complete_observation':True}
        self.now=10;self.manager=manager.Manager(clock=lambda:self.now,factory=FakeCapture)
        self.peer={'handshake':1,'usage':{'rx':0,'tx':0}}
        self.data={'diagnostic_id':str(uuid.uuid4()),'public_key':'test-peer'}
        self.call('start')
    def call(self,operation,**extra):return self.manager.call('udp-diagnostic.'+operation,{**self.data,**extra},self.peer)
    def test_ownership_limit_and_expiry(self):
        with self.assertRaisesRegex(ValueError,'OWNER_MISMATCH'):
            self.call('finish',public_key='other-peer')
        with self.assertRaisesRegex(ValueError,'BUSY'):
            self.call('start',diagnostic_id=str(uuid.uuid4()))
        captured=self.manager.sessions[self.data['diagnostic_id']]['capture'];self.now=191
        with self.assertRaisesRegex(ValueError,'EXPIRED_OR_RESTARTED'):self.call('finish')
        self.assertTrue(captured.closed);self.assertFalse(self.manager.sessions)
    def test_six_steps_no_duplicates_and_authentication_separate(self):
        for address in module.ADDRESSES:
            for port in module.PORTS:
                self.call('begin',address=address,port=port)
                with self.assertRaisesRegex(ValueError,'STEP_CONFLICT'):self.call('begin',address=address,port=port)
                result=self.call('sample',sender_indices=[123],complete=True)
                self.assertFalse(result['kernel_handshake_advanced'])
                with self.assertRaisesRegex(ValueError,'STEP_CONFLICT'):self.call('begin',address=address,port=port)
        result=self.call('finish');self.assertEqual(len(result['trials']),6);self.assertFalse(self.manager.sessions)
    def test_unknown_fields_and_indices_refused_without_closing(self):
        with self.assertRaisesRegex(ValueError,'INVALID_DIAGNOSTIC_FIELDS'):self.call('finish',private_key='SYNTHETIC_SECRET')
        self.call('begin',address='152.67.156.100',port=443)
        with self.assertRaises(ValueError):self.call('sample',sender_indices=[True],complete=True)
        self.assertEqual(self.call('finish')['trials'][0]['index_correlation_available'],False)

if __name__=='__main__':unittest.main()
