import importlib.util
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('oci_audit',Path(__file__).with_name('udp_return_oci_audit.py'))
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)


class FlowRedactionTest(unittest.TestCase):
    def test_only_fixed_flow_metadata_is_returned_without_credentials_or_bodies(self):
        event={'sourceAddress':'10.0.0.6','destinationAddress':'111.55.79.240','protocol':17,'sourcePort':443,'destinationPort':56990,
               'action':'ACCEPT','packets':3,'bytesOut':360,'startTime':100,'endTime':160,'authorization':'SYNTHETIC_SECRET','body':'SYNTHETIC_SECRET'}
        for record in ({'data':event},{'logContent':{'data':event,'requestHeaders':'SYNTHETIC_SECRET'}}):
            safe=audit.flow(record);self.assertEqual(safe['packets'],3);self.assertEqual(safe['startTime'],100)
            self.assertNotIn('SYNTHETIC_SECRET',json.dumps(safe))
        event['sourceAddress']='OTHER_USER'
        self.assertIsNone(audit.flow({'data':event}))

    def test_skipdata_and_missing_counts_do_not_create_zero_delivery_evidence(self):
        self.assertEqual(audit.flow({'data':{'status':'SKIPDATA','startTime':10,'authorization':'secret'}}),{'status':'SKIPDATA','startTime':10})
        self.assertIsNone(audit.flow({'data':None}))
        self.assertIsNone(audit.flow({'logContent':None}))
