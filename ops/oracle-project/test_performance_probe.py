import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import io

spec=importlib.util.spec_from_file_location('performance',Path(__file__).with_name('performance_probe.py'))
performance=importlib.util.module_from_spec(spec);spec.loader.exec_module(performance)

class ProbeTests(unittest.TestCase):
    def test_instance_response_never_exports_identity_tokens_or_tags(self):
        body=io.BytesIO(b'{"id":"PRIVATE","metadata":{"secret":"PRIVATE"},"freeformTags":{"secret":"PRIVATE"},"shape":"VM.Standard.E2.1.Micro","region":"uk-london-1","shapeConfig":{"ocpus":1,"memoryInGBs":1,"unknown":"PRIVATE"}}')
        with patch.object(performance.OPEN,'open',return_value=body):value=performance.metadata()
        self.assertNotIn('PRIVATE',str(value));self.assertEqual(value['shape_config'],{'ocpus':1,'memoryInGBs':1})
    def test_http_error_exports_only_category_and_status(self):
        with patch.object(performance.OPEN,'open',side_effect=OSError('PRIVATE')):value=performance.http_probe('fixed','https://github.com/')
        self.assertEqual(value['error_category'],'OSError');self.assertNotIn('PRIVATE',str(value))
    def test_udp_metrics_ignore_unrelated_protocols_and_unrecognized_fields(self):
        body='Tcp: Secret\nTcp: 123\nUdp: InDatagrams RcvbufErrors SndbufErrors Private\nUdp: 100 2 3 999\n'
        self.assertEqual(performance.udp_counters(body),{'InDatagrams':100,'RcvbufErrors':2,'SndbufErrors':3})
        self.assertEqual(performance.udp_counters('Udp: InErrors\nUdp: private\n'),{})
    def test_qdisc_exports_counters_not_arbitrary_options(self):
        from types import SimpleNamespace
        output='[{"kind":"fq_codel","dev":"ens3","drops":0,"options":{"secret":"PRIVATE"},"handle":"PRIVATE"}]'
        with patch.object(performance.subprocess,'run',return_value=SimpleNamespace(stdout=output)) as call:
            value=performance.qdiscs()
        self.assertNotIn('PRIVATE',str(value))
        self.assertEqual(value['queues'],[{'kind':'fq_codel','dev':'ens3','drops':0}])
        self.assertEqual(call.call_args.args[0],['tc','-j','-s','qdisc','show'])
    def test_download_budget_is_bounded(self):
        self.assertEqual(performance.MAX_DOWNLOAD,8*1024*1024)

if __name__=='__main__':unittest.main()
