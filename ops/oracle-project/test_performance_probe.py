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
    def test_download_budget_is_bounded(self):
        self.assertEqual(performance.MAX_DOWNLOAD,8*1024*1024)

if __name__=='__main__':unittest.main()
