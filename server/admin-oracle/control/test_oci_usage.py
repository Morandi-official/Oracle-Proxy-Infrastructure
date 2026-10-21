import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

spec=importlib.util.spec_from_file_location('oci_probe',Path(__file__).with_name('oci_usage.py'))
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)

class ReadOnlyUsageTests(unittest.TestCase):
 def test_no_metadata_never_invents_a_balance_or_exports_exception(self):
  with patch.object(probe,'metadata',side_effect=OSError('SECRET_SESSION_TOKEN')):
   result=probe.collect()
  self.assertIsNone(result['remaining_bytes']);self.assertIsNone(result['vnic_outbound_bytes'])
  self.assertNotIn('SECRET_SESSION_TOKEN',json.dumps(result));self.assertEqual(result['status'],'METADATA_UNAVAILABLE')
 def test_error_mapping_and_nonfinite_or_negative_metrics_are_rejected(self):
  for status in (401,403,404):self.assertEqual(probe.error_code(type('ApiError',(),{'status':status})()),'IAM_OR_RESOURCE_ACCESS_DENIED')
  for number in ('nan','inf',-1):
   with self.assertRaises(ValueError):probe.finite(number)
 def test_cache_atomic_mode_and_metadata_only_fixed_v2_resource(self):
  with tempfile.TemporaryDirectory() as temporary,patch.object(probe,'CACHE',Path(temporary)/'usage.json'):
   probe.write_cache({'status':'IAM_OR_RESOURCE_ACCESS_DENIED','remaining_bytes':None})
   self.assertEqual(probe.CACHE.stat().st_mode & 0o777,0o600)
   self.assertIsNone(json.loads(probe.CACHE.read_text())['remaining_bytes'])
  for path in ('identity/key.pem','../instance/','http://example.invalid/'):
   with self.assertRaises(ValueError):probe.metadata(path)
