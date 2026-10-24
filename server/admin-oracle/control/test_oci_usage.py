import importlib.util
import datetime as dt
import json
import tempfile
import sys
from types import SimpleNamespace as NS
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
   probe.write_cache({'status':'IAM_OR_RESOURCE_ACCESS_DENIED','remaining_bytes':None,'checked_at':1})
   self.assertEqual(probe.CACHE.stat().st_mode & 0o777,0o600)
   self.assertIsNone(json.loads(probe.CACHE.read_text())['remaining_bytes'])
  for path in ('identity/key.pem','../instance/','http://example.invalid/'):
   with self.assertRaises(ValueError):probe.metadata(path)

 def test_hourly_range_includes_today_but_excludes_partial_hour(self):
  now=dt.datetime(2026,10,21,18,13,tzinfo=dt.timezone(dt.timedelta(hours=8)))
  start,end=probe.billing_range(now)
  self.assertEqual(start,dt.datetime(2026,10,1,tzinfo=dt.timezone.utc))
  self.assertEqual(end,dt.datetime(2026,10,21,10,tzinfo=dt.timezone.utc))
  start,end=probe.billing_range(dt.datetime(2026,11,1,0,13,tzinfo=dt.timezone.utc))
  self.assertEqual(start,end)
 def test_error_diagnostics_do_not_export_messages_headers_or_arbitrary_service_codes(self):
  error=type('ServiceError',(Exception,),{'status':400,'code':'InvalidParameter','headers':{'authorization':'SECRET'}})('SECRET_REQUEST_BODY')
  details=probe.error_details(error)
  self.assertEqual(details,{'http_status':400,'category':'HTTP_ERROR','service_code':'InvalidParameter'})
  self.assertNotIn('SECRET',json.dumps(details))
  error.code='SECRET_SESSION_TOKEN';self.assertEqual(probe.error_details(error)['service_code'],'OTHER')
  self.assertEqual(probe.error_details(AttributeError('SECRET'))['category'],'SDK_RESPONSE_ERROR')

 def fake_collect(self,quantity,part="",pages=1):
  class Frozen(dt.datetime):
   @classmethod
   def now(cls,tz=None):return cls(2026,10,21,10,13,tzinfo=dt.timezone.utc)
  key='ocid1.vnic.oc1..fixture';calls=[]
  def billing(details,**kwargs):
   calls.append(details)
   next_page='second' if pages==2 and not kwargs.get('page') else 'repeat' if pages==-1 else None
   return NS(data=NS(items=[NS(sku_name='Outbound Data Transfer Zone 1',sku_part_number=part,unit='GB Months',computed_quantity=quantity)]),headers={'opc-next-page':next_page} if next_page else {})
  monitor=NS(summarize_metrics_data=lambda *a,**k:NS(data=[NS(name='VnicToNetworkBytes',dimensions={'resourceId':key},aggregated_datapoints=[NS(value=100,timestamp=Frozen(2026,10,20,tzinfo=dt.timezone.utc))])]))
  modules={
   'oci.auth.signers':NS(InstancePrincipalsSecurityTokenSigner=lambda **k:NS(tenancy_id='ocid1.tenancy.fixture')),
   'oci.retry':NS(NoneRetryStrategy=lambda:None),
   'oci.monitoring':NS(MonitoringClient=lambda *a,**k:monitor),
   'oci.monitoring.models':NS(SummarizeMetricsDataDetails=lambda **k:NS(**k)),
   'oci.usage_api':NS(UsageapiClient=lambda *a,**k:NS(request_summarized_usages=billing)),
   'oci.usage_api.models':NS(RequestSummarizedUsagesDetails=lambda **k:NS(**k))}
  metadata={'id':'ocid1.instance.fixture','region':'us-ashburn-1','compartmentId':'ocid1.compartment.fixture','timeCreated':1791763200000}
  with patch.dict(sys.modules,modules),patch.object(probe,'metadata',side_effect=lambda path:metadata if path=='instance/' else [{'vnicId':key}]),patch.object(probe.dt,'datetime',Frozen):
   result=probe.collect()
  return result,calls
 def test_full_collection_uses_complete_hourly_range_and_preserves_metric_history(self):
  result,calls=self.fake_collect(2.5)
  self.assertEqual(calls[0].time_usage_ended,dt.datetime(2026,10,21,10,tzinfo=dt.timezone.utc))
  self.assertEqual(calls[0].granularity,'HOURLY')
  self.assertEqual(calls[0].time_usage_started,dt.datetime(2026,10,1,tzinfo=dt.timezone.utc))
  self.assertEqual(result['billing_status'],'ROWS_REQUIRE_SKU_REVIEW')
  self.assertEqual(result['billing_rows'][0]['quantity'],2.5)
  self.assertEqual(result['vnic_outbound_bytes'],100)
  self.assertEqual(result['instance_created_at'],1791763200)
  self.assertIsNone(result['remaining_bytes'])
 def test_missing_billing_quantity_cannot_be_silently_zero(self):
  result,_=self.fake_collect(None)
  self.assertEqual(result['billing_status'],'API_UNAVAILABLE')
  self.assertEqual(result['billing_error_category'],'SDK_VALIDATION_ERROR')
  self.assertEqual(result['vnic_outbound_bytes'],100)
  self.assertIsNone(result['remaining_bytes'])

 def test_known_official_sku_and_original_api_unit_produce_delayed_free_balance(self):
  result,calls=self.fake_collect(1.25,'B88327')
  self.assertEqual(result['billing_status'],'VERIFIED_USAGE_AND_PRICE_TIER')
  self.assertEqual(result['free_tier_limit_gb'],10240)
  self.assertEqual(result['free_tier_used_gb'],1.25)
  self.assertEqual(result['free_tier_remaining_gb'],10238.75)
  self.assertIsNone(result['remaining_bytes'])
  self.assertIn('skuPartNumber',calls[0].group_by)
 def test_all_billing_pages_are_aggregated_and_repeated_page_never_becomes_balance(self):
  result,calls=self.fake_collect(1.25,'B88327',pages=2)
  self.assertEqual(len(calls),2);self.assertEqual(result['free_tier_used_gb'],2.5)
  result,calls=self.fake_collect(1.25,'B88327',pages=-1)
  self.assertEqual(result['free_tier_status'],'PAGINATED_INCOMPLETE')
  self.assertIsNone(result['free_tier_remaining_gb'])
 def test_missing_unknown_mixed_zone_or_wrong_unit_does_not_invent_free_balance(self):
  row={'sku':'Outbound Data Transfer Zone 1','part_number':'B88327','unit':'GB Months','quantity':1.25}
  for rows in ([],[dict(row,part_number='UNKNOWN')],[dict(row,unit='OCPU Hours')],[row,dict(row,part_number='B93455')]):
   self.assertIsNone(probe.free_tier(rows,True)['free_tier_remaining_gb'])
  self.assertEqual(probe.free_tier([dict(row,quantity=10241)],True)['free_tier_remaining_gb'],0)

 def test_unchanged_bill_updates_query_clock_without_claiming_data_changed(self):
  with tempfile.TemporaryDirectory() as temporary,patch.object(probe,'CACHE',Path(temporary)/'usage.json'):
   value={'checked_at':100,'period':'2026-10','billing_rows':[{'quantity':1}],'billing_status':'VERIFIED_USAGE_AND_PRICE_TIER'}
   probe.write_cache(value);value['checked_at']=200;probe.write_cache(value)
   saved=json.loads(probe.CACHE.read_text());self.assertEqual(saved['checked_at'],200);self.assertEqual(saved['billing_changed_at'],100)
   value['checked_at']=300;value['billing_rows']=[{'quantity':2}];probe.write_cache(value)
   self.assertEqual(json.loads(probe.CACHE.read_text())['billing_changed_at'],300)
