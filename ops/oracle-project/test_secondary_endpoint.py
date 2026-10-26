import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('secondary_test',Path(__file__).with_name('secondary_endpoint.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class SecondaryEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.addresses=[{'local':m.PRIMARY,'prefixlen':24,'label':m.DEVICE,'scope':'global'}]
        self.events=[];self.source=m.PRIMARY;self.break_source=False
        for name,value in [('STATE',Path(self.tmp.name)/'state.json'),('owned_file',lambda p:None),
                           ('metadata',lambda:[{'privateIp':m.PRIMARY,'secondaryPrivateIps':[m.SECONDARY]}]),
                           ('arm_rollback',lambda token:self.events.append('timer')),('run',self.fake_run)]:
            stub=patch.object(m,name,value);stub.start();self.addCleanup(stub.stop)

    def fake_run(self,argv):
        if argv[0]=='systemctl':return SimpleNamespace(stdout='active\n')
        if 'address' in argv and '-j' in argv:value=[{'ifname':m.DEVICE,'addr_info':self.addresses}]
        elif 'route' in argv and 'get' in argv:value=[{'dev':m.DEVICE,'prefsrc':self.source,'dst':argv[-1]}]
        elif 'route' in argv:value=[{'dev':m.DEVICE,'prefsrc':m.PRIMARY,'dst':'default'}]
        elif 'rule' in argv:value=[{'src':'all','table':'local'},{'src':'all','table':'main'},{'src':'all','table':'default'}]
        elif 'add' in argv:
            self.events.append('add');self.assertIn('noprefixroute',argv)
            self.addresses.append({'local':m.SECONDARY,'prefixlen':32,'label':m.LABEL,'scope':'global'})
            if self.break_source:self.source=m.SECONDARY
            value={}
        elif 'del' in argv:
            self.events.append('del');self.addresses=[x for x in self.addresses if x['local']!=m.SECONDARY]
            self.source=m.PRIMARY;value={}
        else:raise AssertionError('Unexpected argv')
        return SimpleNamespace(stdout=json.dumps(value))

    def test_timer_precedes_address_and_apply_is_idempotent_without_lease_extension(self):
        m.apply_locked();state=m.load_state()
        self.assertEqual(self.events,['timer','add'])
        m.apply_locked();self.assertEqual(self.events,['timer','add'])
        self.assertEqual(m.load_state()['expires_at'],state['expires_at'])
        self.assertTrue(m.owned_alias(m.snapshot()[1]))
        m.rollback_locked(state['lease_id']);self.assertEqual(self.events,['timer','add','del'])
        self.assertEqual(m.load_state()['phase'],'rolled_back')

    def test_unverified_imds_or_foreign_existing_alias_cannot_change_address(self):
        with patch.object(m,'metadata',return_value=[{'privateIp':m.PRIMARY,'secondaryPrivateIps':[]}]):
            with self.assertRaisesRegex(ValueError,'IMDS'):m.apply_locked()
        self.assertEqual(self.events,[])
        self.addresses.append({'local':m.SECONDARY,'prefixlen':24,'label':m.DEVICE})
        with self.assertRaises((ValueError,OSError)):m.apply_locked()
        self.assertEqual(self.events,[])

    def test_failed_source_invariant_still_removes_only_the_owned_alias(self):
        self.break_source=True
        with self.assertRaisesRegex(ValueError,'PRIMARY_EGRESS'):m.apply_locked()
        self.assertEqual(self.events,['timer','add','del'])
        self.assertEqual(len(self.addresses),1)

    def test_failed_timer_prevents_any_interface_change(self):
        with patch.object(m,'arm_rollback',side_effect=ValueError('TIMER_FAILED')):
            with self.assertRaisesRegex(ValueError,'TIMER_FAILED'):m.apply_locked()
        self.assertEqual(self.events,[]);self.assertEqual(len(self.addresses),1)

    def test_stale_timer_cannot_delete_a_new_lease_and_foreign_alias_cannot_be_deleted(self):
        m.apply_locked();state=m.load_state()
        m.rollback_locked('0'*32);self.assertNotIn('del',self.events)
        self.addresses[-1]['label']='foreign'
        with self.assertRaisesRegex(ValueError,'FOREIGN_ALIAS'):m.rollback_locked(state['lease_id'])
        self.assertNotIn('del',self.events)

    def test_metadata_requires_the_exact_primary_and_secondary_pair(self):
        self.assertFalse(m.allocated([{'privateIp':'10.0.0.99','secondaryPrivateIps':[m.SECONDARY]}]))
        self.assertFalse(m.allocated([{'privateIp':m.PRIMARY,'secondaryPrivateIps':m.SECONDARY}]))
        self.assertTrue(m.allocated([{'privateIp':m.PRIMARY,'secondaryPrivateIps':[m.SECONDARY]}]))
