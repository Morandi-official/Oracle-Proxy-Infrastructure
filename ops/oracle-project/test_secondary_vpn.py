import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('secondary_vpn_test',Path(__file__).with_name('secondary_vpn.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class PersistentIngressTests(unittest.TestCase):
    def test_nat_requires_native_typed_redirect_first_and_refuses_changed_owned_rules(self):
        native=['-A','PREROUTING','-p','udp','--dport','8443','--u32',
                '0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000',
                '--comment','oracle-proxy-native-udp8443','-j','REDIRECT','--to-ports','51820']
        own=['-A','PREROUTING',*m.RULE]
        for rows,error in [([],True),([native],False),([native,own],False),([own,native],True),
                           ([native,own,own],True),([native,own[:-1]+['10.0.0.99:8443']],True)]:
            with self.subTest(rows=rows),patch.object(m,'nat_rules',return_value=rows):
                if error:
                    with self.assertRaises(ValueError):m.inspect_nat()
                else:self.assertEqual(m.inspect_nat(),len(rows)>1)

    def test_promotion_rotates_old_timer_and_boot_restore_preserves_baseline(self):
        value={'baseline':{'defaults':'unchanged'},'phase':'active','lease_id':'a'*32,'expires_at':99}
        alias=[{'local':m.s.SECONDARY}];commands=[];published=[]
        def persist(v):value.update(v)
        def command(argv):
            commands.append(argv)
            if argv[0]=='ip':alias.append({'local':m.s.SECONDARY})
            return SimpleNamespace(stdout='')
        with patch.object(m.s,'snapshot',side_effect=lambda:(value['baseline'],alias)),\
             patch.object(m.s,'allocation_source',return_value='owner'),patch.object(m.s,'metadata',return_value=[]),\
             patch.object(m.s,'load_state',side_effect=lambda:dict(value)),patch.object(m.s,'persist',side_effect=persist),\
             patch.object(m.s,'owned_alias',side_effect=bool),patch.object(m.s,'run',side_effect=command),\
             patch.object(m,'inspect_nat',side_effect=[False,True,False,True]),\
             patch.object(m,'public_state',side_effect=published.append):
            m.ensure_locked();self.assertNotEqual(value['lease_id'],'a'*32)
            self.assertEqual(value['expires_at'],0);self.assertEqual(value['mode'],'persistent')
            token=value['lease_id'];alias.clear();m.ensure_locked()
            self.assertEqual(value['lease_id'],token);self.assertEqual(published,[True,True])
            self.assertEqual(sum(x[0]=='ip' for x in commands),1)
            self.assertTrue(all('route' not in x and 'flush' not in x for x in commands))

    def test_foreign_nat_cannot_be_deleted_and_public_config_is_disabled_first(self):
        events=[]
        with patch.object(m.s,'load_state',return_value={'vpn_nat_owned':True}),\
             patch.object(m,'public_state',side_effect=lambda b:events.append('metadata-off')),\
             patch.object(m,'nat_rules',return_value=[['-A','PREROUTING','--comment',m.COMMENT,'-j','ACCEPT']]),\
             patch.object(m.s,'run') as run,patch.object(m.s,'rollback_locked') as rollback:
            with self.assertRaisesRegex(ValueError,'FOREIGN_SECONDARY_NAT'):m.stop_locked()
            run.assert_not_called();rollback.assert_not_called();self.assertEqual(events,['metadata-off'])

    def test_foreign_public_config_is_never_overwritten_or_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'transport.json';path.write_text('{"foreign":true}')
            with patch.object(m,'PUBLIC_STATE',path),patch.object(m.s,'owned_file'):
                for enabled in (True,False):
                    with self.assertRaisesRegex(ValueError,'FOREIGN_TRANSPORT'):m.public_state(enabled)
                self.assertEqual(json.loads(path.read_text()),{'foreign':True})
