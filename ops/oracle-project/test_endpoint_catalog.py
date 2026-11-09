"""Changing endpoint metadata must preserve primary routing and foreign aliases."""
import copy
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
catalog=load('catalog_test',ROOT/'server/admin-oracle/console/endpoint_config.py')
manager=load('endpoint_manager_test',Path(__file__).with_name('endpoint_addresses.py'))

class EndpointCatalogTests(unittest.TestCase):
    def setUp(self):self.config=json.loads((ROOT/'ops/network/endpoints.json').read_text())
    def test_catalog_switch_and_bounds(self):
        self.assertIs(catalog.validate(self.config),self.config)
        with patch.object(catalog,'read',return_value=self.config):
            self.assertEqual(catalog.advertised()['primary'],'152.67.154.225')
            self.config['active']='backup'
            self.assertEqual(catalog.advertised()['primary'],'150.230.113.158')
        for change in ({'revision':True},{'schema':True},{'egress_ipv4':['8.8.8.8']},{'primary':{'public_ipv4':'127.0.0.1','private_ipv4':'10.0.0.220'}}):
            config=copy.deepcopy(self.config);config.update(change)
            with self.assertRaises(ValueError):catalog.validate(config)
    def test_apply_preserves_routes_and_foreign_aliases(self):
        # Explicit transition fixture: production may already have retired legacy.
        self.config['legacy']=[{'public_ipv4':'152.67.156.100','private_ipv4':'10.0.0.220'}]
        rows=[{'local':'10.0.0.6','prefixlen':24,'label':'enp0s6'},{'local':'10.0.0.10','prefixlen':32,'label':'enp0s6:existing'},{'local':'10.0.0.99','prefixlen':32,'label':'enp0s6:foreign'}]
        calls=[]
        def run(args):
            calls.append(args)
            if 'add' in args:rows.append({'local':args[4].split('/')[0],'prefixlen':32,'label':args[8]})
            return ''
        with tempfile.TemporaryDirectory() as directory,patch.object(manager,'ROOT',Path(directory)),patch.object(manager,'STATE',Path(directory)/'state.json'),patch.object(manager,'write',side_effect=lambda p,b,*a:p.write_bytes(b)),patch.object(manager,'addresses',side_effect=lambda d:copy.deepcopy(rows)),patch.object(manager,'routes',return_value=['original-v4','original-v6','rules']),patch.object(manager,'run',side_effect=run):
            result=manager.apply_locked(self.config)
            self.assertTrue(result['default_routes_unchanged'])
            self.assertEqual([c[4] for c in calls],['10.0.0.220/32','10.0.0.246/32'])
            self.assertTrue(all('noprefixroute' in c for c in calls))
            self.assertIn('10.0.0.99',[r['local'] for r in rows])
    def test_retired_catalog_removes_only_ledger_owned_old_alias(self):
        self.config['legacy']=[]
        rows=[{'local':'10.0.0.6','prefixlen':24,'label':'enp0s6'},{'local':'10.0.0.220','prefixlen':32,'label':'enp0s6:opmp'},{'local':'10.0.0.246','prefixlen':32,'label':'enp0s6:opmb'},{'local':'10.0.0.99','prefixlen':32,'label':'enp0s6:foreign'}]
        calls=[]
        def run(args):
            calls.append(args)
            if 'del' in args:rows[:]=[r for r in rows if r['local']!=args[4].split('/')[0]]
            return ''
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'state.json'
            state.write_text(json.dumps({'schema':1,'device':'enp0s6','owned':{'10.0.0.220':'enp0s6:opmp','10.0.0.246':'enp0s6:opmb'}}))
            with patch.object(manager,'ROOT',Path(directory)),patch.object(manager,'STATE',state),patch.object(manager,'owned'),patch.object(manager,'write',side_effect=lambda p,b,*a:p.write_bytes(b)),patch.object(manager,'addresses',side_effect=lambda d:copy.deepcopy(rows)),patch.object(manager,'routes',return_value=['v4','v6','rules']),patch.object(manager,'run',side_effect=run):
                manager.apply_locked(self.config)
            self.assertEqual([c[4] for c in calls],['10.0.0.220/32'])
            self.assertEqual({r['local'] for r in rows},{'10.0.0.6','10.0.0.246','10.0.0.99'})
            self.assertEqual(json.loads(state.read_text())['owned'],{'10.0.0.246':'enp0s6:opmb'})

    def test_public_catalog_mode_survives_private_root_umask(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'catalog.json';old=os.umask(0o077)
            try:manager.write(target,b'{}',0o644)
            finally:os.umask(old)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o644)

    def test_collected_transient_service_is_safe_only_when_both_units_are_inactive(self):
        done=lambda code,state='':subprocess.CompletedProcess([],code,state,'')
        with patch.object(manager.subprocess,'run',side_effect=[done(5),done(3,'inactive'),done(4,'unknown')]):manager.stop_timer('known-owned-unit')
        with patch.object(manager.subprocess,'run',side_effect=[done(5),done(0,'active')]):
            with self.assertRaisesRegex(ValueError,'EXPERIMENT_TIMER_NOT_STOPPED'):manager.stop_timer('known-owned-unit')

    def test_route_inspection_requests_json(self):
        with patch.object(manager,'run',return_value='[]') as run:manager.routes()
        self.assertTrue(all('-j' in c.args[0] for c in run.call_args_list))
