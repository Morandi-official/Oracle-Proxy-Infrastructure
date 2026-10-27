import ast
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('cleanup_rc22_dormant_ci',Path(__file__).with_name('cleanup_rc22_dormant_ci.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class CleanupRc22Dormant(unittest.TestCase):
    def row(self,**changes):
        return {**{'key':'a'*43+'=','name':m.MACHINE,'machine_name':m.MACHINE,
                   'client_version':m.VERSION,'confirmed_at':m.cleanup.BEGIN+1},**changes}

    def test_exact_completed_main_receipt_and_two_second_window(self):
        self.assertEqual(m.REQUEST,'rc22-dormant-owned-ci-slot-release-20261027')
        self.assertEqual(m.MACHINE,'runnervma5ucf')
        self.assertEqual(m.VERSION,'0.3.0-rc22+ec22895b9269fff9d8aaff157c0dfa55a022d0f1')
        self.assertEqual(dt.datetime.fromtimestamp(m.cleanup.BEGIN,dt.timezone.utc).isoformat(),'2026-10-27T08:11:01+00:00')
        self.assertEqual(m.cleanup.END-m.cleanup.BEGIN,2)
        self.assertEqual(m.cleanup.MARKER.name,m.REQUEST+'.json')
        for at in (m.cleanup.BEGIN,m.cleanup.BEGIN+1,m.cleanup.END):
            self.assertEqual(m.candidates([self.row(confirmed_at=at)],{},m.cleanup.END+1000),['a'*43+'='])

    def test_real_pc_wrong_name_machine_version_and_time_are_never_selected(self):
        changes=[{'name':'METAWISEBOOK'},{'machine_name':'METAWISEBOOK'},
                 {'name':'morandi'},{'name':'Cloud WebRTC acceptance'},
                 {'machine_name':'runnervma5ucf2'}, {'machine_name':'RUNNERVMA5UCF'},
                 {'client_version':'0.3.0-rc20+30f70a05110e5752581eccd8dd2ce1c97dffd682'},
                 {'client_version':'0.3.0-rc21+fc988d729839'},
                 {'client_version':'0.3.0-rc22+fc988d72983906b74aeb629163a8110bc36ee8ab'},
                 {'confirmed_at':m.cleanup.BEGIN-1},{'confirmed_at':m.cleanup.END+1}]
        for value in changes:
            with self.subTest(value=value):
                self.assertEqual(m.candidates([self.row(**value)],{},m.cleanup.END+1000),[])

    def test_exact_180_second_inactivity_is_required_and_live_is_rejected(self):
        now=m.cleanup.END+1000;row=self.row();key=row['key']
        for idle,expected in ((181,[key]),(180,[key]),(179,[]),(0,[]),(-1,[])):
            with self.subTest(idle=idle):
                self.assertEqual(m.candidates([row],{key:{'handshake':now-idle}},now),expected)

    def test_duplicate_rows_or_second_matching_device_refuse_whole_selection(self):
        for second in (self.row(),self.row(key='b'*43+'=')):
            with self.subTest(second=second),self.assertRaisesRegex(ValueError,'NOT_UNIQUE'):
                m.candidates([self.row(),second],{},m.cleanup.END+1000)

    def test_only_one_saved_key_is_revoked_and_marker_prevents_second_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            state=Path(temporary);marker=state/(m.REQUEST+'.json')
            marker.write_text(json.dumps({'keys':[self.row()['key']],'done':False}))
            (state/'request.json').write_text(json.dumps({'operation':'enable-https','request_id':m.REQUEST}))
            with mock.patch.object(m.cleanup,'STATE',state),mock.patch.object(m.cleanup,'MARKER',marker),\
                 mock.patch.object(m.cleanup,'__file__',str(state/'fixture-helper.py')),\
                 mock.patch.object(m.cleanup.os,'geteuid',return_value=0),\
                 mock.patch.object(m.cleanup.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=1001,pw_gid=1001)),\
                 mock.patch.object(m.cleanup.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='REVOKED')) as revoke:
                m.apply();self.assertTrue(json.loads(marker.read_text())['done']);m.apply()
                self.assertEqual(revoke.call_count,1)
                self.assertEqual(revoke.call_args.kwargs['input'],self.row()['key'])
                self.assertIn("call('peer.revoke'",revoke.call_args.args[0][-1])
                self.assertNotIn('peer.delete',revoke.call_args.args[0][-1])
                self.assertEqual(revoke.call_args.kwargs['user'],1001)

    def test_saved_plan_is_also_limited_to_one_and_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker=Path(temporary)/(m.REQUEST+'.json')
            marker.write_text(json.dumps({'keys':[self.row()['key']]*2,'done':False}))
            with mock.patch.object(m.cleanup,'MARKER',marker),mock.patch.object(m.cleanup,'apply') as execute:
                with self.assertRaisesRegex(ValueError,'ONE_OWNED'):m.apply()
                execute.assert_not_called()
            target=Path(temporary)/'other';target.write_text('{}');marker.unlink();marker.symlink_to(target)
            with mock.patch.object(m.cleanup,'MARKER',marker),mock.patch.object(m.cleanup,'apply') as execute:
                with self.assertRaisesRegex(ValueError,'UNTRUSTED'):m.apply()
                execute.assert_not_called()

    def test_request_dispatch_returns_before_unrelated_https_operations(self):
        # Read the real dispatch implementation, but give it only this test's
        # temporary fixed request. Repository request.json is active ops state.
        source=Path(__file__).with_name('project_operations.py')
        method=next(node for node in ast.parse(source.read_text()).body if isinstance(node,ast.FunctionDef) and node.name=='enable_https')
        module=ast.fix_missing_locations(ast.Module(body=[method],type_ignores=[]));selected=[]
        def load(target):target.apply=lambda:selected.append('only-owned-rc22-dormant-revoke')
        fake_spec=SimpleNamespace(loader=SimpleNamespace(exec_module=load))
        hooks=SimpleNamespace(spec_from_file_location=mock.Mock(return_value=fake_spec),module_from_spec=lambda spec:SimpleNamespace())
        forbidden=mock.Mock(side_effect=AssertionError('Unrelated HTTPS operation'))
        with tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'project_operations.py'
            target.with_name('request.json').write_text(json.dumps({'operation':'enable-https','request_id':m.REQUEST}))
            namespace={'__file__':str(target),'Path':Path,'json':json,'importlib':SimpleNamespace(util=hooks),'install_downloads':forbidden}
            exec(compile(module,str(source),'exec'),namespace);namespace['enable_https']()
            self.assertEqual(selected,['only-owned-rc22-dormant-revoke'])
            self.assertEqual(hooks.spec_from_file_location.call_args.args[1],target.with_name('cleanup_rc22_dormant_ci.py'))
            forbidden.assert_not_called()



if __name__=='__main__':unittest.main()
