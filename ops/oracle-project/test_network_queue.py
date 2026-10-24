import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec=importlib.util.spec_from_file_location('network_queue',Path(__file__).with_name('network_queue.py'))
queue=importlib.util.module_from_spec(spec);spec.loader.exec_module(queue)
FIFO={'kind':'pfifo_fast','dev':'enp0s6','root':True,'options':{'bands':3,'priomap':queue.PRIOMAP}}
FQ={'kind':'fq_codel','dev':'enp0s6','root':True}

class QueuePolicy(unittest.TestCase):
    def test_only_default_single_root_is_eligible(self):
        self.assertTrue(queue.default_fifo(FIFO))
        self.assertFalse(queue.default_fifo(dict(FIFO,options={'bands':2})))
        self.assertFalse(queue.default_fifo(dict(FIFO,options={'unrecognized':1})))
        # tc omits dev in JSON when the command already selects one device.
        filtered=dict(FIFO);filtered.pop('dev')
        with patch.object(queue,'run',return_value=SimpleNamespace(stdout=json.dumps([filtered]))):
            self.assertTrue(queue.default_fifo(queue.observe()))
        for rows in ([],[FIFO,FQ],[dict(FIFO,root=False)],[dict(FIFO,dev='wg0')]):
            with patch.object(queue,'run',return_value=SimpleNamespace(stdout=json.dumps(rows))):
                with self.assertRaises(ValueError):queue.observe()
    def test_apply_uses_fixed_queue_arguments_without_rate_or_global_tuning(self):
        with tempfile.TemporaryDirectory() as root, patch.object(queue,'STATE',Path(root)/'baseline'), patch.object(queue,'write') as write, patch.object(queue,'observe',side_effect=[FIFO,FQ]), patch.object(queue,'run') as run:
            queue.apply()
        self.assertEqual(run.call_args.args[0],['tc','qdisc','replace','dev','enp0s6','root','fq_codel','limit','1024','flows','1024','target','5ms','interval','100ms','ecn'])
        self.assertEqual(json.loads(write.call_args.args[1]),{'schema':1,'device':'enp0s6','previous':'pfifo_fast'})
    def test_failed_apply_rolls_back_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as root, patch.object(queue,'STATE',Path(root)/'baseline'), patch.object(queue,'write'), patch.object(queue,'observe',return_value=FIFO), patch.object(queue,'run',side_effect=RuntimeError('synthetic')), patch.object(queue,'restore') as restore:
            with self.assertRaises(RuntimeError):queue.apply()
            restore.assert_called_once()
    def test_refuse_external_qdisc_and_do_not_rewrite_it_on_rollback(self):
        with patch.object(queue,'baseline'),patch.object(queue,'observe',return_value={'kind':'htb'}),patch.object(queue,'run') as run:
            with self.assertRaises(ValueError):queue.restore()
            run.assert_not_called()
    def test_restore_is_verified_and_idempotent(self):
        with patch.object(queue,'baseline'),patch.object(queue,'observe',side_effect=[FQ,FIFO]),patch.object(queue,'run') as run:
            queue.restore()
            self.assertEqual(run.call_args.args[0],['tc','qdisc','replace','dev','enp0s6','root','pfifo_fast'])
        with patch.object(queue,'baseline'),patch.object(queue,'observe',return_value=FIFO),patch.object(queue,'run') as run:
            queue.restore();run.assert_not_called()

if __name__=='__main__':unittest.main()
