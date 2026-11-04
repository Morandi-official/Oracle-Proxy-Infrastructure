"""The release-delivery request must not enter normal web/network deployment."""
import ast
import json
from pathlib import Path
import tempfile
import unittest

REQUEST='rc29-completed-owned-ci-slot-release-20261104'


class ReleaseDeliveryBoundary(unittest.TestCase):
    def test_exact_delivery_only_mirrors_and_retires_completed_ci(self):
        source=Path(__file__).with_name('project_operations.py')
        module=ast.parse(source.read_text())
        operation=next(n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='enable_https')
        calls=[]
        def forbidden(*args,**kwargs):
            raise AssertionError('UNEXPECTED_DEPLOYMENT_OR_NETWORK_OPERATION')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'request.json').write_text(json.dumps({'operation':'enable-https','request_id':REQUEST}))
            scope={'__file__':str(root/'project_operations.py'),'Path':Path,'json':json,
                   'install_downloads':lambda:calls.append('mirror'),
                   '_retire_rc29_ci_device':lambda:calls.append('retire-ci'),
                   'run':forbidden,'web':forbidden,'deploy':forbidden,
                   'refresh_firewall':forbidden,'configure':forbidden}
            exec(compile(ast.Module(body=[operation],type_ignores=[]),str(source),'exec'),scope)
            scope['enable_https']()
            self.assertEqual(calls,['retire-ci'])
            self.assertEqual({p.name for p in root.iterdir()},{'request.json'})

if __name__=='__main__':unittest.main()
