import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch
from . import transports


class IngressMetadataTests(TestCase):
    def test_only_exact_root_owned_metadata_can_select_secondary(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'transport.json'
            root=SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0,st_size=120)
            with patch.object(transports,'TRANSPORT_STATE',path):
                self.assertEqual(transports.transport_address(),'152.67.156.100')
                for value,expected in [({'schema':1,'owner':'oracle-proxy-secondary-endpoint','transport_address':'141.147.78.44'},'141.147.78.44'),
                    ({'schema':1,'owner':'oracle-proxy-secondary-endpoint','transport_address':'127.0.0.1'},'152.67.156.100'),({},'152.67.156.100')]:
                    path.write_text(json.dumps(value))
                    with patch.object(Path,'lstat',return_value=root):self.assertEqual(transports.transport_address(),expected)
                path.write_text('{bad json')
                with patch.object(Path,'lstat',return_value=root):self.assertEqual(transports.transport_address(),'152.67.156.100')
                path.write_text(json.dumps({'schema':1,'owner':'oracle-proxy-secondary-endpoint','transport_address':'141.147.78.44'}))
                for info in [SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0,st_size=100),
                             SimpleNamespace(st_mode=stat.S_IFREG|0o666,st_uid=0,st_size=100),
                             SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=1000,st_size=100)]:
                    with patch.object(Path,'lstat',return_value=info):self.assertEqual(transports.transport_address(),'152.67.156.100')
