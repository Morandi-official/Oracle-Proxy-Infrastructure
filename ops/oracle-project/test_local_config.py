import base64
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

spec=importlib.util.spec_from_file_location('local_operations',Path(__file__).with_name('project_operations.py'))
operations=importlib.util.module_from_spec(spec);spec.loader.exec_module(operations)


class LocalConfigurationTests(unittest.TestCase):
    def test_twelve_character_password_and_unicode_username_have_fixed_fields(self):
        value={'admin_username':'管理员','admin_password':'synthetic-12'}
        self.assertEqual(operations.parse_configuration(json.dumps(value).encode()),value)
        for invalid in ({**value,'admin_password':'short'}, {**value,'command':'id'},
                        {**value,'admin_username':'name\nADMIN_AUTH_MODE=github'}, {**value,'admin_password':12}):
            with self.assertRaises(ValueError):operations.parse_configuration(json.dumps(invalid).encode())

    def test_password_hash_is_salted_standard_pbkdf2_and_never_raw(self):
        password='synthetic-12'
        encoded=operations.password_hash(password)
        algorithm,iterations,salt,value=encoded.split('$')
        self.assertEqual(algorithm,'pbkdf2_sha256');self.assertGreaterEqual(int(iterations),1000000)
        self.assertEqual(value,base64.b64encode(hashlib.pbkdf2_hmac('sha256',password.encode(),salt.encode(),int(iterations))).decode())
        self.assertNotIn(password,encoded)
