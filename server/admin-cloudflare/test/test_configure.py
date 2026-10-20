import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('configure', Path(__file__).parents[1] / 'configure.py')
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


class ConfigurationTests(unittest.TestCase):
    def values(self):
        return {
            'ADMIN_PUBLIC_ORIGIN': 'https://vpn-admin.morandi.dpdns.org',
            'ADMIN_ACCESS_ISSUER': 'https://example.cloudflareaccess.com',
            'ADMIN_ACCESS_AUD': 'a' * 64, 'ADMIN_EMAILS': 'morandi@nuaa.edu.cn',
            'ADMIN_D1_DATABASE_ID': '00000000-0000-0000-0000-000000000001'
        }

    def test_generates_only_declared_settings(self):
        config = configure.build_config(self.values())
        self.assertEqual(config['routes'][0]['pattern'], 'vpn-admin.morandi.dpdns.org')
        self.assertFalse(config['workers_dev'])
        self.assertTrue(config['assets']['run_worker_first'])
        self.assertEqual(config['vars']['ADMIN_EMAILS'], 'morandi@nuaa.edu.cn')

    def test_rejects_untrusted_origins_and_missing_identity(self):
        for key, value in [
            ('ADMIN_PUBLIC_ORIGIN', 'http://example.com'),
            ('ADMIN_PUBLIC_ORIGIN', 'https://example.com/path'),
            ('ADMIN_PUBLIC_ORIGIN', 'https://user@example.com'),
            ('ADMIN_PUBLIC_ORIGIN', 'https://example.com?next=evil'),
            ('ADMIN_ACCESS_ISSUER', 'https://evil.example.com'),
            ('ADMIN_ACCESS_AUD', ''), ('ADMIN_EMAILS', ''),
            ('ADMIN_D1_DATABASE_ID', 'REPLACE_ME'), ('ADMIN_NODE_ID', '../wg0'),
        ]:
            values = self.values(); values[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                configure.build_config(values)


if __name__ == '__main__':
    unittest.main()
