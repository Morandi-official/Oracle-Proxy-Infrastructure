"""Verify recovery patch scope and refuse unknown native dependency sources."""
import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import unittest
from unittest.mock import patch
import uuid

spec=importlib.util.spec_from_file_location('core_vendor',Path(__file__).with_name('prepare-core-vendor.py'))
vendor=importlib.util.module_from_spec(spec);spec.loader.exec_module(vendor)

class RecoveryPatchBoundaries(unittest.TestCase):
    def test_native_managed_and_core_identity_use_the_same_windows_guid_bytes(self):
        product=Path(__file__).resolve().parents[1]
        native=(product/'native/guard.c').read_text()
        declaration=re.search(r'oracle_tun_guid=\{([^;]+)\};',native).group(1)
        values=[int(value,16) for value in re.findall(r'0x([0-9a-fA-F]+)',declaration)]
        raw=struct.pack('<IHH8B',*values)
        expected=hashlib.md5(b'wintunOracleProxy').digest()
        self.assertEqual(raw,expected)
        managed=re.search(r'AdapterGuid="([^"]+)"',(product/'TunReceipt.cs').read_text()).group(1)
        core=re.search(r'recoveryGUID = "([^"]+)"',(product/'core/recovery_protocol.go').read_text()).group(1)
        self.assertEqual(uuid.UUID(managed).bytes_le,expected)
        self.assertEqual(uuid.UUID(core).bytes_le,expected)

    def test_unknown_dependency_is_refused(self):
        with self.assertRaisesRegex(ValueError,'PINNED_WINDOWS_TUN_SOURCE_REQUIRED'):
            vendor.patched(b'unreviewed native dependency')

    def test_cold_creation_has_no_open_by_name_fallback_and_recovery_is_fixed(self):
        # Synthetic anchors exercise the exact-replacement boundary; no binary
        # or third-party code is executed by this test.
        body=b'''package tun
func New(options Options) {
\tadapter, err := wintun.CreateAdapter(options.Name, TunnelType, generateGUIDByDeviceName(options.Name))
\tif err != nil { return nil, err }
\tnativeTun := "preserve unchanged source"
}
func Close() {
\t\tt.session.End()
\t\tt.adapter.Close()
}
func addRouteList() { /* exact replacement region */ }
func generateGUIDByDeviceName(name string) {}
'''
        with patch.object(vendor,'PREIMAGE',hashlib.sha256(body).hexdigest()):
            actual=vendor.patched(body)
        self.assertNotIn(b'wintun.OpenAdapter(',actual)
        self.assertIn(b'preserve unchanged source',actual)
        self.assertIn(b'func RecoverOracleAdapter(value uint64)',actual)
        self.assertIn(b'row.OperStatus != winipcfg.IfOperStatusDown',actual)
        self.assertIn(b'row.InterfaceGUID != *expected',actual)
        self.assertIn(b'if absent { return nil }',actual)
        self.assertNotIn(b'Uninstall(',actual)
        self.assertNotIn(b'exec.Command',actual)
        self.assertNotIn(b'luid.FlushDNS(',vendor.RECOVERY.encode())
        self.assertIn(b'winipcfg.SetInterfaceDnsSettings',vendor.RECOVERY.encode())

if __name__=='__main__':unittest.main()
