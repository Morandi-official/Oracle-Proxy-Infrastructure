"""Verify recovery patch scope and refuse unknown native dependency sources."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
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

    def test_dormant_recovery_is_read_only_until_own_fresh_creation(self):
        source=vendor.DORMANT_RECOVERY
        self.assertEqual(source.count('wintun.CreateAdapter('),1)
        self.assertEqual(source.count('created.Close()'),1)
        self.assertLess(source.index('verifyOracleDormantEmpty(luid)'),source.index('wintun.CreateAdapter('))
        self.assertLess(source.index('verifyOracleDormantEmpty(fresh)'),source.index('created.Close()'))
        self.assertLess(source.index('created.Close()'),source.index('oracleRecoveryAbsent()'))
        for forbidden in ('OpenAdapter(','.Delete(','.Flush','SetInterfaceDnsSettings','StartSession(',
                          'exec.Command','os.Open','registry.','WFP','Uninstall('):
            self.assertNotIn(forbidden,source)

    def test_dormant_native_snapshot_boundaries_execute_the_patched_audit(self):
        # Run the exact audit algorithm with native-table calls replaced by
        # deterministic snapshots. No Windows driver, interface or network is
        # touched. This exercises missing/error/duplicate rows and phase races,
        # rather than accepting a source-string assertion as an emptiness test.
        source=vendor.DORMANT_RECOVERY.split('func verifyOracleDormantEmpty(',1)[1]
        source='func verifyOracleDormantEmpty('+source
        replacements={
            'winipcfg.LUID':'fakeLUID','windows.AF_UNSPEC':'0',
            'winipcfg.GetUnicastIPAddressTable':'getAddresses',
            'winipcfg.GetIPForwardTable2':'getRoutes',
            'winipcfg.GetAdaptersAddresses':'getAdapters',
            'winipcfg.GAAFlagIncludeAll':'1',
            'winipcfg.IfOperStatusDown':'2','winipcfg.IfTypePropVirtual':'53',
        }
        for original,replacement in replacements.items():source=source.replace(original,replacement)
        declarations='''package dormantcheck
import "fmt"
type fakeLUID uint64
type fakeRow struct { InterfaceLUID fakeLUID }
type fakeAdapter struct {
 LUID fakeLUID; OperStatus int; IfType int
 FirstDNSServerAddress *int; FirstDNSSuffix *int
 name, description, suffix string
}
func (a *fakeAdapter) FriendlyName() string { return a.name }
func (a *fakeAdapter) Description() string { return a.description }
func (a *fakeAdapter) DNSSuffix() string { return a.suffix }
var addresses, routes []fakeRow
var adapters []*fakeAdapter
var addressErr, routeErr, dnsErr error
var identityChecks, identityFailAt int
func getAddresses(int) ([]fakeRow,error) { return addresses,addressErr }
func getRoutes(int) ([]fakeRow,error) { return routes,routeErr }
func getAdapters(int,int) ([]*fakeAdapter,error) { return adapters,dnsErr }
func verifyOracleRecoveryIdentity(fakeLUID) error {
 identityChecks++
 if identityFailAt==identityChecks { return fmt.Errorf("ORPHAN_IDENTITY_FAILED") }
 return nil
}
'''
        checks='''package dormantcheck
import ("errors"; "testing")
func TestNativeSnapshotBoundaries(t *testing.T) {
 tests:=[]struct{name string; setup func(); want string}{
  {"successful snapshot without DNS association",func(){},""},
  {"one empty adapter",func(){adapters=[]*fakeAdapter{empty()}},""},
  {"unrelated LUID untouched",func(){addresses=[]fakeRow{{8}};routes=[]fakeRow{{8}};a:=empty();a.LUID=8;a.FirstDNSServerAddress=new(int);adapters=[]*fakeAdapter{a}},""},
  {"IP query error",func(){addressErr=errors.New("native")},"DORMANT_IP_QUERY_FAILED"},
  {"any own address including automatic linklocal",func(){addresses=[]fakeRow{{7}}},"DORMANT_IP_NOT_EMPTY"},
  {"route query error",func(){routeErr=errors.New("native")},"DORMANT_ROUTE_QUERY_FAILED"},
  {"any own route including multicast",func(){routes=[]fakeRow{{7}}},"DORMANT_ROUTE_NOT_EMPTY"},
  {"DNS query error",func(){dnsErr=errors.New("native")},"DORMANT_DNS_QUERY_FAILED"},
  {"malformed native DNS row",func(){adapters=[]*fakeAdapter{nil}},"DORMANT_DNS_QUERY_FAILED"},
  {"duplicate LUID",func(){adapters=[]*fakeAdapter{empty(),empty()}},"DORMANT_DNS_QUERY_FAILED"},
  {"DNS server present",func(){a:=empty();a.FirstDNSServerAddress=new(int);adapters=[]*fakeAdapter{a}},"DORMANT_DNS_NOT_EMPTY"},
  {"DNS suffix present",func(){a:=empty();a.suffix="example.test";adapters=[]*fakeAdapter{a}},"DORMANT_DNS_NOT_EMPTY"},
  {"DNS suffix list present",func(){a:=empty();a.FirstDNSSuffix=new(int);adapters=[]*fakeAdapter{a}},"DORMANT_DNS_NOT_EMPTY"},
  {"Up rejected",func(){a:=empty();a.OperStatus=1;adapters=[]*fakeAdapter{a}},"ORPHAN_IDENTITY_FAILED"},
  {"alias conflict",func(){a:=empty();a.name="other";adapters=[]*fakeAdapter{a}},"ORPHAN_IDENTITY_FAILED"},
  {"description conflict",func(){a:=empty();a.description="other";adapters=[]*fakeAdapter{a}},"ORPHAN_IDENTITY_FAILED"},
  {"type conflict",func(){a:=empty();a.IfType=6;adapters=[]*fakeAdapter{a}},"ORPHAN_IDENTITY_FAILED"},
  {"identity initially invalid",func(){identityFailAt=1},"ORPHAN_IDENTITY_FAILED"},
  {"identity changed after IP query",func(){identityFailAt=2},"ORPHAN_IDENTITY_FAILED"},
  {"identity changed after route query",func(){identityFailAt=3},"ORPHAN_IDENTITY_FAILED"},
  {"identity changed after DNS query",func(){identityFailAt=4},"ORPHAN_IDENTITY_FAILED"},
 }
 for _,tc:=range tests {t.Run(tc.name,func(t *testing.T){
  addresses=nil;routes=nil;adapters=nil;addressErr=nil;routeErr=nil;dnsErr=nil
  identityChecks=0;identityFailAt=0;tc.setup()
  err:=verifyOracleDormantEmpty(7);got:="";if err!=nil{got=err.Error()}
  if got!=tc.want {t.Fatalf("got %q want %q",got,tc.want)}
  if got==""&&identityChecks!=4 {t.Fatal("successful proof omitted identity recheck")}
 })}
}
func empty() *fakeAdapter {return &fakeAdapter{LUID:7,OperStatus:2,IfType:53,name:"OracleProxy",description:"sing-tun Tunnel"}}
'''
        configured=Path('/workspace/tools/go1.27/go/bin/go')
        go=str(configured) if configured.is_file() else shutil.which('go')
        self.assertIsNotNone(go,'Go is required for native recovery boundary tests')
        with tempfile.TemporaryDirectory(prefix='oracle-dormant-boundary-') as directory:
            root=Path(directory)
            (root/'audit.go').write_text(declarations+source)
            (root/'audit_test.go').write_text(checks)
            environment=os.environ.copy()
            environment.update({'GO111MODULE':'off','GOWORK':'off','GOPROXY':'off','GOTOOLCHAIN':'local'})
            environment.pop('GOOS',None);environment.pop('GOARCH',None)
            result=subprocess.run([go,'test','audit.go','audit_test.go'],cwd=root,env=environment,
                                  text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
            self.assertEqual(result.returncode,0,result.stdout)

if __name__=='__main__':unittest.main()
