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

    def test_fresh_dns_skip_requires_exact_complete_empty_native_snapshot(self):
        start=vendor.CACHE.index('func oraclePreparedDNSAbsent(')
        end=vendor.CACHE.index('func (t *NativeTun) prepareOracleAdapter()',start)
        helper=vendor.CACHE[start:end].replace('winipcfg.LUID','uint64').replace(
            'winipcfg.IPAdapterAddresses','entry').replace(
            'winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagIncludeAllInterfaces)','getAdapters()')
        source='''package check
type suffix struct {Next *suffix; value string}
func (s *suffix) String() string { return s.value }
type entry struct {LUID uint64; FirstDNSServerAddress *int; FirstDNSSuffix *suffix; domain string}
func (e *entry) DNSSuffix() string {return e.domain}
var rows []*entry
var failure error
func getAdapters()([]*entry,error){return rows,failure}
'''+helper
        tests='''package check
import ("errors";"testing")
func TestExactEmptyDNSSnapshot(t *testing.T){
    cycle:=&suffix{};cycle.Next=cycle
    for _,tc:=range []struct{name string;rows []*entry;err bool;reason string}{
        {"one clean owned adapter",[]*entry{{LUID:7}},false,""},
        {"unrelated dirty adapter ignored",[]*entry{{LUID:8,FirstDNSServerAddress:new(int)},{LUID:7}},false,""},
        {"no owned snapshot",[]*entry{{LUID:8}},false,"PARK_INTERFACE_QUERY_FAILED"},
        {"duplicate owned snapshots",[]*entry{{LUID:7,FirstDNSServerAddress:new(int)},{LUID:7}},false,"PARK_INTERFACE_QUERY_FAILED"},
        {"nil snapshot",[]*entry{nil,{LUID:7}},false,"PARK_INTERFACE_QUERY_FAILED"},
        {"query failure",nil,true,"PARK_INTERFACE_QUERY_FAILED"},
        {"DNS server",[]*entry{{LUID:7,FirstDNSServerAddress:new(int)}},false,"PARK_DNS_SERVER_PRESENT"},
        {"blank suffix nodes",[]*entry{{LUID:7,FirstDNSSuffix:&suffix{Next:&suffix{}}}},false,""},
        {"nonempty trailing suffix",[]*entry{{LUID:7,FirstDNSSuffix:&suffix{Next:&suffix{value:"example.invalid"}}}},false,"PARK_DNS_SUFFIX_PRESENT"},
        {"DNS suffix cycle",[]*entry{{LUID:7,FirstDNSSuffix:cycle}},false,"PARK_DNS_LIST_INVALID"},
        {"DNS domain",[]*entry{{LUID:7,domain:"example.invalid"}},false,"PARK_DNS_SUFFIX_PRESENT"},
    } {
        rows=tc.rows;failure=nil
        if tc.err {failure=errors.New("native query")}
        if got:=oraclePreparedDNSProblem(7);got!=tc.reason || oraclePreparedDNSAbsent(7)!=(tc.reason==""){t.Fatalf("%s: %q",tc.name,got)}
    }
}
'''
        go=shutil.which('go')
        self.assertIsNotNone(go,'Go is required for the native snapshot boundary test')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'go.mod').write_text('module check\n\ngo 1.24\n')
            (root/'dns.go').write_text(source)
            (root/'dns_test.go').write_text(tests)
            env=dict(os.environ,GOWORK='off',GOTOOLCHAIN='local')
            result=subprocess.run([go,'test','./...'],cwd=root,env=env,text=True,capture_output=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_dormant_recovery_is_read_only_until_own_fresh_creation(self):
        source=vendor.DORMANT_RECOVERY
        self.assertEqual(source.count('wintun.CreateAdapter('),1)
        self.assertEqual(source.count('created.Close()'),1)
        self.assertLess(source.index('verifyOracleDormantEmpty(luid)'),source.index('wintun.CreateAdapter('))
        self.assertLess(source.index('verifyOracleDormantEmpty(fresh)'),source.index('created.Close()'))
        self.assertLess(source.index('created.Close()'),source.index('oracleRecoveryAbsent()'))
        for forbidden in ('OpenAdapter(','.Delete(','.Flush','SetInterfaceDnsSettings','StartSession(',
                          'exec.Command','os.Open','registry.','WFP','Uninstall(',
                          'entry.FirstDNSServerAddress','entry.DNSSuffix()', 'entry.FirstDNSSuffix'):
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
            'windows.AF_INET6':'23',
            'windows.AF_INET':'2',
            'winipcfg.GetUnicastIPAddressTable':'getAddresses',
            'winipcfg.GetIPForwardTable2':'getRoutes',
            'winipcfg.GetAdaptersAddresses':'getAdapters',
            'winipcfg.GAAFlagIncludeAll':'1',
            'winipcfg.IfOperStatusDown':'2','winipcfg.IfTypePropVirtual':'53',
            'winipcfg.PrefixOriginWellKnown':'2',
            'winipcfg.SuffixOriginLinkLayerAddress':'4',
            'winipcfg.SuffixOriginRandom':'5',
            'winipcfg.RouteProtocolLocal':'2',
        }
        for original,replacement in replacements.items():source=source.replace(original,replacement)
        declarations='''package dormantcheck
import ("fmt"; "net/netip")
type fakeLUID uint64
type fakeSockaddr struct { Family int; value netip.Addr }
func (a *fakeSockaddr) Addr() netip.Addr { return a.value }
type fakePrefix struct { value netip.Prefix }
func (p *fakePrefix) Prefix() netip.Prefix { return p.value }
type fakeRow struct {
 InterfaceLUID fakeLUID; Address fakeSockaddr
 PrefixOrigin, SuffixOrigin, OnLinkPrefixLength int
 DestinationPrefix fakePrefix; NextHop fakeSockaddr; Protocol int
}
type fakeAdapter struct {
 LUID fakeLUID; OperStatus int; IfType int
 FirstDNSServerAddress *int; FirstDNSSuffix *int
 name, description, suffix string
}
func (a *fakeAdapter) FriendlyName() string { return a.name }
func (a *fakeAdapter) Description() string { return a.description }
func (a *fakeAdapter) DNSSuffix() string { panic("dormant recovery must not consume DNS metadata") }
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
import ("errors"; "net/netip"; "testing")
func TestNativeSnapshotBoundaries(t *testing.T) {
 tests:=[]struct{name string; setup func(); want string}{
  {"successful snapshot without DNS association",func(){},""},
  {"one empty adapter",func(){adapters=[]*fakeAdapter{empty()}},""},
  {"unrelated LUID untouched",func(){addresses=[]fakeRow{{InterfaceLUID:8}};routes=[]fakeRow{{InterfaceLUID:8}};a:=empty();a.LUID=8;a.FirstDNSServerAddress=new(int);adapters=[]*fakeAdapter{a}},""},
  {"IP query error",func(){addressErr=errors.New("native")},"DORMANT_IP_QUERY_FAILED"},
  {"automatic random IPv6 linklocal",func(){addresses=[]fakeRow{autoLLA("fe80::1234")}},""},
  {"automatic linklayer IPv6 linklocal",func(){a:=autoLLA("fe80::1234");a.SuffixOrigin=4;addresses=[]fakeRow{a}},""},
  {"only audited local routes",func(){addresses=[]fakeRow{autoLLA("fe80::1234")};routes=[]fakeRow{localRoute("fe80::/64"),localRoute("fe80::1234/128"),localRoute("ff00::/8")}},""},
  {"scoped LLA normalized to exact native bytes",func(){addresses=[]fakeRow{autoLLA("fe80::1234%7")};routes=[]fakeRow{localRoute("fe80::/64"),localRoute("fe80::1234/128")}},""},
  {"zone text cannot override target LUID",func(){addresses=[]fakeRow{autoLLA("fe80::1234%other-name")};routes=[]fakeRow{localRoute("fe80::1234/128")}},""},
  {"automatic multicast without LLA",func(){routes=[]fakeRow{localRoute("ff00::/8")}},""},
  {"automatic IPv4 multicast local route",func(){routes=[]fakeRow{localRoute4("224.0.0.0/4")}},""},
  {"automatic IPv4 limited broadcast local route",func(){routes=[]fakeRow{localRoute4("255.255.255.255/32")}},""},
  {"automatic dual-family local metadata",func(){addresses=[]fakeRow{autoLLA("fe80::1234")};routes=[]fakeRow{localRoute4("224.0.0.0/4"),localRoute4("255.255.255.255/32"),localRoute("fe80::/64"),localRoute("fe80::1234/128"),localRoute("ff00::/8")}},""},
  {"manual origin same linklocal IP",func(){a:=autoLLA("fe80::1234");a.PrefixOrigin=1;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"unknown origin same linklocal IP",func(){a:=autoLLA("fe80::1234");a.PrefixOrigin=0;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"DHCP origin linklocal",func(){a:=autoLLA("fe80::1234");a.PrefixOrigin=3;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"RA origin linklocal",func(){a:=autoLLA("fe80::1234");a.PrefixOrigin=4;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"manual suffix same linklocal IP",func(){a:=autoLLA("fe80::1234");a.SuffixOrigin=1;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"unknown suffix linklocal",func(){a:=autoLLA("fe80::1234");a.SuffixOrigin=0;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"wellknown suffix linklocal",func(){a:=autoLLA("fe80::1234");a.SuffixOrigin=2;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"DHCP suffix linklocal",func(){a:=autoLLA("fe80::1234");a.SuffixOrigin=3;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"different linklocal prefix length",func(){a:=autoLLA("fe80::1234");a.OnLinkPrefixLength=128;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"global IPv6 despite automatic origins",func(){addresses=[]fakeRow{autoLLA("2001:db8::1234")}},"DORMANT_IP_NOT_EMPTY"},
  {"ULA despite automatic origins",func(){addresses=[]fakeRow{autoLLA("fd00::1234")}},"DORMANT_IP_NOT_EMPTY"},
  {"IPv4 linklocal refused",func(){a:=autoLLA("169.254.1.2");a.Address.Family=2;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"dirty manual IPv4 refused",func(){a:=autoLLA("198.18.0.1");a.Address.Family=2;a.PrefixOrigin=1;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"malformed address family refused",func(){a:=autoLLA("fe80::1234");a.Address.Family=0;addresses=[]fakeRow{a}},"DORMANT_IP_NOT_EMPTY"},
  {"duplicate automatic address refused",func(){addresses=[]fakeRow{autoLLA("fe80::1234"),autoLLA("fe80::1234")}},"DORMANT_IP_NOT_EMPTY"},
  {"different zones cannot hide duplicate native address",func(){addresses=[]fakeRow{autoLLA("fe80::1234%7"),autoLLA("fe80::1234%8")}},"DORMANT_IP_NOT_EMPTY"},
  {"route query error",func(){routeErr=errors.New("native")},"DORMANT_ROUTE_QUERY_FAILED"},
  {"route without audited LLA",func(){routes=[]fakeRow{localRoute("fe80::/64")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"same scoped bytes on another LUID cannot authorize target prefix",func(){a:=autoLLA("fe80::1234%7");a.InterfaceLUID=8;addresses=[]fakeRow{a};routes=[]fakeRow{localRoute("fe80::/64")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"same bytes with another LUID and zone cannot authorize target host",func(){a:=autoLLA("fe80::1234%8");a.InterfaceLUID=8;addresses=[]fakeRow{a};routes=[]fakeRow{localRoute("fe80::1234/128")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"local default route refused",func(){routes=[]fakeRow{localRoute("::/0")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"global local-protocol route refused",func(){routes=[]fakeRow{localRoute("2001:db8::1/128")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"broader linklocal route refused",func(){addresses=[]fakeRow{autoLLA("fe80::1234")};routes=[]fakeRow{localRoute("fe80::/10")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"unrelated linklocal prefix refused",func(){addresses=[]fakeRow{autoLLA("fe80::1234")};routes=[]fakeRow{localRoute("fe80:1::/64")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"unaudited linklocal host refused",func(){addresses=[]fakeRow{autoLLA("fe80::1234")};routes=[]fakeRow{localRoute("fe80::4321/128")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"noncanonical prefix refused",func(){addresses=[]fakeRow{autoLLA("fe80::1234")};routes=[]fakeRow{localRoute("fe80::4321/64")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"multicast subprefix refused",func(){routes=[]fakeRow{localRoute("ff00::/16")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"manual route protocol refused",func(){r:=localRoute("ff00::/8");r.Protocol=3;routes=[]fakeRow{r}},"DORMANT_ROUTE_PROTOCOL_NOT_LOCAL"},
  {"unknown route protocol refused",func(){r:=localRoute("ff00::/8");r.Protocol=0;routes=[]fakeRow{r}},"DORMANT_ROUTE_PROTOCOL_NOT_LOCAL"},
  {"gateway linklocal refused",func(){r:=localRoute("ff00::/8");r.NextHop.value=netip.MustParseAddr("fe80::1");routes=[]fakeRow{r}},"DORMANT_ROUTE_NEXT_HOP_UNSAFE"},
  {"unspecified IPv4 next-hop refused",func(){r:=localRoute("ff00::/8");r.NextHop=fakeSockaddr{Family:2,value:netip.MustParseAddr("0.0.0.0")};routes=[]fakeRow{r}},"DORMANT_ROUTE_NEXT_HOP_UNSAFE"},
  {"unknown next-hop family refused",func(){r:=localRoute("ff00::/8");r.NextHop.Family=0;routes=[]fakeRow{r}},"DORMANT_ROUTE_NEXT_HOP_UNSAFE"},
  {"invalid destination prefix refused",func(){r:=localRoute("ff00::/8");r.DestinationPrefix=fakePrefix{};routes=[]fakeRow{r}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 APIPA route refused",func(){routes=[]fakeRow{localRoute4("169.254.0.0/16")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 default route refused",func(){routes=[]fakeRow{localRoute4("0.0.0.0/0")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 loopback route refused",func(){routes=[]fakeRow{localRoute4("127.0.0.0/8")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 ordinary subnet route refused",func(){routes=[]fakeRow{localRoute4("192.168.1.0/24")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 narrower multicast prefix refused",func(){routes=[]fakeRow{localRoute4("224.0.0.0/24")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 multicast host route refused",func(){routes=[]fakeRow{localRoute4("239.255.255.250/32")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 broadcast subnet refused",func(){routes=[]fakeRow{localRoute4("255.255.255.0/24")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 noncanonical multicast prefix refused",func(){routes=[]fakeRow{localRoute4("225.0.0.0/4")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"IPv4 manual multicast protocol refused",func(){r:=localRoute4("224.0.0.0/4");r.Protocol=3;routes=[]fakeRow{r}},"DORMANT_ROUTE_PROTOCOL_NOT_LOCAL"},
  {"IPv4 manual broadcast protocol refused",func(){r:=localRoute4("255.255.255.255/32");r.Protocol=3;routes=[]fakeRow{r}},"DORMANT_ROUTE_PROTOCOL_NOT_LOCAL"},
  {"IPv4 unknown local protocol refused",func(){r:=localRoute4("224.0.0.0/4");r.Protocol=0;routes=[]fakeRow{r}},"DORMANT_ROUTE_PROTOCOL_NOT_LOCAL"},
  {"IPv4 gateway multicast refused",func(){r:=localRoute4("224.0.0.0/4");r.NextHop.value=netip.MustParseAddr("192.168.1.1");routes=[]fakeRow{r}},"DORMANT_ROUTE_NEXT_HOP_UNSAFE"},
  {"IPv4 gateway broadcast refused",func(){r:=localRoute4("255.255.255.255/32");r.NextHop.value=netip.MustParseAddr("192.168.1.1");routes=[]fakeRow{r}},"DORMANT_ROUTE_NEXT_HOP_UNSAFE"},
  {"IPv4 route with IPv6 unspecified next-hop refused",func(){r:=localRoute4("224.0.0.0/4");r.NextHop=fakeSockaddr{Family:23,value:netip.IPv6Unspecified()};routes=[]fakeRow{r}},"DORMANT_ROUTE_NEXT_HOP_UNSAFE"},
  {"IPv4 route with unknown next-hop family refused",func(){r:=localRoute4("224.0.0.0/4");r.NextHop.Family=0;routes=[]fakeRow{r}},"DORMANT_ROUTE_NEXT_HOP_UNSAFE"},
  {"other LUID local route cannot hide target default",func(){r:=localRoute4("224.0.0.0/4");r.InterfaceLUID=8;routes=[]fakeRow{r,localRoute4("0.0.0.0/0")}},"DORMANT_ROUTE_DESTINATION_UNSAFE"},
  {"other LUID route remains untouched",func(){r:=localRoute4("0.0.0.0/0");r.InterfaceLUID=8;routes=[]fakeRow{r,localRoute4("224.0.0.0/4")}},""},
  {"DNS query error",func(){dnsErr=errors.New("native")},"DORMANT_DNS_QUERY_FAILED"},
  {"malformed native DNS row",func(){adapters=[]*fakeAdapter{nil}},"DORMANT_DNS_QUERY_FAILED"},
  {"duplicate LUID",func(){adapters=[]*fakeAdapter{empty(),empty()}},"DORMANT_DNS_QUERY_FAILED"},
  {"Down residual DNS server metadata",func(){a:=empty();a.FirstDNSServerAddress=new(int);adapters=[]*fakeAdapter{a}},""},
  {"Down inherited DNS suffix metadata",func(){a:=empty();a.suffix="example.test";adapters=[]*fakeAdapter{a}},""},
  {"Down inherited DNS suffix-list metadata",func(){a:=empty();a.FirstDNSSuffix=new(int);adapters=[]*fakeAdapter{a}},""},
  {"Down legacy DNS and suffix metadata",func(){adapters=[]*fakeAdapter{legacyDNS()}},""},
  {"Up with legacy DNS remains refused",func(){a:=legacyDNS();a.OperStatus=1;adapters=[]*fakeAdapter{a}},"ORPHAN_IDENTITY_FAILED"},
  {"duplicate LUID with legacy DNS refused",func(){adapters=[]*fakeAdapter{legacyDNS(),empty()}},"DORMANT_DNS_QUERY_FAILED"},
  {"query error with legacy DNS refused",func(){adapters=[]*fakeAdapter{legacyDNS()};dnsErr=errors.New("native")},"DORMANT_DNS_QUERY_FAILED"},
  {"identity conflict with legacy DNS refused",func(){a:=legacyDNS();a.name="other";adapters=[]*fakeAdapter{a}},"ORPHAN_IDENTITY_FAILED"},
  {"dirty IPv4 with legacy DNS refused",func(){a:=autoLLA("198.18.0.1");a.Address.Family=2;a.PrefixOrigin=1;addresses=[]fakeRow{a};adapters=[]*fakeAdapter{legacyDNS()}},"DORMANT_IP_NOT_EMPTY"},
  {"manual route with legacy DNS refused",func(){r:=localRoute4("224.0.0.0/4");r.Protocol=3;routes=[]fakeRow{r};adapters=[]*fakeAdapter{legacyDNS()}},"DORMANT_ROUTE_PROTOCOL_NOT_LOCAL"},
  {"gateway route with legacy DNS refused",func(){r:=localRoute4("224.0.0.0/4");r.NextHop.value=netip.MustParseAddr("192.168.1.1");routes=[]fakeRow{r};adapters=[]*fakeAdapter{legacyDNS()}},"DORMANT_ROUTE_NEXT_HOP_UNSAFE"},
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
func legacyDNS() *fakeAdapter {a:=empty();a.FirstDNSServerAddress=new(int);a.FirstDNSSuffix=new(int);a.suffix="legacy.example.test";return a}
func autoLLA(ip string) fakeRow {return fakeRow{InterfaceLUID:7,Address:fakeSockaddr{Family:23,value:netip.MustParseAddr(ip)},PrefixOrigin:2,SuffixOrigin:5,OnLinkPrefixLength:64}}
func localRoute(prefix string) fakeRow {return fakeRow{InterfaceLUID:7,DestinationPrefix:fakePrefix{netip.MustParsePrefix(prefix)},NextHop:fakeSockaddr{Family:23,value:netip.IPv6Unspecified()},Protocol:2}}
func localRoute4(prefix string) fakeRow {return fakeRow{InterfaceLUID:7,DestinationPrefix:fakePrefix{netip.MustParsePrefix(prefix)},NextHop:fakeSockaddr{Family:2,value:netip.IPv4Unspecified()},Protocol:2}}
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

    def test_park_dns_cleanup_and_down_require_readback_on_same_creator(self):
        source = vendor.PARKED.split('func ParkOracleAdapter()', 1)[1].split('func VerifyParkedOracleAdapter()', 1)[0]
        source = 'func ParkOracleAdapter()' + source
        source = source.replace('windows.', '').replace('winipcfg.', '')
        declarations = '''package parkflow
import ("fmt"; "sync"; "time")
type LUID uint64
const AF_INET=2
const AF_INET6=23
const AF_UNSPEC=0
const NetIfAdminStatusUp=1
const NetIfAdminStatusDown=2
const DnsInterfaceSettingsVersion1=1
const DnsInterfaceSettingsFlagNameserver=2
const DnsInterfaceSettingsFlagSearchList=4
const DnsInterfaceSettingsFlagDomain=32
const DnsInterfaceSettingsFlagIPv6=1
type AddressFamily int
type DnsInterfaceSettings struct {Version,Flags int; NameServer,SearchList,Domain *uint16}
type creator struct{}
func (*creator) LUID() uint64{return 7}
var oracleAdapterMutex sync.Mutex
var oraclePreparedAdapter *creator
var oracleStrictlyParked bool
var initialDNS,currentDNS,downResult string
var clearFailureFlags,writeCalls,downCalls,identityCalls,failIdentityAt,readbacks int
var clearImmediately bool
func UTF16PtrFromString(value string)(*uint16,error){if value!=""{panic("unexpected DNS setting")};return new(uint16),nil}
func generateGUIDByDeviceName(name string)*int{ if name!="OracleProxy"{panic("unexpected target")};v:=42;return &v}
func checkLUID(l LUID){if l!=7 {panic("touched other adapter")}}
func verifyOracleDormantEmpty(l LUID)error{checkLUID(l);return nil}
func verifyOracleRecoveryIdentity(l LUID)error{
    checkLUID(l);identityCalls++
    if failIdentityAt==identityCalls{return fmt.Errorf("ORPHAN_IDENTITY_FAILED")}
    return nil
}
func verifyOracleParkedEmpty(l LUID)error{
    checkLUID(l);readbacks++;if currentDNS!=""{return fmt.Errorf("%s",currentDNS)};return nil
}
func oraclePreparedDNSProblem(l LUID)string{checkLUID(l);return initialDNS}
func(l LUID) FlushIPAddresses(f int)error{checkLUID(l);if f!=AF_UNSPEC{panic("wrong family")};return nil}
func(l LUID) FlushRoutes(f int)error{checkLUID(l);if f!=AF_UNSPEC{panic("wrong family")};return nil}
func SetInterfaceDnsSettings(guid int, s *DnsInterfaceSettings)error{
    if guid!=42||s.Version!=1||s.NameServer==nil||*s.NameServer!=0||s.SearchList==nil||*s.SearchList!=0||s.Domain==nil||*s.Domain!=0 {panic("unscoped or nonempty write")}
    wanted:=2|4|32
    if writeCalls==1{wanted|=1}
    if wanted!=s.Flags{panic("unexpected DNS flags")}
    writeCalls++
    if s.Flags==clearFailureFlags{return fmt.Errorf("write failed")}
    if writeCalls==2 && clearImmediately{currentDNS=""}
    return nil
}
func setOracleParkedAdmin(l LUID,from,to int)error{
    checkLUID(l);if from!=1||to!=2{panic("unexpected admin change")};downCalls++;currentDNS=downResult;return nil
}
'''
        cases = '''package parkflow
import "testing"
func TestOwnedCleanupAndIndependentVerification(t *testing.T){
    const server="PARK_DNS_SERVER_PRESENT"
    const suffix="PARK_DNS_SUFFIX_PRESENT"
    for _,tc:=range []struct{name,initial,input,afterDown,want string; clearNow bool; failFlags,failAt,writes,disables int}{
        {"already empty","","","","",false,0,0,0,0},
        {"configured suffix clears on exact write",suffix,suffix,"", "",true,0,0,2,0},
        {"default servers cleared by admin-down",server,server,"","",false,0,0,2,1},
        {"IPv6 clear refused; actual Down still empty",server,server,"","",false,39,0,2,1},
        {"IPv4 clear refused and still present",server,server,server,"PARK_DNS4_CLEAR_FAILED",false,38,0,2,1},
        {"IPv6 clear refused and still present",server,server,server,"PARK_DNS6_CLEAR_FAILED",false,39,0,2,1},
        {"DNS still present despite successful calls",server,server,server,server,false,0,0,2,1},
        {"malformed DNS while address rows exist","PARK_DNS_LIST_INVALID","PARK_IP_NOT_EMPTY","","PARK_DNS_LIST_INVALID",false,0,0,0,0},
        {"ambiguous GAA ownership","PARK_INTERFACE_QUERY_FAILED","PARK_IP_NOT_EMPTY","","PARK_INTERFACE_QUERY_FAILED",false,0,0,0,0},
        {"identity lost before second family",server,server,"","ORPHAN_IDENTITY_FAILED",false,0,2,1,0},
    }{
        t.Run(tc.name,func(t *testing.T){
            oraclePreparedAdapter=&creator{};oracleStrictlyParked=false;initialDNS=tc.initial;currentDNS=tc.input;downResult=tc.afterDown
            clearImmediately=tc.clearNow;clearFailureFlags=tc.failFlags;failIdentityAt=tc.failAt
            writeCalls=0;downCalls=0;identityCalls=0;readbacks=0
            err:=ParkOracleAdapter();got:="";if err!=nil{got=err.Error()}
            if got!=tc.want || oracleStrictlyParked!=(tc.want=="") || writeCalls!=tc.writes || downCalls!=tc.disables || readbacks==0{
                t.Fatalf("got %q parked=%v writes=%d disables=%d independent-readbacks=%d",got,oracleStrictlyParked,writeCalls,downCalls,readbacks)
            }
        })
    }
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'park.go').write_text(declarations + source)
            (root / 'park_test.go').write_text(cases)
            env = dict(os.environ, GO111MODULE='off', GOWORK='off', GOPROXY='off', GOTOOLCHAIN='local')
            for key in ('GOOS', 'GOARCH'):
                env.pop(key, None)
            result = subprocess.run(['go', 'test', 'park.go', 'park_test.go'], cwd=root, env=env,
                                    text=True, capture_output=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_parked_adapter_requires_zero_native_tables_and_complete_identity(self):
        start = vendor.PARKED.index('func verifyOracleParkedEmpty(')
        end = vendor.PARKED.index('var oracleSetIfEntry', start)
        dns_start = vendor.CACHE.index('func oracleAdapterDNSProblem(')
        dns_end = vendor.CACHE.index('func (t *NativeTun) prepareOracleAdapter()', dns_start)
        source = (vendor.CACHE[dns_start:dns_end] + vendor.PARKED[start:end]).replace(
            'winipcfg.IPAdapterAddresses', 'adapter').replace('winipcfg.', '').replace('windows.', '')
        harness = '''package parked
import "fmt"
type LUID uint64
const AF_UNSPEC=0
const GAAFlagIncludeAllInterfaces=0x100
type row struct { InterfaceLUID LUID }
type adapter struct {
    LUID LUID
    FirstUnicastAddress, FirstAnycastAddress, FirstMulticastAddress, FirstDNSServerAddress *int
    FirstDNSSuffix *suffixNode
    suffix string
}
type suffixNode struct {Next *suffixNode; value string}
func (s *suffixNode) String() string {return s.value}
func (a *adapter) DNSSuffix() string {return a.suffix}
var ips,routes []row
var entries []*adapter
var ipErr,routeErr,adapterErr error
var identityCalls,failOnIdentity int
func verifyOracleRecoveryIdentity(luid LUID) error {
    identityCalls++
    if luid!=7 || identityCalls==failOnIdentity {return fmt.Errorf("IDENTITY")}
    return nil
}
func GetUnicastIPAddressTable(int)([]row,error){return ips,ipErr}
func GetIPForwardTable2(int)([]row,error){return routes,routeErr}
func GetAdaptersAddresses(family,flags int)([]*adapter,error){
    if family!=AF_UNSPEC || flags!=GAAFlagIncludeAllInterfaces {return nil,fmt.Errorf("unexpected enumeration scope")}
    return entries,adapterErr
}
'''
        tests = '''package parked
import ("fmt"; "testing")
func TestLiteralOff(t *testing.T) {
    value:=1
    for _,tc:=range []struct{name string; change func(); want bool}{
        {"empty",func(){},true},
        {"foreign entries",func(){ips=[]row{{8}};routes=[]row{{8}};entries=append(entries,&adapter{LUID:8,FirstDNSServerAddress:&value})},true},
        {"link local row on own interface",func(){ips=[]row{{7}}},false},
        {"local multicast route on own interface",func(){routes=[]row{{7}}},false},
        {"unicast metadata",func(){entries[0].FirstUnicastAddress=&value},false},
        {"anycast metadata",func(){entries[0].FirstAnycastAddress=&value},false},
        {"multicast membership",func(){entries[0].FirstMulticastAddress=&value},false},
        {"dns server",func(){entries[0].FirstDNSServerAddress=&value},false},
        {"blank suffix list",func(){entries[0].FirstDNSSuffix=&suffixNode{Next:&suffixNode{}}},true},
        {"dns suffix list",func(){entries[0].FirstDNSSuffix=&suffixNode{Next:&suffixNode{value:"local"}}},false},
        {"dns suffix",func(){entries[0].suffix="example.test"},false},
        {"missing exact record",func(){entries=nil},false},
        {"duplicate exact record",func(){entries=append(entries,entries[0])},false},
        {"ambiguous snapshot",func(){entries=append(entries,nil)},false},
        {"unicast read error",func(){ipErr=fmt.Errorf("io")},false},
        {"route read error",func(){routeErr=fmt.Errorf("io")},false},
        {"adapter read error",func(){adapterErr=fmt.Errorf("io")},false},
        {"owner changed before audit",func(){failOnIdentity=1},false},
        {"owner changed during audit",func(){failOnIdentity=2},false},
    } {
        ips=nil; routes=nil; entries=[]*adapter{{LUID:7}}
        ipErr=nil;routeErr=nil;adapterErr=nil;identityCalls=0;failOnIdentity=0
        tc.change()
        if got:=verifyOracleParkedEmpty(7)==nil; got!=tc.want {t.Fatalf("%s: got %v",tc.name,got)}
    }
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'parked.go').write_text(harness + source)
            (root / 'parked_test.go').write_text(tests)
            env = dict(os.environ, GO111MODULE='off', GOWORK='off', GOPROXY='off', GOTOOLCHAIN='local')
            for variable in ('GOOS', 'GOARCH'):
                env.pop(variable, None)
            result = subprocess.run(['go', 'test', 'parked.go', 'parked_test.go'], cwd=root,
                                    capture_output=True, text=True, env=env, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_parked_admin_change_writes_only_exact_roundtripped_index(self):
        start = vendor.PARKED.index('func setOracleParkedAdmin(')
        source = vendor.PARKED[start:].replace('winipcfg.', '').replace('windows.', '')
        harness = '''package parked
import ("fmt"; "unsafe")
type LUID uint64
type NetIfAdminStatus uint32
const NetIfAdminStatusDown NetIfAdminStatus = 2
var oracleParkedAdminDown bool
type MibIfRow struct { Index,AdminStatus uint32 }
type iface struct { InterfaceLUID LUID; InterfaceIndex uint32; AdminStatus NetIfAdminStatus }
var current iface
var roundTrip LUID
var writeCount,identityCalls int
var procFailure,writeFailure,wrongReadback,postIdentityFailure bool
func (luid LUID) Interface() (*iface,error) {row:=current;return &row,nil}
func LUIDFromIndex(idx uint32)(LUID,error){if idx!=42{return 0,fmt.Errorf("index")}; return roundTrip,nil}
func verifyOracleRecoveryIdentity(luid LUID)error{
    identityCalls++
    if luid!=7||(postIdentityFailure && identityCalls==2){return fmt.Errorf("identity")}
    return nil
}
type testProc struct{}
var oracleSetIfEntry=testProc{}
func (testProc)Find()error{if procFailure{return fmt.Errorf("unavailable")};return nil}
func (testProc)Call(ptr uintptr)(uintptr,uintptr,error){
    req:=(*MibIfRow)(unsafe.Pointer(ptr));writeCount++
    if req.Index!=42||writeFailure{return 1,0,nil}
    if !wrongReadback{current.AdminStatus=NetIfAdminStatus(req.AdminStatus)}
    return 0,0,nil
}
'''
        tests = '''package parked
import "testing"
func TestExactOwner(t *testing.T) {
    for _,tc:=range []struct{name string; change func(); want bool; writes int}{
        {"correct disable",func(){},true,1},
        {"wrong source state",func(){current.AdminStatus=2},false,0},
        {"invalid index",func(){current.InterfaceIndex=0},false,0},
        {"foreign LUID",func(){current.InterfaceLUID=8},false,0},
        {"index reassigned",func(){roundTrip=8},false,0},
        {"missing API",func(){procFailure=true},false,0},
        {"OS rejected write",func(){writeFailure=true},false,1},
        {"different state after write",func(){wrongReadback=true},false,1},
        {"identity lost after write",func(){postIdentityFailure=true},false,1},
    }{
        current=iface{7,42,1};roundTrip=7;identityCalls=0;writeCount=0
        writeFailure=false;procFailure=false;wrongReadback=false;postIdentityFailure=false
        oracleParkedAdminDown=false
        tc.change()
        got:=setOracleParkedAdmin(7,1,2)==nil
        if oracleParkedAdminDown!=(tc.writes==1 && !writeFailure){t.Fatalf("%s: restore witness",tc.name)}
        if got!=tc.want||writeCount!=tc.writes{t.Fatalf("%s: ok=%v writes=%d",tc.name,got,writeCount)}
    }
    current=iface{7,42,2};roundTrip=7;identityCalls=0;postIdentityFailure=false
    if err:=setOracleParkedAdmin(7,2,1);err!=nil||current.AdminStatus!=1{t.Fatal(err)}
}
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'admin.go').write_text(harness + source)
            (root / 'admin_test.go').write_text(tests)
            env = dict(os.environ, GO111MODULE='off', GOWORK='off', GOPROXY='off', GOTOOLCHAIN='local')
            for variable in ('GOOS', 'GOARCH'):
                env.pop(variable, None)
            result = subprocess.run(['go', 'test', 'admin.go', 'admin_test.go'], cwd=root,
                                    capture_output=True, text=True, env=env, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

if __name__=='__main__':unittest.main()
