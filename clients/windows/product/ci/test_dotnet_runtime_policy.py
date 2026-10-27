import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from datetime import date

SPEC = importlib.util.spec_from_file_location('runtime_policy', Path(__file__).with_name('dotnet-runtime-policy.py'))
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class RuntimePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.product = Path(self.temp.name)
        (self.product / 'global.json').write_text(json.dumps({'sdk': {'version': '10.0.403', 'rollForward': 'disable', 'allowPrerelease': False}}))
        (self.product / 'Directory.Build.props').write_text('<Project><PropertyGroup><RuntimeFrameworkVersion>10.0.14</RuntimeFrameworkVersion><TargetLatestRuntimePatch>false</TargetLatestRuntimePatch><OracleDotNetPackageVersion>10.0.14</OracleDotNetPackageVersion></PropertyGroup></Project>')
        for name in policy.PROJECTS:
            path = self.product / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('<Project><PropertyGroup><TargetFramework>net10.0-windows</TargetFramework><SelfContained>true</SelfContained><PublishSingleFile>true</PublishSingleFile></PropertyGroup><ItemGroup><PackageReference Include="System.ServiceProcess.ServiceController" Version="$(OracleDotNetPackageVersion)"/><PackageReference Include="System.Security.Cryptography.ProtectedData" Version="$(OracleDotNetPackageVersion)"/></ItemGroup></Project>')
        self.current = {'sdk': '10.0.403', 'runtime': '10.0.14'}
        self.metadata = {'channel-version': '10.0', 'release-type': 'lts', 'support-phase': 'active',
                         'latest-sdk': '10.0.404', 'latest-runtime': '10.0.15', 'eol-date': '2028-11-14',
                         'releases': [{'runtime': {'version': '10.0.15'}, 'windowsdesktop': {'version': '10.0.15'},
                                       'sdk': {'version': '10.0.404', 'runtime-version': '10.0.15'}}]}

    def config(self, options):
        path = self.product / 'bin/Release/net10.0-windows/win-x64/OracleProxy.runtimeconfig.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'runtimeOptions': options}))

    def test_all_product_and_test_targets_must_be_supported_self_contained(self):
        self.assertEqual(policy.check_source(self.product), self.current)
        target = self.product / policy.PROJECTS[2]
        target.write_text(target.read_text().replace('net10.0-windows', 'net8.0-windows'))
        with self.assertRaisesRegex(ValueError, 'ALL_SHIPPED'):
            policy.check_source(self.product)

    def test_framework_dependent_or_wrong_runtime_bundle_is_rejected(self):
        valid = {'tfm': 'net10.0', 'includedFrameworks': [
            {'name': 'Microsoft.NETCore.App', 'version': '10.0.14'},
            {'name': 'Microsoft.WindowsDesktop.App', 'version': '10.0.14'}]}
        self.config(valid)
        self.assertEqual(policy.check_published(self.product), self.current)
        for invalid in ({'tfm': 'net10.0', 'frameworks': valid['includedFrameworks']},
                        {'tfm': 'net10.0', 'includedFrameworks': valid['includedFrameworks'][:1]},
                        {'tfm': 'net10.0', 'includedFrameworks': [dict(item, version='10.0.13') for item in valid['includedFrameworks']]},
                        {'tfm': 'net8.0', 'includedFrameworks': valid['includedFrameworks']}):
            with self.subTest(invalid=invalid):
                self.config(invalid)
                with self.assertRaisesRegex(ValueError, 'BUNDLED_CORE'):
                    policy.check_published(self.product)

    def test_preview_major_mismatch_or_unmatched_sdk_release_is_rejected(self):
        target, end = policy.latest(self.metadata, self.current, date(2026, 10, 27))
        self.assertEqual(target, {'sdk': '10.0.404', 'runtime': '10.0.15'})
        self.assertEqual(end, '2028-11-14')
        for update in ({'channel-version': '11.0'}, {'release-type': 'sts'},
                       {'support-phase': 'eol'}, {'latest-runtime': '10.0.16-preview.1'},
                       {'latest-sdk': '11.0.100'}, {'releases': []}):
            with self.subTest(update=update):
                with self.assertRaises(ValueError):
                    policy.latest(dict(self.metadata, **update), self.current, date(2026, 10, 27))

    def test_metadata_downgrade_or_near_end_of_support_fails(self):
        for update in ({'latest-runtime': '10.0.13'}, {'latest-sdk': '10.0.402'},
                       {'eol-date': '2027-01-01'}):
            with self.subTest(update=update):
                with self.assertRaises(ValueError):
                    policy.latest(dict(self.metadata, **update), self.current, date(2026, 10, 27))

    def test_refresh_changes_only_two_authorities_and_requires_reviewed_new_build(self):
        before = {p.relative_to(self.product).as_posix(): p.read_bytes() for p in self.product.rglob('*') if p.is_file()}
        target, _ = policy.latest(self.metadata, self.current, date(2026, 10, 27))
        policy.refresh(self.product, target)
        self.assertEqual(policy.check_source(self.product), target)
        after = {p.relative_to(self.product).as_posix(): p.read_bytes() for p in self.product.rglob('*') if p.is_file()}
        self.assertEqual(before.keys(), after.keys())
        self.assertEqual({name for name in before if before[name] != after[name]}, {'global.json', 'Directory.Build.props'})
        self.assertEqual(json.loads((self.product / 'global.json').read_text())['sdk']['rollForward'], 'disable')
        with self.assertRaises(ValueError):
            policy.refresh(self.product, self.current)

    def test_unpinned_sdk_or_conditional_runtime_authority_is_rejected(self):
        path = self.product / 'global.json'
        value = json.loads(path.read_text())
        value['sdk']['rollForward'] = 'latestFeature'
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'EXACT_STABLE_SDK'):
            policy.check_source(self.product)
        value['sdk']['rollForward'] = 'disable'
        path.write_text(json.dumps(value))
        props = self.product / 'Directory.Build.props'
        props.write_text(props.read_text().replace('<RuntimeFrameworkVersion>', '<RuntimeFrameworkVersion Condition="false">'))
        with self.assertRaisesRegex(ValueError, 'ONE_UNCONDITIONAL'):
            policy.check_source(self.product)

    def test_package_or_runtime_pin_drift_is_rejected(self):
        props = self.product / 'Directory.Build.props'
        props.write_text(props.read_text().replace('<OracleDotNetPackageVersion>10.0.14', '<OracleDotNetPackageVersion>10.0.13'))
        with self.assertRaisesRegex(ValueError, 'MUST_AGREE'):
            policy.check_source(self.product)


if __name__ == '__main__':
    unittest.main()
