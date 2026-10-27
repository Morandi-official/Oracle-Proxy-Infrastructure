"""Check or refresh only the shipped client's pinned .NET 10 LTS SDK/runtime.

Scheduled checks are read-only. Refresh stages a patch update for normal review,
Windows acceptance and a new distribution; it never updates installed clients.
"""
import argparse
from datetime import date
import json
from pathlib import Path
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET

PRODUCT = Path(__file__).resolve().parents[1]
METADATA_URL = 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json'
PROJECTS = ('OracleProxy.Product.csproj', 'ci/OracleProxy.Product.Tests.csproj',
            'ci/OracleProxy.BadUpgrade.csproj')


def version(value, kind):
    pattern = r'10\.0\.[0-9]{3}' if kind == 'sdk' else r'10\.0\.[0-9]+'
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError('STABLE_DOTNET_10_' + kind.upper() + '_REQUIRED')
    return tuple(map(int, value.split('.')))


def pins(product=PRODUCT):
    sdk_json = json.loads((product / 'global.json').read_text(encoding='utf-8'))
    sdk = sdk_json['sdk']
    version(sdk.get('version'), 'sdk')
    if sdk.get('rollForward') != 'disable' or sdk.get('allowPrerelease') is not False:
        raise ValueError('EXACT_STABLE_SDK_REQUIRED')
    root = ET.parse(product / 'Directory.Build.props').getroot()
    result = {'sdk': sdk['version']}
    for name in ('RuntimeFrameworkVersion', 'OracleDotNetPackageVersion', 'TargetLatestRuntimePatch'):
        elements = list(root.iter(name))
        if len(elements) != 1 or elements[0].attrib:
            raise ValueError('ONE_UNCONDITIONAL_RUNTIME_PIN_REQUIRED')
        result[name] = elements[0].text
    version(result['RuntimeFrameworkVersion'], 'runtime')
    if (result['OracleDotNetPackageVersion'] != result['RuntimeFrameworkVersion'] or
            result['TargetLatestRuntimePatch'] != 'false'):
        raise ValueError('RUNTIME_AND_FIRST_PARTY_PACKAGE_PINS_MUST_AGREE')
    return {'sdk': result['sdk'], 'runtime': result['RuntimeFrameworkVersion']}


def check_source(product=PRODUCT):
    current = pins(product)
    for name in PROJECTS:
        root = ET.parse(product / name).getroot()
        values = {tag: [element.text for element in root.iter(tag)]
                  for tag in ('TargetFramework', 'SelfContained', 'PublishSingleFile')}
        if values != {'TargetFramework': ['net10.0-windows'], 'SelfContained': ['true'],
                      'PublishSingleFile': ['true']}:
            raise ValueError('ALL_SHIPPED_AND_ACCEPTANCE_PROJECTS_REQUIRE_SELF_CONTAINED_NET10')
        references = {element.get('Include'): element.get('Version')
                      for element in root.iter('PackageReference')}
        for package in ('System.ServiceProcess.ServiceController',
                        'System.Security.Cryptography.ProtectedData'):
            if references.get(package) != '$(OracleDotNetPackageVersion)':
                raise ValueError('FIRST_PARTY_PACKAGE_MUST_USE_RUNTIME_PIN')
    return current


def check_published(product=PRODUCT):
    current = check_source(product)
    config = product / 'bin/Release/net10.0-windows/win-x64/OracleProxy.runtimeconfig.json'
    options = json.loads(config.read_text(encoding='utf-8'))['runtimeOptions']
    frameworks = options.get('includedFrameworks', [])
    actual = {item['name']: item['version'] for item in frameworks}
    expected = {'Microsoft.NETCore.App': current['runtime'],
                'Microsoft.WindowsDesktop.App': current['runtime']}
    if (options.get('tfm') != 'net10.0' or options.get('framework') or options.get('frameworks') or
            len(frameworks) != 2 or actual != expected):
        raise ValueError('BUNDLED_CORE_AND_DESKTOP_RUNTIME_MUST_MATCH_EXACT_LTS_PIN')
    return current


def latest(metadata, current, today=None):
    if (metadata.get('channel-version') != '10.0' or metadata.get('release-type') != 'lts' or
            metadata.get('support-phase') not in ('active', 'maintenance')):
        raise ValueError('SUPPORTED_DOTNET_10_LTS_METADATA_REQUIRED')
    result = {'sdk': metadata.get('latest-sdk'), 'runtime': metadata.get('latest-runtime')}
    for name in ('sdk', 'runtime'):
        if version(result[name], name) < version(current[name], name):
            raise ValueError('RUNTIME_METADATA_DOWNGRADE_REJECTED')
    support_end = date.fromisoformat(metadata['eol-date'])
    days = (support_end - (today or date.today())).days
    if days <= 180:
        raise ValueError('DOTNET_LTS_SUPPORT_ENDS_WITHIN_180_DAYS_PLAN_NEXT_LTS')
    # Cross-check the top-level latest pointers against one published stable
    # runtime + Windows Desktop release and its SDK/runtime compatibility row.
    found = False
    for release in metadata.get('releases', []):
        if (release.get('runtime', {}).get('version') != result['runtime'] or
                release.get('windowsdesktop', {}).get('version') != result['runtime']):
            continue
        sdks = [release.get('sdk', {})] + release.get('sdks', [])
        if any(item.get('version') == result['sdk'] and
               item.get('runtime-version') == result['runtime'] for item in sdks):
            found = True
    if not found:
        raise ValueError('MATCHING_STABLE_DESKTOP_RUNTIME_AND_SDK_RELEASE_REQUIRED')
    return result, support_end.isoformat()


def refresh(product, target):
    # Validate every replacement before writing either authority. No package,
    # workflow, major version, execution hook or other file can come from metadata.
    current = check_source(product)
    for name in ('sdk', 'runtime'):
        if version(target[name], name) < version(current[name], name):
            raise ValueError('PIN_DOWNGRADE_REJECTED')
    sdk_path, props_path = product / 'global.json', product / 'Directory.Build.props'
    sdk_json = json.loads(sdk_path.read_text(encoding='utf-8'))
    sdk_json['sdk']['version'] = target['sdk']
    props = props_path.read_text(encoding='utf-8')
    for name in ('RuntimeFrameworkVersion', 'OracleDotNetPackageVersion'):
        pattern = r'(<'+name+r'>)'+re.escape(current['runtime'])+r'(</'+name+r'>)'
        props, count = re.subn(pattern, lambda m: m[1]+target['runtime']+m[2], props)
        if count != 1:
            raise ValueError('EXACT_RUNTIME_PIN_REPLACEMENT_REQUIRED')
    staged = [(sdk_path, json.dumps(sdk_json, indent=2)+'\n'), (props_path, props)]
    for path, contents in staged:
        temporary = path.with_name(path.name+'.refresh.tmp')
        temporary.write_text(contents, encoding='utf-8')
        temporary.replace(path)
    check_source(product)


def fetch_metadata():
    # Fixed HTTPS origin and bounded response; metadata never supplies a URL to
    # execute or download. Preserve the environment's normal proxy/CA validation.
    request = urllib.request.Request(METADATA_URL, headers={'User-Agent': 'OracleProxy-runtime-check'})
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read(8*1024*1024+1)
    if len(body) > 8*1024*1024:
        raise ValueError('RUNTIME_METADATA_TOO_LARGE')
    return json.loads(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['check', 'check-published', 'check-updates', 'refresh'])
    args = parser.parse_args()
    current = check_published() if args.operation == 'check-published' else check_source()
    if args.operation in ('check', 'check-published'):
        print('DOTNET_LTS_POLICY='+json.dumps(current, sort_keys=True))
        return 0
    target, end = latest(fetch_metadata(), current)
    print('DOTNET_LTS_CURRENT='+json.dumps(current, sort_keys=True))
    print('DOTNET_LTS_LATEST='+json.dumps(target, sort_keys=True))
    print('DOTNET_LTS_SUPPORT_END='+end)
    if target == current:
        print('DOTNET_LTS_PATCH_CHECK=UP_TO_DATE')
        return 0
    if args.operation == 'refresh':
        refresh(PRODUCT, target)
        print('DOTNET_LTS_PINS_REFRESHED=REVIEW_AND_WINDOWS_ACCEPTANCE_REQUIRED')
        return 0
    print('::error title=.NET LTS patch available::New SDK/runtime pins require a reviewed build and new portable/setup release. Run python clients/windows/product/ci/dotnet-runtime-policy.py refresh; no installed client was changed.')
    return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, ET.ParseError, json.JSONDecodeError) as error:
        print('::error title=.NET LTS policy check failed::'+str(error), file=sys.stderr)
        sys.exit(1)
