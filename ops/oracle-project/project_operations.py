"""Project operations executed as root only after the SSH bridge verifies current main."""
import importlib.util
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SERVER = REPO / 'server/admin-oracle'
CADDY_MAIN = Path('/etc/caddy/Caddyfile')
CADDY_DIRECTORY = Path('/etc/caddy/oracle-proxy-admin')
WEB_BACKUPS = Path('/var/backups/oracle-project-ops')
spec = importlib.util.spec_from_file_location('oracle_admin_host', SERVER / 'deploy/host.py')
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)
runtime_spec = importlib.util.spec_from_file_location('oracle_runtime_install', Path(__file__).with_name('runtime_install.py'))
runtime = importlib.util.module_from_spec(runtime_spec)
runtime_spec.loader.exec_module(runtime)


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def runtime_python():
    for name in (str(runtime.PYTHON), 'python3.13', 'python3.12', 'python3.11', 'python3'):
        binary = shutil.which(name)
        if binary and subprocess.run([binary, '-c', 'import sys;sys.exit(sys.version_info<(3,11))'],
                                     check=False, stdout=subprocess.DEVNULL).returncode == 0:
            return binary
    raise ValueError('PYTHON_311_OR_NEWER_REQUIRED')


def ipv6_readiness():
    """Read-only readiness categories; never exports host addresses or changes routes."""
    result = {'status': 'OBSERVED', 'physical_global_address_count': 0,
              'physical_route_present': False, 'wireguard_address_count': 0,
              'forwarding_enabled': None, 'external_forwarding_acceptance': 'NOT_TESTED'}
    try:
        addresses = subprocess.run(['ip', '-j', '-6', 'address', 'show'],
                                   capture_output=True, text=True, check=True, timeout=5)
        route = subprocess.run(['ip', '-j', '-6', 'route', 'get', '2606:4700:4700::1111'],
                              capture_output=True, text=True, check=False, timeout=5)
        if len(addresses.stdout) > 65536 or len(route.stdout) > 65536 or route.returncode not in (0, 2):
            raise ValueError('INVALID_NETWORK_OBSERVATION')
        for interface in json.loads(addresses.stdout):
            name = interface.get('ifname')
            for item in interface.get('addr_info', []):
                if item.get('family') != 'inet6' or any(flag in item.get('flags', []) for flag in ('tentative', 'dadfailed')):
                    continue
                address = ipaddress.IPv6Address(item['local'])
                if name == 'wg0' and not address.is_link_local:
                    result['wireguard_address_count'] += 1
                elif name not in ('wg0', 'lo') and address.is_global:
                    result['physical_global_address_count'] += 1
        result['physical_route_present'] = route.returncode == 0 and any(
            item.get('dev') not in (None, 'lo', 'wg0') and not item.get('error') for item in json.loads(route.stdout))
        flag = Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip()
        if flag not in ('0', '1'): raise ValueError('INVALID_FORWARDING_OBSERVATION')
        result['forwarding_enabled'] = flag == '1'
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result['status'] = 'OBSERVATION_UNAVAILABLE'
    return result


def official_usage_status():
    """Export only fixed public observation fields, never the complete root cache."""
    path = Path('/var/lib/oracle-proxy-control/oci-usage.json')
    try:
        if path.is_symlink() or path.stat().st_size > 32768:
            raise ValueError('INVALID_USAGE_CACHE')
        value = json.loads(path.read_text())
        if not isinstance(value, dict) or value.get('schema') != 1:
            raise ValueError('INVALID_USAGE_CACHE')
        fields = ('checked_at', 'period', 'status', 'monitoring_status', 'billing_status',
                  'vnic_count', 'vnic_outbound_bytes', 'metric_points', 'metric_from', 'metric_through',
                  'metric_query_from', 'metric_query_to', 'instance_created_at', 'billing_through',
                  'billing_error_http_status', 'billing_error_category', 'billing_error_service_code')
        result = {name: value.get(name) for name in fields}
        if any(not (item is None or type(item) is int or isinstance(item, str) and len(item) <= 96)
               for item in result.values()):
            raise ValueError('INVALID_USAGE_SUMMARY')
        rows = value.get('billing_rows', [])
        if not isinstance(rows, list) or len(rows) > 32:
            raise ValueError('INVALID_BILLING_SUMMARY')
        result['billing_rows'] = []
        for row in rows:
            if not isinstance(row, dict): raise ValueError('INVALID_BILLING_SUMMARY')
            sku, unit, quantity = row.get('sku'), row.get('unit'), row.get('quantity')
            if (not isinstance(sku, str) or len(sku) > 160 or not isinstance(unit, str) or len(unit) > 40 or
                type(quantity) not in (int, float) or not math.isfinite(quantity) or not 0 <= quantity <= 10**18):
                raise ValueError('INVALID_BILLING_SUMMARY')
            result['billing_rows'].append({'sku': sku, 'unit': unit, 'quantity': quantity})
        result['remaining_bytes'] = None
        return result
    except (OSError, ValueError):
        return {'status': 'CACHE_UNAVAILABLE', 'remaining_bytes': None}


def preflight():
    try:
        value = host.preflight()
    except OSError:
        value = {'required_network_inspection_tools': 'missing'}
    value['os_release'] = Path('/etc/os-release').read_text() if Path('/etc/os-release').exists() else 'unknown'
    value['application_configured'] = False
    try:
        host.read_environment(); value['application_configured'] = True
    except (OSError, ValueError):
        pass
    value['ipv6_readiness'] = ipv6_readiness()
    value['official_usage'] = official_usage_status()
    print(json.dumps(value, indent=2))


def install_runtime():
    runtime.seal_permissions()
    if not all(shutil.which(name) for name in ('ipset','wg','ip','iptables','ip6tables')):
        run(['apt-get','update'],env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l'})
        run(['apt-get','install','-y','--no-install-recommends','ipset','wireguard-tools','iproute2','iptables'],
            env={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l'})
    try:
        python = runtime_python()
        if shutil.which('caddy') and subprocess.run([python, '-c', 'import venv,ensurepip'],
                                                  check=False, stdout=subprocess.DEVNULL,
                                                  stderr=subprocess.DEVNULL).returncode == 0:
            print('PROJECT_RUNTIME=ALREADY_READY'); return
    except ValueError:
        pass
    # These are fixed distro packages, not caller-provided package names or scripts.
    if not shutil.which('apt-get'):
        raise ValueError('RUNTIME_AUTOMATION_CURRENTLY_REQUIRES_APT_DISTRO')
    run(['apt-get', 'update'], env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    runtime.install()
    runtime_python()
    print('PROJECT_RUNTIME=READY')


def parse_configuration(body):
    if len(body) > 4096:
        raise ValueError('CONFIGURATION_REJECTED')
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError):
        raise ValueError('CONFIGURATION_REJECTED') from None
    if not isinstance(value, dict) or set(value) != {'client_id', 'client_secret'}:
        raise ValueError('CONFIGURATION_REJECTED')
    if (not isinstance(value['client_id'], str) or not re.fullmatch(r'[A-Za-z0-9]{8,100}', value['client_id']) or
        not isinstance(value['client_secret'], str) or not re.fullmatch(r'[A-Za-z0-9_=-]{16,256}', value['client_secret'])):
        raise ValueError('CONFIGURATION_REJECTED')
    return value


def configure(body):
    value = parse_configuration(body)
    try:
        host.prepare_configuration()
    except ValueError:
        # First creation intentionally writes a protected placeholder config.
        # Validate ownership independently before changing only OAuth fields.
        pass
    info = host.regular(host.CONFIG)
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('UNTRUSTED_HOST_CONFIGURATION')
    old = host.CONFIG.read_bytes()
    text = old.decode()
    for name, key in (('ADMIN_GITHUB_CLIENT_ID', 'client_id'), ('ADMIN_GITHUB_CLIENT_SECRET', 'client_secret')):
        text, count = re.subn(r'^' + name + r'=.*$', name + '=' + value[key], text, flags=re.MULTILINE)
        if count != 1: raise ValueError('HOST_CONFIGURATION_FIELD_MISSING')
    atomic(host.CONFIG, text.encode(), 0o600)
    try: host.read_environment()
    except Exception:
        atomic(host.CONFIG, old, 0o600)
        raise
    print('PROJECT_OAUTH_CONFIGURATION=UPDATED; existing session and MFA keys retained')


def atomic(path, body, mode):
    if path.is_symlink(): raise ValueError('SYMLINK_CONFIGURATION_REJECTED')
    descriptor, temporary = tempfile.mkstemp(prefix='.oracle-project-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream: stream.write(body)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def enable_web_firewall():
    helper = Path('/usr/local/libexec/oracle-project/web_firewall.py')
    unit = Path('/etc/systemd/system/oracle-proxy-admin-web-firewall.service')
    marker = 'Description=Oracle Proxy admin HTTP HTTPS firewall allowance'
    if unit.is_symlink() or (unit.exists() and marker not in unit.read_text()):
        raise ValueError('FOREIGN_FIREWALL_UNIT_REJECTED')
    # Capture the prior rules for diagnosis without replacing or flushing any chains.
    for name in ('iptables-save', 'ip6tables-save'):
        if shutil.which(name):
            backup = WEB_BACKUPS / ('before-web-' + name)
            if not backup.exists():
                atomic(backup, subprocess.check_output([name]), 0o600)
    atomic(helper, Path(__file__).with_name('web_firewall.py').read_bytes(), 0o644)
    atomic(unit, (f'[Unit]\n{marker}\nAfter=network-pre.target netfilter-persistent.service\n'
                 'Before=caddy.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                 'ExecStart=/usr/bin/python3 -I /usr/local/libexec/oracle-project/web_firewall.py\n'
                 '[Install]\nWantedBy=multi-user.target\n').encode(), 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'oracle-proxy-admin-web-firewall.service'])
    run(['systemctl', 'restart', 'oracle-proxy-admin-web-firewall.service'])


def deploy(revision):
    current = host.ROOT / 'current'
    if current.is_symlink() and current.resolve().name == revision:
        run(['systemctl', 'restart', host.UNIT_NAMES[0]])
        if not host.healthy(): raise ValueError('APPLICATION_UNHEALTHY')
        install_control()
        verify_control()
        install_usage_probe()
        print('PROJECT_DEPLOYMENT=ALREADY_CURRENT_HEALTHY'); return
    python = runtime_python()
    run([python, '-I', str(SERVER / 'deploy/host.py'), 'install', '--revision', revision])
    install_control()
    verify_control()
    install_usage_probe()


def verify_control():
    import urllib.request
    import time
    for _ in range(15):
        request=urllib.request.Request('http://127.0.0.1:8787/api/health',headers={'Host':host.HOST,'X-Forwarded-Proto':'https'})
        try:
            with urllib.request.urlopen(request,timeout=4) as response:
                summary=json.load(response)['control']
            if summary['ready']:
                print('PROJECT_POLICY_CONTROL_HEALTH='+json.dumps(summary,sort_keys=True));return
        except (OSError,ValueError,KeyError):pass
        time.sleep(1)
    raise ValueError('POLICY_CONTROL_OBSERVATION_NOT_READY')


def install_usage_probe():
    atomic(Path('/usr/local/libexec/oracle-project/oci-usage.py'),(SERVER/'control/oci_usage.py').read_bytes(),0o644)
    for name in ('oracle-proxy-oci-usage.service','oracle-proxy-oci-usage.timer'):
        path=Path('/etc/systemd/system')/name
        if path.is_symlink() or (path.exists() and 'Description=Oracle Proxy' not in path.read_text()): raise ValueError('FOREIGN_USAGE_PROBE_UNIT')
        atomic(path,(SERVER/'deploy'/name).read_bytes(),0o644)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now','oracle-proxy-oci-usage.timer'])
    # Independent bounded process: failures cannot pause kernel lease renewal.
    result=subprocess.run(['systemctl','start','oracle-proxy-oci-usage.service'],check=False,timeout=90)
    cache=Path('/var/lib/oracle-proxy-control/oci-usage.json')
    if result.returncode==0 and cache.is_file():
        value=json.loads(cache.read_text())
        print('OCI_READ_ONLY_API_PROBE='+json.dumps({k:value.get(k) for k in ('status','monitoring_status','billing_status','vnic_count','vnic_outbound_bytes','metric_through',
                 'instance_created_at','metric_from','metric_points','billing_through',
                 'billing_error_http_status','billing_error_category','billing_error_service_code')},sort_keys=True))
    else: print('OCI_READ_ONLY_API_PROBE=UNAVAILABLE; budget remains unknown')


def install_control():
    # This helper stays independent of the web current/previous symlink, preserving
    # kernel enforcement and the root-only ledger even during a web rollback.
    target = Path('/usr/local/libexec/oracle-project/control-agent.py')
    unit = Path('/etc/systemd/system/oracle-proxy-control.service')
    if unit.is_symlink() or (unit.exists() and 'Description=Oracle Proxy restricted policy' not in unit.read_text()):
        raise ValueError('FOREIGN_CONTROL_UNIT')
    for module in ('ip_set_hash_ip','ip_set_hash_net','xt_set'):
        run(['modprobe',module])
    lock = Path('/run/xtables.lock')
    if lock.is_symlink(): raise ValueError('UNTRUSTED_FIREWALL_LOCK')
    lock.touch(exist_ok=True)
    previous = target.read_bytes() if target.exists() else None
    atomic(target,(SERVER/'control/agent.py').read_bytes(),0o644)
    atomic(unit,(SERVER/'deploy/oracle-proxy-control.service').read_bytes(),0o644)
    dropin = Path('/etc/systemd/system/wg-quick@wg0.service.d')
    if dropin.is_symlink(): raise ValueError('UNTRUSTED_WIREGUARD_UNIT_DIRECTORY')
    dropin.mkdir(mode=0o755,exist_ok=True)
    atomic(dropin/'oracle-proxy-control.conf',b'[Unit]\nWants=oracle-proxy-control.service\nAfter=oracle-proxy-control.service\n[Service]\nExecStartPre=/usr/bin/systemctl is-active --quiet oracle-proxy-control.service\n',0o644)
    run(['systemctl','daemon-reload'])
    run(['systemctl','enable','oracle-proxy-control.service'])
    try:
        run(['systemctl','restart','oracle-proxy-control.service'])
        import time
        for _ in range(20):
            if subprocess.run(['systemctl','is-active','--quiet','oracle-proxy-control.service'],check=False).returncode==0 and Path('/run/oracle-proxy-control/control.sock').exists():
                print('PROJECT_POLICY_CONTROL=ACTIVE; no existing Peer enrolled or quota enabled automatically')
                return
            time.sleep(1)
        raise ValueError('CONTROL_STARTUP_FAILED')
    except Exception:
        if previous is not None:
            atomic(target,previous,0o644)
            subprocess.run(['systemctl','restart','oracle-proxy-control.service'],check=False)
        raise


def enable_https():
    main = CADDY_MAIN
    directory = CADDY_DIRECTORY
    snippet = directory / 'admin.caddy'
    if main.is_symlink() or directory.is_symlink() or snippet.is_symlink():
        raise ValueError('SYMLINK_WEB_CONFIGURATION_REJECTED')
    existed = main.exists()
    info = main.stat() if existed else None
    original = main.read_bytes() if existed else b''
    main_mode = (info.st_mode & 0o777) if info else 0o644
    previous_snippet = snippet.read_bytes() if snippet.exists() else None
    marker = b'import /etc/caddy/oracle-proxy-admin/*.caddy'
    if host.HOST.encode() in original:
        raise ValueError('HOST_ALREADY_DEFINED_IN_EXISTING_WEB_CONFIGURATION')
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    directory.chmod(0o755)
    backup_dir = WEB_BACKUPS
    if backup_dir.is_symlink(): raise ValueError('SYMLINK_BACKUP_DIRECTORY_REJECTED')
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup_dir.chmod(0o700)
    # Preserve the exact prior files, including a missing snippet, for host recovery.
    backup = backup_dir / ('caddy-' + str(os.stat(main).st_mtime_ns if main.exists() else 0))
    if not backup.exists(): atomic(backup, original, 0o600)
    if previous_snippet is not None:
        atomic(backup_dir / 'previous-admin.caddy', previous_snippet, 0o600)
    updated = original if marker in original.splitlines() else original + b'\n' + marker + b'\n'
    atomic(snippet, (SERVER / 'deploy/Caddyfile').read_bytes(), 0o644)
    candidate = main.parent / '.oracle-project-candidate'
    atomic(candidate, updated, 0o644)
    try:
        run(['caddy', 'validate', '--config', str(candidate), '--adapter', 'caddyfile'])
        enable_web_firewall()
        atomic(main, updated, main_mode)
        if info is not None: os.chown(main, info.st_uid, info.st_gid)
        run(['systemctl', 'reload', 'caddy'])
    except Exception:
        if existed:
            atomic(main, original, main_mode)
            os.chown(main, info.st_uid, info.st_gid)
        else: main.unlink(missing_ok=True)
        if previous_snippet is None: snippet.unlink(missing_ok=True)
        else: atomic(snippet, previous_snippet, 0o644)
        subprocess.run(['systemctl', 'reload', 'caddy'], check=False, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        raise
    finally:
        candidate.unlink(missing_ok=True)
    print('PROJECT_HTTPS_CONFIGURATION=ENABLED; existing Caddy hosts preserved')


def status():
    for unit in (*host.UNIT_NAMES, 'caddy.service', 'wg-quick@wg0.service'):
        result = subprocess.run(['systemctl', 'show', unit, '--property=ActiveState,SubState,User'],
                                capture_output=True, text=True, check=False)
        print(unit + '\n' + result.stdout.strip())
    print('LOCAL_APPLICATION_HEALTHY=' + str(host.healthy()))
    try:
        print('ADMIN_DNS=' + json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(host.HOST, 443)})))
    except OSError: print('ADMIN_DNS=UNRESOLVED')
    # Read-only networking diagnostics; no private keys, config bodies or Peer inventories.
    for command in (['ss', '-lnt', '( sport = :80 or sport = :443 or sport = :8787 )'],
                    ['iptables', '-S', 'INPUT'], ['ip6tables', '-S', 'INPUT'],
                    ['ufw', 'status'],
                    ['journalctl', '--no-pager', '-n', '25', '-u', 'caddy.service']):
        if shutil.which(command[0]):
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=15)
            print('DIAGNOSTIC=' + command[0] + '\n' + result.stdout[:20000])


def logs():
    result = subprocess.run(['journalctl', '--no-pager', '-n', '80', '-u', host.UNIT_NAMES[0],
                             '-u', host.UNIT_NAMES[1]], capture_output=True, text=True, check=False)
    text = result.stdout
    try:
        for key, value in host.read_environment().items():
            if 'SECRET' in key or 'KEY' in key:
                text = text.replace(value, '[REDACTED]')
    except (OSError, ValueError):
        # No raw diagnostic log is exported when redaction keys are unavailable.
        print('PROJECT_LOGS=UNAVAILABLE_UNTIL_CONFIGURATION_READY'); return
    print(text)


def main(arguments):
    if os.geteuid() != 0 or len(arguments) != 2 or not re.fullmatch(r'[a-f0-9]{40}', arguments[1]):
        raise ValueError('ROOT_PROJECT_OPERATION_REQUIRED')
    operation, revision = arguments
    if operation == 'preflight': preflight()
    elif operation == 'install-runtime': install_runtime()
    elif operation == 'configure': configure(sys.stdin.buffer.read(4097))
    elif operation == 'deploy': deploy(revision)
    elif operation == 'enable-https': enable_https()
    elif operation == 'status': status()
    elif operation == 'logs': logs()
    elif operation in ('start', 'stop', 'restart'):
        run(['systemctl', operation, host.UNIT_NAMES[0]])
    elif operation == 'rollback': host.rollback()
    else: raise ValueError('OPERATION_REJECTED')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except Exception:
        print('PROJECT_OPERATION_FAILED_CHECK_PREFLIGHT_OR_SERVICE_STATUS', file=sys.stderr)
        raise SystemExit(2) from None
