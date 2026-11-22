"""Apply a choice of two existing public/private pairs through the policy controller."""
from concurrent.futures import ThreadPoolExecutor
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


def catalog_module():
    source = Path(__file__).with_name('endpoint_config.py')
    if not source.exists():
        source = Path(__file__).resolve().parents[1] / 'console' / 'endpoint_config.py'
    spec = spec_from_file_location('switch_endpoint_catalog', source)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def prove_mapping(pair):
    try:
        result = subprocess.run(
            ['curl', '--fail', '--silent', '--noproxy', '*', '--proto', '=https',
             '--interface', pair['private_ipv4'], '--connect-timeout', '3', '--max-time', '5',
             '--max-filesize', '4096', 'https://1.1.1.1/cdn-cgi/trace'],
            capture_output=True, text=True, check=True, timeout=6,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return [line[3:] for line in result.stdout.splitlines() if line.startswith('ip=')] == [pair['public_ipv4']]


def verify_kernel(controller, value):
    primary = value['primary']['private_ipv4']
    backup = value['backup']['private_ipv4']
    marker = '-m comment --comment proxy-user-ingress-v1'
    nat = [
        f'-A OPX_INGRESS_EGRESS -m connmark --mark 0x20000000/0x20000000 {marker} -j SNAT --to-source {backup}',
        f'-A OPX_INGRESS_EGRESS {marker} -j SNAT --to-source {primary}',
    ]
    observed = controller.call(['iptables', '-w', '5', '-t', 'nat', '-S', 'OPX_INGRESS_EGRESS']).stdout
    if [shlex.split(line) for line in observed.splitlines() if line.startswith('-A ')] != [shlex.split(line) for line in nat]:
        raise ValueError('ENDPOINT_EGRESS_RULES_MISMATCH')
    for chain, address, dnat in (('OPX_PRIMARY_PORT', primary, False), ('OPX_INGRESS_PORT', backup, True)):
        for port in ('443', '8443', '51820'):
            rule = ['iptables', '-w', '5', '-C', chain, '-p', 'udp', '-m', 'conntrack']
            if dnat:
                rule.extend(['--ctstate', 'DNAT'])
            rule.extend(['--ctorigdst', address, '--ctorigdstport', port, *marker.split(), '-j', 'ACCEPT'])
            controller.call(rule)
    for port in ('443', '8443', '51820'):
        controller.call(['iptables', '-w', '5', '-t', 'nat', '-C', 'PREROUTING',
                         '-d', backup+'/32', '-p', 'udp', '--dport', port, '-m', 'u32', '--u32',
                         '0>>22&0x3C@8=0x01000000,0x02000000,0x03000000,0x04000000',
                         *marker.split(), '-j', 'DNAT', '--to-destination', backup+':51821'])


def save(catalog, base, candidate):
    record = {
        'baseline': catalog.version(base),
        'revision': candidate['revision'],
        'primary': candidate['primary']['public_ipv4'],
        'backup': candidate['backup']['public_ipv4'],
    }
    with tempfile.NamedTemporaryFile(dir=catalog.SELECTION_DIR, mode='w', delete=False, encoding='ascii') as stream:
        temporary = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), 0o644)
            json.dump(record, stream, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temporary, catalog.SELECTION_DIR / 'selection.json')
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise


def session_result(value, catalog, changed=False):
    return {key: value[key] for key in ('primary', 'backup', 'revision')} | {
        'version': catalog.version(value), 'changed': changed,
    }


def apply(controller, data):
    if set(data) != {'primary', 'backup', 'version'} or not isinstance(data['version'], str):
        raise ValueError('INVALID_ENDPOINT_SELECTION')
    catalog = catalog_module()
    with catalog.selection_lock():
        base = catalog.read_base()
        current = catalog.read()
        if base is None or current is None:
            raise ValueError('ENDPOINT_CATALOG_UNAVAILABLE')
        if catalog.version(current) != data['version']:
            raise ValueError('ENDPOINT_CATALOG_STALE')
        proposed = catalog.propose_selection(current, data['primary'], data['backup'], current['revision'])
        if proposed is None:
            return session_result(current, catalog)
        # Reconstruct the candidate in baseline order, as every reader will do.
        canonical = catalog.propose_selection(base, data['primary'], data['backup'], base['revision'])
        proposed = dict(canonical or base, revision=proposed['revision'])
        with ThreadPoolExecutor(max_workers=2) as probes:
            if not all(list(probes.map(prove_mapping, (proposed['primary'], proposed['backup'])))):
                raise ValueError('ENDPOINT_BINDING_NOT_VERIFIED')
        try:
            controller.ensure(controller.configure(proposed)[1])
            verify_kernel(controller, proposed)
            save(catalog, base, proposed)
        except Exception:
            controller.ready = False
            try:
                controller.ensure(controller.configure(current)[1])
                verify_kernel(controller, current)
            except Exception:
                controller.ready = False
                raise ValueError('ENDPOINT_ROLLBACK_UNVERIFIED') from None
            raise ValueError('ENDPOINT_SWITCH_ROLLED_BACK') from None
        return session_result(proposed, catalog, changed=True)
