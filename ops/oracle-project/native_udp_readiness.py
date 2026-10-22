"""Read-only, bounded WireGuard listener and direct INPUT-rule summary.

This is not a reachability verdict: jumps, cloud rules and the client's network
still need independent evidence. Never export raw firewall rows or peer data.
"""
import json
import shlex
import subprocess


def summarize_rules(body, port):
    all_sources = restricted = 0
    for line in body.splitlines():
        fields = shlex.split(line)
        if fields[:2] != ['-A', 'INPUT'] or '-j' not in fields or fields[fields.index('-j')+1] != 'ACCEPT':
            continue
        def value(name, default=None):
            return fields[fields.index(name)+1] if name in fields else default
        if value('-p') != 'udp' or value('--dport') != str(port):
            continue
        # Only the simple literal rule can count as unrestricted. Anything
        # unfamiliar is reported as conditional, not silently treated as open.
        remainder = list(fields[2:])
        for pair in (['-p','udp'], ['-m','udp'], ['--dport',str(port)], ['-j','ACCEPT'], ['-s','0.0.0.0/0']):
            for i in range(len(remainder)-1):
                if remainder[i:i+2] == pair:
                    del remainder[i:i+2];break
        if not remainder: all_sources += 1
        else: restricted += 1
    return {'simple_any_source_accept_rules':all_sources, 'conditional_accept_rules':restricted}


def observe():
    result = {'status':'OBSERVATION_UNAVAILABLE', 'external_reachability':'NOT_TESTED'}
    try:
        def read(command):
            value=subprocess.run(command,capture_output=True,text=True,check=True,timeout=5).stdout
            if len(value)>262144: raise ValueError('OUTPUT_TOO_LARGE')
            return value
        text=read(['wg','show','wg0','listen-port']).strip()
        if not text.isdecimal() or not 1<=int(text)<=65535: raise ValueError('INVALID_PORT')
        port=int(text)
        listeners=read(['ss','-H','-lun',f'sport = :{port}'])
        rules=read(['iptables','-w','5','-S','INPUT'])
        result.update(status='OBSERVED',listen_port=port,udp_listener_present=bool(listeners.strip()),
                      direct_input_rules=summarize_rules(rules,port))
    except (OSError,ValueError,subprocess.SubprocessError):
        pass
    return result


if __name__=='__main__': print(json.dumps(observe(),sort_keys=True))
