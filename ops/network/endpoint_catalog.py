"""Public, validated endpoint parameters for CI and maintenance tools."""
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('owner_endpoint_schema',ROOT/'server/admin-oracle/console/endpoint_config.py')
schema=importlib.util.module_from_spec(spec);spec.loader.exec_module(schema)

def load():return schema.validate(json.loads((ROOT/'ops/network/endpoints.json').read_text()))

def targets(config=None,legacy=False):
    config=config or load()
    roles=[config['active'],'backup' if config['active']=='primary' else 'primary']
    rows=[config[role] for role in roles]+(config['legacy'] if legacy else [])
    return list(dict.fromkeys(row['public_ipv4'] for row in rows))

if __name__=='__main__':
    import sys
    if sys.argv[1:] not in ([],['--legacy']):raise ValueError('INVALID_ARGUMENTS')
    print('\n'.join(targets(legacy=bool(sys.argv[1:]))))
