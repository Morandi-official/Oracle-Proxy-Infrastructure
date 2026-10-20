"""Materialize non-secret deployment settings from GitHub environment variables."""
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit


def build_config(values):
    origin = values['ADMIN_PUBLIC_ORIGIN']
    url = urlsplit(origin)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.path or url.query or url.fragment or url.port not in (None, 443)):
        raise ValueError('ADMIN_PUBLIC_ORIGIN must be a bare HTTPS origin')
    issuer = values['ADMIN_ACCESS_ISSUER']
    if not re.fullmatch(r'https://[a-z0-9-]+\.cloudflareaccess\.com', issuer):
        raise ValueError('Invalid Access issuer')
    if not re.fullmatch(r'[a-f0-9]{64}', values['ADMIN_ACCESS_AUD']):
        raise ValueError('Invalid Access application audience')
    if not re.fullmatch(r'[a-f0-9-]{36}', values['ADMIN_D1_DATABASE_ID']):
        raise ValueError('Invalid D1 database ID')
    emails = [email.strip() for email in values['ADMIN_EMAILS'].split(',')]
    if not emails or any(not re.fullmatch(r'[^\s@,]+@[^\s@,]+\.[^\s@,]+', email) for email in emails):
        raise ValueError('Explicit administrator emails required')
    node = values.get('ADMIN_NODE_ID', 'oracle-primary')
    if not re.fullmatch(r'[a-z0-9-]{1,64}', node):
        raise ValueError('Invalid node ID')
    config = json.loads(Path(__file__).with_name('wrangler.example.jsonc').read_text())
    config['routes'][0]['pattern'] = url.hostname
    config['vars'] = {'PUBLIC_ORIGIN': origin, 'ACCESS_ISSUER': issuer,
                      'ACCESS_AUD': values['ADMIN_ACCESS_AUD'], 'ADMIN_EMAILS': ','.join(emails),
                      'NODE_ID': node}
    config['d1_databases'][0]['database_id'] = values['ADMIN_D1_DATABASE_ID']
    return config


if __name__ == '__main__':
    try:
        config = build_config(os.environ)
    except (KeyError, ValueError):
        raise SystemExit('Missing or invalid administrator deployment variables') from None
    Path(__file__).with_name('wrangler.jsonc').write_text(json.dumps(config, indent=2) + '\n')
