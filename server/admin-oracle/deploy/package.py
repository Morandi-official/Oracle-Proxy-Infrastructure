"""Create the source artifact; excludes runtime state, real secrets, and CI-only root harness."""
import hashlib
import os
import re
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
revision = os.environ.get('GITHUB_SHA', '')
if not re.fullmatch(r'[0-9a-f]{40}', revision):
    raise SystemExit('Verified build source SHA is required')
out = root / 'dist'
out.mkdir(exist_ok=True)
archive = out / 'OracleProxy-Admin-Oracle-SelfHosted.zip'
manifest = []
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise SystemExit('Source symlink rejected')
        if any(part in ('dist', 'staticfiles', '__pycache__', '.venv') for part in relative.parts):
            continue
        if not path.is_file() or path.name in ('ci_smoke.py', '.gitignore'):
            continue
        if path.suffix not in ('.py', '.html', '.css', '.js', '.md', '.txt', '.service', '.timer') and path.name != 'Caddyfile':
            raise SystemExit(f'Unexpected artifact file: {relative}')
        body = path.read_bytes()
        bundle.writestr(str(relative), body)
        manifest.append(f'{hashlib.sha256(body).hexdigest()}  {relative}')
    bundle.writestr('SOURCE_REVISION', revision + '\n')
    bundle.writestr('SHA256SUMS.txt', '\n'.join(manifest) + '\n')
(out / 'SHA256SUMS.txt').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
print(f'ORACLE_ADMIN_SOURCE_PACKAGE={archive.name}')
