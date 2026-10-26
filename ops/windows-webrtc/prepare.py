"""Retrieve only the already accepted public rc19 binary. No credentials."""
import hashlib,json,urllib.request,zipfile
from pathlib import Path
root=Path(__file__).resolve().parents[2]
out=root/'dist/product';out.mkdir(parents=True,exist_ok=True)
archive=root/'dist/accepted-rc19.zip'
url='https://github.com/Morandi-official/Oracle-Proxy-Infrastructure/releases/download/v0.3.0-rc19/OracleProxy-0.3.0-rc19-win-x64-c0908e3c5ac9.zip'
h=hashlib.sha256();count=0
with urllib.request.urlopen(url,timeout=30) as source,archive.open('wb') as target:
 if not source.geturl().startswith('https://release-assets.githubusercontent.com/'):raise ValueError('UNEXPECTED_RELEASE_DESTINATION')
 while data:=source.read(1024*1024):
  count+=len(data)
  if count>100*1024*1024:raise ValueError('RELEASE_TOO_LARGE')
  h.update(data);target.write(data)
if h.hexdigest()!='de976f26aded8b0523f607f68c4e42450cbc85f70107a8b25380d6974135fc71':raise ValueError('PINNED_ACCEPTED_RELEASE_REQUIRED')
with zipfile.ZipFile(archive) as z:
 if len(z.read('BUILD.json'))>32768:raise ValueError('BUILD_TOO_LARGE')
 build=json.loads(z.read('BUILD.json'))
 if build['source_revision']!='c0908e3c5ac9c7874158f96acdcdf030946170c4' or build['real_oracle_acceptance_passed'] is not True:raise ValueError('ACCEPTANCE_REQUIRED')
 for name in ('OracleProxy.exe','OracleProxy.Core.exe','OracleProxy.Guard.dll'):
  data=z.read(name)
  if hashlib.sha256(data).hexdigest()!=build['payload_sha256'][name]:raise ValueError('PAYLOAD_MISMATCH')
  (out/name).write_bytes(data)
pins=root/'clients/windows/product/BuildPins.cs'
pins.write_text(pins.read_text().replace('BUILD_MUST_PIN_CORE',build['payload_sha256']['OracleProxy.Core.exe']).replace('BUILD_MUST_PIN_GUARD',build['payload_sha256']['OracleProxy.Guard.dll']))
print('PINNED_ACCEPTED_RC19_BINARIES_VERIFIED=PASS')
