"""Verify the immutable public observer bytes and browser download headers."""
import hashlib
import importlib.util
from pathlib import Path
import urllib.request

spec=importlib.util.spec_from_file_location('publish_boot_observer',Path(__file__).with_name('publish_boot_observer.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
url='https://vpn-admin.morandi.dpdns.org/downloads/diagnostics/'+m.NAME
with urllib.request.urlopen(url,timeout=15) as response:
    body=response.read(65537)
    if response.status!=200 or response.url!=url or not response.headers.get('Content-Disposition','').lower().startswith('attachment') or response.headers.get_content_type()!='application/octet-stream':raise ValueError('OBSERVER_DOWNLOAD_HEADER_REJECTED')
if len(body)>65536 or hashlib.sha256(body).hexdigest()!=m.DIGEST:raise ValueError('OBSERVER_DOWNLOAD_DIGEST_REJECTED')
print('PUBLIC_BOOT_OBSERVER_HEADERS_AND_FULL_SHA256=PASS')
