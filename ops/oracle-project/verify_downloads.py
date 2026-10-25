"""Check Oracle serves exact client bytes and byte ranges without redirects."""
import hashlib
import design_previews
import json
import urllib.error
import urllib.request
from pathlib import Path

BASE = 'https://vpn-admin.morandi.dpdns.org/downloads/'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def main():
    value = json.loads(Path(__file__).with_name('downloads-current.json').read_text())
    opener = urllib.request.build_opener(NoRedirect)
    for item in value['assets']:
        url = BASE+value['version']+'/'+item['name']
        with opener.open(urllib.request.Request(url,method='HEAD'),timeout=20) as response:
            assert response.status == 200 and int(response.headers['Content-Length']) == item['size']
            assert response.headers['X-Content-Type-Options'] == 'nosniff'
        with opener.open(urllib.request.Request(url,headers={'Range':'bytes=0-1023'}),timeout=20) as response:
            assert response.status == 206
            assert response.headers['Content-Range'] == f"bytes 0-{min(1023,item['size']-1)}/{item['size']}"
            assert len(response.read(1025)) == min(1024,item['size'])
        if item['name'].endswith('.zip') and not item['name'].endswith('-source.zip'):
            digest = hashlib.sha256(); size = 0
            with opener.open(url,timeout=30) as response:
                assert response.status == 200
                for block in iter(lambda:response.read(1024*1024),b''):
                    size += len(block); assert size <= item['size']; digest.update(block)
            assert size == item['size'] and digest.hexdigest() == item['sha256']
    print('ORACLE_DIRECT_DOWNLOAD_FULL_CLIENT_SHA256_AND_ALL_RANGES=PASS')
    for name,item in design_previews.PINS.items():
        with opener.open(BASE+design_previews.VERSION+'/'+name,timeout=30) as response:
            assert response.status==200 and response.headers.get_content_type()=='image/png'
            assert response.headers['X-Content-Type-Options']=='nosniff'
            body=response.read(item['size']+1)
            assert len(body)==item['size'] and hashlib.sha256(body).hexdigest()==item['sha256']
        print('PUBLIC_DESIGN_PREVIEW_'+name.split('-')[2]+'_PNG_SHA256=PASS')


if __name__ == '__main__': main()
