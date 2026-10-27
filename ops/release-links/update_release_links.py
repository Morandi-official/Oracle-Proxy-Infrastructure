"""Add verified Oracle/GitHub links after successful mirror deployment. No SSH secrets."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

REPO='Morandi-official/Oracle-Proxy-Infrastructure'
ROOT=Path(__file__).resolve().parents[2]
BASE='https://vpn-admin.morandi.dpdns.org/downloads/'
START='<!-- oracle-proxy-downloads:start -->'
END='<!-- oracle-proxy-downloads:end -->'


def api(path):
    return json.loads(subprocess.check_output(['gh','api','repos/'+REPO+'/'+path],stderr=subprocess.DEVNULL))


def verify_release(release,value):
    actual={item['name']:item for item in release['assets']}
    if (release.get('draft') is not False or release.get('target_commitish')!=value['source_revision'] or
        release.get('tag_name')!=value['version'] or set(actual)!={item['name'] for item in value['assets']}):
        raise ValueError('EXACT_PUBLIC_RELEASE_REQUIRED')
    for item in value['assets']:
        found=actual[item['name']]
        if found.get('size')!=item['size'] or found.get('digest')!='sha256:'+item['sha256']:
            raise ValueError('PUBLIC_RELEASE_DIGEST_MISMATCH')


def render(body,value):
    if len(body)>32768 or body.count(START)!=body.count(END) or body.count(START)>1:
        raise ValueError('RELEASE_NOTES_SECTION_REJECTED')
    if START in body:
        match=re.search(re.escape(START)+'.*?'+re.escape(END),body,re.S)
        if not match:raise ValueError('RELEASE_NOTES_SECTION_REJECTED')
        body=body[:match.start()]+body[match.end():]
    client=next(item['name'] for item in value['assets'] if item['name'].endswith('.zip') and not item['name'].endswith('-source.zip'))
    source=client[:-4]+'-source.zip'
    oracle=BASE+value['version']+'/'
    github='https://github.com/'+REPO+'/releases/download/'+value['version']+'/'
    setup=next((item['name'] for item in value['assets'] if item['name'].endswith('-setup.exe')),None)
    links=f'- 便携版 ZIP：[Oracle 下载]({oracle+client}) · [GitHub 下载]({github+client})\n'
    if setup:links+=f'- 安装版 EXE：[Oracle 下载]({oracle+setup}) · [GitHub 下载]({github+setup})\n'
    return body.rstrip()+'\n\n'+START+'\n### 下载\n\n'+links+f'- [SHA-256 校验]({oracle}SHA256SUMS.txt) · [配套源码]({oracle+source})\n'+END+'\n'



class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None


def main():
    if os.environ.get('GITHUB_REF')!='refs/heads/main' or os.environ.get('GITHUB_REPOSITORY')!=REPO:
        raise ValueError('MAIN_ONLY_RELEASE_NOTES_UPDATE')
    spec=importlib.util.spec_from_file_location('downloads',ROOT/'ops/oracle-project/downloads.py')
    downloads=importlib.util.module_from_spec(spec);spec.loader.exec_module(downloads)
    value=downloads.manifest()
    release=api('releases/tags/'+value['version']);verify_release(release,value)
    opener=urllib.request.build_opener(NoRedirect)
    for item in value['assets']:
        with opener.open(urllib.request.Request(BASE+value['version']+'/'+item['name'],method='HEAD'),timeout=15) as response:
            if response.status!=200 or int(response.headers['Content-Length'])!=item['size']:
                raise ValueError('ORACLE_MIRROR_NOT_PUBLIC')
    body=render(release.get('body') or '',value)
    if body!=release.get('body'):
        with tempfile.TemporaryDirectory(prefix='oracle-release-links-') as temporary:
            payload=Path(temporary)/'body.json';payload.write_text(json.dumps({'body':body}),encoding='utf-8')
            subprocess.run(['gh','api','--method','PATCH','repos/'+REPO+'/releases/'+str(release['id']),'--input',str(payload)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if api('releases/'+str(release['id'])).get('body')!=body:raise ValueError('RELEASE_LINK_UPDATE_NOT_VERIFIED')
    print('RELEASE_VERIFIED_ORACLE_AND_GITHUB_DOWNLOAD_LINKS=PASS')

if __name__=='__main__':main()
