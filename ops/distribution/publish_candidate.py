"""Promote only the pinned, accepted rc9 artifacts to a draft-first prerelease.

Runs downloaded archives through hashing/metadata checks, never executes them.
No Oracle credentials are needed. Publishing is restricted to this repo's main.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = 'Morandi-official/Oracle-Proxy-Infrastructure'
MANIFEST = Path(__file__).with_name('windows-rc9.json')


def gh(*args, output=None):
    return subprocess.run(['gh', *map(str,args)], check=True, stdout=output or subprocess.PIPE,
                          stderr=subprocess.DEVNULL).stdout


def api(path): return json.loads(gh('api',f'repos/{REPO}/{path}'))


def validate_run(run, manifest):
    if not (run.get('id')==manifest['run_id'] and run.get('head_sha')==manifest['source_revision'] and
            run.get('head_branch')=='main' and run.get('event')=='push' and
            run.get('status')=='completed' and run.get('conclusion')=='success' and
            run.get('path')=='.github/workflows/windows-product-candidate.yml' and
            run.get('head_repository',{}).get('full_name')==REPO):
        raise ValueError('ACCEPTED_MAIN_WORKFLOW_REQUIRED')


def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def read_archive(archive, output, expected_prefix):
    with zipfile.ZipFile(archive) as bundle:
        names=bundle.namelist()
        allowed={expected_prefix+'.zip',expected_prefix+'-source.zip','SHA256SUMS.txt','BUILD.json'}
        if len(set(names))!=len(names) or not set(names)<=allowed: raise ValueError('ARTIFACT_CONTENTS_REJECTED')
        for entry in bundle.infolist():
            if entry.file_size>512*1024*1024 or entry.is_dir() or (entry.external_attr>>16)&0o170000==0o120000:
                raise ValueError('ARTIFACT_ENTRY_REJECTED')
            # All entries are exact flat allowlisted names. Never extract paths.
            destination=output/entry.filename
            if destination.exists():
                if entry.file_size>32768 or destination.read_bytes()!=bundle.read(entry):
                    raise ValueError('ARTIFACT_METADATA_MISMATCH')
                continue
            with bundle.open(entry) as source, destination.open('xb') as target:
                import shutil
                shutil.copyfileobj(source,target,1024*1024)


def main():
    if sys.argv[1:] not in (['--check'],['--publish']): raise ValueError('INVALID_ARGUMENTS')
    manifest=json.loads(MANIFEST.read_text())
    if manifest['version']!='0.3.0-rc9': raise ValueError('ONLY_RC9_PRERELEASE_SUPPORTED')
    validate_run(api(f"actions/runs/{manifest['run_id']}"),manifest)
    for artifact in manifest['artifacts']:
        value=api(f"actions/artifacts/{artifact['id']}")
        if (value.get('expired') is not False or value.get('digest')!='sha256:'+artifact['sha256'] or
            value.get('workflow_run',{}).get('id')!=manifest['run_id'] or
            value.get('workflow_run',{}).get('head_sha')!=manifest['source_revision']):
            raise ValueError('PINNED_ARTIFACT_REQUIRED')
    if sys.argv[1]=='--check': print('PINNED_ACCEPTED_MAIN_ARTIFACTS=PASS');return
    if (os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('GITHUB_REF')!='refs/heads/main' or
        os.environ.get('GITHUB_REPOSITORY')!=REPO): raise ValueError('MAIN_PUBLICATION_REQUIRED')
    prefix='OracleProxy-'+manifest['version']+'-win-x64-'+manifest['source_revision'][:12]
    with tempfile.TemporaryDirectory(prefix='oracle-candidate-release-') as temporary:
        root=Path(temporary);assets=root/'assets';assets.mkdir()
        for index,artifact in enumerate(manifest['artifacts']):
            archive=root/f'artifact-{index}.zip'
            with archive.open('xb') as stream:
                gh('api',f"repos/{REPO}/actions/artifacts/{artifact['id']}/zip",output=stream)
            if digest(archive)!=artifact['sha256']: raise ValueError('ARTIFACT_DIGEST_MISMATCH')
            read_archive(archive,assets,prefix)
        expected={prefix+'.zip',prefix+'-source.zip','SHA256SUMS.txt','BUILD.json'}
        if {p.name for p in assets.iterdir()}!=expected: raise ValueError('COMPLETE_SOURCE_AND_PAYLOAD_REQUIRED')
        metadata=json.loads((assets/'BUILD.json').read_text())
        if not (metadata.get('version')==manifest['version'] and metadata.get('source_revision')==manifest['source_revision'] and
                metadata.get('real_oracle_acceptance_passed') is True and metadata.get('publisher_signed') is False and
                metadata.get('channel')=='unsigned-acceptance-candidate' and str(metadata.get('workflow_run'))==str(manifest['run_id'])):
            raise ValueError('CANDIDATE_ATTESTATION_REJECTED')
        sums={line.split('  ',1)[1]:line.split('  ',1)[0] for line in (assets/'SHA256SUMS.txt').read_text().splitlines()}
        if set(sums)!={prefix+'.zip',prefix+'-source.zip'}: raise ValueError('CHECKSUM_SET_REJECTED')
        for name,value in sums.items():
            if digest(assets/name)!=value: raise ValueError('PAYLOAD_OR_SOURCE_DIGEST_MISMATCH')
        notes=root/'notes.md'
        notes.write_text('Windows 10/11 x64 便携验收版；完整解压后打开 OracleProxy.exe，首次安装或升级服务需要 UAC。\n\n'
                         '连接方式可选：自动、WireGuard UDP、QUIC / HTTP3。自动优先原生 UDP；HTTPS/TLS 仅自动兜底。实际使用的通道单独显示。\n\n'
                         '界面重新划分为连接、账号与用量、诊断与测试三个对齐区块，加入本次已验证出口 IP 及本机 VPN 实时上下行速率。账号登录与退出、用量进度、到期日和已登记设备数集中展示。\n\n'
                         '原生 UDP 在同一个 WireGuard 实例内优先 51820，必要时尝试 443；QUIC 使用真实 HTTP3 CONNECT-UDP。修复核心被强制结束后旧会话阻挡新连接的问题。\n\n'
                         '修复 VPN 内访问管理网站：仅 SYSTEM 控制及载体连接绑定物理网卡，普通浏览器通过加密隧道访问管理网站，普通程序物理绕行继续被阻断。\n\n'
                         '验收要求强制选择 UDP 和 HTTP3 各三次冷启动，屏蔽 51820 时验证原生 UDP443，HTTP3 核心被结束后的三次恢复，并核对 Oracle 出口、TCP/UDP DNS、管理网站及物理绕行阻断。实际结果见下方完整记录；云端耗时不能代表 MetaWise 实机表现。\n\n'
                         '本轮云端冷启动：UDP 3383 / 1851 / 1783 ms；HTTP3 1757 / 2763 / 2758 ms。预备后的 UDP 连接 572 ms；屏蔽原生 UDP 时预备后的 HTTP3 重连 326 / 285 / 299 ms。冷启动尚未达到一秒，也不能据此承诺 MetaWise 实机时延。\n\n'
                         '**仍为未签名候选版：IPv6 当前阻断；真实 UU 会话的故障与重启连续性仍待实机验收。**\n\n'
                         f"构建提交：`{manifest['source_revision']}`；[完整验收记录](https://github.com/{REPO}/actions/runs/{manifest['run_id']})。配套源码、SHA256SUMS.txt 和 BUILD.json 随包发布。\n",encoding='utf-8')
        tag='v'+manifest['version']
        if api('git/matching-refs/tags/'+tag): raise ValueError('EXISTING_RC_TAG_REQUIRES_REVIEW')
        request=root/'draft.json'
        request.write_text(json.dumps({'tag_name':tag,'target_commitish':manifest['source_revision'],
            'name':'Oracle Proxy '+manifest['version']+' · Windows x64','draft':True,
            'prerelease':True,'body':notes.read_text()}))
        release=json.loads(gh('api','--method','POST',f'repos/{REPO}/releases','--input',request))
        release_id=release['id']
        gh('release','upload',tag,'--repo',REPO,*[assets/name for name in sorted(expected)])
        release=api(f'releases/{release_id}')
        actual={asset['name']:asset for asset in release['assets']}
        if set(actual)!=expected or release.get('draft') is not True or release.get('prerelease') is not True:
            raise ValueError('DRAFT_ASSETS_REJECTED')
        for name in expected:
            if actual[name].get('digest')!='sha256:'+digest(assets/name) or actual[name]['size']!=(assets/name).stat().st_size:
                raise ValueError('UPLOADED_ASSET_DIGEST_MISMATCH')
        request.write_text(json.dumps({'draft':False,'prerelease':True}))
        gh('api','--method','PATCH',f'repos/{REPO}/releases/{release_id}','--input',request)
        print('CANDIDATE_PRERELEASE=https://github.com/'+REPO+'/releases/tag/'+tag)


if __name__=='__main__': main()
