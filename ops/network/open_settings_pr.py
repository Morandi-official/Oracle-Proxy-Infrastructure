"""Create a two-file endpoint PR; never push the default branch or call OCI."""
import json
import os
import re
import subprocess
from pathlib import Path
from endpoint_catalog import ROOT,load

REPO='Morandi-official/Oracle-Proxy-Infrastructure'
FILES=('ops/network/endpoints.json','ops/oracle-project/request.json')
def api(path,value=None):
    args=['gh','api','repos/'+REPO+'/'+path]
    if value is not None:args+=['--method','POST','--input','-']
    result=subprocess.run(args,input=json.dumps(value) if value is not None else None,text=True,capture_output=True,timeout=45)
    if result.returncode:raise RuntimeError('GITHUB_API_REQUEST_FAILED:'+str(result.returncode))
    return json.loads(result.stdout)

def main():
    if os.environ.get('GITHUB_REPOSITORY')!=REPO or os.environ.get('GITHUB_REF')!='refs/heads/main':raise ValueError('MAIN_REPOSITORY_ONLY')
    base=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    if api('git/ref/heads/main')['object']['sha']!=base:raise ValueError('MAIN_MOVED_RERUN_SETTINGS')
    changed=subprocess.check_output(['git','diff','--name-only'],text=True).splitlines()
    if not changed:
        Path(os.environ['GITHUB_STEP_SUMMARY']).write_text('当前 Environment 参数与仓库配置一致，无需创建变更，也未修改服务器。\n')
        print('ENDPOINT_SETTINGS=NO_CHANGES');return
    if not set(changed)<=set(FILES):raise ValueError('ONLY_ENDPOINT_METADATA_MAY_CHANGE')
    load()
    if json.loads((ROOT/FILES[1]).read_text())!={'operation':'preflight','request_id':'endpoint-catalog-apply'}:raise ValueError('FIXED_ENDPOINT_APPLY_REQUEST_REQUIRED')
    run=os.environ.get('GITHUB_RUN_ID','')
    if not re.fullmatch('[0-9]{1,20}',run):raise ValueError('GITHUB_RUN_ID_REQUIRED')
    branch='config/endpoints-'+run
    tree=api('git/trees',{'base_tree':api('git/commits/'+base)['tree']['sha'],'tree':[{'path':p,'mode':'100644','type':'blob','content':(ROOT/p).read_text()} for p in FILES]})
    # API calls are deliberately not retried after an uncertain mutation result.
    commit=api('git/commits',{'message':'Update confirmed primary and backup endpoint settings','tree':tree['sha'],'parents':[base]})
    api('git/refs',{'ref':'refs/heads/'+branch,'sha':commit['sha']})
    compare='https://github.com/'+REPO+'/compare/main...'+branch+'?expand=1'
    summary=Path(os.environ['GITHUB_STEP_SUMMARY'])
    try:
        pr=api('pulls',{'head':branch,'base':'main','title':'Apply confirmed primary/backup endpoint settings','body':'Generated from non-secret oracle-ops Environment variables after operator confirmation of OCI bindings. Review the exact public/private mapping and expected exit before merging. This PR changes only the endpoint catalog and its lightweight apply request; it does not create, rebind or delete OCI resources or change DNS.\n\nGitHub Actions does not automatically retrigger PR workflows with GITHUB_TOKEN. The generating workflow validates the schema and proposal rules; a human merge triggers the main endpoint-only checks and deployment.'})
        with summary.open('a') as stream:stream.write('\n配置提案已生成，尚未应用到服务器：[查看并合并 PR]('+pr['html_url']+')。\n')
        print('ENDPOINT_SETTINGS_PR='+pr['html_url'])
    except RuntimeError:
        # Some repositories disallow Actions-created PRs. The branch is retained
        # for an owner to open the same concrete diff through GitHub's web UI.
        with summary.open('a') as stream:stream.write('\n配置分支已生成，尚未应用。仓库可能未允许 Actions 创建 PR；请打开 [此比较页面]('+compare+') 创建 PR。不要再次运行创建任务。\n')
        print('ENDPOINT_SETTINGS_MANUAL_PR='+compare)

if __name__=='__main__':main()
