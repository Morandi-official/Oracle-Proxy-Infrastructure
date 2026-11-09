"""Only exact endpoint JSON requests can skip unrelated application matrices."""
import json
import os
from pathlib import Path
import re
import subprocess

FILES={'ops/network/endpoints.json','ops/oracle-project/request.json'}
def endpoint_only(changed,request):
    return bool(changed) and set(changed)<=FILES and request=={'operation':'preflight','request_id':'endpoint-catalog-apply'}

def main():
    base=os.environ.get('SCOPE_BASE','')
    changed=subprocess.check_output(['git','diff','--name-only',base,'HEAD'],text=True).splitlines() if re.fullmatch('[a-f0-9]{40}',base) and base!='0'*40 else []
    value=endpoint_only(changed,json.loads(Path('ops/oracle-project/request.json').read_text()))
    with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('endpoint_only='+str(value).lower()+'\n')
if __name__=='__main__':main()
