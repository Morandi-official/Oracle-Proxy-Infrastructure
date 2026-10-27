"""Compile the real Inno script with labelled synthetic inputs; never run output."""
import os
from pathlib import Path
import subprocess
import tempfile

if os.name!='nt' or os.environ.get('GITHUB_ACTIONS')!='true' or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted':
    raise ValueError('HOSTED_WINDOWS_SYNTAX_PREFLIGHT_REQUIRED')
compiler=Path(os.environ['ProgramFiles(x86)'])/'Inno Setup 6/ISCC.exe'
if not compiler.is_file():raise ValueError('INNO_COMPILER_REQUIRED')
script=Path(__file__).resolve().parents[1]/'installer/OracleProxy.iss'
with tempfile.TemporaryDirectory(prefix='oracle-syntax-only-') as folder:
    root=Path(folder);payload=root/'synthetic';payload.mkdir();(payload/'licenses').mkdir();out=root/'not-for-distribution';out.mkdir()
    for name in ('OracleProxy.exe','OracleProxy.Core.exe','OracleProxy.Guard.dll'):
        (payload/name).write_bytes(b'MZsynthetic compiler input; never executed')
    for name in ('BUILD.json','SHA256SUMS.txt','请先阅读.txt'):
        (payload/name).write_text('Synthetic syntax test only; never execute or distribute.',encoding='utf-8-sig')
    (payload/'licenses/OracleProxy-GPL-3.0.txt').write_text('Synthetic compiler input; not a product licence.')
    subprocess.run([str(compiler),'/Qp','/DPayloadDir='+str(payload),'/DOutputDir='+str(out),
                    '/DProductVersion=0.3.0-rc22','/DVersionNumbers=0.3.0.22','/DArtifactStem=syntax-only',str(script)],check=True)
print('INNO_REAL_SCRIPT_SYNTAX_PREFLIGHT_NO_OUTPUT_EXECUTION_OR_PUBLICATION=PASS')
