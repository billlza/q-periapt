from pathlib import Path
import json, subprocess, sys
w=Path(__file__).resolve().parent
c=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
for mode in (sys.argv[1:] or ('c','swift','kotlin')):
 label='tls-cut-typed-'+mode+'-flow-'+('02' if mode=='kotlin' else '01')
 r=json.loads((w/(label+'.json')).read_text());assert r['completed']
 code="""from pathlib import Path
import json, sys
import continuity_witnessed_cancellation as gate
w=Path(sys.argv[1]);label=sys.argv[2];mode=sys.argv[3]
r=json.loads((w/(label+'.json')).read_text());root=Path(r['public_evidence']);log=(w/(label+'.log')).read_bytes()
result=gate.export(log,root,root.parent/(label+'-verified'),language=mode.capitalize())
assert len(result['public_readbacks'])==544
(w/(label+'-readback.json')).write_text(json.dumps(result,indent=2)+'\\n')
print(mode,len(result['public_readbacks']))
"""
 subprocess.run(['sh','artifact/python-run.sh','-c',code,str(w),label,mode],cwd=c,check=True)
