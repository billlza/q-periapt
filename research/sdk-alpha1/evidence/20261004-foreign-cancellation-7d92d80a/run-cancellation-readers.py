"""Retest the complete CodeQL inventory boundary after adding both real source paths."""
from pathlib import Path
import hashlib,json,os,re,subprocess,time
w=Path(__file__).resolve().parent;root=Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
commit='7d92d80a4b6b217c7f571ff336df68bf80edbdfc';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==commit
assert subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True)==''
tracked=subprocess.check_output(['git','ls-files','-z','--','*.rs'],cwd=root).split(b'\0');assert len([x for x in tracked if x])==315
sources={n:sha(root/n) for n in ['artifact/codeql_rust_quality.py','artifact/test_codeql_rust_quality.py','ARTIFACT.md']}
env={k:v for k,v in os.environ.items() if not k.startswith(('GIT_','PYTHON'))}
command=['sh','artifact/python-run.sh','-c','import unittest; unittest.main(module=None, argv=["unittest", "-v", "test_continuity_witnessed_cancellation", "test_continuity_witnessed_renewal", "test_continuity_witnessed_policy_expiry", "test_continuity_c_enrollment", "test_continuity_c_consumer", "test_continuity_package", "test_continuity_swift_consumer", "test_continuity_kotlin_consumer"], warnings="error")']
label='cancellation-foreign-readers-04';log=w/(label+'.log');start=time.monotonic()
with log.open('xb') as out:r=subprocess.run(command,cwd=root,env=env,stdout=out,stderr=subprocess.STDOUT)
assert all(sha(root/n)==h for n,h in sources.items())
text=log.read_text();counts=re.findall(r'Ran (\d+) tests in ([0-9.]+)s',text)
completed=r.returncode==0 and len(counts)==1 and int(counts[0][0])>0 and re.findall(r'^OK$',text,re.M)==['OK']
record=dict(command=command,cwd=str(root),source_commit=commit,source_hashes=sources,returncode=r.returncode,observed_test_summary=counts,completed=completed,seconds=time.monotonic()-start,log_sha256=sha(log),tracked_rust_sources=315,release_claim_eligible=False)
(w/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2));raise SystemExit(0 if completed else r.returncode or 1)
