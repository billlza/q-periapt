from pathlib import Path
import hashlib, json, os, subprocess, sys, time

w = Path(__file__).resolve().parent
c = Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
d = w / sys.argv[1]
d.mkdir(mode=0o700)
workflow = c / '.github/workflows/ci.yml'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
before = sha(workflow)
head = subprocess.check_output(['git','rev-parse','HEAD'], cwd=c, text=True).strip()
baseline = d / 'baseline.yml'
baseline.write_bytes(subprocess.check_output(['git','show','HEAD:.github/workflows/ci.yml'], cwd=c))
lint = {}
for label, path in [('baseline', baseline), ('candidate', workflow)]:
    command = ['/opt/homebrew/bin/actionlint', str(path)]
    result = subprocess.run(command, cwd=c, capture_output=True, text=True)
    (d / f'{label}-actionlint.log').write_text(result.stdout + result.stderr)
    lint[label] = {'command':command, 'returncode':result.returncode, 'output':(result.stdout+result.stderr).replace(str(path),'WORKFLOW').replace(os.path.relpath(path,c),'WORKFLOW')}
assert lint['baseline']['output'] == lint['candidate']['output']
assert lint['baseline']['output'].count('[runner-label]') == 2

job = workflow.read_text().split('  continuity-installed-swift:\n',1)[1].split('\n  continuity-identity-candidate:',1)[0]
script = job.split('        run: |\n',1)[1].split('      - name: Retain native packages',1)[0]
script = '\n'.join(line[10:] for line in script.splitlines())+'\n'
(d/'workflow-step.sh').write_text(script)
syntax = subprocess.run(['/bin/bash','-n',str(d/'workflow-step.sh')],capture_output=True,text=True)
assert syntax.returncode == 0, syntax.stderr
command = ['sh','artifact/python-run.sh','-c',
    'import unittest; unittest.main(module=None, argv=["unittest", "-v", "test_continuity_package", "test_workflow_artifact", "test_proof_to_byte_release.ProofToByteReleaseMarkerTests.test_canonical_rust_toolchain_is_source_pinned_and_provisioned", "test_proof_to_byte_release.BoundVerifierWiringTests.test_every_workflow_action_is_full_sha_pinned"], warnings="error")']
env = {k:v for k,v in os.environ.items() if not k.startswith(('PYTHON','QPERIAPT_','GIT_'))}
start = time.monotonic()
with (d/'tests.log').open('xb') as out:
    result = subprocess.run(command,cwd=c,env=env,stdout=out,stderr=subprocess.STDOUT)
assert before == sha(workflow)
record = {'source_commit':head,'workflow_sha256':before,'command':command,'returncode':result.returncode,'seconds':time.monotonic()-start,'tests_log_sha256':sha(d/'tests.log'),'bash_syntax_returncode':syntax.returncode,'actionlint':lint,'actionlint_new_diagnostics':False,'actionlint_clean':False,'release_claim_eligible':False}
(d/'RESULT.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k!='actionlint'},indent=2))
print((d/'tests.log').read_text()[-6000:])
raise SystemExit(result.returncode)
