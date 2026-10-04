from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time

w = Path(__file__).resolve().parent
root = w.parent / 'credential-lifecycle-integration'
label, mode = sys.argv[1:]
assert mode in ('bootstrap', 'anchor')
name = 'verify_public_vectors.py' if mode == 'bootstrap' else 'verify_anchor_vectors.py'
script = root / 'research/continuity-identity-candidate/scripts' / name
output = w / (label + '-output')
fixtures = w / 'witness-joint-vectors-01-fixtures'
arguments = [str(script), '--fixtures', str(fixtures), '--output', str(output),
             '--openssl', '/opt/homebrew/opt/openssl@3/bin/openssl']
if mode == 'bootstrap':
    arguments += ['--with-rekey']
command = ['sh', 'artifact/python-run.sh', '-c',
           'import runpy,sys,warnings; warnings.simplefilter("error"); sys.argv = '
           + repr(arguments) + '; runpy.run_path(sys.argv[0], run_name="__main__")']
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
sources = {str(p.relative_to(root)): sha(p) for p in script.parent.glob('verify_*vectors.py')}
fixture_hashes = {p.name: sha(p) for p in fixtures.iterdir() if p.is_file()}
env = {k:v for k,v in os.environ.items() if not k.startswith(('PYTHON', 'QPERIAPT_', 'QPC_', 'GIT_'))}
log = w / (label + '.log')
start = time.monotonic()
with log.open('xb') as stream:
    result = subprocess.run(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
assert all(sha(root / name) == value for name,value in sources.items())
assert all(sha(fixtures / name) == value for name,value in fixture_hashes.items())
record = dict(command=command, cwd=str(root), returncode=result.returncode,
              completed=result.returncode == 0, seconds=time.monotonic()-start,
              source_hashes=sources, fixture_hashes=fixture_hashes, log_sha256=sha(log))
if result.returncode == 0:
    report = json.loads((output / 'result.json').read_text())
    assert report['signed_envelopes'] > 0
    if mode == 'anchor':
        assert report['signed_envelopes'] == 57 and report['signature_negative_controls'] == 285
    record['result'] = report
(w / (label + '.json')).write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k not in ('source_hashes', 'fixture_hashes', 'result')}, indent=2))
print(log.read_text()[-4000:])
raise SystemExit(result.returncode)
