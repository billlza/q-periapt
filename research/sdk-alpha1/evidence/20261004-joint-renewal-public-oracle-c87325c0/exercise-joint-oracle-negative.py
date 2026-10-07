from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

w = Path(__file__).resolve().parent
root = w.parent / 'credential-lifecycle-integration'
script = root / 'research/continuity-identity-candidate/scripts/verify_anchor_vectors.py'
original = w / 'witness-joint-vectors-01-fixtures'
output = w / 'witness-joint-oracle-negative-01'
output.mkdir()
env = {k:v for k,v in os.environ.items() if not k.startswith(('PYTHON', 'QPERIAPT_', 'QPC_', 'GIT_'))}
results = []
for name, reason in [('stale-authentic-reply', 'joint reply exact observation'),
                     ('nonadjacent-proposal', 'adjacent proposal expectations'),
                     ('authentic-predecessor-as-target', 'successor same-key extension'),
                     ('missing-joint-vectors', 'No such file or directory')]:
    case = output / name
    case.mkdir()
    fixtures = case / 'fixtures'
    shutil.copytree(original, fixtures)
    if name == 'stale-authentic-reply':
        shutil.copyfile(fixtures / 'joint-applied-2-reply.bin', fixtures / 'joint-applied-3-reply.bin')
    elif name == 'nonadjacent-proposal':
        p = fixtures / 'joint-applied-proposal.bin'
        data = bytearray(p.read_bytes())
        data[256:264] = (3).to_bytes(8, 'big')
        p.write_bytes(data)
    elif name == 'authentic-predecessor-as-target':
        p = fixtures / 'anchor-renewal-grant.bin'
        data = p.read_bytes()
        offset, fields = 8, []
        for _ in range(6):
            size = int.from_bytes(data[offset:offset+2], 'big')
            offset += 2
            fields.append(data[offset:offset+size])
            offset += size
        assert offset == len(data)
        fields[3] = fields[1]
        p.write_bytes(data[:8] + b''.join(len(f).to_bytes(2, 'big') + f for f in fields))
    else:
        (fixtures / 'anchor-renewal-grant.bin').unlink()
    arguments = [str(script), '--fixtures', str(fixtures), '--output', str(case / 'verification'),
                 '--openssl', '/opt/homebrew/opt/openssl@3/bin/openssl']
    command = ['sh', 'artifact/python-run.sh', '-c',
               'import runpy,sys,warnings; warnings.simplefilter("error"); sys.argv = '
               + repr(arguments) + '; runpy.run_path(sys.argv[0], run_name="__main__")']
    with (case / 'result.log').open('xb') as stream:
        result = subprocess.run(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT)
    log = (case / 'result.log').read_text()
    assert result.returncode != 0 and reason in log, (name, result.returncode, log[-2000:])
    results.append(dict(case=name, returncode=result.returncode, reason=reason,
                        log_sha256=hashlib.sha256(log.encode()).hexdigest()))
record = dict(completed=True, cases=results, scope='Four actual signed-fixture mutations are rejected at their intended boundaries; no signatures or verifier calls are mocked')
(w / 'JOINT_ORACLE_NEGATIVE_QUALIFICATION.json').write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps(record, indent=2))
