from pathlib import Path
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time

root = Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004')
work = Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite/target/credential-renewal-20261004')
base = Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244')
tc = base / 'rustup/toolchains/1.98.1-aarch64-apple-darwin'
java = Path('/opt/homebrew/Cellar/openjdk@21/21.0.11/libexec/openjdk.jdk/Contents/Home')
env = {k: v for k, v in os.environ.items() if not k.startswith(('CARGO_', 'RUST', 'QPERIAPT_', 'QPC_', 'DYLD_', 'LD_', 'PYTHON', 'GIT_'))}
env.update(RUSTUP_HOME=str(base / 'rustup'), RUSTUP_TOOLCHAIN=tc.name,
           RUSTUP_AUTO_INSTALL='0', RUSTUP_NO_UPDATE_CHECK='1',
           RUSTC=str(tc / 'bin/rustc'), RUSTDOC=str(tc / 'bin/rustdoc'),
           CARGO_HOME=str(base / 'apple-cargo-home-ff4a153e'), CARGO_NET_OFFLINE='true',
           CARGO_BUILD_JOBS='1', JAVA_HOME=str(java),
           DYLD_FALLBACK_LIBRARY_PATH=str(tc / 'lib'), DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',
           PATH=str(tc / 'bin') + ':' + str(java / 'bin') + ':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
label, mode, *selection = sys.argv[1:]
if selection:
    assert selection == ['integrated'] and mode == 'native-metadata'
    root = Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite/target/credential-lifecycle-integration')
source_files = list((root / 'research/continuity-identity-candidate/src').rglob('*.rs')) + list((root / 'research/continuity-identity-candidate').glob('*.md'))
source_hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
head = subprocess.check_output(['/usr/bin/git', 'rev-parse', 'HEAD'], cwd=root, env=env, text=True).strip()
results_sha = hashlib.sha256((root / 'artifact/results.json').read_bytes()).hexdigest()
if mode == 'source':
    command = ['sh', 'artifact/python-run.sh', 'artifact/source_results_assembler.py',
               'ci-source-gate', '--profile', 'sdk-020', results_sha, head]
elif mode == 'tests':
    command = ['sh', 'artifact/python-run.sh', '-c',
               'import unittest; unittest.main(module=None, argv=["unittest", "discover", "-s", "artifact", "-p", "test_*.py", "-v"], warnings="error")']
elif mode == 'delta':
    command = ['sh', 'artifact/python-run.sh', '-c',
               'import unittest; unittest.main(module=None, argv=["unittest", "-v", "test_jvm_sdk_package", "test_c_package_manifest", "test_proof_to_byte_release", "test_release_index", "test_apple_sdk_profile", "test_apple_distribution", "test_codeql_rust_quality"], warnings="error")']
elif mode == 'account-ci':
    command = ['sh', 'artifact/python-run.sh', '-c',
               'import unittest; unittest.main(module=None, argv=["unittest", "-v", "test_continuity_c_account_tls_loss", "test_continuity_c_account_delivery", "test_proof_to_byte_release"], warnings="error")']
elif mode == 'native-metadata':
    command = ['sh', 'artifact/python-run.sh', '-c',
               'import unittest; unittest.main(module=None, argv=["unittest", "-v", "test_continuity_contract", "test_continuity_identity_candidate", "test_continuity_package", "test_continuity_c_consumer", "test_continuity_c_enrollment"], warnings="error")']
else:
    raise SystemExit('unsupported mode')
record = {'command': command, 'cwd': str(root), 'source_commit': head,
          'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'results_sha256': results_sha, 'mode': mode,
          'toolchain': str(tc), 'java_home': str(java), 'completed': False, 'source_hashes': source_hashes}
receipt = work / (label + '.json')
receipt.write_text(json.dumps(record, indent=2) + '\n')
log = work / (label + '.log')
started = time.monotonic()
with log.open('xb') as stream:
    result = subprocess.run(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, check=False)
assert all(hashlib.sha256((root / p).read_bytes()).hexdigest() == value for p, value in source_hashes.items())
data = log.read_bytes()
record.update(returncode=result.returncode, elapsed_seconds=time.monotonic() - started,
              log=str(log), log_sha256=hashlib.sha256(data).hexdigest(),
              completed=result.returncode == 0)
if mode in ('tests', 'delta', 'native-metadata', 'account-ci'):
    counts = re.findall(rb'Ran ([0-9]+) tests in ([0-9.]+)s', data)
    record['observed_test_summary'] = [[int(a), float(b)] for a, b in counts]
    record['completed'] = (record['completed'] and len(counts) == 1 and int(counts[0][0]) > 0
                           and re.findall(rb'^OK$', data, re.MULTILINE) == [b'OK'])
receipt.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({k:v for k,v in record.items() if k != 'source_hashes'}, indent=2))
if not record['completed']:
    print(data[-20000:].decode(errors='replace'))
    raise SystemExit(result.returncode or 2)
