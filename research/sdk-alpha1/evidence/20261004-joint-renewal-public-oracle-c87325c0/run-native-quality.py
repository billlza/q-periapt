from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time

w = Path(__file__).resolve().parent
label, version, checkout, mode = sys.argv[1:]
assert version in ('1.90.0', '1.98.1')
root = Path('/Users/bill/Documents/Codex/sdk-020-arm64-ci-20261004') if checkout == 'clean' else w.parent / 'credential-lifecycle-integration'
assert checkout in ('clean', 'integrated')
candidate = root / 'research/continuity-identity-candidate'
base = Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244')
tc = base / ('rustup/toolchains/' + version + '-aarch64-apple-darwin')
env = {k:v for k,v in os.environ.items() if not k.startswith(('CARGO_', 'RUST', 'QPERIAPT_', 'QPC_', 'DYLD_', 'LD_', 'PYTHON', 'GIT_'))}
env.update(RUSTUP_HOME=str(base / 'rustup'), RUSTUP_TOOLCHAIN=tc.name,
           RUSTUP_AUTO_INSTALL='0', RUSTUP_NO_UPDATE_CHECK='1',
           RUSTC=str(tc / 'bin/rustc'), RUSTDOC=str(tc / 'bin/rustdoc'),
           CARGO_HOME=str(base / 'apple-cargo-home-ff4a153e'), CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='1',
           CARGO_TARGET_DIR=str(w / ('quality-target-' + version)),
           DYLD_FALLBACK_LIBRARY_PATH=str(tc / 'lib'), DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',
           PATH=str(tc / 'bin') + ':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
if mode == 'clippy':
    command = [str(tc / 'bin/cargo'), 'clippy', '--all-targets', '--all-features', '--locked', '--offline', '--', '-D', 'warnings']
elif mode == 'vectors':
    command = [str(tc / 'bin/cargo'), 'run', '--locked', '--offline', '--example', 'public_vectors', '--', str(w / (label + '-fixtures')), '--with-anchor', '--with-rekey']
elif mode == 'intent-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--all-features', '--locked', '--offline', '--lib', 'durable::write_intent::tests::', '--', '--test-threads=2']
elif mode == 'preparation-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--all-features', '--locked', '--offline', '--lib', 'durable::anchoring::tests::credential_preparation::', '--', '--test-threads=2']
else:
    raise ValueError(mode)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
sources = {str(p.relative_to(candidate)): sha(p) for part in ['src', 'examples', 'tests'] for p in (candidate / part).rglob('*.rs')}
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
start = time.monotonic()
log = w / (label + '.log')
with log.open('xb') as stream:
    if mode == 'clippy':
        processes = subprocess.check_output(['ps', '-axo', 'command='], text=True)
        assert not any(line.strip().startswith(env['CARGO_TARGET_DIR'] + '/') for line in processes.splitlines())
        subprocess.run([str(tc / 'bin/cargo'), 'clean', '--locked', '--offline', '-p',
                        'q-periapt-continuity-identity-candidate'], cwd=candidate, env=env,
                       stdout=stream, stderr=subprocess.STDOUT, check=True)
    result = subprocess.run(command, cwd=candidate, env=env, stdout=stream, stderr=subprocess.STDOUT)
assert all(sha(candidate / name) == value for name,value in sources.items())
record = dict(command=command, cwd=str(candidate), source_commit=head, source_hashes=sources,
              returncode=result.returncode, completed=result.returncode == 0,
              seconds=time.monotonic()-start, log_sha256=sha(log))
(w / (label + '.json')).write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps({k:v for k,v in record.items() if k != 'source_hashes'}, indent=2))
print(log.read_text()[-5000:])
raise SystemExit(result.returncode)
