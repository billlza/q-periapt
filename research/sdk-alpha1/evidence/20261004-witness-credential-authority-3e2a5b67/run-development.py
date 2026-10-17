"""Run the isolated candidate with the explicitly pinned archived dependency graph."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

root = Path('/Users/bill/.codex/worktrees/sdk-continuity/pqt_hybrid_suite')
work = root / 'target/credential-renewal-20261004'
cwd = work / 'development'
base = Path('/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244')
tc = base / 'rustup/toolchains/1.98.1-aarch64-apple-darwin'
env = {k: v for k, v in os.environ.items() if not k.startswith(('CARGO_', 'RUST', 'QPERIAPT_', 'QPC_', 'DYLD_', 'LD_', 'PYTHON'))}
env.update(RUSTUP_HOME=str(base / 'rustup'), RUSTUP_TOOLCHAIN=tc.name,
           RUSTUP_AUTO_INSTALL='0', RUSTUP_NO_UPDATE_CHECK='1',
           RUSTC=str(tc / 'bin/rustc'), RUSTDOC=str(tc / 'bin/rustdoc'),
           CARGO_HOME=str(base / 'apple-cargo-home-ff4a153e'), CARGO_NET_OFFLINE='true',
           CARGO_BUILD_JOBS='1', CARGO_TARGET_DIR=str(root / 'target/continuity-c-enrollment'),
           DYLD_FALLBACK_LIBRARY_PATH=str(tc / 'lib'), DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer',
           PATH=str(tc / 'bin') + ':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin')
label, mode, *stage = sys.argv[1:]
if stage:
    assert stage in (['journal'], ['local'], ['operations'], ['expired'], ['integrated'], ['c-owner'])
    cwd = (root / 'target/credential-lifecycle-integration/research/continuity-identity-candidate'
           if stage == ['integrated'] else work / {'journal':'development-journal', 'local':'development-local-renewal', 'operations':'development-renewed-operations', 'expired':'development-expired-renewal', 'c-owner':'development-c-owner'}[stage[0]])
    env['CARGO_TARGET_DIR'] = str(root / 'target/continuity-renewal-journal')
    if stage == ['c-owner']:
        env['CARGO_TARGET_DIR'] = str(root / 'target/continuity-c-enrollment')
if mode == 'format':
    command = [str(tc / 'bin/cargo'), 'fmt', '--all']
elif mode == 'format-check':
    command = [str(tc / 'bin/cargo'), 'fmt', '--all', '--check']
elif mode == 'initialize':
    assert not (cwd / 'Cargo.lock').exists()
    shutil.copyfile(root / 'target/enrollment-c-20261004/consumer/Cargo.lock', cwd / 'Cargo.lock')
    command = [str(tc / 'bin/cargo'), 'metadata', '--offline', '--format-version', '1']
elif mode == 'test':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'identity::renewal::tests::', '--', '--nocapture']
elif mode == 'peer-test':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'durable::rosters::tests::renewal::', '--', '--nocapture']
elif mode == 'roster-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'durable::rosters::tests::', '--', '--nocapture']
elif mode == 'retained-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'installation::tests::reopen::renewal::', '--', '--nocapture']
elif mode == 'retained-boundary-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'durable::messages::tests::renewal::', '--', '--nocapture']
elif mode == 'reopen-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'installation::tests::reopen::', '--', '--nocapture']
elif mode == 'local-renewal-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'enrollment::tests::renewal::', '--', '--nocapture']
elif mode == 'local-journal-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'durable::rosters::local_renewal::tests::', '--', '--nocapture']
elif mode == 'local-next-renewal-test':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'enrollment::tests::renewal::next_renewal_reconciles_completed_predecessor_receipt_without_deleting_pending_target_receipt', '--', '--exact', '--nocapture']
elif mode == 'local-connection-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'enrollment::tests::renewal::connection::', '--', '--nocapture']
elif mode == 'enrollment-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'enrollment::tests::', '--', '--nocapture']
elif mode == 'prekey-renewal-test':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'current_successor_replays_original_reserved_material_across_process_loss', '--', '--nocapture']
elif mode == 'prekey-publication-test':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'policy_closed_after_publication_withholds_leaf_and_preserves_original_available_entry', '--', '--nocapture']
elif mode == 'fresh-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'renewed_operations::', '--', '--nocapture']
elif mode == 'expired-renewal-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'expired_renewal::', '--', '--nocapture']
elif mode == 'fresh-witness-test':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'fresh_peer_admission_requires_each_original_witness_query_and_release', '--', '--nocapture']
elif mode == 'c-owner-build':
    assert stage == ['c-owner']
    command = [str(tc / 'bin/cargo'), 'rustc', '--locked', '--offline', '--lib', '--', '-C', 'link-arg=-Wl,-install_name,@rpath/libq_periapt_continuity_c_consumer.dylib']
elif mode == 'c-owner-cbuild':
    assert stage == ['c-owner']
    installed = work / 'c-owner-installed'
    installed.mkdir(exist_ok=True)
    prefix = str(installed / 'qpc-c-client')
    processes = subprocess.check_output(['ps', '-axo', 'pid=,command='], text=True)
    assert not any(len(line.strip().split(None, 1)) == 2 and line.strip().split(None, 1)[1].startswith(prefix) for line in processes.splitlines()), 'C client still live'
    shutil.copy2(Path(env['CARGO_TARGET_DIR']) / 'debug/libq_periapt_continuity_c_consumer.dylib', installed / 'libq_periapt_continuity_c_consumer.dylib')
    compiler = subprocess.check_output(['/usr/bin/xcrun', '--sdk', 'macosx', '--find', 'clang'], env=env, text=True).strip()
    platform_sdk = subprocess.check_output(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], env=env, text=True).strip()
    command = [compiler, '-isysroot', platform_sdk, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-pthread', str(cwd / 'client.c'), str(cwd / 'recovery_client.c'), str(cwd / 'opening_client.c'), '-I', str(cwd), '-L', str(installed), '-lq_periapt_continuity_c_consumer', '-Wl,-rpath,@loader_path', '-o', str(installed / 'qpc-c-client')]
elif mode == 'c-owner-renewal-tests':
    assert stage == ['c-owner']
    env['QPERIAPT_C_OWNER_CLIENT'] = str(work / 'c-owner-installed/qpc-c-client')
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--test', 'enrollment', 'credential_renewal::', '--', '--nocapture']
elif mode == 'c-owner-original-enrollment':
    assert stage == ['c-owner']
    env['QPERIAPT_C_OWNER_CLIENT'] = str(work / 'c-owner-installed/qpc-c-client')
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--test', 'enrollment', 'c_registration_owns_original_identity_through_connection_and_roster_refresh', '--', '--exact', '--nocapture']
elif mode == 'c-owner-unit':
    assert stage == ['c-owner']
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--lib', '--', '--test-threads=2']
elif mode == 'regression':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', '--', '--test-threads=2']
elif mode == 'anchor-store-tests':
    command = [str(tc / 'bin/cargo'), 'test', '--locked', '--offline', '--all-features', '--lib', 'anchor::store::tests::', '--', '--test-threads=2', '--nocapture']
elif mode == 'doc':
    env['RUSTDOCFLAGS'] = '-D warnings'
    command = [str(tc / 'bin/cargo'), 'doc', '--locked', '--offline', '--all-features', '--no-deps']
elif mode == 'clippy':
    command = [str(tc / 'bin/cargo'), 'clippy', '--locked', '--offline', '--all-features', '--lib', '--tests', '--', '-D', 'warnings']
else:
    raise ValueError(mode)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
source_root = cwd / ('src' if stage in (['integrated'], ['c-owner']) else 'candidate/src')
before = {str(p.relative_to(cwd)): sha(p) for p in source_root.rglob('*.rs')}
assert before, 'No candidate Rust source was selected'
if stage == ['c-owner']:
    before.update({str(p.relative_to(cwd)): sha(p) for p in (cwd / 'tests').rglob('*.rs')})
    before.update({str(p.relative_to(cwd)): sha(p) for p in cwd.iterdir() if p.suffix in ('.c', '.h')})
runner_sha256 = sha(Path(__file__))
dependency_before = {}
if stage == ['c-owner']:
    native_sources = root / 'target/credential-lifecycle-integration/research/continuity-identity-candidate'
    dependency_before = {str(p): sha(p) for sub in ('src', 'tests') for p in (native_sources / sub).rglob('*.rs')}
installed_before = {}
if stage == ['c-owner'] and mode in ('c-owner-renewal-tests', 'c-owner-original-enrollment'):
    installed_before = {str(work / 'c-owner-installed' / name): sha(work / 'c-owner-installed' / name) for name in ('qpc-c-client', 'libq_periapt_continuity_c_consumer.dylib')}
start = time.monotonic()
cache_reset = None
if command[1] in ('test', 'clippy', 'rustc'):
    # These source copies share a dependency target, while Cargo emits relative
    # candidate depfiles and the same package hash. Older copied mtimes can make
    # another source's binary look fresh. Rebuild only this candidate package;
    # dependency artifacts remain cached. Never replace a live child's executable.
    processes = subprocess.check_output(['ps', '-axo', 'pid=,command='], text=True)
    prefix = env['CARGO_TARGET_DIR'] + '/debug/deps/'
    running = [line.strip() for line in processes.splitlines()
               if len(line.strip().split(None, 1)) == 2
               and line.strip().split(None, 1)[1].startswith(prefix)]
    if running:
        raise RuntimeError('Refusing candidate rebuild while native tests are live: ' + repr(running))
    selected_package = 'q-periapt-continuity-c-consumer' if stage == ['c-owner'] else 'q-periapt-continuity-identity-candidate'
    cache_reset = [str(tc / 'bin/cargo'), 'clean', '--locked', '--offline', '-p', selected_package]
with (work / (label + '.log')).open('xb') as log:
    if cache_reset is not None:
        subprocess.run(cache_reset, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    result = subprocess.run(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
validation_error = None
passed_tests = None
if command[1] == 'test' and result.returncode == 0:
    counts = re.findall(r'test result: ok\. (\d+) passed;', (work / (label + '.log')).read_text())
    passed_tests = sum(map(int, counts))
    if not counts or passed_tests == 0:
        validation_error = 'Successful cargo invocation did not execute any selected tests'
if mode != 'format':
    assert all(sha(cwd / name) == value for name, value in before.items())
    assert all(sha(Path(name)) == value for name, value in dependency_before.items())
    assert all(sha(Path(name)) == value for name, value in installed_before.items())
record = dict(command=command, cwd=str(cwd), source_hashes=before, dependency_source_hashes=dependency_before, installed_artifacts_before=installed_before, runner_sha256=runner_sha256, exit=result.returncode,
              seconds=time.monotonic() - start, completed=result.returncode == 0 and validation_error is None,
              candidate_cache_reset=cache_reset, passed_tests=passed_tests, validation_error=validation_error,
              scope='isolated incomplete credential-renewal candidate', release_claim_eligible=False)
if (cwd / 'Cargo.lock').exists(): record['lock_sha256'] = sha(cwd / 'Cargo.lock')
if stage == ['c-owner'] and mode in ('c-owner-cbuild', 'c-owner-renewal-tests', 'c-owner-original-enrollment'):
    record['installed_library_sha256'] = sha(work / 'c-owner-installed/libq_periapt_continuity_c_consumer.dylib')
    if (work / 'c-owner-installed/qpc-c-client').exists(): record['C_client_sha256'] = sha(work / 'c-owner-installed/qpc-c-client')
(work / (label + '.json')).write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({k: v for k, v in record.items() if k not in ('source_hashes', 'dependency_source_hashes')}, indent=2))
if mode != 'initialize': print((work / (label + '.log')).read_text()[-12000:])
raise SystemExit(result.returncode if result.returncode else (70 if validation_error else 0))
