from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys
import time

from bounded_process import capture_output

assert sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
root = Path.cwd()
stage = Path(__file__).resolve().parent
out = stage / 'validation-02'
out.mkdir()
build = stage / 'build'
assert build.is_dir() and (stage / 'BINARY_PRESERVATION.json').is_file()
tool = Path('/Users/bhmq03@durham.ac.uk/.rustup/toolchains/1.98.1-aarch64-apple-darwin')
cache = Path('/Users/bhmq03@durham.ac.uk/Documents/Codex/2026-10-30/la/work/rust-runtime/cargo')
assert not any((cache / name).exists() for name in ('config', 'config.toml', 'credentials', 'credentials.toml'))
env = {key: value for key, value in os.environ.items() if not key.startswith(('CARGO_', 'RUST', 'DYLD_', 'LD_'))}
env.update(CARGO_HOME=str(cache), CARGO_TARGET_DIR=str(build), CARGO_NET_OFFLINE='true', CARGO_INCREMENTAL='0',
    CARGO_TERM_COLOR='never', RUSTC=str(tool / 'bin/rustc'), RUSTDOC=str(tool / 'bin/rustdoc'),
    RUSTFLAGS='-D warnings', RUSTDOCFLAGS='-D warnings', RUSTUP_AUTO_INSTALL='0',
    DYLD_FALLBACK_LIBRARY_PATH=str(tool / 'lib'), PATH=str(tool / 'bin') + os.pathsep + env.get('PATH', os.defpath),
    OPENSSL_DIR='/Users/bhmq03@durham.ac.uk/Documents/Codex/2026-10-30/la/work/release-020/openssl-3.5.9-preparation/installed',
    OPENSSL_STATIC='0')
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
paths = subprocess.run(['git', 'ls-files', 'crates', 'research/continuity-identity-candidate', 'Cargo.lock'],
    check=True, stdout=subprocess.PIPE).stdout.decode().splitlines()
inputs = {name: sha(root / name) for name in paths}
parent = subprocess.run(['git', 'rev-parse', 'HEAD'], check=True, stdout=subprocess.PIPE).stdout.decode().strip()
assert parent == '9b370749f53b3145544b1b6892cd765dde71bc42'
(out / 'INPUTS.json').write_text(json.dumps(inputs, indent=2) + '\n')
selected = [
    'public_pending_write_recovery_preserves_staged_joint_authorization',
    'public_pending_write_recovery_preserves_original_operation_through_joint_renewal',
    'expired_cleanup_intent_distinguishes_applied_reply_loss_from_blocked_renewal',
]
commands = []
def run(argv, label):
    print(label, flush=True)
    row = {'argv': argv, 'started_utc': datetime.now(timezone.utc).isoformat(), 'completed': False, 'timeout_seconds': 900}
    started = time.monotonic()
    try:
        with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
            result = capture_output(argv, timeout_seconds=900, maximum_stdout_bytes=16*1024**2,
                maximum_stderr_bytes=16*1024**2, environment=env,
                stdout_sink=stdout.write, stderr_sink=stderr.write)
        row.update(completed=True, returncode=result.returncode)
        assert result.returncode == 0, label
        return result
    finally:
        row['seconds'] = time.monotonic() - started
        (out / (label + '.json')).write_text(json.dumps(row, indent=2) + '\n')
        commands.append(row)
manifest = 'research/continuity-identity-candidate/Cargo.toml'
common = ['--manifest-path', manifest, '--locked', '--offline', '--features', 'anchor-tls,control-tls,connection-tls', '-j', '2']
record = {'completed': False, 'parent_commit': parent, 'native_tests': {}, 'release_claim_eligible': False,
    'scope': 'Source native pending-offer closure metadata, original pending-write recovery and independent joint-authorization evidence. No product implementation change, secrecy theorem, machine proof, installed-package or physical-power-loss qualification.'}
try:
    run([str(tool / 'bin/cargo'), 'fmt', '--manifest-path', manifest, '--all', '--check'], 'fmt')
    for profile in ('debug', 'release'):
        built = run([str(tool / 'bin/cargo'), 'test', *common, '--lib', '--no-run', '--message-format=json',
                     *(['--release'] if profile == 'release' else [])], profile + '-build')
        binaries = [row for line in built.stdout.splitlines() if (row := json.loads(line)).get('executable')
                    and row.get('reason') == 'compiler-artifact' and row['target']['name'] == 'q_periapt_continuity_identity_candidate']
        assert len(binaries) == 1 and binaries[0]['profile']['test'] is True
        binary = Path(binaries[0]['executable']).resolve(strict=True)
        assert binary.is_relative_to(build / profile)
        digest = sha(binary)
        listed = run([str(binary), '--list'], profile + '-catalog').stdout.decode().splitlines()
        outcomes = []
        for index, name in enumerate(selected):
            matches = [line.removesuffix(': test') for line in listed if line.endswith('::' + name + ': test')]
            assert len(matches) == 1
            assert sha(binary) == digest
            result = run([str(binary), '--exact', matches[0], '--nocapture'], profile + '-test-' + str(index + 1))
            assert re.search(rb'^test result: ok\. 1 passed; 0 failed; 0 ignored;', result.stdout, re.M)
            assert sha(binary) == digest
            markers = [line.decode() for line in result.stderr.splitlines() if line.startswith(
                (b'PUBLIC_PENDING_STAGED ', b'PUBLIC_PENDING_RECOVERY ', b'EXPIRED_CLEANUP_RENEWAL '))]
            if index == 0:
                expected = ['PUBLIC_PENDING_STAGED originally_applied=' + applied
                    + ' closed_p0=true query_loss_before_after=true exact_query_retry=true'
                    + ' staged_gt_preserved=true complete_report_ack=true pending_rekey_offer=' + pending
                    + ' pending_epoch=' + ('Some(1)' if pending == 'true' else 'None')
                    for pending in ('false', 'true') for applied in ('false', 'true')]
                assert markers == expected
            elif index == 1:
                assert len(markers) == 4 and all('cleanup_complete=true' in marker for marker in markers)
            else:
                assert len(markers) == 4
                expected = ['EXPIRED_CLEANUP_RENEWAL policy_expired=' + expired + ' applied=' + applied
                    + ' request_available=' + applied + ' original_intent_preserved=' + ('true' if applied == 'false' else 'false')
                    for expired in ('false', 'true') for applied in ('false', 'true')]
                assert markers == expected
            outcomes.append({'test': matches[0], 'markers': markers})
        record['native_tests'][profile] = {'binary': str(binary), 'sha256': digest, 'executions': outcomes}
    run([str(tool / 'bin/cargo-clippy'), 'clippy', *common, '--all-targets', '--', '-D', 'warnings'], 'clippy')
    assert {name: sha(root / name) for name in paths} == inputs
    record.update(completed=True, source_inputs_unchanged=True)
finally:
    record.update(commands=commands, finished_utc=datetime.now(timezone.utc).isoformat())
    (out / 'RESULT.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record), flush=True)
