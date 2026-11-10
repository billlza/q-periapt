#!/usr/bin/env python3
"""Run one real native publication fault and recover the exact original request.

The scoped patch only orchestrates the test counterpart's pipe and processes.
Cryptography, storage and the recovered native binary remain unmodified.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import runpy
import signal
import subprocess
import sys
import time
from unittest import mock
from continuity_native_approval_instrument import source_inputs
from git_provenance import git_commit
from evidence_io import parse_strict_json_bytes

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / 'research/continuity-openssl-peer'
LANES = ('first', 'later', 'unactivated', 'unactivated-later')
STAGES = ('staging', 'file', 'prepared', 'published', 'synced')
CASES = tuple(f'{lane}:{stage}:{kind}' for lane in LANES for stage in STAGES for kind in ('kill', 'io'))
IO_ERROR = b'\x02injected approval publication I/O failure'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path, maximum):
    with path.open('rb') as stream:
        value = stream.read(maximum + 1)
    require(len(value) <= maximum, 'fault observation exceeds its bound')
    return value


def verify_build(build):
    report = parse_strict_json_bytes(read(build / 'BUILD.json', 1024 * 1024), label='native publication fault build')
    require(report['completed_build'] is True and report['runtime_qualified'] is False, 'fault build scope differs')
    require(report['source_commit'] == git_commit(ROOT),
            'fault build source commit differs')
    require(report['source_inputs'] == source_inputs(), 'fault build source changed')
    require(report['instrumenter_sha256'] == digest(ROOT / 'artifact/continuity_native_approval_instrument.py'),
            'fault instrumenter changed')
    require(digest(build / 'original-counterpart') == report['native_sha256']
            and digest(build / 'fault-counterpart') == report['fault_native_sha256'], 'fault build binaries changed')
    return report


def exercise(args):
    driver_hash = digest(Path(__file__))
    lane, stage, kind = args.case.split(':')
    selected_lane = 'later' if lane == 'unactivated-later' else lane
    now = 181 if lane.startswith('unactivated') else 191 if lane == 'later' else 170
    build = args.build.resolve(strict=True)
    before = verify_build(build)
    original, instrumented = build / 'original-counterpart', build / 'fault-counterpart'
    sys.path.insert(0, str(SOURCE))
    import run
    transfer = run.Counterpart.transfer
    observation = None
    directory = None

    def recover(native, data):
        nonlocal directory, observation
        if directory is None:
            directory = native.cases.parent
            with (directory / 'approval-fault-selection').open('xb') as stream:
                stream.write(f'{selected_lane}:{stage}:{kind}'.encode())
        require(native.cases.parent == directory, 'fault case created another native fixture')
        try:
            reply = transfer(native, data)
        except RuntimeError as error:
            if kind != 'kill' or str(error) != 'native output ended before complete response':
                raise
            reply = None
        if reply is not None and (kind != 'io' or reply != IO_ERROR):
            return reply
        require(observation is None, 'fault recovery attempted more than once')
        old = native.process
        marker = read(directory / 'approval-fault-marker', 128).decode().splitlines()
        require(marker == [selected_lane, stage, kind, str(old.pid)], 'fault marker differs')
        require(data[0] == (60 if lane == 'unactivated' else 56 if 'later' in lane else 52), 'wrong fault controller')
        require(data[1:] == read(directory / 'approval-fault-request', 32768), 'original approval request changed')
        status = old.wait(timeout=10)
        require(status == (-signal.SIGKILL if kind == 'kill' else 1), 'fault did not terminate the original process')
        public = directory / 'public'
        private = Path(read(public / 'private-fixture-path', 4096).decode())
        witness = Path(read(public / 'private-witness-path', 4096).decode())
        files = [private / name for name in ('key', 'identity')]
        files += [witness / name for name in ('key', 'witness-id', 'witness-key-id', 'device-key-id',
                                             'witness-signer', 'device-signer', 'prekey-host-key', 'prekey-reservation')]
        preserved = {str(path): digest(path) for path in files}
        selected = public / ('root-successor-later' if selected_lane == 'later' else 'root-successor')
        require(selected.exists() == (stage in ('published', 'synced')), 'publication stage differs')
        if selected.exists():
            require(read(selected / 'control', 32768) == data[1:], 'published approval differs')
            require(read(selected / 'private-fixture-path', 4096) == read(public / 'private-fixture-path', 4096),
                    'publication changed the original journal')
        old_stderr = Path(native.stderr.name)
        if kind == 'io':
            diagnostic = read(old_stderr, 65536)
            require(b'successor approval publication failed; reopen original fixture' in diagnostic
                    and b'panicked at' not in diagnostic, 'publication error did not propagate explicitly')
        observation = {'completed': False, 'case': args.case, 'old_pid': old.pid, 'old_returncode': status,
            'original_request_sha256': hashlib.sha256(data[1:]).hexdigest(),
            'original_error': None if reply is None else reply[1:].decode(), 'original_stderr_sha256': digest(old_stderr),
            'preserved_files': preserved, 'native_sha256': before['native_sha256'],
            'fault_native_sha256': before['fault_native_sha256']}
        report_path = directory / 'APPROVAL_FAULT.json'
        report_path.write_text(json.dumps(observation, indent=2) + '\n')
        old.stdin.close(); old.stdout.close(); native.stderr.close()
        native.executable = original
        stderr_path = directory / 'approval-retry.stderr'
        native.stderr = stderr_path.open('xb')
        native.process = subprocess.Popen([str(original), str(public), '--resume-successor', str(now)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=native.stderr, bufsize=0, start_new_session=True)
        require(native.process.stdin is not None and native.process.stdout is not None, 'missing recovery pipes')
        os.set_blocking(native.process.stdin.fileno(), False); os.set_blocking(native.process.stdout.fileno(), False)
        observation.update(new_pid=native.process.pid, stderr=str(stderr_path))
        report_path.write_text(json.dumps(observation, indent=2) + '\n')
        deadline = time.monotonic() + 30
        require(native.read(4, deadline) == b'\0\0\0\6' and native.read(6, deadline) == b'\1ready',
                'original fixture did not reopen')
        native.command('approval-resume-old-controller', 8, b'', 2, b'resumed fixture only admits its original successor')
        native.command('approval-resume-changed-request', data[0], data[1:-1], 2)
        answer = transfer(native, data)
        require(answer[:1] == b'\x01', 'exact original approval retry failed')
        require(all(digest(Path(name)) == value for name, value in preserved.items()), 'recovery replaced original keys')
        observation.update(completed=True, exact_retry_response_sha256=hashlib.sha256(answer[1:]).hexdigest(),
                           old_controller_refused=True, changed_request_refused=True)
        report_path.write_text(json.dumps(observation, indent=2) + '\n')
        native.restarts.append({'case': 'approval-publication-' + stage, 'root_revision': 3 if 'later' in lane else 2,
            'signal': 'SIGKILL' if kind == 'kill' else 'normal-error-exit', 'old_pid': old.pid,
            'new_pid': native.process.pid, 'old_returncode': status, 'completed': True, 'preserved_files': preserved})
        return answer

    mode = ['--root-unactivated-retirement', 'planned-restart'] if lane.startswith('unactivated') else [
        '--root-successor-process-restart', 'peer-root-continuation' if lane == 'later' else 'peer']
    argv = [str(SOURCE / 'enrollment_session_checks.py'), '--implementation-root', str(args.implementation_root),
            '--provider-root', str(args.provider_root), '--native', str(instrumented), *mode, '--output', str(args.output)]
    with mock.patch.object(run.Counterpart, 'transfer', recover), mock.patch.object(sys, 'argv', argv):
        runpy.run_path(argv[0], run_name='__main__')
    require(observation is not None and observation['completed'], 'selected publication fault did not execute')
    lifecycle = parse_strict_json_bytes(read(args.output / 'RESULT.json', 32 * 1024**2), label='native publication lifecycle')
    require(lifecycle['completed'], 'complete lifecycle did not finish')
    require(verify_build(build) == before, 'fault build changed during lifecycle')
    require(digest(Path(__file__)) == driver_hash, 'fault driver changed during lifecycle')
    result = {'completed': True, 'case': args.case, 'source_commit': before['source_commit'],
              'build_sha256': digest(build / 'BUILD.json'), 'driver_sha256': driver_hash,
              'lifecycle_sha256': digest(args.output / 'RESULT.json'), 'publication_fault': observation,
              'scope': 'Actual fault termination, unmodified process reopening the original stores, exact approved retry and complete peer traffic/rekey. Not powerloss, mobile, PCS or release qualification.'}
    (args.output / 'PUBLICATION_FAULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print('NATIVE_APPROVAL_PUBLICATION_PASS case=' + args.case)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=CASES, required=True)
    for name in ('build', 'implementation-root', 'provider-root', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parsed = parser.parse_args()
    parsed.implementation_root = parsed.implementation_root.resolve(strict=True)
    parsed.provider_root = parsed.provider_root.resolve(strict=True)
    parsed.output = parsed.output.absolute()
    exercise(parsed)
