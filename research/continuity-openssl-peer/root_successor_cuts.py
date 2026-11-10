"""Kill the actual successor owner, then reopen its original approved inputs."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
from bounded_process import capture_output
from evidence_io import parse_strict_json_bytes
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.wire import require
from worker_process import command

STAGES = ('stage-synced:intent', 'published:intent', 'committed:intent', 'stage-synced:head',
          'published:head', 'committed:head', 'removed:intent', 'committed:removal')
PHASES = {'configuration': ('client-config:', 1), 'child': ('client-root-child:', 1),
          'registration': ('client-device:registration-store:', 1), 'ready': ('client-config:', 2),
          'activation': ('client-device:registration-store:', 2)}
CUTS = tuple((phase, stage) for phase in PHASES for stage in STAGES) + (('child', 'witness:advanced'),)


def implementation_receipt():
    package = Path(sys.modules['qperiapt_continuity_reference'].__file__).resolve().parent
    files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(package.glob('*.py'))}
    loaded = [Path(module.__file__).resolve() for name, module in sys.modules.items()
              if name == 'qperiapt_continuity_reference' or name.startswith('qperiapt_continuity_reference.')]
    require(files and loaded and all(path.is_relative_to(package) for path in loaded),
            'successor cut loaded a different product implementation')
    return {'root': str(package.parent), 'modules': len(files),
            'sha256': hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()}


def preserved_orphans(private):
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (private / 'root-target').rglob('.stage-*')
            if path.is_file() and path.name != '.stage-head'}


def exercise(owner, registry, plan, *, cut, private, identity, key, now, address):
    phase, stage = cut
    require(cut in CUTS, 'successor cut boundary')
    family, pin = registry.family, registry.witness
    config = private / 'successor-cut-inputs.json'; marker = private / 'successor-cut.json'
    value = {'private': str(private), 'family': family.hex(), 'witness': pin.identity.hex(),
             'witness_key': pin.key.raw.hex(), 'operation': plan.operation.hex(), 'now': now, 'address': address}
    with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
        json.dump(value, out); out.flush(); os.fsync(out.fileno())
    keys = {str(private / name): hashlib.sha256((private / name).read_bytes()).hexdigest()
            for name in ('host-key-and-id', 'registry-key-and-id', 'root-target/host-key-and-id')}
    implementation = implementation_receipt()
    provider = Path(sys.modules['cryptography'].__file__).resolve().parent.parent
    argv = command(Path(__file__).with_name('root_successor_worker.py'),
                   '--implementation-root', implementation['root'], '--provider-root', str(provider),
                   '--configuration', str(config), '--marker', str(marker), '--phase', phase, '--cut', stage)
    owner.close(); registry.close()
    result = capture_output(argv, timeout_seconds=30, maximum_stdout_bytes=16384, maximum_stderr_bytes=16384)
    (private / 'successor-cut.stdout').write_bytes(result.stdout)
    (private / 'successor-cut.stderr').write_bytes(result.stderr)
    with (private / 'successor-cut-result.json').open('x') as out:
        json.dump({'argv': argv, 'returncode': result.returncode}, out, indent=2); out.write('\n')
    require(result.returncode == -signal.SIGKILL and not result.stderr,
            'successor worker did not reach exact SIGKILL boundary')
    row = parse_strict_json_bytes(marker.read_bytes(), label='successor cut marker')
    require(row == parse_strict_json_bytes(result.stdout, label='successor cut stdout')
            and row['phase'] == phase and row['stage'] == stage and row['occurrence'] == PHASES[phase][1]
            and type(row['pid']) is int and row['pid'] > 0 and row['pid'] != os.getpid()
            and row['implementation'] == implementation, 'successor cut marker differs')
    require(all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected for path, expected in keys.items()),
            'successor cut replaced original host or registry keys')
    orphans = preserved_orphans(private)
    report = {'returncode': result.returncode, 'marker': row, 'preserved_keys': keys, 'orphans': orphans}
    with (private / 'successor-cut-process.json').open('x') as out:
        json.dump(report | {'argv': argv}, out, indent=2); out.write('\n')
    original = (private / 'registry-key-and-id').read_bytes()
    require(len(original) == 64, 'original registry key/id shape')
    registry = AccountAuthority.open(private / 'account-registry', original[:32], original[32:], family, pin)
    try:
        owner = RootRecovery.open(private / 'client', identity, key, registry, plan.operation)
        return owner, registry, report
    except BaseException:
        registry.close(); raise
