"""Later approved root preparation revokes the original successor's permission."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import sys
from contextlib import closing

from bounded_process import capture_output
from evidence_io import parse_strict_json_bytes
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport
from root_successor_cuts import implementation_receipt
from root_target_fixture import prepare
from worker_process import command


def exercise(recovery, registry, plan, *, bridge, now, client_path, identity, key, session, refuse, commit=False, cut=None):
    private = client_path.parent
    target = private / 'root-target'
    host = (target / 'host-key-and-id').read_bytes()
    registered = (private / 'registry-key-and-id').read_bytes()
    require(len(host) == len(registered) == 64, 'original authority test key/id shape')
    family, pin = registry.family, registry.witness
    predecessor = recovery._access.observation()[3]
    expected = registry.current(recovery._binding.application)
    require(expected.revision == 2 and expected.account == plan.successor.account,
            'later preparation requires the original selected successor')

    def snapshot():
        return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in target.rglob('*') if path.is_file()}

    try:
        with closing(EnrollmentClient.open(target / 'client', host[32:], host[:32],
                                           account_authority=registry)) as client:
            _, image = client._registration._image()
            inputs = image.child.inputs
            context = inputs.original(image.child.context, now)
            fresh = bridge.call('later-root-fresh-peer-materials', 45, now.to_bytes(8, 'big'))
            following = private / 'later-root'; following.mkdir(mode=0o700)
            later = prepare(following, expected.application, inputs.pins, inputs.materials,
                            context, now, fresh, root_revision=3)
            with client.connection_session(now, transport=TcpTransport(bridge.address)) as child:
                require(child.connection_identity(now=now) == session, 'later root lost original session')
                before = snapshot(); requests = len(bridge.records)
                require(registry.begin_preparation(expected, later) == 'Preparing',
                        'later root did not retain its approved preparation')
                refuse('later-root-revokes-cached-successor-session',
                       lambda: child.next_id(now=now), 'account authority suspended')
        refuse('later-root-revokes-successor-checkpoint', lambda: registry.admit(expected),
               'account authority suspended')
        with RootRecovery.open(target / 'client', host[32:], host[:32], registry, later.operation) as reader:
            observation = reader.inspect_child(now)
        require(observation.subject == context.witness.subject(plan.journal) and observation.root_bound,
                'later root recovery inspection selected another child')
        metadata_head = observation.local_head.wire().hex()
        require(snapshot() == before and len(bridge.records) == requests,
                'later preparation changed original client files or dispatched traffic')
        head = hashlib.sha256((private / 'account-registry/head').read_bytes()).hexdigest()
        implementation = implementation_receipt()
        config = private / 'later-root-probe-inputs.json'; marker = private / 'later-root-probe.json'
        value = {'private': str(private), 'family': family.hex(), 'witness': pin.identity.hex(),
                 'witness_key': pin.key.raw.hex(), 'operation': later.operation.hex(),
                 'now': now, 'address': bridge.address}
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
            json.dump(value, out); out.flush(); os.fsync(out.fileno())
        provider = Path(sys.modules['cryptography'].__file__).resolve().parent.parent
        argv = command(Path(__file__).with_name('root_successor_worker.py'),
                       '--implementation-root', implementation['root'], '--provider-root', str(provider),
                       '--configuration', str(config), '--marker', str(marker), '--probe-suspension')
        recovery.close(); registry.close()
        result = capture_output(argv, timeout_seconds=30, maximum_stdout_bytes=16384,
                                maximum_stderr_bytes=16384)
        (private / 'later-root-probe.stdout').write_bytes(result.stdout)
        (private / 'later-root-probe.stderr').write_bytes(result.stderr)
        require(result.returncode == 0 and not result.stderr, 'later-root fresh-process probe failed')
        row = parse_strict_json_bytes(marker.read_bytes(), label='later root probe marker')
        require(row == parse_strict_json_bytes(result.stdout, label='later root probe stdout')
                and row['completed'] is True and row['operation'] == later.operation.hex()
                and row['rejection'] == 'account authority suspended'
                and row['metadata_head'] == metadata_head
                and type(row['pid']) is int and row['pid'] > 0 and row['pid'] != os.getpid()
                and row['implementation'] == implementation, 'later root probe identity differs')
        require(snapshot() == before and len(bridge.records) == requests
                and hashlib.sha256((private / 'account-registry/head').read_bytes()).hexdigest() == head,
                'reopened suspended successor changed original state or dispatched')
        registry = AccountAuthority.open(private / 'account-registry', registered[:32], registered[32:], family, pin)
        require(registry.operation(later.operation)[1:3] == ('Preparing', later.wire()),
                'later root preparation did not persist unchanged')
        refuse('reopened-registry-retains-successor-suspension', lambda: registry.admit(expected),
               'account authority suspended')
        committed = None
        if commit:
            from root_later_commit_fixture import exercise as commit_later
            registry, committed = commit_later(registry, later, predecessor, plan, private=private, host=host,
                                               now=now, observation=observation, bridge=bridge, refuse=refuse, cut=cut)
        recovery = RootRecovery.open(client_path, identity, key, registry, plan.operation)
        return recovery, registry, {'completed': True, 'operation': later.operation.hex(),
                'original_root_revision': 2, 'prepared_root_revision': 3,
                'registry_head_sha256': head, 'process_probe': row, 'original_files_unchanged': snapshot() == before,
                'preparation_original_files_unchanged': True, 'suspension_witness_requests': 0,
                'additional_witness_requests': len(bridge.records) - requests, 'commit': committed,
                'scope': (committed['scope'] if committed is not None else
                          'Later locally approved preparation suspends the active successor and survives a fresh process; no later witness freeze, root commit, power-loss or global revocation claim.')}
    except BaseException:
        recovery.close(); registry.close(); raise
