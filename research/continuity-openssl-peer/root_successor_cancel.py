"""Reentrant cancellation stops publication and resumes only original state."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport
from root_successor_cuts import PHASES, implementation_receipt

BOUNDARIES = tuple((phase, 'committed:intent') for phase in PHASES) + (('child', 'witness:advanced'),)
CASES = tuple((action, *boundary) for action in ('owner', 'registry') for boundary in BOUNDARIES)


def exercise(recovery, registry, plan, *, case, bridge, now, private, identity, key):
    require(case in CASES, 'successor cancellation case')
    action, phase, stage = case; prefix, occurrence = PHASES[phase]
    family, pin = registry.family, registry.witness
    target_path = private / 'root-target'; host = (target_path / 'host-key-and-id').read_bytes()
    require(len(host) == 64, 'original successor host identity')
    observed = 0; stopped = None; later = []

    def files():
        return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in target_path.rglob('*') if p.is_file()}

    def stop(value):
        nonlocal observed, stopped
        if stopped is not None:
            later.append(value); return
        if value != prefix + stage: return
        observed += 1
        if observed != occurrence: return
        (recovery if action == 'owner' else registry).close()
        stopped = {'files': files(), 'witness_requests': len(bridge.records)}

    target = EnrollmentClient.open(target_path / 'client', host[32:], host[:32], observer=stop)
    client = None; failure = None
    try:
        client = recovery.activate_successor(target, now, transport=TcpTransport(bridge.address))
    except (ValueError, OSError) as error:
        failure = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if client is not None: client.close()
        target.close()
    require(stopped is not None and observed == occurrence, 'successor cancellation boundary not reached')
    after = files(); requests = len(bridge.records) - stopped['witness_requests']
    changed = sorted(p for p in after.keys() | stopped['files'].keys() if after.get(p) != stopped['files'].get(p))
    report = {'action': action, 'phase': phase, 'stage': stage, 'occurrence': occurrence,
              'failure': failure, 'returned_client': client is not None, 'events_after_close': later,
              'changed_after_close': changed, 'additional_witness_requests': requests,
              'captured': stopped, 'after': after, 'implementation': implementation_receipt()}
    with os.fdopen(os.open(private / 'successor-cancel.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
        json.dump(report, out, indent=2); out.write('\n'); out.flush(); os.fsync(out.fileno())
    require(client is None and failure is not None and 'closed' in failure['message'],
            'successor cancellation did not refuse the result')
    require(not changed and requests == 0 and not later, 'successor continued after owner cancellation')
    recovery.close(); registry.close()
    registered = (private / 'registry-key-and-id').read_bytes()
    require(len(registered) == 64, 'original registry key/id shape')
    registry = AccountAuthority.open(private / 'account-registry', registered[:32], registered[32:], family, pin)
    try:
        recovery = RootRecovery.open(private / 'client', identity, key, registry, plan.operation)
        return recovery, registry, report
    except BaseException:
        registry.close(); raise
