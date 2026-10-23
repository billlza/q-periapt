"""Continue the original committed root chain through the same native witness."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import closing
import hashlib

from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.wire import require
from qperiapt_continuity_reference.witness import TcpTransport
from root_retirement_fixture import control, field, pair


def exercise(registry, plan, predecessor, original_plan, *, private, host, now, observation, bridge, refuse, cut=None):
    original = private / 'root-target'
    following = private / 'later-root/root-target'
    target_host = (following / 'host-key-and-id').read_bytes()
    require(len(target_host) == 64, 'later root original target key/id')
    expected = registry.operation(plan.operation)[0]
    request = field(predecessor) + control(plan)
    require(len(request) + 1 <= 32768, 'later root control exceeds original pipe bound')
    reserved = {directory / name for directory in (original / 'client/registration', original / 'session')
                for name in ('.stage-root-fence-pending', '.stage-root-fence-retired')}

    def snapshot():
        return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in original.rglob('*') if path.is_file() and path.name != 'root-fence'
                and not path.name.startswith('.stage-')}

    def orphan_files():
        return {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in private.rglob('.stage-*') if path.is_file() and path.name != '.stage-head'
                and path not in reserved}

    def staged_fences():
        stages = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in reserved if path.exists()}
        require(len(stages) == (1 if cut[1].endswith('stage-synced:root-fence') else 0),
                'root cut reserved fence stage differs')
        return stages

    def published(stages):
        # Reserved output slots are consumed, not retained as random orphans.
        # Check their exact bytes became the authenticated formal fence first.
        for path, expected in stages.items():
            require(not path.exists() and hashlib.sha256((path.parent / 'root-fence').read_bytes()).hexdigest() == expected,
                    'root recovery did not publish the exact original staged fence')

    def reopen():
        return RootRecovery.open(original / 'client', host[32:], host[:32], registry, plan.operation)

    before = snapshot()
    bridge.call('later-root-cannot-use-original-controller', 50, control(plan), status=2,
                expected=b'root control changes original account')
    bridge.call('later-root-wrong-predecessor', 54,
                field(predecessor[:-1]) + control(plan), status=2)
    changed = bytearray(predecessor); changed[-1] ^= 1
    bridge.call('later-root-changed-predecessor', 54, field(bytes(changed)) + control(plan), status=2)
    bridge.call('later-root-wrong-lineage', 54,
                field(predecessor) + control(original_plan), status=2,
                expected=b'root control changes original account')
    canonical, freeze = pair(bridge.call('later-root-freeze', 54, request))
    plan.verify_plan(canonical)
    decision = plan.bind(freeze)
    selected = [row for row in decision.subjects() if row.subject == observation.subject]
    require(len(selected) == 1 and selected[0].head == observation.local_head,
            'later native freeze differs from original active successor')
    owner = reopen()
    process_cut = None; orphans = None; stages = {}
    try:
        if cut is not None and cut[0] == 'bind':
            from root_retirement_cuts import exercise as interrupt
            owner, registry, process_cut = interrupt(owner, registry, plan, freeze, cut=cut, private=private,
                identity=host[32:], key=host[:32], now=now, client_path=original / 'client')
            orphans = orphan_files(); stages = staged_fences()
        require(owner.bind_freeze(freeze, now=now) == decision.wire(), 'later root local freeze differs')
        published(stages)
        require(snapshot() == before, 'later freeze rewrote original successor business state')
        native_decision, retired = pair(bridge.call('later-root-retirement', 55, request + field(decision.wire())))
        decision.verify_decision(native_decision); decision.verify_retirement(retired)
        # Lose the first controller result and reopen the same persistent witness.
        bridge.call('later-root-witness-reopen', 32, b'', b'witness reopened')
        repeated_decision, repeated_retired = pair(bridge.call(
            'later-root-retirement-retry', 55, request + field(decision.wire())))
        decision.verify_decision(repeated_decision); decision.verify_retirement(repeated_retired)
        if cut is not None and cut[0] == 'retire':
            from root_retirement_cuts import exercise as interrupt
            owner, registry, process_cut = interrupt(owner, registry, plan, repeated_retired, cut=cut, private=private,
                identity=host[32:], key=host[:32], now=now, client_path=original / 'client')
            orphans = orphan_files(); stages = staged_fences()
        current = owner.retain_witness_retirement(repeated_retired, now=now)
        if cut is not None and cut[0] == 'retire':published(stages)
        require(current.revision == 3 and current.account == plan.successor.account
                and registry.current(current.application) == current, 'third root registry selection differs')
        require(snapshot() == before and owner.inspect_child(now) == observation,
                'later retirement changed original successor state')
        fences = [original / 'client/registration/root-fence', original / 'session/root-fence']
        require(all(path.is_file() for path in fences), 'later retirement omitted an original fence')
        retained = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in fences}
        refuse('retired-second-root-cannot-regain-lease', lambda: registry.admit(expected),
               'account authority checkpoint differs')
        with closing(owner.activate_successor(EnrollmentClient.open(
                following / 'client', target_host[32:], target_host[:32]), now,
                transport=TcpTransport(bridge.address))) as client:
            require(client.status()['journal'] == plan.journal, 'third root changed prepared journal')
            with client.session(now, transport=TcpTransport(bridge.address)) as child:
                require(child.status() == 'Waiting', 'third root emitted unsolicited bootstrap flight')
        ready = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in following.rglob('*') if path.is_file()}
        with closing(owner.activate_successor(EnrollmentClient.open(
                following / 'client', target_host[32:], target_host[:32], account_authority=registry), now,
                transport=TcpTransport(bridge.address))) as client:
            require(client.status()['journal'] == plan.journal, 'third root retry changed original journal')
        require(ready == {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in following.rglob('*') if path.is_file()}, 'third root retry rewrote ready state')
        require(owner.retain_witness_retirement(retired, now=now) == current
                and registry.current(current.application) == current
                and retained == {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in fences},
                'later retirement retry changed the selected root or first retained fences')
        require((following / 'host-key-and-id').read_bytes() == target_host,
                'later recovery replaced original third-root keys')
        require(orphans is None or orphan_files() == orphans, 'later recovery changed preserved orphan files')
        return registry, {'completed': True, 'registry_revision': 3, 'account': current.account.hex(),
                'operation': plan.operation.hex(), 'target_journal': plan.journal.hex(),
                'original_second_root_files_unchanged': snapshot() == before, 'fences': retained,
                'native_control_refusals': 4, 'native_witness_reopened': True,
                'process_cut': process_cut, 'preserved_orphans': orphans,
                'staged_fences_published_exactly': {str(path): expected for path, expected in stages.items()},
                'original_prepared_third_root_activated': True, 'activation_retry_unchanged': True,
                'registry_head_sha256': hashlib.sha256((private / 'account-registry/head').read_bytes()).hexdigest(),
                'scope': 'Actual native witness commits the second-to-third root transition after original successor traffic, then the installed client retains both retirement fences and admits the original prepared third root. Any actual SIGKILL boundary is recorded separately. No third-root peer traffic, power-loss or PCS claim.'}
    except BaseException:
        registry.close(); raise
    finally:
        owner.close()
