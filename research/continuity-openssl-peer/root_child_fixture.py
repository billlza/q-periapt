"""Actual original-parent inspection after a separately approved root preparation."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import os
from types import SimpleNamespace
from qperiapt_continuity_reference.client_root_adoption import RootAdoption
from qperiapt_continuity_reference.client_root_recovery import RootRecovery
from qperiapt_continuity_reference.client_configuration import Configuration
from qperiapt_continuity_reference.durable import Session
from qperiapt_continuity_reference.registration_session import selected_parts
from qperiapt_continuity_reference.wire import require
from root_target_fixture import prepare


def terminal_cut(client, owner, mode, now, refuse):
    """Retain terminal control after intent removal, before completed control."""
    def stop(stage):
        if stage == 'client-device:session-store:committed:removal':
            raise OSError('original maintenance terminal retained before cleanup')
    client._observer = stop
    operation = owner.close_proposal if mode.endswith('-closed') else lambda: owner.commit(now=now)
    refuse(mode + '-before-cleanup', operation, 'maintenance terminal retained')


def prepare_roster(client, context, public, bridge, transport, mode, refuse):
    from qperiapt_continuity_reference.account_request import AccountRequest
    public = public / 'account'
    for cycle, now in ((1, 210), (2, 310)):
        grant = (public / f'grant-{cycle}-1').read_bytes()
        companions = [(public / f'grant-{cycle}-{member}').read_bytes() for member in (2, 3)]
        target = (public / f'checkpoint-{cycle + 1}').read_bytes()
        request = AccountRequest.parse(grant, companions, context.devices[0], context.family, context.policy_digest, target)
        bridge.call(f'root-inspection-g{cycle}-clock', 33, now.to_bytes(8, 'big'), b'witness clock set')
        with client.credential_renewal(request.local.operation, now, transport=transport()) as owner:
            proposal = owner.prepare_account(grant, companions, target, now=now)
            bridge.call(f'root-inspection-g{cycle}-approval', 34, proposal, b'Prepared')
            require(owner.commit(now=now) == 'Applied', 'original G before root roster inspection')
        bridge.call(f'root-inspection-native-g{cycle}', 40, cycle.to_bytes(8, 'big') + now.to_bytes(8, 'big'))
    bridge.call('root-inspection-native-r4', 40, (4).to_bytes(8, 'big') + (310).to_bytes(8, 'big'))
    with client.roster_refresh(os.urandom(32), 310, transport=transport()) as owner:
        proposal = owner.prepare((public / 'roster-4').read_bytes(), (public / 'checkpoint-4').read_bytes(), now=310)
        if mode != 'roster':
            bridge.call('root-inspection-r-approval', 39, proposal, b'Prepared')
            terminal_cut(client, owner, mode, 310, refuse)


def prepare_policy(client, pins, materials, context, public, bridge, transport, mode, refuse):
    from local_policy_checks import policy_inputs
    operation = os.urandom(32)
    bridge.call('root-inspection-policy-clock', 33, (190).to_bytes(8, 'big'), b'witness clock set')
    with client.policy_renewal(operation, 190, transport=transport()) as owner:
        request = owner.request()
        payload = (2).to_bytes(8, 'big') + (190).to_bytes(8, 'big') + request['scope']
        for field in ('current_credential', 'current_roster'):
            payload += len(request[field]).to_bytes(2, 'big') + request[field]
        approval = bridge.call('root-inspection-policy-approval', 41, payload)
        source = SimpleNamespace(public=public, pins=pins, materials=materials, pin=context.witness.pin)
        policy_pins, policy_materials = policy_inputs(source, 2)
        proposal = owner.prepare(approval, policy_pins, policy_materials, now=190)
        if mode != 'policy':
            controller = proposal + len(approval).to_bytes(2, 'big') + approval + payload
            bridge.call('root-inspection-p-approval', 43, controller, b'Prepared')
            terminal_cut(client, owner, mode, 190, refuse)


def exercise(client, registry, *, mode, private, client_path, identity, key, session_path,
             pins, materials, context, transport, bridge, refuse, public):
    fresh = bridge.call('fresh-successor-peer-materials', 45, (170).to_bytes(8, 'big'))
    plan = prepare(private, client._authority.application, pins, materials, context, 170, fresh)
    before_identity = client.status(); old_request = client.request
    recovery = None; adoption = None
    try:
        if mode in ('partial', 'partial-bound', 'partial-intent'):
            adoption = client.begin_root_adoption(registry, 170, transport=transport()); adoption.close()
            if mode == 'partial-bound':
                def stop(stage):
                    if stage == 'client-root-child:committed:removal': raise OSError('retained child binding before parent')
                adoption = RootAdoption.open(client_path, identity, key, registry, observer=stop)
                refuse('partial-child-binding', lambda: adoption.commit(170, transport=transport()), 'retained child binding')
            elif mode == 'partial-intent':
                adoption = RootAdoption.open(client_path, identity, key, registry)
                bridge.arm('before', 2)
                refuse('partial-binding-intent', lambda: adoption.commit(170, transport=transport()), 'truncated witness reply')
            checkpoint = registry.current(client._authority.application)
            registry.begin_preparation(checkpoint, plan)
            recovery = RootRecovery.open(client_path, identity, key, registry, plan.operation)
        else:
            if mode.startswith('ordinary-') or mode == 'tamper-intent':
                with client.session(170, transport=transport()) as child:
                    message = child.next_id(now=170); bridge.arm('before' if mode == 'tamper-intent' else mode.removeprefix('ordinary-'), 2)
                    refuse('original-child-unknown-write', lambda: child.send(message, b'original retained secret', b'root', now=170),
                           'truncated witness reply')
                from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
                client = EnrollmentClient.open(client_path, identity, key, account_authority=registry)
            elif mode.startswith('credential'):
                operation = (public / 'local-renewal-1-operation').read_bytes()
                grant = (public / 'local-renewal-1').read_bytes(); target = (public / 'pin-local-renewal-1-target').read_bytes()
                with client.credential_renewal(operation, 210, transport=transport()) as owner:
                    proposal = owner.prepare(grant, target, now=210)
                    if mode != 'credential':
                        bridge.call('root-inspection-g-approval', 34, proposal, b'Prepared')
                        terminal_cut(client, owner, mode, 210, refuse)
            elif mode.startswith('roster'):
                prepare_roster(client, context, public, bridge, transport, mode, refuse)
            elif mode.startswith('policy'):
                prepare_policy(client, pins, materials, context, public, bridge, transport, mode, refuse)
            if mode.endswith(('-terminal', '-closed')):
                from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
                client = EnrollmentClient.open(client_path, identity, key, account_authority=registry)
            checkpoint = registry.current(client._authority.application)
            recovery = client.prepare_account_root(registry, plan)
        paths = (client_path, session_path)
        def snapshot():
            return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for path in paths for p in path.rglob('*') if p.is_file()}
        if mode.startswith('tamper-'):
            from cryptography.exceptions import InvalidTag
            from qperiapt_continuity_reference.private_files import PrivateDirectory
            from qperiapt_continuity_reference.witness_journal import WitnessJournal
            formal = session_path / ('intent' if mode == 'tamper-intent' else 'head')
            original = formal.read_bytes()
            with os.fdopen(os.open(private / ('untampered-' + mode), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
                out.write(original); out.flush(); os.fsync(out.fileno())
            corrupted = bytearray(original)
            offset = WitnessJournal.image_overhead - 24 if mode == 'tamper-binding' else len(corrupted) - 1
            corrupted[offset] ^= 1
            formal.write_bytes(corrupted)  # Explicit fresh-fixture corruption; both versions remain retained.
            before = snapshot(); requests = len(bridge.records)
            if mode == 'tamper-head':
                try: recovery.inspect_child(170)
                except InvalidTag as error: rejection = type(error).__name__
                else: raise ValueError('missing root child authentication refusal')
            else:
                reason = 'root child original binding differs' if mode == 'tamper-binding' else 'write-intent authentication'
                refuse(mode, lambda: recovery.inspect_child(170), reason)
                rejection = reason
            require(snapshot() == before and len(bridge.records) == requests, 'root corruption inspection changed files or dispatched')
            for path in paths:
                lease = PrivateDirectory(path)
                try: lease.check()
                finally: lease.close()
            return {'completed':True, 'mode':mode, 'constructed_corruption':True, 'inspection_witness_requests':0,
                    'rejection':rejection,
                    'inspection_preserved_files':True, 'failed_owner_leases_released':True,
                    'scope':'Fresh isolated malformed child; original and corrupted bytes retained. Explicit authentication/binding refusal, no repair or permission grant.'}
        before = snapshot(); requests = len(bridge.records)
        kind = mode.split('-')[0]
        now = {'credential':210, 'roster':310, 'policy':190}.get(kind, 170)
        observation = recovery.inspect_child(now)
        require(snapshot() == before and len(bridge.records) == requests, 'root inspection mutated or dispatched')
        require(observation.subject == context.witness.subject(before_identity['journal']), 'root inspection original subject')
        expected_kind = ('ordinary' if mode.startswith('ordinary-') else 'root-binding' if mode == 'partial-intent'
                         else kind if kind in ('credential', 'roster', 'policy') else None)
        require(observation.pending_kind == expected_kind, 'wrong retained root operation kind')
        if mode.endswith('-terminal'):
            require(observation.local_phase == 'AppliedRecorded' and observation.intent_digest is None
                    and observation.local_head == observation.target and observation.target_metadata == observation.local_metadata,
                    'root inspection lost original applied maintenance boundary')
        elif mode.endswith('-closed'):
            require(observation.local_phase == 'ClosedRecorded' and observation.intent_digest is None
                    and observation.local_head == observation.expected and observation.target_metadata is None,
                    'root inspection lost original closed maintenance boundary')
        require(observation.root_bound == (mode not in ('partial', 'partial-intent')), 'wrong retained root header phase')
        status = recovery.status()
        require(status['root_adoption_pending'] == mode.startswith('partial'), 'parent adoption phase changed')
        require(status['signing_id'] == before_identity['signing_id'] and status['journal'] == before_identity['journal'],
                'root recovery changed original parent identity')
        refuse('old-client-stays-closed', lambda: old_request(170), 'closed enrollment client')
        refuse('registry-preparation-revokes-live-lease', lambda: registry.admit(checkpoint), 'account authority suspended')
        _, image = recovery._image()
        scope, child_key = selected_parts(key, recovery._registration.scope.identity, image, context)
        refuse('root-metadata-access-is-not-live', lambda: Session._scope(context, scope, recovery._access),
               'live account root lease required')
        if mode.startswith('partial'):
            require(not Configuration.read(recovery._configuration.read().payload).root_ready,
                    'root recovery marked partial adoption ready')
        recovery.close(); recovery = RootRecovery.open(client_path, identity, key, registry, plan.operation)
        require(recovery.inspect_child(now) == observation,
                'root observation changed across original reopen')
        require(snapshot() == before and len(bridge.records) == requests, 'root reopen mutated or dispatched child')
        cached = recovery.inspect_child; registry.close()
        refuse('closed-registry-revokes-child-inspection', lambda: cached(now), 'closed account authority owner')
        require(snapshot() == before and len(bridge.records) == requests, 'closed root inspection changed original state')
        return {'completed':True, 'mode':mode, 'kind':observation.pending_kind, 'local_phase':observation.local_phase,
                'bound':observation.root_bound,
                'local_head':observation.local_head.wire().hex(), 'target':None if observation.target is None else observation.target.wire().hex(),
                'inspection_witness_requests':0, 'original_files_unchanged':True,
                'metadata_sha256':hashlib.sha256(observation.local_metadata).hexdigest(),
                'scope':'Actual parent/child and real prepared independent target in the native policy family; local registry preparation and read-only inspection. No signed witness freeze/retirement or successor activation.'}
    finally:
        if recovery is not None: recovery.close()
        if adoption is not None: adoption.close()
        client.close()
