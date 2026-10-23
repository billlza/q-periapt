#!/usr/bin/env python3
"""Exercise the public enrollment client against the real native test issuer.

Fixture clocks and independently selected test authority are explicit. This is
not another live account authorization or a production network acceptance test.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import copy
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time


def exercise(args, label):
    from fixture_inputs import load, load_witness_pin
    from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
    from qperiapt_continuity_reference.pending_recovery_protocol import Proposal
    from qperiapt_continuity_reference.registration_inputs import Inputs
    from qperiapt_continuity_reference.registration_protocol import Intent
    from qperiapt_continuity_reference.wire import ldh, require
    from qperiapt_continuity_reference.witness import TcpTransport
    from run import Counterpart
    from traffic_checks import application
    from witness_fixture import Bridge

    out = args.output / label; out.mkdir(); native_out = out / 'native'; native_out.mkdir()
    private = Path(tempfile.mkdtemp(prefix='qperiapt-client-session-')).resolve()
    (out / 'private-fixture-path').write_text(str(private) + '\n')
    client_path, session_path = private / 'client', private / 'session'
    client_path.mkdir(mode=0o700); session_path.mkdir(mode=0o700)
    identity, key = os.urandom(32), os.urandom(32)
    with os.fdopen(os.open(private / 'host-key-and-id', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
        file.write(key + identity); file.flush(); os.fsync(file.fileno())
    inspection_kind = (args.root_child_inspection or '').split('-')[0]
    native = Counterpart(args.native, native_out, registration=True,
                         local_lifecycle=inspection_kind not in ('roster', 'policy'),
                         required_witness=label == 'witness',
                         account_members=3 if inspection_kind in ('roster', 'policy') else None,
                         enrolled_peer=inspection_kind in ('roster', 'policy'),
                         policy_lifecycle=inspection_kind == 'policy')
    client = None; bridge = None; registry = None; root_bound = False; refusals = []; observed = []
    encode = lambda value: json.dumps(value, separators=(',', ':')).encode()
    b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b'=').decode()

    def refuse(name, call, reason):
        try: call()
        except (ValueError, OSError) as error:
            require(reason in str(error), 'wrong client refusal: ' + name + ': ' + str(error))
            refusals.append({'case': name, 'error': str(error), 'type': type(error).__name__})
        else: raise ValueError('missing client refusal: ' + name)

    def call(name, command, wire=b'', expected=None):
        return (native.command(name, command, wire, 1, expected) if bridge is None
                else bridge.call(name, command, wire, expected))

    def transport(): return None if bridge is None else TcpTransport(bridge.address)
    def reopen(observer=None): return EnrollmentClient.open(client_path, identity, key, observer=observer,
                                                           account_authority=registry if root_bound else None)

    try:
        deadline = time.monotonic() + 30
        size = int.from_bytes(native.read(4, deadline), 'big')
        require(size == 2058, 'native intent frame')
        prelude = native.read(size, deadline); require(prelude[0] == 1, 'native intent status')
        intent = Intent.from_trusted(prelude[1:])
        authority = {'schema':'qperiapt-host-authority/1', 'application':list(os.urandom(32)),
                     'root_revision':1, 'root':b64(intent.root.raw), 'family':list(intent.family)}
        invitation = {'operation':list(os.urandom(32)), 'request_id':list(os.urandom(32)),
                      'application':authority['application'], 'root_revision':1, 'root':authority['root'],
                      'family':authority['family'], 'device':list(intent.device), 'generation':intent.generation,
                      'valid_from':intent.validity.start, 'valid_until':intent.validity.end,
                      'deadline':intent.validity.end, 'predecessor':None}
        client = EnrollmentClient.begin(client_path, identity, key, encode(authority), encode(invitation), 150)
        proof = client.request(150); original_identity = client.status()
        require(native.transfer(proof) == b'\1ready', 'native original proof issuance')
        public = native_out / 'public'
        if label == 'witness': bridge = Bridge(native, out)
        witness = load_witness_pin(public) if bridge is not None else None
        pins, materials, context = load(public, 150, witness_pin=witness)
        head = {'version':pins.initiator.roster_version, 'digest':list(pins.initiator.roster_digest)}
        issued = {'operation':invitation['operation'], 'root_revision':1,
                  'certificate':b64(materials.initiator_credential), 'roster':b64(materials.initiator_roster), 'checkpoint':head}
        current = {'revision':1, 'account':list(pins.initiator.account), 'public_key':authority['root'],
                   'family':authority['family'], 'suspended':False,
                   'roster':{'checkpoint':head, 'bytes':b64(materials.initiator_roster)}}
        policy_pins = {'schema':'qperiapt-policy-pins/1', 'sdk_root':b64(pins.sdk_root), 'sdk_state':b64(pins.sdk_state),
                       'policy_root':b64(pins.policy_root.raw), 'policy_version':pins.policy_version,
                       'policy_digest':list(pins.policy_digest),
                       'witness':None if witness is None else {'identity':list(witness.identity), 'key':b64(witness.key.raw)}}
        policy_materials = {'schema':'qperiapt-policy-materials/1', 'sdk_document':b64(materials.sdk_document),
                            'sdk_signature':b64(materials.sdk_signature), 'policy':b64(materials.policy)}
        journal = client.accept(encode(invitation), encode(issued), encode(current),
                                encode(policy_pins), encode(policy_materials), 150)
        inputs = Inputs(pins, materials, witness)
        if args.account_root_binding or args.account_root_adoption or args.root_child_inspection:
            from qperiapt_continuity_reference.account_authority import AccountAuthority
            from qperiapt_continuity_reference.wire import SigningKey
            from qperiapt_continuity_reference.witness import Pin
            registry_path=private/'account-registry';registry_path.mkdir(mode=0o700)
            registry_key,registry_identity=os.urandom(32),os.urandom(32)
            registry_pin=witness if witness is not None else Pin(os.urandom(32),SigningKey().public())
            with os.fdopen(os.open(private/'registry-key-and-id',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as file:
                file.write(registry_key+registry_identity);file.flush();os.fsync(file.fileno())
            registry=AccountAuthority.provision(registry_path,registry_key,registry_identity,intent.family,registry_pin)
            if args.account_root_binding or (args.root_child_inspection and not args.root_child_inspection.startswith('partial')):
                client.bind_account_root(registry); root_bound = True
        # A configuration directory is not a session path, even if it is private.
        refuse('configuration-directory-alias', lambda: client.prepare(client_path / 'configuration', inputs, 150),
               'directories must be separate')
        client = reopen()
        genesis = client.prepare(session_path, inputs, 150)
        require(client.prepare(session_path, inputs, 150) == genesis, 'original child preparation changed')
        if root_bound:
            from qperiapt_continuity_reference.durable import Session
            from qperiapt_continuity_reference.witness_session import WitnessSession
            from qperiapt_continuity_reference.registered_owner import _Signer
            from qperiapt_continuity_reference.registration_session import selected
            from qperiapt_continuity_reference.witness import Client
            _,retained=client._registration._image()
            child_scope,child_key=selected(client._registration,retained,context)
            if witness is None:
                unguarded=lambda:Session.open(session_path,child_scope,child_key,context)
            else:
                raw_client=Client(witness,context.witness.subject(journal),_Signer(client._registration),transport())
                unguarded=lambda:WitnessSession.open(session_path,child_scope,child_key,context,client=raw_client)
            refuse('raw-child-missing-root-lease',unguarded,'original root registry lease required')
        refuse('prepared-child-refuses-roster-retarget',
               lambda: client.refresh_roster(encode(current), encode(policy_pins), encode(policy_materials), 150),
               'child was already prepared')
        client = reopen()
        if bridge is not None: call('enroll-original-child', 30, genesis, b'enrolled')
        with client.session(150, transport=transport()) as child:
            initial = child.initial(now=150); reply = call('reply', 4, initial)
            final = child.finish(reply, now=150); session = call('complete', 5, final)
            require(child.activate(now=170) == session, 'client/native session differs')
            call('native-activate', 6, expected=session)
            message_id = child.next_id(now=170)
            ciphertext = child.send(message_id, b'client-owned traffic', b'client', now=170)
            call('receive', 7, application(b'client', ciphertext), b'client-owned traffic')
            offer = child.prepare_rekey_offer(now=170); response = call('rekey-response', 14, offer)
            final = child.accept_rekey_response(response, now=170); receipt = call('rekey-receipt', 15, final)
            require(child.accept_rekey_receipt(receipt, now=170) == 1, 'owned client rekey')
        if args.root_child_inspection:
            from root_child_fixture import exercise as inspect_original
            require(bridge is not None, 'root inspection fixture requires witnessed child')
            result = inspect_original(client, registry, mode=args.root_child_inspection, private=private,
                retirement=args.root_retirement is not None,
                retirement_cut=args.root_retirement_cut,
                successor=args.root_successor,
                successor_cut=args.root_successor_cut,
                client_path=client_path, identity=identity, key=key, session_path=session_path, pins=pins, materials=materials,
                context=context, transport=transport, bridge=bridge, refuse=refuse, public=public)
            result.update(profile=label, native_commands=len(native.commands), witness_requests=len(bridge.records), refusals=refusals)
            (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n'); return result
        if args.account_root_adoption:
            from root_adoption_client_fixture import Inputs as MigrationInputs, migrate
            migration = MigrationInputs(client_path, identity, key, registry_path, registry_key,
                                        registry_identity, intent.family, registry_pin)
            client, registry = migrate(client, registry, migration, transport, refuse, bridge, out,
                                        args.adoption_cut, args.adoption_expiry, call)
            root_bound = True
            if args.adoption_expiry is not None:
                from root_adoption_client_fixture import resume_expired
                operation, grant, target = resume_expired(client, transport, refuse, public, message_id, bridge is not None)
                client = reopen()
                with client.credential_renewal(operation, 210, transport=transport()) as renewal:
                    if bridge is None:
                        renewal.stage(grant, target, now=210)
                        require(renewal.commit(now=210)['status'] == 'Committed', 'local renewal after parent binding')
                    else:
                        proposal = renewal.prepare(grant, target, now=210)
                        call('approve-renewal-after-parent-binding', 34, proposal, b'Prepared')
                        require(renewal.commit(now=210) == 'Applied', 'renewal after parent binding')
                with client.session(210, transport=transport()) as child:
                    require(child.resume(message_id, now=210) == ciphertext, 'parent expiry recovery changed original ciphertext')
                    renewed_id = child.next_id(now=210)
                    renewed_wire = child.send(renewed_id, b'after original parent adoption', b'client', now=210)
                    call('receive-after-parent-adoption', 7, application(b'client', renewed_wire), b'after original parent adoption')
                require(client.status()['journal'] == journal, 'parent expiry recovery replaced original journal')
                result = {'completed':True, 'profile':label, 'adoption_loss':args.adoption_expiry,
                          'native_commands':len(native.commands), 'witness_requests':0 if bridge is None else len(bridge.records),
                          'refusal_cases':[row['case'] for row in refusals],
                          'scope':'Original parent+child binding, exact pending recovery at fixture expiry210, same-key G, original ciphertext and new traffic. No root retirement or elapsed expiry claim.'}
                (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
                return result
        client.close(); client = reopen()
        with client.session(170, transport=transport()) as child:
            require(child.resume(message_id, now=170) == ciphertext, 'original ciphertext after client reopen')
        stale = client.session(170, transport=transport()); retained = stale.next_id
        client.close(); client = reopen()
        refuse('closed-client-revokes-child', lambda: retained(now=170), 'closed registration')
        with client.session(170, transport=transport()) as child: child.next_id(now=170)
        client.close()

        def close_at_commit(stage):
            if stage == 'client-device:protocol:send-committed':
                observed.append(stage)
                refuse('nested-client-operation', client.status, 'in progress')
                client.close()
        client = reopen(close_at_commit)
        with client.session(170, transport=transport()) as child:
            callback_id = child.next_id(now=170)
            refuse('callback-close-withholds-result', lambda: child.send(callback_id, b'original callback', b'client', now=170), 'closed')
        require(observed == ['client-device:protocol:send-committed'], 'actual commit callback not reached')
        client = reopen()
        with client.session(170, transport=transport()) as child:
            callback_wire = child.resume(callback_id, now=170)
            call('receive-original-callback', 7, application(b'client', callback_wire), b'original callback')
        if registry is not None:
            client.close();root_observed=[]
            def close_registry(stage):
                if stage=='client-device:protocol:send-committed':
                    root_observed.append(stage);registry.close()
            client=reopen(close_registry)
            with client.session(170,transport=transport()) as child:
                root_callback_id=child.next_id(now=170)
                refuse('root-close-withholds-committed-result',
                       lambda:child.send(root_callback_id,b'original root callback',b'client',now=170),
                       'closed account authority owner')
            require(root_observed==['client-device:protocol:send-committed'],'root close did not reach actual commit')
            registry=AccountAuthority.open(registry_path,registry_key,registry_identity,intent.family,registry_pin)
            client=reopen()
            with client.session(170,transport=transport()) as child:
                root_callback_wire=child.resume(root_callback_id,now=170)
                call('receive-original-root-callback',7,application(b'client',root_callback_wire),b'original root callback')
        child = client.session(170, transport=transport())
        # Only this private fixture's outer directory mode is faulted. Child
        # journal inode/bytes stay untouched; the failed owner must be revoked.
        client_path.chmod(0o750)
        try: refuse('outer-directory-admission', child.status, 'mode 0700')
        finally: client_path.chmod(0o700)
        replacement = reopen(); replacement.close()  # all failed-owner leases released
        refuse('repaired-path-does-not-revive-child', child.status, 'closed registration')
        client = reopen()
        pending_id = None
        if bridge is not None:
            with client.session(170, transport=transport()) as child:
                pending_id = child.next_id(now=170); bridge.arm('before', 2)
                refuse('original-write-result-unknown', lambda: child.send(pending_id, b'pending original', b'client', now=170), 'truncated witness reply')
            client = reopen()
            call('witness-expiry', 33, (210).to_bytes(8, 'big'), b'witness clock set')
            with client.pending_write_recovery(210, transport=transport()) as recovery:
                request = recovery.request(); proposal = Proposal.decode(request.proposal)
                expected = ldh(b'Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1', request.proposal) + (4).to_bytes(8, 'big') * 2
                call('approve-exact-pending', 36, request.proposal + request.metadata, expected)
                call('complete-exact-pending', 37, request.signed_request, proposal.target.wire())
                require(recovery.confirm(request.proposal, request.metadata) == proposal.target.wire(), 'original pending confirmation')
        operation = (public / 'local-renewal-1-operation').read_bytes()
        grant = (public / 'local-renewal-1').read_bytes(); target = (public / 'pin-local-renewal-1-target').read_bytes()
        with client.credential_renewal(operation, 210, transport=transport()) as renewal:
            if bridge is None:
                renewal.stage(grant, target, now=210)
                require(renewal.commit(now=210)['status'] == 'Committed', 'local client renewal')
            else:
                proposal = renewal.prepare(grant, target, now=210)
                call('approve-joint-renewal', 34, proposal, b'Prepared')
                require(renewal.commit(now=210) == 'Applied', 'joint client renewal')
        with client.session(210, transport=transport()) as child:
            # Resolve the one retained reservation before requesting a different
            # historical send; ordinary recovery cannot skip that operation.
            if pending_id is not None:
                pending = child.resume(pending_id, now=210)
                call('receive-recovered-pending', 7, application(b'client', pending), b'pending original')
            require(child.resume(message_id, now=210) == ciphertext, 'renewal changed original message')
            require(child.resume(callback_id, now=210) == callback_wire, 'renewal changed callback message')
            if registry is not None:
                require(child.resume(root_callback_id,now=210)==root_callback_wire,'renewal changed root callback message')
        final = client.status()
        require(final['phase'] == 'Active' and final['journal'] == journal
                and final['signing_id'] == original_identity['signing_id'], 'original client lineage')
        result = {'completed':True, 'profile':label, 'native_commands':native.commands,
                  'refusals':refusals, 'witness_requests':0 if bridge is None else len(bridge.records),
                  'journal':journal.hex(), 'session':session.hex(), 'request_sha256':hashlib.sha256(proof).hexdigest(),
                  'original_ciphertext_sha256':hashlib.sha256(ciphertext).hexdigest(),
                  'callback_ciphertext_sha256':hashlib.sha256(callback_wire).hexdigest(),
                  'scope':'Public EnrollmentClient session/controlled signer/rekey/renewal and witnessed exact recovery. Real native issuer and protocol traffic with explicit fixture clocks150/170/210. No live-account, real-time expiry, network deployment or full release admission.'}
        if registry is not None:
            result['account_root_binding']={'binding':client.bind_account_root(registry).wire().hex(),
                'unknown_callback_ciphertext_sha256':hashlib.sha256(root_callback_wire).hexdigest(),
                'scope':'Original registry guard, client/registration binding, guarded session headers and root-owner cancellation/reopen. No root preparation/retirement or successor activation claim.'}
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        return {k:result[k] for k in ('completed','profile','witness_requests')} | {
            'native_commands':len(native.commands), 'refusal_cases':[row['case'] for row in refusals]}
    finally:
        if client is not None: client.close()
        if registry is not None: registry.close()
        if bridge is not None:
            (out / 'WITNESS.json').write_text(json.dumps(bridge.records, indent=2) + '\n'); bridge.close()
        (out / 'NATIVE.json').write_text(json.dumps(native.commands, indent=2) + '\n')
        (out / 'REFUSALS.json').write_text(json.dumps(refusals, indent=2) + '\n')
        native.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('implementation-root', 'provider-root', 'native', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    root_mode = parser.add_mutually_exclusive_group()
    root_mode.add_argument('--account-root-binding',action='store_true')
    root_mode.add_argument('--account-root-adoption',action='store_true')
    root_mode.add_argument('--root-adoption-cuts',action='store_true')
    root_mode.add_argument('--root-adoption-expiry',action='store_true')
    root_mode.add_argument('--root-retirement', choices=('steady','ordinary-before','ordinary-after',
        'credential','credential-terminal','credential-closed','partial','partial-bound','partial-intent'))
    root_mode.add_argument('--root-retirement-cuts',action='store_true')
    root_mode.add_argument('--root-successor',choices=('steady','credential','before','after','parent','ready',
                                                     'peer','peer-credential','peer-before','peer-after'))
    root_mode.add_argument('--root-successor-cuts',nargs='?',const='all',
                          choices=('all','configuration','child','registration','ready','activation'))
    root_mode.add_argument('--root-child-inspection', choices=('steady', 'ordinary-before', 'ordinary-after',
                                                             'credential', 'credential-terminal', 'credential-closed',
                                                             'roster', 'roster-terminal', 'roster-closed',
                                                             'policy', 'policy-terminal', 'policy-closed',
                                                             'partial', 'partial-bound', 'partial-intent',
                                                             'tamper-head', 'tamper-binding', 'tamper-intent'))
    args = parser.parse_args(); args.implementation_root = args.implementation_root.resolve(strict=True)
    if args.root_retirement is not None: args.root_child_inspection=args.root_retirement
    if args.root_successor is not None:
        args.root_retirement=args.root_child_inspection='credential' if args.root_successor in ('credential','peer-credential') else 'steady'
    args.root_retirement_cut=None;args.root_successor_cut=None
    if args.root_retirement_cuts:args.root_retirement=args.root_child_inspection='steady'
    if args.root_successor_cuts:
        args.root_retirement=args.root_child_inspection='steady';args.root_successor='peer'
    sys.path.insert(0, str(args.implementation_root))
    from qperiapt_continuity_reference.provider import load_provider
    provider, _ = load_provider(args.provider_root)
    from qperiapt_continuity_reference import enrollment_client
    assert Path(enrollment_client.__file__).resolve().is_relative_to(args.implementation_root)
    helper_root=Path(__file__).resolve().parent
    # Fixture helpers are source test tools; the package was already selected
    # and imported from implementation-root. Do not put the source package first.
    sys.path.append(str(helper_root))
    sources={str(path):hashlib.sha256(path.read_bytes()).hexdigest()
             for path in (args.implementation_root/'qperiapt_continuity_reference').glob('*.py')}
    sources.update({str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in helper_root.glob('*.py')})
    native_hash = hashlib.sha256(args.native.read_bytes()).hexdigest()
    args.output.mkdir()
    args.adoption_cut = None
    args.adoption_expiry = None
    if args.root_successor_cuts:
        from root_successor_cuts import CUTS
        selected_cuts=[cut for cut in CUTS if args.root_successor_cuts in ('all',cut[0])]
        profiles=[]
        for index,cut in enumerate(selected_cuts):
            selected=copy.copy(args);selected.root_successor_cut=cut
            selected.output=args.output/(cut[0]+'-'+str(index));selected.output.mkdir()
            profiles.append(exercise(selected,'witness'))
    elif args.root_retirement_cuts:
        from root_retirement_cuts import CUTS
        profiles=[]
        for index,cut in enumerate(CUTS):
            selected=copy.copy(args);selected.root_retirement_cut=cut
            selected.output=args.output/str(index);selected.output.mkdir()
            profiles.append(exercise(selected,'witness'))
    elif args.root_adoption_cuts:
        from root_adoption_client_fixture import PHASES, STAGES
        profiles = []
        for phase in PHASES:
            for index, stage in enumerate(STAGES):
                selected = copy.copy(args); selected.account_root_adoption = True
                selected.adoption_cut = (phase, stage); selected.output = args.output / (phase + '-' + str(index))
                selected.output.mkdir(); profiles.append(exercise(selected, 'local') | {'phase': phase, 'cut': stage})
    elif args.root_adoption_expiry:
        profiles = []
        for loss in ('local', 'before', 'after'):
            selected = copy.copy(args); selected.account_root_adoption = True; selected.adoption_expiry = loss
            selected.output = args.output / loss; selected.output.mkdir()
            profiles.append(exercise(selected, 'local' if loss == 'local' else 'witness'))
    elif args.root_child_inspection:
        profiles = [exercise(args, 'witness')]
    else:
        profiles = [exercise(args, label) for label in ('local','witness')]
    result = {'completed':True, 'provider':provider.__version__,
              'implementation':str(Path(enrollment_client.__file__).resolve()),
              'native_sha256':native_hash,
              'profiles':profiles}
    assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected for path,expected in sources.items())
    assert hashlib.sha256(args.native.read_bytes()).hexdigest()==result['native_sha256']
    loaded={name:str(Path(module.__file__).resolve()) for name,module in sys.modules.items()
            if name=='qperiapt_continuity_reference' or name.startswith('qperiapt_continuity_reference.')}
    assert loaded and all(Path(path).is_relative_to(args.implementation_root) for path in loaded.values())
    result['source_files']=sources
    result['loaded_product_modules']=loaded
    (args.output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__': main()
