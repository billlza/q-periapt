#!/usr/bin/env python3
"""Adopt original sessions against the native peer and authenticated witness.

Explicit test clocks advance 150 -> 170 -> 210, never backdate. The witnessed
cases lose the exact binding reply before/after native commit, then use the
existing purpose-26 recovery and real same-key renewal. No root retirement or
parent-client migration completion is claimed by this child-journal test.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile


def exercise(args, label):
    from fixture_inputs import load, load_witness_pin
    from run import Counterpart
    from signing_fixture import write
    from traffic_checks import application
    from witness_fixture import Bridge
    from qperiapt_continuity_reference.account_authority import AccountAuthority
    from qperiapt_continuity_reference.durable import Session, owner_binding
    from qperiapt_continuity_reference.journal import Scope
    from qperiapt_continuity_reference.local_credential import LocalCredentialRenewal
    from qperiapt_continuity_reference.local_renewal import LocalRenewal
    from qperiapt_continuity_reference.pending_recovery import PendingWriteRecovery
    from qperiapt_continuity_reference.pending_recovery_protocol import Proposal
    from qperiapt_continuity_reference.registration_inputs import Inputs
    from qperiapt_continuity_reference.root_adoption_journal import adopt
    from qperiapt_continuity_reference.wire import SigningKey, ldh, require
    from qperiapt_continuity_reference.witness import Client, Pin, TcpTransport
    from qperiapt_continuity_reference.witness_session import WitnessSession

    out = args.output / label; out.mkdir(); (out / 'native').mkdir()
    private = Path(tempfile.mkdtemp(prefix='qperiapt-root-adoption-')).resolve()
    (out / 'private-fixture-path').write_text(str(private) + '\n')
    native = Counterpart(args.native, out / 'native', local_lifecycle=True, required_witness=label != 'local')
    bridge = None; registry = None; owner = None; maintenance = None; refusals = []
    def refuse(name, action, reason):
        try: action()
        except (ValueError, OSError) as error:
            require(reason in str(error), 'wrong refusal: ' + name + ': ' + str(error))
            refusals.append({'case': name, 'type': type(error).__name__, 'error': str(error)})
        else: raise ValueError('missing refusal: ' + name)
    def call(name, command, wire=b'', expected=None):
        return (native.command(name, command, wire, 1, expected) if bridge is None
                else bridge.call(name, command, wire, expected))
    try:
        signer = SigningKey(); write(private / 'signer', signer)
        require(native.transfer(signer.public().raw) == b'\1ready', 'native ready')
        public = out / 'native/public'
        pin = load_witness_pin(public) if label != 'local' else None
        pins, materials, context = load(public, 150, witness_pin=pin)
        if pin is not None: bridge = Bridge(native, out)
        scope = Scope(os.urandom(32), owner_binding(context), context.digest)
        key, registry_key, registry_id, application_id = (os.urandom(32) for _ in range(4))
        with os.fdopen(os.open(private / 'host-keys', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
            file.write(key + scope.wire() + registry_key + registry_id + application_id)
            file.flush(); os.fsync(file.fileno())
        path = private / 'session'; path.mkdir(mode=0o700)
        registry_path = private / 'registry'; registry_path.mkdir(mode=0o700)
        registry_pin = pin if pin is not None else Pin(os.urandom(32), SigningKey().public())
        registry = AccountAuthority.provision(registry_path, registry_key, registry_id, context.family, registry_pin)
        checkpoint = registry.associate(application_id, pins.initiator, materials.initiator_credential, materials.initiator_roster)
        lease = registry.admit(checkpoint)
        def client():
            return None if pin is None else Client(pin, context.witness.subject(scope.identity), signer, TcpTransport(bridge.address))
        def open_owner(bound, observer=None):
            arguments = {'observer': observer, 'root_lease': lease if bound else None}
            return (Session.open(path, scope, key, context, **arguments) if pin is None else
                    WitnessSession.open(path, scope, key, context, client=client(), **arguments))
        def adoption(now):
            return adopt(path, scope, key, context, now, root_lease=lease, client=client())
        if pin is None:
            owner = Session.create(path, scope, key, context, signer, 150)
        else:
            genesis = WitnessSession.provision(path, scope, key, context, signer, 150)
            call('enroll-original', 30, genesis.wire(), b'enrolled'); owner = open_owner(False)
        initial = owner.initial(now=150); reply = call('reply', 4, initial)
        final = owner.finish(reply, now=150); session = call('complete', 5, final)
        require(owner.activate(now=170) == session, 'original session differs')
        call('native-activate', 6, expected=session)
        message = owner.next_id(now=170)
        ciphertext = owner.send(message, b'original unacknowledged message', b'adoption', now=170)
        call('receive-original', 7, application(b'adoption', ciphertext), b'original unacknowledged message')
        offer = owner.prepare_rekey_offer(signer, now=170)
        original = owner._journal.read(); owner.close(); owner = None
        before = (path / 'head').read_bytes()
        refuse('normal-open-cannot-start-adoption', lambda: open_owner(True), 'missing original root binding intent')
        require((path / 'head').read_bytes() == before and not (path / 'intent').exists(), 'normal open changed original head')
        if pin is None:
            require(adoption(170) == lease.binding, 'local adoption binding')
        else:
            bridge.arm('before' if label == 'witness-before' else 'after', 2)
            refuse('binding-result-unknown', lambda: adoption(170), 'truncated witness reply')
            retained = (path / 'intent').read_bytes(); head = (path / 'head').read_bytes()
            requests = len(bridge.records)
            refuse('pending-bound-target-missing-registry', lambda: open_owner(False), 'original root registry lease required')
            require(len(bridge.records) == requests and (path / 'head').read_bytes() == head
                    and (path / 'intent').read_bytes() == retained, 'missing registry dispatched or changed original pending state')
            call('advance-fixture-clock-to-expiry', 33, (210).to_bytes(8, 'big'), b'witness clock set')
            # The existing recovery owner may inspect the exact unbound source
            # and bound target. It issues no ordinary Advance during inspection.
            requests = len(bridge.records)
            maintenance = PendingWriteRecovery.open(path, scope, key, context, client=client(), root_lease=lease)
            request = maintenance.request(); proposal = Proposal.decode(request.proposal)
            require(len(bridge.records) == requests and (path / 'intent').read_bytes() == retained,
                    'pending recovery inspection dispatched or changed original intent')
            expected = ldh(b'Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1', request.proposal) + (4).to_bytes(8, 'big') * 2
            call('approve-original-binding-recovery', 36, request.proposal + request.metadata, expected)
            call('complete-original-binding-recovery', 37, request.signed_request, proposal.target.wire())
            require(maintenance.confirm(request.proposal, request.metadata) == proposal.target.wire(), 'exact binding confirmation')
            maintenance.close(); maintenance = None
            require(not (path / 'intent').exists(), 'binding intent remains after exact confirmation')
            refuse('expired-adoption-is-not-current-permission', lambda: adoption(210), 'expired or premature authority')
        owner = open_owner(True); bound = owner._journal.read()
        require(bound.payload == original.payload and bound.revision == original.revision + 1, 'binding changed business state or revision')
        owner.close(); owner = None
        # Renew the original key under the selected root; no journal recreation.
        operation = (public / 'local-renewal-1-operation').read_bytes()
        grant = (public / 'local-renewal-1').read_bytes(); target = (public / 'pin-local-renewal-1-target').read_bytes()
        arguments = {'inputs': Inputs(pins, materials, pin), 'root_lease': lease}
        if pin is None:
            maintenance = LocalCredentialRenewal.open(path, scope, key, context, operation, **arguments)
            maintenance.stage(grant, target, now=210)
            require(maintenance.commit(now=210)['status'] == 'Committed', 'local renewal')
        else:
            maintenance = LocalRenewal.open(path, scope, key, context, operation, client=client(), **arguments)
            proposal = maintenance.prepare(grant, target, now=210)
            call('approve-renewal-after-binding', 34, proposal, b'Prepared')
            require(maintenance.commit(now=210) == 'Applied', 'witnessed renewal')
        maintenance.close(); maintenance = None
        require(adoption(210) == lease.binding, 'current same-binding retry')
        owner = open_owner(True)
        require(owner.resume(message, now=210) == ciphertext, 'adoption or renewal changed original ciphertext')
        require(owner.prepare_rekey_offer(signer, now=210) == offer, 'adoption changed retained rekey contribution')
        reply = call('rekey-response', 14, offer)
        final = owner.accept_rekey_response(reply, signer, now=210); receipt = call('rekey-receipt', 15, final)
        require(owner.accept_rekey_receipt(receipt, now=210) == 1, 'original pending rekey after adoption')
        message2 = owner.next_id(now=210); ciphertext2 = owner.send(message2, b'after original adoption', b'adoption', now=210)
        call('receive-after-binding', 7, application(b'adoption', ciphertext2), b'after original adoption')
        result = {'completed': True, 'profile': label, 'same_payload': True, 'adoption_revision_increment': 1,
                  'retained_ciphertext': True, 'retained_rekey_offer': True, 'renewal': True,
                  'native_commands': len(native.commands), 'witness_requests': 0 if bridge is None else len(bridge.records),
                  'refusals': refusals, 'session': session.hex()}
        (out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        if maintenance is not None: maintenance.close()
        if owner is not None: owner.close()
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
    args = parser.parse_args()
    args.implementation_root = args.implementation_root.resolve(strict=True)
    args.native = args.native.resolve(strict=True); args.output = args.output.resolve()
    sys.path.insert(0, str(args.implementation_root))
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    sys.path.append(str(Path(__file__).resolve().parent))
    sources = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in (args.implementation_root / 'qperiapt_continuity_reference').glob('*.py')}
    sources.update({str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in Path(__file__).resolve().parent.glob('*.py')})
    native = hashlib.sha256(args.native.read_bytes()).hexdigest(); args.output.mkdir()
    report = {'completed': False, 'source_files': sources, 'native_sha256': native,
              'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()},
              'scope': 'Child-journal binding, preserved traffic/rekey, witnessed unknown commit and G renewal. No parent migration or root retirement/activation admission.'}
    (args.output / 'INPUTS.json').write_text(json.dumps(report, indent=2) + '\n')
    report['cases'] = [exercise(args, label) for label in ('local', 'witness-before', 'witness-after')]
    require(all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == sha for path, sha in sources.items())
            and hashlib.sha256(args.native.read_bytes()).hexdigest() == native, 'adoption test inputs changed')
    loaded = {name: str(Path(module.__file__).resolve()) for name, module in tuple(sys.modules.items())
              if name.startswith('qperiapt_continuity_reference.') and getattr(module, '__file__', None)}
    require(loaded and all(Path(path).is_relative_to(args.implementation_root) for path in loaded.values()), 'unselected product modules')
    report['loaded_product_modules'] = loaded; report['completed'] = True
    (args.output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'completed': True, 'cases': len(report['cases']), 'output': str(args.output)}))


if __name__ == '__main__': main()
