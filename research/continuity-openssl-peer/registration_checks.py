#!/usr/bin/env python3
"""Original protected registration through interruption, traffic and renewal."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import sys


def exercise(args, label):
    from registration_fixture import Fixture
    from registration_controls import before_accept, before_prepare, lifetime, callback_close, missing_active
    from peer.pending_recovery_protocol import Proposal
    from peer.wire import require, ldh
    from traffic_checks import application
    f = Fixture(args, label)
    try:
        before_accept(f)
        f.worker('acceptance-result-lost', 'registration_accept', now=150, cut='registration:acceptance-committed')
        accepted = f.worker('accepted-original-status', 'registration_status', now=150)
        journal = f.value('acceptance-original-retry', 'registration_accept', now=150)
        require(accepted['phase'] == 'Accepted' and accepted['journal'] == journal.hex(), 'one original future journal')
        before_prepare(f)
        prepare_args = (str(f.session_path).encode(),)
        f.worker('child-intent-result-lost', 'registration_prepare', prepare_args, now=150, cut='registration:child-intent-committed')
        require(not (f.session_path / 'head').exists() and not (f.session_path / 'intent').exists(), 'child was created before its original intent')
        f.worker('child-original-intent-cut', 'registration_prepare', prepare_args, now=150, cut='session-store:committed:intent')
        sealed = (f.session_path / 'intent').read_bytes()
        genesis = f.value('original-child-prepared', 'registration_prepare', prepare_args, now=150)
        require(f.value('original-child-preparation-retry', 'registration_prepare', prepare_args, now=150) == genesis,
                'original child preparation changed')
        require(not (f.session_path / 'intent').exists(), 'original child intent not reconciled')
        if f.bridge:
            f.worker('unenrolled-child-not-active', 'initial', now=150, refusal='truncated witness reply')
            require(f.worker('unenrolled-registration-status', 'registration_status', now=150)['phase'] == 'Prepared',
                    'unenrolled witness granted active registration')
            f.call('independent-original-enrollment', 30, genesis, b'enrolled')
        f.worker('activation-result-lost', 'initial', now=150, cut='registration:activation-committed')
        require(f.worker('original-active-status', 'registration_status', now=150)['journal'] == journal.hex(), 'active original journal')
        initial = f.value('initial', 'initial', now=150); reply = f.call('reply', 4, initial)
        f.worker('confirmation-result-lost', 'finish', (reply,), now=150, cut='protocol:final-committed')
        final = f.value('original-final', 'finish', (reply,), now=150); session = f.call('complete', 5, final)
        require(f.value('activate', 'activate', now=170) == session, 'registered original session')
        f.call('native-activate', 6, expected=session)
        original_id = f.value('original-id', 'next_id', now=170)
        f.worker('reserved-send-result-lost', 'send', (original_id, b'original registered message', b'registered'),
                 now=170, cut='protocol:send-reserved')
        original = f.value('original-reserved-resume', 'resume', (original_id,), now=170)
        f.call('native-original-receive', 7, application(b'registered', original), b'original registered message')
        # The public test issuer directory is unavailable to this fresh worker.
        # Its registration-owned original inputs must suffice for reopening.
        hidden = f.out / 'original-public-inputs-held'; f.public.rename(hidden)
        try:
            require(f.value('reopen-without-issuer-files', 'resume', (original_id,), now=170) == original, 'registration depended on external fixture files')
        finally: hidden.rename(f.public)
        lifetime(f)
        callback_id = f.value('callback-message-id', 'next_id', now=170)
        callback_close(f, callback_id)
        callback_wire = f.value('closed-callback-original-recovered', 'resume', (callback_id,), now=170)
        f.call('receive-closed-callback-original', 7, application(b'registered', callback_wire), b'closed callback original')
        offer = f.value('owned-rekey-offer', 'prepare_rekey_offer', now=170)
        response = f.call('owned-rekey-response', 14, offer)
        final_rekey = f.value('owned-rekey-final', 'accept_rekey_response', (response,), now=170)
        receipt = f.call('owned-rekey-receipt', 15, final_rekey)
        require(f.worker('owned-rekey-complete', 'accept_rekey_receipt', (receipt,), now=170) == 1, 'owned identity-signed rekey')
        pending_id = None
        if f.bridge:
            pending_id = f.value('before-expiry-pending-id', 'next_id', now=170)
            f.bridge.arm('before', 2)
            f.worker('ordinary-write-lost', 'send', (pending_id, b'original expired reservation', b'registered'), now=170,
                     refusal='truncated witness reply')
            original_intent = (f.session_path / 'intent').read_bytes()
            f.call('actual-witness-expiry', 33, (210).to_bytes(8, 'big'), b'witness clock set')
            request = f.pending_request('registered-pending-request', 210); p = Proposal.decode(request[0])
            require(f.context.initiator.open(request[2], 26, 393) == request[0], 'original registration signed recovery request')
            f.call('unapproved-pending-request-refused', 37, request[2], status=2)
            expected = ldh(b'Q-PERIAPT-CONTINUITY-PENDING-WRITE-RECOVERY/v1', request[0]) + (4).to_bytes(8, 'big') * 2
            f.call('independent-exact-write-approval', 36, request[0] + request[1], expected)
            f.call('independent-exact-write-completion', 37, request[2], p.target.wire())
            args_confirm = f.confirmation_arguments('registered-pending-request')
            f.worker('registered-confirmation-result-lost', 'pending_recovery_confirm_files', args_confirm, now=210,
                     cut='pending-recovery:confirmed')
            require(f.value('registered-confirmation-retry', 'pending_recovery_confirm_files', args_confirm, now=210) == p.target.wire(), 'original registered pending completion')
            require((f.session_path / 'head').read_bytes() == original_intent[52:-32] and not (f.session_path / 'intent').exists(), 'registered recovery resealed original target')
        f.worker('expired-registration-is-not-permission', 'next_id', now=210,
                 refusal='witness current authority denied' if f.bridge else 'expired or premature authority')
        public = f.public
        operation = (public / 'local-renewal-1-operation').read_bytes()
        renewal_args = (operation, (public / 'local-renewal-1').read_bytes(), (public / 'pin-local-renewal-1-target').read_bytes())
        action = 'credential_prepare' if f.bridge else 'credential_stage'
        f.worker('renewal-original-preparation-cut', action, renewal_args, now=210,
                 cut='renewal:prepared' if f.bridge else 'local-credential:staged')
        prepared = f.worker('renewal-original-preparation-retry', action, renewal_args, now=210)
        if f.bridge: f.call('independent-credential-approval', 34, bytes.fromhex(prepared), b'Prepared')
        f.worker('renewal-result-lost', 'credential_commit', (operation,), now=210,
                 cut='renewal:terminal-durable' if f.bridge else 'local-credential:committed')
        result = f.worker('renewal-original-recovered', 'credential_recover' if f.bridge else 'credential_commit', (operation,), now=210)
        require(result == 'Applied' if f.bridge else result['status'] == 'Committed', 'original registered renewal outcome')
        if pending_id is not None:
            pending = f.value('original-expired-reservation-resumed', 'resume', (pending_id,), now=210)
            f.call('receive-expired-reservation', 7, application(b'registered', pending), b'original expired reservation')
        require(f.value('original-message-after-renewal', 'resume', (original_id,), now=210) == original
                and f.value('callback-message-after-renewal', 'resume', (callback_id,), now=210) == callback_wire, 'registration renewal changed original messages')
        for name, identity, count in [('first', original_id, 1), ('callback', callback_id, 2)]:
            current_ack = f.call('native-consume-' + name, 10, identity)
            require(f.worker('registered-current-ACK-' + name, 'accept_acknowledgement', (current_ack,), now=210) == 0,
                    'current-epoch acknowledgement incorrectly retired original history')
            acknowledgement = f.call('native-original-epoch-ACK-' + name, 20, (0).to_bytes(8, 'big'))
            require(f.worker('registered-ACK-' + name, 'accept_acknowledgement', (acknowledgement,), now=210) == count,
                    'registered original native consumption')
        missing_active(f)
        fresh_id = f.value('renewed-new-id', 'next_id', now=210)
        fresh = f.value('renewed-new-send', 'send', (fresh_id, b'new registered effect', b'registered'), now=210)
        f.call('native-new-receive', 7, application(b'registered', fresh), b'new registered effect')
        final_status = f.worker('final-original-registration', 'registration_status', now=210)
        require(final_status['phase'] == 'Active' and final_status['journal'] == journal.hex()
                and final_status['signing_id'] == f.observations['signing_id'], 'original registration lineage')
        f.observations.update(journal=journal.hex(), session=session.hex(), original_id=original_id.hex(),
             original_ciphertext_sha256=hashlib.sha256(original).hexdigest(), callback_id=callback_id.hex(),
             callback_ciphertext_sha256=hashlib.sha256(callback_wire).hexdigest(), fresh_id=fresh_id.hex(),
             fresh_ciphertext_sha256=hashlib.sha256(fresh).hexdigest(), initial_sealed_intent_sha256=hashlib.sha256(sealed).hexdigest())
        result = dict(f.observations, worker_operations=f.driver.operations, native_commands=f.native.commands,
                      witness_attempts=[] if f.bridge is None else f.bridge.records, refusals=f.refusals,
                      process_kills=sum('signal' in r for r in f.driver.operations),
                      scope='Independent protected enrollment and child lifecycle with real native proof verification/issuance, one original reference session and root-approved renewal. Separate fixture controller is not deployed account authentication. Native traffic time170; no physical erasure/powerloss/PCS or complete multidevice lifecycle claim.')
        (f.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        return {'workers': len(f.driver.operations), 'native_commands': len(f.native.commands), 'process_kills': result['process_kills']}
    finally: f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from provider import load_provider
    args = arguments(); args.output = args.output.resolve(); args.native = args.native.resolve(); args.provider_root = args.provider_root.resolve()
    crypto, backend = load_provider(args.provider_root)
    from peer.wire import require
    root = Path(__file__).resolve().parent
    files = [*sorted((root / 'peer').glob('*.py')), *sorted(root.glob('*.py')), *sorted((root / 'native/src').glob('*.rs')),
             root / 'native/Cargo.toml', root / 'native/Cargo.lock', root / 'requirements.txt']
    def sources(): return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    source_files = sources(); native = hashlib.sha256(args.native.read_bytes()).hexdigest(); args.output.mkdir()
    result = {'source_files': source_files, 'native_sha256': native, 'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()}}
    (args.output / 'INPUTS.json').write_text(json.dumps(result, indent=2) + '\n')
    for label in ['local', 'witness']: result[label] = exercise(args, label)
    require(sources() == source_files and hashlib.sha256(args.native.read_bytes()).hexdigest() == native, 'registered qualification inputs changed')
    (args.output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({k:v for k,v in result.items() if k != 'source_files'}))


if __name__ == '__main__': main()
