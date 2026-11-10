#!/usr/bin/env python3
"""Independent ordinary-intent recovery through genuine privileged witness control."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import sys


def exercise(args, label):
    from pending_recovery_fixture import Fixture
    from pending_recovery_controls import malformed, cannot_relabel_renewal_head
    from qperiapt_continuity_reference.pending_recovery_protocol import Proposal
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    f = Fixture(args, label)
    try:
        original = f.value('original-id', 'next_id')
        original_wire = f.value('original-send', 'send', (original, b'original unknown delivery', b'recovery'))
        f.call('receive-original-without-ACK', 7, application(b'recovery', original_wire), b'original unknown delivery')
        pending_id = f.value('pending-id', 'next_id')
        f.bridge.arm('after' if label == 'already-applied' else 'before', 2)
        f.worker('ordinary-original-write-lost', 'send', (pending_id, b'original reserved message', b'recovery'), refusal='truncated witness reply')
        original_head, original_intent = (f.path / 'head').read_bytes(), (f.path / 'intent').read_bytes()
        require(original_intent.startswith(b'QPREFI01'), 'original ordinary intent')
        if label != 'already-applied':
            early = f.request('pre-expiry-request', 170)
            f.call('signature-alone-is-not-independent-approval', 37, early[2], status=2)
            f.approve('independent-pre-expiry-approval', early)
            f.call('live-authority-cannot-use-recovery-exception', 37, early[2], status=2)
            require((f.path / 'head').read_bytes() == original_head and (f.path / 'intent').read_bytes() == original_intent,
                    'live recovery exception altered pending state')
        now = 401 if label == 'expired-policy' else 210
        f.clock(now)
        if label != 'already-applied':
            prefix = 'local-renewal-1'
            materials = tuple((f.public / n).read_bytes() for n in [prefix + '-operation', prefix, 'pin-' + prefix + '-target'])
            f.worker('grant-cannot-replace-ordinary-intent', 'local_renewal_prepare', materials, now=now,
                     refusal='truncated witness reply')
            require((f.path / 'head').read_bytes() == original_head and (f.path / 'intent').read_bytes() == original_intent,
                    'grant altered unrelated pending state')
        request = f.request('original-request', now)
        repeat = f.request('semantic-request-retry', now)
        require(request[:2] == repeat[:2], 'read-only request changed original expectation')
        if label != 'already-applied': require(request[:2] == early[:2], 'expiry changed original recovery request')
        malformed(f, request)
        p = Proposal.decode(request[0]); target = p.target.wire()
        require(p.expected.digest == hashlib.sha256(original_head).digest()
                and p.target.digest == hashlib.sha256(original_intent[52:-32]).digest(), 'original sealed target identity')
        if label != 'already-applied':
            f.confirm('unapplied-query-is-not-success', 'original-request', now,
                      refusal='exact target and original command not confirmed')
            require((f.path / 'head').read_bytes() == original_head and (f.path / 'intent').read_bytes() == original_intent,
                    'unconfirmed query changed state')
        f.call('ordinary-handler-refuses-purpose-26', 31, request[2], status=2)
        if label == 'already-applied': f.call('signature-alone-is-not-independent-approval', 37, request[2], status=2)
        if label != 'already-applied':
            f.approve('independent-retained-approval', request)
            f.call('wrong-signature-purpose-refused', 37, f.signer.sign(7, request[0]), status=2)
            # The device confirmation never relies on this controller result.
            # Retain its raw bytes, reopen the actual witness, and retry exactly.
            f.call('independent-exact-completion', 37, request[2], target)
            f.call('witness-reopened', 32, expected=b'witness reopened')
            f.call('independent-completion-retry', 37, repeat[2], target)
        before_confirm = len(f.bridge.records)
        if label == 'cancelled':
            owner = None
            def cancel(stage):
                if stage == 'pending-recovery:queried':
                    f.refuses('nested-recovery-refused', owner.request, 'operation already in progress')
                    owner.close()
            owner = f.owner(cancel)
            try:
                f.refuses('query-close-withholds-result', lambda: owner.confirm(request[0], request[1]), 'closed store directory')
            finally: owner.close()
            require((f.path / 'head').read_bytes() == original_head and (f.path / 'intent').read_bytes() == original_intent,
                    'cancelled confirmation mutated original state')
        for index, cut in enumerate(['pending-recovery:queried', 'stage-synced:head', 'committed:head',
                                     'removed:intent', 'pending-recovery:confirmed']):
            f.confirm('confirm-cut-' + str(index), 'original-request', now, cut=cut)
        require(bytes.fromhex(f.confirm('confirmed-original', 'original-request', now)) == target, 'original confirmed head')
        require(bytes.fromhex(f.confirm('confirmed-retry-without-intent', 'original-request', now)) == target, 'lost local result recovery')
        require(not (f.path / 'intent').exists() and (f.path / 'head').read_bytes() == original_intent[52:-32],
                'confirmation resealed target or retained intent')
        query_records = f.bridge.records[before_confirm:]
        require(query_records and all(row['kind'] == 1 for row in query_records), 'confirmation used a mutation or authority call')
        f.worker('recovery-does-not-restore-output', 'next_id', now=now, refusal='witness current authority denied')
        observations = {'original_id': original.hex(), 'original_ciphertext_sha256': hashlib.sha256(original_wire).hexdigest(),
                        'pending_id': pending_id.hex(), 'original_intent_sha256': hashlib.sha256(original_intent).hexdigest(),
                        'proposal_sha256': hashlib.sha256(request[0]).hexdigest(), 'metadata_bytes': len(request[1]),
                        'confirmed_head': target.hex(), 'query_only_confirmation_attempts': len(query_records)}
        if label == 'expired-policy':
            prefix = 'local-renewal-1'
            materials = tuple((f.public / n).read_bytes() for n in [prefix + '-operation', prefix, 'pin-' + prefix + '-target'])
            f.worker('expired-policy-refuses-new-renewal', 'local_renewal_prepare', materials, now=now,
                     refusal='expired or premature authority')
        else:
            f.renew('first-renewal', 1, 210)
            cannot_relabel_renewal_head(f, request)
            f.worker('original-reservation-order-refused', 'resume', (original,), now=210, refusal='different reserved operation')
            resumed = f.value('reserved-original-resumed', 'resume', (pending_id,), now=210)
            require(f.value('reserved-original-replayed', 'resume', (pending_id,), now=210) == resumed
                    and f.value('original-outbox-replayed', 'resume', (original,), now=210) == original_wire,
                    'renewal changed original work')
            f.call('receive-reserved-original', 7, application(b'recovery', resumed), b'original reserved message')
            for tag, identity, count in [('original', original, 1), ('reserved', pending_id, 2)]:
                ack = f.call('consume-' + tag, 10, identity)
                require(f.worker('accept-' + tag + '-ACK', 'accept_acknowledgement', (ack,), now=210) == count,
                        'actual native consumed prefix')
            offer = f.value('renewed-rekey-offer', 'prepare_rekey_offer', now=210)
            response = f.call('renewed-rekey-response', 14, offer)
            final = f.value('renewed-rekey-final', 'accept_rekey_response', (response,), now=210)
            receipt = f.call('renewed-rekey-receipt', 15, final)
            require(f.worker('renewed-rekey-confirm', 'accept_rekey_receipt', (receipt,), now=210) == 1, 'same-session rekey')
            observations['reserved_ciphertext_sha256'] = hashlib.sha256(resumed).hexdigest()
            if label == 'two-cycles':
                f.clock(250)
                second_id = f.value('second-pending-id', 'next_id', now=250)
                f.bridge.arm('before', 2)
                f.worker('second-ordinary-lost', 'send', (second_id, b'second original reservation', b'recovery'), now=250,
                         refusal='truncated witness reply')
                second_intent = (f.path / 'intent').read_bytes()
                f.clock(310)
                second = f.request('second-original-request', 310); second_p = Proposal.decode(second[0])
                require(len(second[1]) > 32768, 'renewed authority did not exercise larger metadata')
                f.approve('second-independent-retained-approval', second)
                f.call('second-independent-completion', 37, second[2], second_p.target.wire())
                f.confirm('second-confirm-head-cut', 'second-original-request', 310, cut='committed:head')
                require(bytes.fromhex(f.confirm('second-confirmed', 'second-original-request', 310)) == second_p.target.wire()
                        and (f.path / 'head').read_bytes() == second_intent[52:-32], 'second exact original target')
                f.worker('second-recovery-not-activation', 'next_id', now=310, refusal='witness current authority denied')
                f.renew('second-renewal', 2, 310)
                second_wire = f.value('second-original-resumed', 'resume', (second_id,), now=310)
                f.call('receive-second-original', 7, application(b'recovery', second_wire), b'second original reservation')
                observations['second_metadata_bytes'] = len(second[1])
                now = 310
            else: now = 210
            new_id = f.value('new-message-id', 'next_id', now=now)
            new_wire = f.value('new-current-send', 'send', (new_id, b'new after exact recovery', b'recovery'), now=now)
            f.call('receive-new-current', 7, application(b'recovery', new_wire), b'new after exact recovery')
            observations['new_ciphertext_sha256'] = hashlib.sha256(new_wire).hexdigest()
        if label == 'already-applied':
            require(not any(row['command'] == 36 and row['status'] == 1 for row in f.native.commands), 'already-applied recovery requested new approval')
        result = dict(observations, worker_operations=f.driver.operations, native_commands=f.native.commands,
                      witness_attempts=f.bridge.records, refusals=f.refusals,
                      process_kills=sum(row.get('signal') == 'SIGKILL' for row in f.driver.operations),
                      scope='Actual native witness control with independent metadata/signatures and original private state. Privileged approval is a separate fixture control plane, not a deployed account-authentication service. Native traffic time170; no whole-native restart, physical erasure, power-loss or PCS claim.')
        (f.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
        return {k: result[k] for k in ['process_kills', 'metadata_bytes', 'query_only_confirmation_attempts']}
    finally: f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments(); crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    root = Path(__file__).resolve().parent
    files = [*sorted((root / 'qperiapt_continuity_reference').glob('*.py')), *sorted(root.glob('*.py')), *sorted((root / 'native/src').glob('*.rs')),
             root / 'native/Cargo.toml', root / 'native/Cargo.lock', root / 'requirements.txt']
    def sources(): return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    source_files = sources(); args.output.mkdir()
    result = {'source_files': source_files, 'native_sha256': hashlib.sha256(args.native.read_bytes()).hexdigest(),
              'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()}}
    (args.output / 'INPUTS.json').write_text(json.dumps(result, indent=2) + '\n')
    for label in ['unapplied', 'already-applied', 'expired-policy', 'cancelled', 'two-cycles']:
        result[label] = exercise(args, label)
    require(sources() == source_files, 'source changed during pending qualification')
    (args.output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({k:v for k,v in result.items() if k != 'source_files'}))


if __name__ == '__main__': main()
