#!/usr/bin/env python3
"""Local-policy credential transactions, exact process recovery and expiry floors."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import sys


def exercise(args, label):
    from local_credential_fixture import Fixture
    from qperiapt_continuity_reference.wire import require
    from traffic_checks import application
    f = Fixture(args, label, short_roster=label == 'expired-roster', combined=label == 'combined')
    w, v = f.worker, f.value
    try:
        def status(value, expected, operation):
            require(set(value) == {'status', 'operation', 'statement', 'target', 'time_floor', 'expired_observation'}
                    and value['status'] == expected and value['operation'] == operation.hex(), 'original credential status')
            return value
        def stage(name, materials, now, **options):
            return w(name, 'local_credential_stage', materials, now=now, **options)
        def original_traffic(now):
            w('different-reservation-refused', 'resume', (original,), now=now, refusal='different reserved operation')
            resumed = v('reserved-resumed', 'resume', (reserved,), now=now)
            require(v('reserved-replayed', 'resume', (reserved,), now=now) == resumed, 'reserved ciphertext changed')
            require(v('original-replayed', 'resume', (original,), now=now) == old_wire, 'original ciphertext changed')
            f.call('receive-original', 7, application(b'local', old_wire), b'original local message')
            ack = f.call('consume-original', 10, original)
            require(w('accept-original-ACK', 'accept_acknowledgement', (ack,), now=now) == 1, 'original ACK floor')
            f.call('receive-reserved', 7, application(b'local', resumed), b'reserved before local expiry')
            ack = f.call('consume-reserved', 10, reserved)
            require(w('accept-reserved-ACK', 'accept_acknowledgement', (ack,), now=now) == 2, 'reserved ACK floor')
            return hashlib.sha256(resumed).hexdigest()
        def rekey(now):
            offer = v('renewed-rekey-offer', 'prepare_rekey_offer', now=now)
            response = f.call('renewed-rekey-response', 14, offer)
            final = v('renewed-rekey-final', 'accept_rekey_response', (response,), now=now)
            receipt = f.call('renewed-rekey-receipt', 15, final)
            require(w('renewed-rekey-confirm', 'accept_rekey_receipt', (receipt,), now=now) == 1, 'renewed epoch')
        first = f.materials(1); op = (first[0],)
        original = v('original-id', 'next_id')
        old_wire = v('original-send', 'send', (original, b'original local message', b'local'))
        reserved = v('reserved-id', 'next_id')
        w('reserved-send-kill', 'send', (reserved, b'reserved before local expiry', b'local'), cut='protocol:send-reserved')
        now = 170 if label == 'expired-roster' else 210
        stage('stage-intent-kill', first, now, cut='committed:intent')
        intent = (f.path / 'intent').read_bytes()
        require(intent[:8] == b'QPREFI01' and len(intent) == 84 + int.from_bytes(intent[48:52], 'big'), 'original stage intent')
        target_hash = hashlib.sha256(intent[52:-32]).hexdigest()
        w('pending-normal-owner-refused', 'storage_format', now=now, refusal='local credential renewal remains pending')
        status(w('recover-original-stage', 'local_credential_status', op, now=now), 'Pending', first[0])
        require(hashlib.sha256((f.path / 'head').read_bytes()).hexdigest() == target_hash, 'stage target was resealed')
        unchanged = (f.path / 'head').read_bytes()
        resigned = (f.public / 'local-renewal-1-resigned').read_bytes()
        status(stage('resigned-stage-retry', (first[0], resigned, first[2]), now), 'Pending', first[0])
        require((f.path / 'head').read_bytes() == unchanged, 'semantic retry replaced original grant')
        stage('another-pending-grant-refused', f.materials(2), now, refusal='another local credential renewal remains pending')
        observation = {'original_id': original.hex(), 'original_ciphertext_sha256': hashlib.sha256(old_wire).hexdigest(),
                       'reserved_id': reserved.hex(), 'original_stage_target_sha256': target_hash}
        if label in ('committed', 'combined'):
            w('commit-stage-kill', 'local_credential_commit', op, now=now, cut='stage-synced:head')
            committed_intent = (f.path / 'intent').read_bytes(); files = len(list(f.path.iterdir()))
            for index in range(2):
                w('same-target-stage-kill-' + str(index), 'local_credential_status', op, now=now, cut='stage-synced:head')
                require((f.path / 'intent').read_bytes() == committed_intent and len(list(f.path.iterdir())) == files,
                        'recovery changed target or grew staging')
            w('committed-head-kill', 'local_credential_status', op, now=now, cut='committed:head')
            w('intent-removal-kill', 'local_credential_status', op, now=now, cut='removed:intent')
            status(w('committed-readback', 'local_credential_status', op, now=now), 'Committed', first[0])
            require(hashlib.sha256((f.path / 'head').read_bytes()).hexdigest() == hashlib.sha256(committed_intent[52:-32]).hexdigest(),
                    'original committed image changed')
            require(w('format-eight', 'storage_format', now=now) == 8, 'conditional local format')
            if label == 'combined':
                w('still-expired-peer-refused', 'resume', (original,), now=210, refusal='expired or premature authority')
                peer = f.materials(1, peer=True)
                require(v('admit-peer-first', 'admit_peer_credential_renewal', (peer[1], peer[0], peer[2]), now=210) == peer[2],
                        'peer first renewal')
                second = f.materials(2)
                status(stage('stage-second-with-peer-metadata', second, 250), 'Pending', second[0])
                owner = f.coordinator(second[0])
                try:
                    with owner._state() as (_snapshot, state, _current, _record):
                        metadata = len(state.peer_authority.encode()) + len(state.local_authority.encode()) + len(state.local_renewal.encode()) + 1
                        require(73728 < metadata <= 213291, 'combined metadata fixture missed old bound')
                        observation['combined_metadata_bytes'] = metadata
                finally:
                    owner.close()
                status(w('commit-second-with-peer', 'local_credential_commit', (second[0],), now=250), 'Committed', second[0])
                observation['reserved_ciphertext_sha256'] = original_traffic(250); rekey(250)
                peer = f.materials(2, peer=True)
                require(v('admit-peer-second', 'admit_peer_credential_renewal', (peer[1], peer[0], peer[2]), now=310) == peer[2],
                        'peer second renewal')
                identity = v('combined-new-id', 'next_id', now=310)
                wire = v('combined-new-send', 'send', (identity, b'both current identities', b'local'), now=310)
                f.call('receive-both-current', 7, application(b'local', wire), b'both current identities')
            else:
                observation['reserved_ciphertext_sha256'] = original_traffic(210); rekey(210)
                second = f.materials(2)
                f.cancelled_stage(second, 210)
                status(stage('second-stage-after-close', second, 310), 'Pending', second[0])
                w('second-commit-result-kill', 'local_credential_commit', (second[0],), now=310, cut='local-credential:committed')
                status(w('second-expired-recovery', 'local_credential_expire', (second[0],), now=401), 'Committed', second[0])
                status(w('second-historical-commit', 'local_credential_commit', (second[0],), now=401), 'Committed', second[0])
                w('older-completion-unavailable', 'local_credential_status', op, now=401, refusal='outcome unavailable')
        else:
            boundary, expired_now = (180, 190) if label == 'expired-roster' else (300, 310)
            w('live-target-expiry-refused', 'local_credential_expire', op, now=boundary - 1, refusal='target is not expired')
            w('new-expired-commit-refused', 'local_credential_commit', op, now=boundary, refusal='expired or premature authority')
            observed = (f.path / 'head').read_bytes()
            w('expiry-intent-kill', 'local_credential_expire', op, now=expired_now, cut='committed:intent')
            expiry_intent = (f.path / 'intent').read_bytes(); files = len(list(f.path.iterdir()))
            for index in range(2):
                w('expiry-original-target-kill-' + str(index), 'local_credential_status', op, now=expired_now,
                  cut='stage-synced:head')
                require((f.path / 'intent').read_bytes() == expiry_intent, 'expiry recovery changed trusted observation')
                if index: require(len(list(f.path.iterdir())) == files, 'expiry recovery grew staging')
                files = len(list(f.path.iterdir()))
            terminal = status(w('expiry-terminal-recovery', 'local_credential_expire', op, now=expired_now + 1),
                              'ExpiredUncommitted', first[0])
            require(terminal['time_floor'] == terminal['expired_observation']['at'] == expired_now
                    and terminal['expired_observation']['digest'] == hashlib.sha256(observed).hexdigest(), 'original expiry observation')
            require(hashlib.sha256((f.path / 'head').read_bytes()).digest() == hashlib.sha256(expiry_intent[52:-32]).digest(),
                    'expired terminal resealed on retry')
            observation['expiry_terminal'] = terminal
            if label == 'expired-roster':
                f.context.check_established(expired_now)
                observation['original_authority_still_live'] = True
            w('expired-terminal-denies-activation', 'storage_format', now=expired_now,
              refusal='expired uncommitted renewal denies activation')
            status(stage('same-expired-stage-is-historical', first, expired_now), 'ExpiredUncommitted', first[0])
            w('abandoned-operation-cannot-commit', 'local_credential_commit', op, now=expired_now,
              refusal='expired uncommitted renewal cannot commit')
            stage('wrong-current-predecessor', f.materials(2), expired_now, refusal='renewal predecessor differs')
            alternate = f.materials('alternate')
            stage('backdated-new-grant-refused', alternate, expired_now - 1, refusal='time precedes durable floor')
            stage('alternate-stage-kill', alternate, expired_now, cut='local-credential:staged')
            status(w('prior-expiry-survives-new-pending', 'local_credential_status', op, now=expired_now),
                   'ExpiredUncommitted', first[0])
            w('alternate-commit-kill', 'local_credential_commit', (alternate[0],), now=expired_now, cut='committed:head')
            completed = status(w('alternate-completed', 'local_credential_status', (alternate[0],), now=expired_now),
                               'Committed', alternate[0])
            require(completed['time_floor'] == expired_now, 'completion lost monotonic floor')
            w('business-time-floor-retained', 'resume', (original,), now=expired_now - 1, refusal='time precedes durable floor')
            w('retired-expiry-unavailable', 'local_credential_status', op, now=expired_now, refusal='outcome unavailable')
            observation['reserved_ciphertext_sha256'] = original_traffic(expired_now); rekey(expired_now)
        f.check_codec(401)
        w('expired-policy-output-denied', 'next_id', now=401, refusal='expired or premature authority')
        return f.report(observation)
    finally:
        f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from qperiapt_continuity_reference.provider import load_provider
    args = arguments(); crypto, backend = load_provider(args.provider_root)
    from qperiapt_continuity_reference.wire import require
    root = Path(__file__).resolve().parent
    files = [*sorted((root / 'qperiapt_continuity_reference').glob('*.py')), *sorted(root.glob('*.py')), *sorted((root / 'native/src').glob('*.rs')),
             root / 'native/Cargo.toml', root / 'native/Cargo.lock', root / 'requirements.txt']
    def sources():return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    source_files = sources(); args.output.mkdir()
    report = {'source_files': source_files, 'native_sha256': hashlib.sha256(args.native.read_bytes()).hexdigest(),
              'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()}}
    (args.output / 'INPUTS.json').write_text(json.dumps(report, indent=2) + '\n')
    for label in ('committed', 'expired-credential', 'expired-roster', 'combined'):
        report[label] = exercise(args, label)
    require(sources() == source_files, 'source changed during local credential qualification')
    (args.output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({name: report[name] for name in ('committed', 'expired-credential', 'expired-roster', 'combined')}))


if __name__ == '__main__':
    main()
