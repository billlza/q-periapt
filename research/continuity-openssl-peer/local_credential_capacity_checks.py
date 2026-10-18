#!/usr/bin/env python3
"""Real full-traffic admission distinguishes pending and completed local identities."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
from pathlib import Path
import sys


def exercise(args):
    from dataclasses import replace
    from local_credential_fixture import Fixture
    from local_budget_controls import check_bounds, inventory
    from peer.identity_state import IdentityState
    from peer.journal import MAX_STATE
    from peer.renewal import verify
    from peer.state_codec import encode, decode
    from peer.wire import require
    from traffic_checks import application
    f = Fixture(args, 'capacity'); owner = coordinator = None
    try:
        first = f.materials(1)
        current = IdentityState.initial(f.context, role=0)
        grant = verify(first[1], current.original, f.context.family, f.context.policy_digest, first[2], now=210)
        successor = current.renew(f.context, first[1], first[0], first[2], 210)
        cap = MAX_STATE - 65536; owner = f.open_session()
        plaintext = bytes(range(256)) * 64
        original_id = owner.next_id(170); original_wire = owner.send(original_id, plaintext, b'', 170)
        for _ in range(63): owner.send(owner.next_id(170), plaintext, b'', 170)
        offer = owner.prepare_rekey_offer(f.signer, 170)
        response = f.call('capacity-rekey-response', 14, offer)
        final = owner.accept_rekey_response(response, f.signer, 170)
        receipt = f.call('capacity-rekey-receipt', 15, final)
        require(owner.accept_rekey_receipt(receipt, 170) == 1, 'capacity epoch')
        def current_inventory():
            with owner._state(operational=False) as (_snapshot, state): return inventory(state)
        rows = 64
        while current_inventory()['traffic_bytes'] < cap:
            before = current_inventory()['traffic_bytes']; remaining = cap - before
            require(remaining >= 153 and rows < 128, 'capacity fixture row/byte bound')
            size = min(16384, remaining - 153)
            if 0 < remaining - 153 - size < 153: size -= 153
            require(0 <= size <= 16384, 'boundary plaintext size')
            last_id = owner.next_id(170); last_plaintext = b'c' * size
            last_wire = owner.send(last_id, last_plaintext, b'', 170); rows += 1
            require(current_inventory()['traffic_bytes'] - before == 153 + size, 'actual committed row size')
        original_inventory = current_inventory()
        require(original_inventory['traffic_bytes'] == cap and original_inventory['outboxes'] == rows == 123, 'full business inventory')
        with owner._state(operational=False) as (snapshot, state):
            bounds = check_bounds(f, grant, successor, state)
            original_head = snapshot.digest
        f.refuses('business-bound-before-renewal', lambda: owner.send(owner.next_id(170), b'x', b'', 170),
                  'reserved final traffic capacity')
        owner.close(); owner = None
        before = (f.path / 'head').read_bytes()
        f.worker('expired-original-output-refused', 'resume', (last_id,), now=210, refusal='expired or premature authority')
        require((f.path / 'head').read_bytes() == before, 'expired output changed original full state')
        f.worker('full-stage-intent-kill', 'local_credential_stage', first, now=210, cut='committed:intent')
        staged = (f.path / 'intent').read_bytes()
        pending = f.worker('full-pending-recovered', 'local_credential_status', (first[0],), now=210)
        require(pending['status'] == 'Pending' and hashlib.sha256((f.path / 'head').read_bytes()).digest()
                == hashlib.sha256(staged[52:-32]).digest(), 'exact full pending target')
        f.worker('full-pending-output-refused', 'resume', (last_id,), now=210, refusal='local credential renewal remains pending')
        f.worker('full-commit-head-kill', 'local_credential_commit', (first[0],), now=210, cut='committed:head')
        require(f.worker('full-committed-recovered', 'local_credential_status', (first[0],), now=210)['status'] == 'Committed', 'full original commit')
        owner = f.open_session()
        after_first = current_inventory(); require(after_first == original_inventory, 'first renewal altered retained traffic')
        require(owner.storage_format() == 8 and owner.resume(original_id, 210) == original_wire
                and owner.resume(last_id, 210) == last_wire, 'first renewal original ciphertexts')
        f.refuses('metadata-budget-cannot-fund-business', lambda: owner.send(owner.next_id(210), b'x', b'', 210),
                  'reserved final traffic capacity')
        owner.close(); owner = None
        second = f.materials(2)
        f.worker('full-second-stage', 'local_credential_stage', second, now=250)
        large_image_bytes = (f.path / 'head').stat().st_size
        require(large_image_bytes > MAX_STATE + 128, 'actual large image not exercised')
        coordinator = f.coordinator(second[0])
        with coordinator._state() as (snapshot, state, _current, _record):
            f.refuses('legacy-tag-cannot-admit-large-image', lambda: decode(b'QPREFS07' + snapshot.payload[8:], f.context),
                      'legacy snapshot aggregate capacity')
            f.refuses('large-state-cannot-downgrade-seven', lambda: encode(replace(state, format_version=7)),
                      'traffic capacity reserves control completion')
        coordinator.close(); coordinator = None
        f.worker('full-second-commit-kill', 'local_credential_commit', (second[0],), now=310, cut='removed:intent')
        require(f.worker('full-second-recovered', 'local_credential_status', (second[0],), now=310)['status'] == 'Committed', 'full second recovery')
        owner = f.open_session()
        after_second = current_inventory(); require(after_second == original_inventory, 'second renewal altered retained traffic')
        require(owner.resume(original_id, 310) == original_wire and owner.resume(last_id, 310) == last_wire, 'second renewal original ciphertexts')
        owner.close(); owner = None
        f.call('receive-original-outbox', 7, application(b'', original_wire), plaintext)
        f.call('receive-surviving-outbox', 7, application(b'', last_wire), last_plaintext)
        f.worker('expired-policy-output-refused', 'resume', (last_id,), now=401, refusal='expired or premature authority')
        observation = {'bounds': bounds, 'traffic_bytes': cap, 'rows': rows, 'original_inventory': original_inventory,
                       'after_first_inventory': after_first, 'after_second_inventory': after_second,
                       'original_head_sha256': original_head.hex(), 'large_pending_image_bytes': large_image_bytes,
                       'original_operation': first[0].hex(), 'original_id': original_id.hex(),
                       'original_ciphertext_sha256': hashlib.sha256(original_wire).hexdigest(),
                       'surviving_id': last_id.hex(), 'surviving_ciphertext_sha256': hashlib.sha256(last_wire).hexdigest(),
                       'host_accounted_unknown_outboxes': 0, 'final_format': 8,
                       'scope': 'Exact full business allowance retained across root-authorized renewal after original expiry. No host cleanup, output downgrade or enlarged business allowance; only bounded lifecycle metadata has extra physical capacity.'}
        return f.report(observation)
    finally:
        if owner is not None: owner.close()
        if coordinator is not None: coordinator.close()
        f.close()


def main():
    sys.path.append(str(Path(__file__).resolve().parent))
    from run import arguments
    from provider import load_provider
    args = arguments(); crypto, backend = load_provider(args.provider_root)
    from peer.wire import require
    root = Path(__file__).resolve().parent
    files = [*sorted((root / 'peer').glob('*.py')), *sorted(root.glob('*.py')), *sorted((root / 'native/src').glob('*.rs')),
             root / 'native/Cargo.toml', root / 'native/Cargo.lock', root / 'requirements.txt']
    def sources():return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    original = sources(); args.output.mkdir()
    report = {'source_files': original, 'native_sha256': hashlib.sha256(args.native.read_bytes()).hexdigest(),
              'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()}}
    (args.output / 'INPUTS.json').write_text(json.dumps(report, indent=2) + '\n')
    report['capacity'] = exercise(args)
    from local_budget_controls import legacy_roundtrip
    report['legacy-seven'] = legacy_roundtrip(args)
    require(sources() == original, 'sources changed during local capacity qualification')
    (args.output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n');print(json.dumps(report['capacity']))


if __name__ == '__main__':
    main()
