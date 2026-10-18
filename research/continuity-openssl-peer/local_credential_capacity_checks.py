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
    from peer.identity_state import IdentityState
    from peer.journal import MAX_STATE
    from peer.local_renewal_record import Record
    from peer.renewal import verify
    from peer.state_codec import encode
    from peer.traffic_codec import encode_traffic
    from peer.wire import require
    from application_fixture import record as record_application
    from traffic_checks import application
    f = Fixture(args, 'capacity'); owner = coordinator = None
    try:
        operation, grant_wire, target = f.materials(1)
        current = IdentityState.initial(f.context, role=0)
        grant = verify(grant_wire, current.original, f.context.family, f.context.policy_digest, target, now=170)
        successor = current.renew(f.context, grant_wire, operation, target, 170)
        pending_bytes = len(Record(pending=grant).encode()) + 1
        completed_bytes = len(successor.encode()) + len(Record().encode()) + 1
        require(completed_bytes > pending_bytes, 'fixture does not distinguish pending/final capacity')
        limit = MAX_STATE - 65536; target_traffic = limit - pending_bytes
        owner = f.open_session()
        plaintext = bytes(range(256)) * 64
        for _ in range(64):
            owner.send(owner.next_id(170), plaintext, b'', 170)
        offer = owner.prepare_rekey_offer(f.signer, 170)
        response = f.call('capacity-rekey-response', 14, offer)
        final = owner.accept_rekey_response(response, f.signer, 170)
        receipt = f.call('capacity-rekey-receipt', 15, final)
        require(owner.accept_rekey_receipt(receipt, 170) == 1, 'capacity epoch')
        def traffic_bytes():
            with owner._state(operational=False) as (_snapshot, state):
                return 2 + sum(len(encode_traffic(t)) for t in state.traffic.epochs.values())
        rows = 64; last_id = last_wire = last_plaintext = None
        while traffic_bytes() < target_traffic:
            before = traffic_bytes(); remaining = target_traffic - before
            require(remaining >= 153 and rows < 128, 'capacity fixture row/byte bound')
            size = min(16384, remaining - 153)
            if 0 < remaining - 153 - size < 153:
                size -= 153
            require(0 <= size <= 16384, 'boundary plaintext size')
            last_id = owner.next_id(170); last_plaintext = b'c' * size
            last_wire = owner.send(last_id, last_plaintext, b'', 170); rows += 1
            require(traffic_bytes() - before == 153 + size, 'actual committed row size')
        require(traffic_bytes() == target_traffic and last_id is not None, 'exact pending capacity boundary')
        with owner._state(operational=False) as (snapshot, state):
            pending = replace(state, local_renewal=Record(pending=grant), format_version=7)
            pending_image = encode(pending)
            completed = replace(state, local_authority=successor, local_renewal=Record(), format_version=7)
            f.refuses('completed-target-does-not-fit', lambda: encode(completed), 'traffic capacity reserves control completion')
            original_head = snapshot.digest
        owner.close(); owner = None
        original = (f.path / 'head').read_bytes()
        coordinator = f.coordinator(operation)
        f.refuses('stage-reserves-completed-target', lambda: coordinator.stage(grant_wire, target, 170),
                  'traffic capacity reserves control completion')
        coordinator.close(); coordinator = None
        require((f.path / 'head').read_bytes() == original and not (f.path / 'intent').exists(),
                'rejected stage pinned or changed original traffic')
        owner = f.open_session()
        require(owner.storage_format() == 5 and owner.resume(last_id, 170) == last_wire, 'stage rejection lost old owner/outbox')
        # Explicit host accounting frees old retained traffic while the original
        # authority is still current. This is not a forged peer consumption ACK.
        resolution = owner.begin_closed_epoch_resolution(0, 170).public_record()
        require(len(resolution['outgoing']) == 64 and resolution['acknowledged_before'] == 0, 'full old outbox accounting')
        decision = record_application(f.private / 'application-decision', f.session, 1, resolution)
        (f.out / 'APPLICATION_DECISION.json').write_text(json.dumps(decision, indent=2) + '\n')
        (f.out / 'RESOLUTION.json').write_text(json.dumps(resolution, indent=2) + '\n')
        owner.acknowledge_closed_epoch_resolution(0, bytes.fromhex(resolution['id']), 170)
        require(all(owner.status(bytes.fromhex(row['id'])) == 'DeliveryUnknown' for row in resolution['outgoing']),
                'local cleanup invented peer delivery')
        require(owner.resume(last_id, 170) == last_wire, 'cleanup changed surviving current outbox')
        owner.close(); owner = None
        coordinator = f.coordinator(operation)
        require(coordinator.stage(grant_wire, target, 210)['status'] == 'Pending', 'stage after explicit accounting')
        require(coordinator.commit(210)['status'] == 'Committed', 'commit after explicit accounting')
        coordinator.close(); coordinator = None
        owner = f.open_session()
        require(owner.resume(last_id, 210) == last_wire, 'renewal changed surviving ciphertext')
        f.call('receive-surviving-outbox', 7, application(b'', last_wire), last_plaintext)
        observation = {'pending_metadata_bytes': pending_bytes, 'completed_metadata_bytes': completed_bytes,
                       'traffic_bytes': target_traffic, 'traffic_cap_without_metadata': limit, 'rows': rows,
                       'pending_encoding_fits': len(pending_image) <= MAX_STATE,
                       'completed_metadata_excess': completed_bytes - pending_bytes,
                       'original_head_sha256': original_head.hex(), 'stage_refusal_preserved_head': True,
                       'host_accounted_unknown_outboxes': 64, 'original_operation': operation.hex(),
                       'surviving_id': last_id.hex(), 'surviving_ciphertext_sha256': hashlib.sha256(last_wire).hexdigest(),
                       'final_format': owner.storage_format(),
                       'limitation': 'A full store first encountered after authority expiry may still need a separately authorized cleanup/replacement path. This test frees space while original authority is current; it does not relax expired operations.'}
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
    require(sources() == original, 'sources changed during local capacity qualification')
    (args.output / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n');print(json.dumps(report['capacity']))


if __name__ == '__main__':
    main()
