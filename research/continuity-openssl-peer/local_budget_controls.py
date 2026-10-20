"""Boundaries and archived writer interoperability for local lifecycle storage."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import hashlib
import importlib
from qperiapt_continuity_reference.journal import Journal, LocalSessionJournal
from qperiapt_continuity_reference.local_renewal_record import Record
from qperiapt_continuity_reference.private_files import PrivateDirectory
from qperiapt_continuity_reference.state_codec import encode, decode
from qperiapt_continuity_reference.storage_budget import MAX_STATE, MAX_LOCAL_STATE, MAX_LOCAL_METADATA, MAX_SHARED_STATE
from qperiapt_continuity_reference.traffic_codec import encode_traffic
from qperiapt_continuity_reference.wire import require


def inventory(state):
    records = [(epoch, hashlib.sha256(encode_traffic(traffic)).hexdigest())
               for epoch, traffic in state.traffic.epochs.items()]
    return {'traffic_bytes': 2 + sum(len(encode_traffic(t)) for t in state.traffic.epochs.values()),
            'epoch_record_hashes': records,
            'outboxes': sum(len(t._outbox) for t in state.traffic.epochs.values())}


def check_bounds(f, grant, successor, state):
    # Old schemas retain the exact business/aggregate rule. An altered magic is
    # not an upgrade and must not make the larger allocation available.
    old_pending = replace(state, local_renewal=Record(pending=grant), format_version=7)
    f.refuses('old-schema-still-charges-metadata', lambda: encode(old_pending),
              'traffic capacity reserves control completion')
    new_pending = replace(old_pending, format_version=8)
    first = encode(new_pending)
    require(len(first) - len(Record(pending=grant).encode()) - 1 <= MAX_STATE, 'base state cap')
    completed = replace(state, local_authority=successor, local_renewal=Record(), format_version=8)
    require(len(encode(completed)) <= MAX_LOCAL_STATE, 'completed local image cap')
    excess = first + bytes(MAX_LOCAL_STATE + 1 - len(first))
    f.refuses('overall-state-bound', lambda: decode(excess, f.context), 'snapshot aggregate capacity')
    def unreachable(_payload):
        raise RuntimeError('oversized journal input reached its validator')
    for kind, cls, size in [('raw', Journal, MAX_STATE + 1), ('local', LocalSessionJournal, MAX_SHARED_STATE + 1)]:
        path = f.private / (kind + '-bound'); path.mkdir(mode=0o700)
        journal = cls(path, f.scope, f.key, unreachable)
        try:
            f.refuses(kind + '-journal-bound', lambda: journal._seal(1, bytes(size)), 'journal payload/revision capacity')
        finally:
            journal.close()
    f.refuses('private-file-upper-bound', lambda: PrivateDirectory(f.path, max_file=MAX_SHARED_STATE + 4097),
              'private file bound')
    require(MAX_LOCAL_METADATA == 213291 and MAX_LOCAL_STATE == 2310443, 'derived lifecycle ceiling')
    # Shallow preview states share secret owners with state: never close them.
    return {'v7_refused_full_metadata': True, 'pending_bytes': len(first),
            'completed_bytes': len(encode(completed)), 'maximum_local_state': MAX_LOCAL_STATE}


def legacy_roundtrip(args):
    from archived_fixture import load_version
    from local_credential_fixture import Fixture
    from traffic_checks import application
    f = Fixture(args, 'legacy-seven'); old_owner = owner = None
    try:
        old, old_hash = load_version(f.private, 7)
        archived = importlib.import_module(old.__package__ + '.local_credential')
        old_context = authenticate_archived(f.public, old)
        require(old_context.digest == f.context.digest, 'archived authentication context differs')
        first = f.materials(1)
        identity = f.value('legacy-original-id', 'next_id')
        wire = f.value('legacy-original-send', 'send', (identity, b'original version seven outbox', b''))
        old_owner = archived.LocalCredentialRenewal.open(f.path, f.scope, f.key, old_context, first[0])
        pending = old_owner.stage(first[1], first[2], 210)
        require(pending['status'] == 'Pending', 'actual archived v7 writer')
        with old_owner._state() as (snapshot, state, _identity, _record):
            require(state.format_version == 7, 'archived version seven target')
            old_payload = snapshot.payload
        old_owner.close(); old_owner = None
        require(f.worker('legacy-pending-recovered', 'local_credential_status', (first[0],), now=210) == pending,
                'new reader changed old pending')
        f.worker('legacy-commit-cut', 'local_credential_commit', (first[0],), now=210, cut='committed:head')
        require(f.worker('legacy-committed', 'local_credential_status', (first[0],), now=210)['status'] == 'Committed',
                'old original target recovery')
        require(f.worker('legacy-format-seven', 'storage_format', now=210) == 7, 'old commit implicitly upgraded')
        require(f.value('legacy-original-replayed', 'resume', (identity,), now=210) == wire, 'old ciphertext changed')
        second = f.materials(2)
        f.worker('legacy-new-stage-cut', 'local_credential_stage', second, now=250, cut='committed:intent')
        require(f.worker('legacy-new-pending', 'local_credential_status', (second[0],), now=250)['status'] == 'Pending', 'new explicit transition')
        f.worker('legacy-new-commit', 'local_credential_commit', (second[0],), now=310)
        owner = f.open_session()
        with owner._state(operational=False) as (_snapshot, state):
            require(state.format_version == 8, 'explicit renewed format eight')
            f.refuses('archived-seven-reader-refuses-eight', lambda: old.decode(encode(state), old_context), 'snapshot schema/context')
        require(owner.resume(identity, 310) == wire, 'new allocation lost archived outbox')
        owner.close(); owner = None
        f.call('receive-archived-original', 7, application(b'', wire), b'original version seven outbox')
        f.worker('legacy-expired-policy-output', 'resume', (identity,), now=401, refusal='expired or premature authority')
        return f.report({'archived_codec_sha256': old_hash, 'archived_pending_payload_sha256': hashlib.sha256(old_payload).hexdigest(),
                         'original_id': identity.hex(), 'original_ciphertext_sha256': hashlib.sha256(wire).hexdigest(),
                         'old_commit_format': 7, 'new_stage_format': 8})
    finally:
        if old_owner is not None: old_owner.close()
        if owner is not None: owner.close()
        f.close()


def authenticate_archived(public, old):
    """Feed original public bytes through the archived verifier's own types."""
    from fixture_inputs import load
    pins, materials, _context = load(public, 150)
    authority = importlib.import_module(old.__package__ + '.authority')
    def device(pin):
        return authority.DevicePin(authority.VerificationKey(pin.root.raw), pin.account,
                                   pin.roster_version, pin.roster_digest, pin.device, pin.generation)
    selected = authority.Pins(pins.sdk_root, pins.sdk_state, authority.VerificationKey(pins.policy_root.raw),
                              pins.policy_version, pins.policy_digest, device(pins.initiator),
                              device(pins.responder), pins.directory)
    return authority.authenticate(selected, materials, 150)
