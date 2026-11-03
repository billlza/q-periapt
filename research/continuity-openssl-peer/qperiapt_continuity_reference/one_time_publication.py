"""Explicit four-role publication verification; no session or directory authority.

The old Publication/Inputs schemas remain reusable-both. This independent reader
authenticates one-time selection only; it neither leases nor consumes a key.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .authority import SUITE, authenticate_policy
from .enrollment_exchange import checkpoint, decode, encoded, identifier
from .identity import verify_device
from .wire import Interval, Reader, digest, generation, ldh, lp, nonzero, require

SCHEMA = 'qperiapt-native-one-time-publication/1'
ROLES = (1, 2, 3, 4)


def _proof(wire, expected_index):
    r = Reader(wire)
    require(r.integer(2) == expected_index, 'one-time publication proof order')
    leaf = r.take(r.integer(2))
    p = Reader(leaf)
    require(p.take(8) == b'QPLEAF01', 'one-time publication leaf tag')
    kind = p.integer(1)
    require(kind in ROLES, 'one-time publication leaf role')
    validity = Interval.read(p)
    public = nonzero(p.take(32 if kind in (1, 2) else 1184))
    p.finish()
    require(r.integer(1) == 2, 'one-time publication requires four-leaf proof')
    siblings = (r.take(32), r.take(32))
    r.finish()
    return kind, public, validity, leaf, siblings


@dataclass(frozen=True)
class VerifiedOneTimeSelection:
    """Public verification result, not a bootstrap Context or storage capability."""
    record: bytes
    digest: bytes
    quality: int
    responder_prekey: bytes
    intervals: tuple[Interval, ...]

    def check(self, now):
        for interval in self.intervals:
            interval.check(now)


@dataclass(frozen=True)
class OneTimePublication:
    """Strict, explicitly selected four-role advertisement; trust stays separate."""
    journal: bytes
    identity: bytes
    checkpoint: tuple[int, bytes]
    certificate: bytes
    roster: bytes
    manifest: bytes
    intent: bytes
    requests: tuple[bytes, ...]
    proofs: tuple[bytes, ...]

    @classmethod
    def decode(cls, raw):
        value = decode(raw, 'schema journal publication artifact certificate roster checkpoint', 65536)
        require(value['schema'] == SCHEMA, 'one-time publication schema')
        journal, identity = identifier(value['journal']), identifier(value['publication'])
        generation(int.from_bytes(identity[:8], 'big'))
        bound = ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ID/v1', journal + identity[:8])
        require(identity[8:] == bound[:24], 'one-time publication journal correlation')
        r = Reader(encoded(value['artifact'], 16384))
        require(r.take(8) == b'QPPUBA01' and r.take(32) == identity, 'one-time artifact identity')
        intent, commitment = nonzero(r.take(32)), nonzero(r.take(32))
        require(r.integer(4) == 3667, 'one-time publication manifest width')
        manifest = r.take(3667)
        require(r.integer(2) == 4, 'one-time publication requires four roles')
        requests = tuple(nonzero(r.take(32)) for _ in ROLES)
        require(len(set(requests)) == 4, 'one-time inventory correlation repeats')
        proofs, public = [], {}
        for index in range(4):
            length = r.integer(2)
            require(62 <= length <= 1534, 'one-time publication proof capacity')
            proof = r.take(length)
            kind, key, _, _, _ = _proof(proof, index)
            require(kind not in public, 'one-time publication duplicate role')
            public[kind] = key
            proofs.append(proof)
        r.finish()
        require(set(public) == set(ROLES), 'one-time publication missing role')
        # Public-key plan order is fixed [1,2,3,4]; proofs use canonical leaf-ID
        # order instead. This unkeyed correlation is not a service signature.
        expected = ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ARTIFACT/v1',
                       intent + manifest + b''.join(public[kind] for kind in ROLES))
        require(commitment == expected, 'one-time publication artifact commitment')
        return cls(journal, identity, checkpoint(value['checkpoint']),
                   encoded(value['certificate'], 8192), encoded(value['roster'], 8192),
                   manifest, intent, requests, tuple(proofs))

    def verify_selection(self, policy_pins, policy_materials, responder_pin, directory, now, *,
                         required_quality, witness_pin=None):
        """Verify OneTimeBoth with independently supplied authority and time.

        No implicit mode fallback, directory lease, consumption, Context, retained
        Inputs or EnrollmentClient admission is produced by this operation.
        """
        require(type(required_quality) is int and required_quality == 1,
                'explicit OneTimeBoth selection required')
        require(type(directory) is bytes and len(directory) == 32 and any(directory),
                'independent directory checkpoint')
        policy = authenticate_policy(policy_pins, policy_materials, now,
                                     witness_pin=witness_pin, required_quality=required_quality)
        device = verify_device(responder_pin, self.certificate, self.roster, policy.family, now)
        require(self.checkpoint == (responder_pin.roster_version, responder_pin.roster_digest),
                'one-time publication differs from independently current roster')
        require(not device.key.shares_component(policy_pins.policy_root)
                and device.key.raw[:1952] != policy_pins.sdk_root, 'device/policy key separation')
        if witness_pin is not None:
            require(not witness_pin.key.shares_component(device.key)
                    and not witness_pin.key.shares_component(responder_pin.root),
                    'witness/device/account key separation')
        manifest = device.key.open(self.manifest, 3, 290)
        r = Reader(manifest)
        require(r.take(8) == b'QPMANF01', 'one-time manifest tag')
        scope = r.take(248)
        require(r.integer(2) == 4, 'one-time manifest leaf count')
        root = nonzero(r.take(32)); r.finish()
        r = Reader(scope)
        require(r.take(32) == responder_pin.account and r.take(16) == responder_pin.device
                and r.integer(8) == responder_pin.generation and r.take(32) == device.credential
                and r.integer(8) == responder_pin.roster_version
                and r.take(32) == responder_pin.roster_digest, 'one-time manifest device scope')
        epoch = generation(r.integer(8))
        require(epoch.to_bytes(8, 'big') == self.identity[:8], 'one-time publication manifest ordinal')
        require(r.take(32) == policy.sdk.policy_digest and r.take(32) == SUITE
                and r.take(32) == directory, 'one-time manifest policy/directory scope')
        validity = Interval.read(r); r.finish(); validity.check(now)
        require(policy.validity.contains(validity) and device.validity.contains(validity)
                and device.roster_validity.contains(validity),
                'one-time manifest authority interval')
        plan_time = validity.start.to_bytes(8, 'big') + validity.end.to_bytes(8, 'big')
        plan = directory + plan_time + (4).to_bytes(2, 'big') + b''.join(
            bytes([kind]) + plan_time + bytes(33) for kind in ROLES)
        intent = ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-INTENT/v1',
                     policy.sdk.wire() + policy.history.checkpoint() + scope + plan)
        require(self.intent == intent, 'one-time publication original plan intent')
        requests = tuple(ldh(b'Q-PERIAPT-CONTINUITY-PUBLICATION-PREKEY/v1',
                             self.identity + index.to_bytes(2, 'big')) for index in range(4))
        require(self.requests == requests, 'one-time generated inventory identity')
        require(len(self.proofs) == 4, 'one-time publication proof count')
        ordered, members = [], {}
        for index, proof in enumerate(self.proofs):
            kind, public, leaf_time, leaf, siblings = _proof(proof, index)
            require(kind not in members, 'one-time publication duplicate role')
            leaf_time.check(now)
            require(leaf_time == validity, 'one-time generated plan leaf interval')
            identity = digest(b'PREKEY-LEAF', scope + leaf)
            node = identity
            for height, sibling in enumerate(siblings):
                pair = sibling + node if (index >> height) & 1 else node + sibling
                node = digest(b'PREKEY-NODE', pair)
            require(node == root, 'one-time prekey membership proof')
            ordered.append(identity)
            members[kind] = (identity, public, leaf_time)
        require(set(members) == set(ROLES) and ordered == sorted(set(ordered)),
                'one-time manifest order or duplicate')
        level = [digest(b'PREKEY-NODE', ordered[i] + ordered[i + 1]) for i in (0, 2)]
        require(digest(b'PREKEY-NODE', level[0] + level[1]) == root, 'one-time complete manifest root')
        require(members[1][1] != members[2][1] and members[3][1] != members[4][1],
                'one-time selected key aliases reusable key')
        record = b''.join(lp(field) for field in (
            b'Q-PERIAPT-CONTINUITY-PREKEY-SELECTION/v1', b'\0\1', SUITE,
            responder_pin.account, responder_pin.device, responder_pin.generation.to_bytes(8, 'big'),
            device.credential, epoch.to_bytes(8, 'big'), directory, digest(b'MANIFEST', manifest),
            b'\1', members[1][0], members[2][0], b'\1', members[3][0], members[4][0]))
        require(len(record) == 492, 'one-time selection canonical size')
        return VerifiedOneTimeSelection(record,
            ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-SELECTION-DIGEST/v1', record), 1,
            members[4][1] + members[2][1],
            (policy.validity, device.validity, device.roster_validity, validity)
            + tuple(members[kind][2] for kind in ROLES))
