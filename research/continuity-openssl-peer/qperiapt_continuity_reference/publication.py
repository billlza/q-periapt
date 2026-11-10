"""Untrusted native advertisement; original client and peer trust stay separate.

This adapter consumes the native reference CLI's closed two-member profile.
Decoding checks framing/correlation, not account membership or permission.
The existing BootstrapBundle verifier authenticates all signed inputs before use.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .bootstrap_bundle import BootstrapBundle
from .authority import Materials
from .enrollment_exchange import checkpoint, decode, encoded, identifier
from .registration_inputs import Inputs
from .wire import MAX_U64, Reader, generation, ldh, nonzero, require


def _proof(wire, index):
    r = Reader(wire)
    require(r.integer(2) == index, 'publication proof order')
    leaf = Reader(r.take(r.integer(2)))
    require(leaf.take(8) == b'QPLEAF01', 'publication leaf tag')
    kind = leaf.integer(1)
    require(kind in (1, 3), 'publication role is outside reusable profile')
    leaf.take(16)  # Signed validity is authenticated by BootstrapBundle.verify.
    public = nonzero(leaf.take(32 if kind == 1 else 1184)); leaf.finish()
    require(r.integer(1) == 1, 'publication requires two-leaf membership proof')
    r.take(32); r.finish()
    return kind, public


@dataclass(frozen=True)
class Publication:
    """Public producer assertions, never a local journal or selected trust pin."""
    journal: bytes
    identity: bytes
    checkpoint: tuple[int, bytes]
    certificate: bytes
    roster: bytes
    manifest: bytes
    classical_proof: bytes
    pq_proof: bytes

    @classmethod
    def decode(cls, raw):
        value = decode(raw, 'schema journal publication artifact certificate roster checkpoint', 65536)
        require(value['schema'] == 'qperiapt-native-publication/1', 'native publication schema')
        journal, identity = identifier(value['journal']), identifier(value['publication'])
        ordinal = generation(int.from_bytes(identity[:8], 'big'))
        require(ordinal < MAX_U64, 'publication ordinal exhausted')
        bound = ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ID/v1', journal + identity[:8])
        require(identity[8:] == bound[:24], 'publication journal correlation')
        r = Reader(encoded(value['artifact'], 16384))
        require(r.take(8) == b'QPPUBA01' and r.take(32) == identity, 'publication artifact identity')
        intent, commitment = nonzero(r.take(32)), nonzero(r.take(32))
        require(r.integer(4) == 3667, 'publication manifest width')
        manifest = r.take(3667)
        require(r.integer(2) == 2, 'publication requires explicit reusable profile')
        requests = tuple(nonzero(r.take(32)) for _ in range(2))
        require(len(set(requests)) == 2, 'publication inventory correlation repeats')
        proofs, public = {}, {}
        for index in range(2):
            length = r.integer(2)
            require(62 <= length <= 1534, 'publication proof capacity')
            proof = r.take(length); kind, key = _proof(proof, index)
            require(kind not in proofs, 'publication duplicate role')
            proofs[kind], public[kind] = proof, key
        r.finish()
        require(set(proofs) == {1, 3}, 'publication missing reusable role')
        # The native CLI's plan orders classical then PQ; proof order is instead
        # canonical Merkle order. These unkeyed checks confer no authenticity.
        expected = ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ARTIFACT/v1',
                       intent + manifest + public[1] + public[3])
        require(commitment == expected, 'publication artifact commitment')
        return cls(journal, identity, checkpoint(value['checkpoint']),
                   encoded(value['certificate'], 8192), encoded(value['roster'], 8192),
                   manifest, proofs[1], proofs[3])

    def bundle(self, initiator_certificate, initiator_roster):
        """Assemble existing QPBNDL01 public bytes, without choosing any pins."""
        fields = (initiator_certificate, initiator_roster, self.certificate, self.roster,
                  self.manifest, self.classical_proof, self.pq_proof, b'', b'')
        require(all(type(x) is bytes and len(x) <= 8192 for x in fields), 'publication bundle field capacity')
        return BootstrapBundle(b'QPBNDL01\2' + b''.join(len(x).to_bytes(2, 'big') + x for x in fields))

    def verify(self, pins, policy_materials, initiator_certificate, initiator_roster, now, *, witness_pin=None):
        """Authenticate current public input under separately provisioned trust.

        A verified context still needs its original registration/storage owner.
        The producer journal/operation IDs never select the client's local state.
        """
        require(self.checkpoint == (pins.responder.roster_version, pins.responder.roster_digest),
                'publication differs from independently current roster')
        bundle = self.bundle(initiator_certificate, initiator_roster)
        context = bundle.verify(pins, policy_materials.sdk_document, policy_materials.sdk_signature,
                                policy_materials.policy, now, required_quality=2, witness_pin=witness_pin)
        # The verified canonical selection's eighth LP8 field is the manifest
        # epoch. Reuse it instead of re-verifying the same signature.
        r = Reader(context.selection)
        for _ in range(7): r.take(r.integer(8))
        require(r.take(r.integer(8)) == self.identity[:8], 'publication manifest ordinal differs')
        return context

    def inputs(self, pins, policy_materials, initiator_certificate, initiator_roster, *, witness_pin=None):
        """Inputs for EnrollmentClient.prepare, which performs live owner admission.

        Call verify first to check producer metadata; preparing the original
        client repeats time and authorization checks at its durable boundary.
        """
        m = policy_materials
        return Inputs(pins, Materials(m.sdk_document, m.sdk_signature, m.policy,
                      initiator_certificate, initiator_roster, self.certificate, self.roster,
                      self.manifest, self.classical_proof, self.pq_proof), witness_pin)
