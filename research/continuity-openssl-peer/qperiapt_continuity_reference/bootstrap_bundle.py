"""Untrusted QPBNDL01 bytes; trust, policy inputs, quality and time stay separate."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from .authority import Materials, authenticate
from .wire import MAX_U64, Reader, require

MAX_BUNDLE = 65536
MAX_FIELD = 8192
FIELDS = ('initiator_credential', 'initiator_roster', 'responder_credential',
          'responder_roster', 'manifest', 'classical_proof', 'pq_proof')


def decode(wire):
    require(type(wire) is bytes and 27 <= len(wire) <= MAX_BUNDLE, 'bootstrap bundle size')
    r = Reader(wire); require(r.take(8) == b'QPBNDL01', 'bootstrap bundle tag')
    quality = r.integer(1); require(quality in (1, 2, 3, 4), 'bootstrap bundle quality')
    fields = []
    for index in range(9):
        size = r.integer(2); require(size <= MAX_FIELD and (index >= 7 or size > 0), 'bootstrap bundle field size')
        fields.append(r.take(size))
    r.finish()
    require(bool(fields[7]) == (quality in (1, 4)) and bool(fields[8]) == (quality in (1, 3)),
            'bootstrap bundle optional proof shape')
    return quality, tuple(fields)


@dataclass(frozen=True)
class BootstrapBundle:
    """Parsing validates bounded framing only; it does not authenticate anything."""
    wire: bytes

    def __post_init__(self):
        decode(self.wire)

    @classmethod
    def from_materials(cls, materials):
        # This independent implementation explicitly supports reusable-both.
        # Parsing the other canonical qualities never implies implementing them.
        fields = tuple(getattr(materials, name) for name in FIELDS) + (b'', b'')
        require(all(type(x) is bytes and len(x) <= MAX_FIELD for x in fields), 'bootstrap bundle field bound')
        return cls(b'QPBNDL01\2' + b''.join(len(x).to_bytes(2, 'big') + x for x in fields))

    def _materials(self, sdk_document, sdk_signature, policy, required_quality):
        quality, fields = decode(self.wire)
        require(type(required_quality) is int and required_quality == quality, 'independent required prekey quality differs')
        require(quality == 2, 'independent prekey quality is not implemented')
        return Materials(sdk_document, sdk_signature, policy, *fields[:7])

    def verify(self, pins, sdk_document, sdk_signature, policy, now, *, required_quality, witness_pin=None):
        """Authenticate current inputs; no storage, trust enrollment or key use."""
        materials = self._materials(sdk_document, sdk_signature, policy, required_quality)
        return authenticate(pins, materials, now, witness_pin=witness_pin)

    def verify_original(self, pins, sdk_document, sdk_signature, policy, now, *,
                        original_context, required_quality, witness_pin=None):
        """Reconstruct an independently pinned original snapshot without permission.

        The caller's original_context must come from retained trusted state, never
        the received bundle. The ordinary owner must still authenticate its exact
        journal/scope and check current authority before any operational output.
        This does not create a live native SDK policy/runtime owner.
        """
        require(type(now) is int and 0 <= now < MAX_U64, 'trusted current time')
        require(type(original_context) is bytes and len(original_context) == 32 and any(original_context),
                'original context expectation')
        materials = self._materials(sdk_document, sdk_signature, policy, required_quality)
        from .historical_inputs import snapshot_start
        start = snapshot_start(materials)
        require(start <= now, 'original snapshot is in the future')
        # Only select a possible common instant. The unchanged ordinary verifier
        # still authenticates every signature, pin and membership and checks all
        # signed intervals at that instant. Hints cannot bypass those checks.
        context = authenticate(pins, materials, start, witness_pin=witness_pin)
        require(context.digest == original_context, 'original context commitment differs')
        return context
