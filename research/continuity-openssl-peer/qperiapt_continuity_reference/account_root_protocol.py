"""Independent original-plan and signed account-root outcome verification.

Inputs are independently selected original account/witness/target expectations.
These immutable public statements grant no account selection, live traffic,
delivery, erasure or post-compromise guarantee. Durable owner coordination is
separate. No native engine, fixture signer or clock override is used here.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass

from .authority import HistoricalPolicy
from .identity import DevicePin, credential, roster
from .wire import Interval, Reader, VerificationKey, digest, generation, ldh, require
from .witness import Head, Pin, fixed

MAX_SUBJECTS = 256
REQUEST_BYTES = 8 + 32 + 32 + 1985
SIGNED_BYTES = 4 + 72 + 3373


def _subject(raw):
    require(type(raw) is bytes and len(raw) == 96, 'root subject length')
    for offset in (0, 32, 64): fixed(raw[offset:offset + 32], 32)
    return raw


@dataclass(frozen=True)
class FrozenSubject:
    subject: bytes
    head: Head
    last: bytes | None
    state: bytes

    @classmethod
    def read(cls, reader):
        subject, head = _subject(reader.take(96)), Head.read(reader)
        present, last, state = reader.integer(1), reader.take(32), fixed(reader.take(32), 32)
        require((present == 0 and last == bytes(32) and head.fence == head.revision == 1)
                or (present == 1 and any(last) and (head.fence != 1 or head.revision != 1)),
                'root frozen last command')
        return cls(subject, head, last if present else None, state)


@dataclass(frozen=True)
class Terminal:
    """Historical verified observation; deliberately contains no operating owner."""
    state: str
    binding: bytes
    receipt: bytes


@dataclass(frozen=True)
class Plan:
    witness: Pin
    operation: bytes
    freeze_operation: bytes
    previous_root: VerificationKey
    successor: DevicePin
    certificate: bytes
    listing: bytes
    policy: HistoricalPolicy
    journal: bytes
    genesis: bytes

    def _parts(self):
        """Recheck signed metadata because Python objects are not opaque handles."""
        fixed(self.operation, 32); fixed(self.freeze_operation, 32)
        fixed(self.journal, 32); fixed(self.genesis, 32)
        require(self.operation != self.freeze_operation, 'distinct root operation identities')
        self.policy.verify_metadata()
        require(self.policy.anchor == self.witness.binding, 'root policy original witness')
        next_root = self.successor.root
        require(not self.previous_root.shares_component(next_root)
                and not self.previous_root.shares_component(self.witness.key)
                and not next_root.shares_component(self.witness.key), 'root key separation')
        cert = credential(self.successor, self.certificate, self.policy.family)
        listing = roster(self.successor, self.listing, expected=self.successor.checkpoint())
        require(listing.contains(self.successor, cert.digest), 'root target current membership')
        require(not cert.key.shares_component(self.witness.key), 'root target witness key separation')
        self.policy.check_external_signer(cert.key)
        validity = Interval(max(cert.validity.start, listing.validity.start, self.policy.validity.start),
                            min(cert.validity.end, listing.validity.end, self.policy.validity.end))
        require(validity.start < validity.end, 'root target validity intersection')
        owner = ldh(b'Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/storage-owner',
                    self.successor.account + self.successor.device
                    + generation(self.successor.generation).to_bytes(8, 'big') + cert.digest)
        subject = _subject(self.journal + owner + self.policy.digest)
        request = b'QPAFRQ01' + self.witness.binding + self.freeze_operation + self.previous_root.raw
        authority = digest(b'AUTHORITY', self.successor.account + listing.checkpoint() + self.policy.family)
        interval = lambda value: value.start.to_bytes(8, 'big') + value.end.to_bytes(8, 'big')
        identity = (self.successor.account + self.successor.device + self.successor.generation.to_bytes(8, 'big')
                    + interval(cert.validity) + self.policy.family)
        target = (b'QPARPL01' + self.witness.binding + self.operation + self.previous_root.raw + next_root.raw
                  + identity + subject + self.genesis
                  + ldh(b'Q-PERIAPT-CONTINUITY-REPLACEMENT-KEY/v1', cert.key.raw) + authority
                  + interval(validity) + listing.checkpoint() + self.policy.checkpoint()
                  + interval(self.policy.validity) + bytes(2))
        require(len(request) == REQUEST_BYTES and len(target) <= 65536, 'root plan capacity')
        return request, target, subject

    def wire(self):
        request, target, _ = self._parts()
        wire = b'QPAFPL01' + request + len(target).to_bytes(4, 'big') + target
        require(len(wire) <= 8192, 'root plan capacity')
        return wire

    @property
    def binding(self):
        return ldh(b'Q-PERIAPT-CONTINUITY-ACCOUNT-PREPARATION/v1', self.wire())

    def verify_plan(self, wire):
        require(type(wire) is bytes and wire == self.wire(), 'root plan differs from independent target')

    def verify_closed(self, receipt):
        expected = b'QPAPCL01' + self.witness.binding + self.binding
        require(self.witness.key.open(receipt, 25, 72) == expected, 'root plan closure scope')
        return Terminal('ClosedPlan', self.binding, receipt)

    def _frozen(self, receipt):
        request, _, target = self._parts()
        require(type(receipt) is bytes and SIGNED_BYTES <= len(receipt)
                <= 8 + REQUEST_BYTES + 2 + 209 * MAX_SUBJECTS + SIGNED_BYTES, 'root freeze capacity')
        raw, signed = receipt[:-SIGNED_BYTES], receipt[-SIGNED_BYTES:]
        reader = Reader(raw)
        require(reader.take(8) == b'QPAFRZ01' and reader.take(REQUEST_BYTES) == request, 'root original freeze request')
        count = reader.integer(2); require(count <= MAX_SUBJECTS, 'root freeze subject capacity')
        subjects = tuple(FrozenSubject.read(reader) for _ in range(count)); reader.finish()
        previous = b''
        for entry in subjects:
            require(entry.subject > previous and entry.subject != target, 'root frozen subject order or target')
            previous = entry.subject
        binding = ldh(b'Q-PERIAPT-CONTINUITY-ACCOUNT-FREEZE/v1', raw)
        require(self.witness.key.open(signed, 23, 72) == b'QPAFRS01' + self.witness.binding + binding,
                'root freeze signed scope')
        return raw, binding, subjects

    def bind(self, receipt):
        self._frozen(receipt)
        return Decision(self, receipt)


@dataclass(frozen=True)
class Decision:
    plan: Plan
    freeze_receipt: bytes

    def wire(self):
        raw, binding, _ = self.plan._frozen(self.freeze_receipt)
        _, target, _ = self.plan._parts()
        # Keep the approved target exactly. Replace only its schema, preparation
        # binding and empty subject count with the authenticated frozen snapshot.
        result = b'QPARPL02' + binding + target[8:-2] + raw[8 + REQUEST_BYTES:]
        require(len(result) <= 65536, 'root bound decision capacity')
        return result

    @property
    def binding(self):
        return ldh(b'Q-PERIAPT-CONTINUITY-ACCOUNT-ROOT-REPLACEMENT/v1', self.wire())

    def verify_decision(self, wire):
        require(type(wire) is bytes and wire == self.wire(), 'root decision differs from approved freeze and target')

    def subjects(self):
        return self.plan._frozen(self.freeze_receipt)[2]

    def _verify(self, receipt, purpose, tag, state):
        binding = self.binding
        require(self.plan.witness.key.open(receipt, purpose, 72) == tag + self.plan.witness.binding + binding,
                'root terminal signed scope')
        return Terminal(state, binding, receipt)

    def verify_retirement(self, receipt):
        return self._verify(receipt, 22, b'QPARTR01', 'RetiredAccount')

    def verify_closed(self, receipt):
        return self._verify(receipt, 24, b'QPARNM01', 'ClosedDecision')
