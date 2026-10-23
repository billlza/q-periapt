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


class _PlanStatement:
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
class Plan(_PlanStatement):
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
        fixed(self.freeze_operation,32)
        require(self.operation!=self.freeze_operation,'distinct root operation identities')
        target,subject=_target_statement(self.witness,self.operation,self.previous_root,self.successor,
            self.certificate,self.listing,self.policy,self.journal,self.genesis)
        request=b'QPAFRQ01'+self.witness.binding+self.freeze_operation+self.previous_root.raw
        require(len(request)==REQUEST_BYTES,'root request capacity')
        return request,target,subject

def _target_statement(witness,operation,previous_root,successor,certificate,listing,policy,journal,genesis):
    """Recheck the exact signed target, independently of any local preparation."""
    fixed(operation, 32)
    fixed(journal, 32); fixed(genesis, 32)
    policy.verify_metadata()
    require(policy.anchor == witness.binding, 'root policy original witness')
    next_root = successor.root
    require(not previous_root.shares_component(next_root)
            and not previous_root.shares_component(witness.key)
            and not next_root.shares_component(witness.key), 'root key separation')
    cert = credential(successor, certificate, policy.family)
    listing = roster(successor, listing, expected=successor.checkpoint())
    require(listing.contains(successor, cert.digest), 'root target current membership')
    require(not cert.key.shares_component(witness.key), 'root target witness key separation')
    policy.check_external_signer(cert.key)
    validity = Interval(max(cert.validity.start, listing.validity.start, policy.validity.start),
                        min(cert.validity.end, listing.validity.end, policy.validity.end))
    require(validity.start < validity.end, 'root target validity intersection')
    owner = ldh(b'Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANDIDATE/v1/storage-owner',
                successor.account + successor.device
                + generation(successor.generation).to_bytes(8, 'big') + cert.digest)
    subject = _subject(journal + owner + policy.digest)
    authority = digest(b'AUTHORITY', successor.account + listing.checkpoint() + policy.family)
    interval = lambda value: value.start.to_bytes(8, 'big') + value.end.to_bytes(8, 'big')
    identity = (successor.account + successor.device + successor.generation.to_bytes(8, 'big')
                + interval(cert.validity) + policy.family)
    target = (b'QPARPL01' + witness.binding + operation + previous_root.raw + next_root.raw
              + identity + subject + genesis
              + ldh(b'Q-PERIAPT-CONTINUITY-REPLACEMENT-KEY/v1', cert.key.raw) + authority
              + interval(validity) + listing.checkpoint() + policy.checkpoint()
              + interval(policy.validity) + bytes(2))
    require(len(target) <= 65536, 'root target capacity')
    return target, subject

@dataclass(frozen=True)
class Decision:
    plan: _PlanStatement
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


@dataclass(frozen=True)
class CommittedAdoption:
    """Independent winner approval plus authenticated original loss and commit.

    A Decision constructed from signed, independently selected target inputs and
    its actual freeze chooses the winner. Neither incoming terminal receipt may
    choose that target. This object grants no live owner or current permission.
    """
    original: Plan
    winner: Decision
    noncommit: bytes
    retirement: bytes

    def verify(self):
        from .account_root_record import RetainedPlan,RetainedWinner
        require(type(self.original) is Plan and type(self.winner) is Decision
                and type(self.winner.plan) is Plan,'independently approved original and winner required')
        old=RetainedPlan(self.original.witness,self.original.wire())
        new=RetainedWinner(self.winner.plan.witness,self.winner.wire())
        require(old.witness==new.witness and old.target.previous==new.target.previous
                and old.target.family==new.target.family and old.target.operation!=new.target.operation,
                'committed adoption original account or witness differs')
        self.original.verify_closed(self.noncommit)
        self.winner.verify_retirement(self.retirement)
        return old,new
