"""Canonical original expectations inside an authenticated authority journal.

Decoding supplies no new approval. Fresh approvals must use Plan, which rechecks
the independently selected signed inputs. This reader mirrors the retained
native descriptor and never turns historical metadata into live permission.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
from functools import cached_property

from .account_root_protocol import FrozenSubject,MAX_SUBJECTS,REQUEST_BYTES,_PlanStatement,_subject
from .wire import Interval,Reader,VerificationKey,digest,generation,ldh,require
from .witness import Pin,fixed


def checkpoint(reader):
    return generation(reader.integer(8)).to_bytes(8,'big')+fixed(reader.take(32),32)


@dataclass(frozen=True)
class Descriptor:
    wire: bytes
    preparation: bytes | None
    witness: bytes
    operation: bytes
    previous: VerificationKey
    successor: VerificationKey
    account: bytes
    family: bytes
    subject: bytes
    genesis: bytes
    roster: bytes
    policy: bytes
    validity: Interval
    subjects: tuple[FrozenSubject,...]
    observations: bytes

    @classmethod
    def read(cls,wire):
        require(type(wire) is bytes and len(wire)<=65536,'retained root descriptor capacity')
        r=Reader(wire);tag=r.take(8)
        require(tag in (b'QPARPL01',b'QPARPL02'),'retained root descriptor schema')
        preparation=fixed(r.take(32),32) if tag==b'QPARPL02' else None
        witness,operation=fixed(r.take(32),32),fixed(r.take(32),32)
        previous,successor=VerificationKey(r.take(1985)),VerificationKey(r.take(1985))
        account=fixed(r.take(32),32);fixed(r.take(16),16);generation(r.integer(8))
        credential_validity=Interval.read(r);family=fixed(r.take(32),32)
        subject=_subject(r.take(96));genesis=fixed(r.take(32),32);fixed(r.take(32),32)
        authority=fixed(r.take(32),32);validity=Interval.read(r)
        roster_head,policy_head=checkpoint(r),checkpoint(r);policy_validity=Interval.read(r)
        offset=r.offset;count=r.integer(2);require(count<=MAX_SUBJECTS,'retained root subject capacity')
        subjects=tuple(FrozenSubject.read(r) for _ in range(count));r.finish()
        require(not previous.shares_component(successor) and account==digest(b'ACCOUNT',successor.raw)
                and subject[64:]==policy_head[8:] and authority==digest(b'AUTHORITY',account+roster_head+family)
                and credential_validity.contains(validity) and policy_validity.contains(validity),'retained root descriptor scope')
        last=b''
        for old in subjects:
            require(last<old.subject and old.subject!=subject,'retained root descriptor subject order')
            last=old.subject
        return cls(wire,preparation,witness,operation,previous,successor,account,family,subject,genesis,
                   roster_head,policy_head,validity,subjects,wire[offset:])

    @property
    def binding(self):
        return ldh(b'Q-PERIAPT-CONTINUITY-ACCOUNT-ROOT-REPLACEMENT/v1',self.wire)


@dataclass(frozen=True)
class RetainedPlan(_PlanStatement):
    """Only an original MAC-authenticated journal may select these expectations."""
    witness: Pin
    original: bytes

    @cached_property
    def decoded(self):
        require(type(self.original) is bytes and len(self.original)<=8192,'retained root plan capacity')
        r=Reader(self.original);require(r.take(8)==b'QPAFPL01','retained root plan schema')
        request=r.take(REQUEST_BYTES);q=Reader(request)
        require(q.take(8)==b'QPAFRQ01' and q.take(32)==self.witness.binding,'retained root freeze witness')
        operation=fixed(q.take(32),32);previous=VerificationKey(q.take(1985));q.finish()
        size=r.integer(4);require(size<=8192,'retained target capacity')
        target=Descriptor.read(r.take(size));r.finish()
        require(target.preparation is None and not target.subjects and target.witness==self.witness.binding
                and target.previous==previous and target.operation!=operation
                and not previous.shares_component(self.witness.key)
                and not target.successor.shares_component(self.witness.key),'retained root plan target scope')
        return request,target

    def _parts(self):
        request,target=self.decoded
        return request,target.wire,target.subject

    @property
    def target(self):return self.decoded[1]

    def check_decision(self,wire):
        target=Descriptor.read(wire)
        require(target.preparation is not None,'retained root decision is unbound')
        # Reconstruct the original empty target and the exact original freeze.
        original=b'QPARPL01'+wire[40:len(wire)-len(target.observations)]+bytes(2)
        require(original==self.target.wire,'retained root decision target changed')
        snapshot=b'QPAFRZ01'+self.decoded[0]+target.observations
        require(target.preparation==ldh(b'Q-PERIAPT-CONTINUITY-ACCOUNT-FREEZE/v1',snapshot),
                'retained root decision freeze changed')
        return target

    def verify_retirement(self,wire,receipt):
        target=self.check_decision(wire)
        require(self.witness.key.open(receipt,22,72)==b'QPARTR01'+self.witness.binding+target.binding,
                'retained root retirement scope')
        return target

    def verify_decision_closure(self,wire,receipt):
        target=self.check_decision(wire)
        require(self.witness.key.open(receipt,24,72)==b'QPARNM01'+self.witness.binding+target.binding,
                'retained root decision closure scope')
        return target
