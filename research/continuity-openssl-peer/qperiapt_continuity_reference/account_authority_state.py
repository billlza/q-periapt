"""Authenticated application/root history; pure validation, never a live lease."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass

from .account_root_record import RetainedPlan,RetainedWinner,checkpoint
from .wire import Reader,VerificationKey,digest,generation,require
from .witness import fixed
from .storage_budget import MAX_AUTHORITY_ACCOUNTS as MAX_ACCOUNTS,MAX_ROOT_REPLACEMENTS as MAX_REPLACEMENTS,MAX_AUTHORITY_STATE as MAX_IMAGE

PREPARING,PENDING,CLOSED_PLAN,CLOSED_DECISION,COMMITTED,ADOPTING,ADOPTED=range(7)


@dataclass(frozen=True)
class Checkpoint:
    application: bytes
    revision: int
    account: bytes

    def __post_init__(self):
        fixed(self.application,32);fixed(self.account,32)
        require(type(self.revision) is int,'authority revision type');generation(self.revision)


@dataclass(frozen=True)
class Initial:
    application: bytes
    root: VerificationKey
    roster: bytes


@dataclass(frozen=True)
class Replacement:
    application: bytes
    revision: int
    expectation: RetainedPlan | RetainedWinner
    phase: int
    bound: bytes=b''
    original_operation: bytes | None=None


@dataclass(frozen=True)
class Current:
    checkpoint: Checkpoint
    root: VerificationKey
    roster: bytes
    pending: bool=False
    retry: tuple[bytes | None,bytes | None] | None=None


@dataclass(frozen=True)
class Image:
    initial: tuple[Initial,...]=()
    replacements: tuple[Replacement,...]=()

    def current(self,family,pin):
        require(len(self.initial)<=MAX_ACCOUNTS and len(self.replacements)<=MAX_REPLACEMENTS,'authority record capacity')
        roots=set();applications={};last=b'';operations={};closed_roots={}
        for entry in self.initial:
            fixed(entry.application,32)
            require(entry.application>last and not entry.root.shares_component(pin.key),'authority initial order or witness key')
            r=Reader(entry.roster);checkpoint(r);r.finish()
            account=digest(b'ACCOUNT',entry.root.raw)
            require(account not in roots,'authority initial root reuse');roots.add(account);last=entry.application
            applications[entry.application]=Current(Checkpoint(entry.application,1,account),entry.root,entry.roster)
        for record in self.replacements:
            require(type(record.phase) is int and record.phase in range(7),'authority replacement phase')
            require(record.application in applications,'authority replacement account absent')
            selected=applications[record.application];target=record.expectation.target
            adopted=record.phase in (ADOPTING,ADOPTED)
            require(type(record.expectation) is (RetainedWinner if adopted else RetainedPlan),
                    'authority approval kind differs from phase')
            require(record.expectation.witness==pin and target.family==family and target.previous==selected.root
                    and record.revision==selected.checkpoint.revision,'authority replacement original mapping')
            require(target.operation not in operations and (target.account not in roots or
                    adopted and closed_roots.get(target.account)==record.application),'authority operation or root reuse')
            bound=record.expectation.check_decision(record.bound) if record.bound else None
            require((record.phase==PREPARING and bound is None) or
                    (record.phase in (PENDING,CLOSED_DECISION,COMMITTED,ADOPTING,ADOPTED) and bound is not None) or
                    record.phase==CLOSED_PLAN,'authority bound decision phase')
            if adopted:
                original=operations.get(record.original_operation)
                require(original is not None and original.phase in (CLOSED_PLAN,CLOSED_DECISION)
                        and (original.application,original.revision)==(record.application,record.revision)
                        and selected.pending,'adoption requires the original closed preparation')
            else:require(record.original_operation is None,'preparation has an adoption origin')
            previous_retry=selected.retry
            if selected.pending:
                require(previous_retry is not None,'original authority operation still pending')
                request,binding=previous_retry
                require((adopted or request is None or request==record.expectation.decoded[0])
                        and (binding is None or bound is None or bound.preparation==binding),
                        'authority original freeze retry scope')
            operations[target.operation]=record;roots.add(target.account)
            if record.phase in (CLOSED_PLAN,CLOSED_DECISION):closed_roots[target.account]=record.application
            else:closed_roots.pop(target.account,None)
            if record.phase in (COMMITTED,ADOPTED):
                applications[record.application]=Current(Checkpoint(record.application,generation(record.revision+1),target.account),
                                                        target.successor,target.roster)
            else:
                retry=None
                if record.phase in (CLOSED_PLAN,CLOSED_DECISION):
                    retry=(record.expectation.decoded[0],bound.preparation) if bound is not None else (previous_retry or (None,None))
                applications[record.application]=Current(selected.checkpoint,selected.root,selected.roster,True,retry)
        return applications

    def encode(self,family,pin):
        self.current(family,pin)
        adopted=any(record.phase in (ADOPTING,ADOPTED) for record in self.replacements)
        body=bytearray((b'QPRFAA02' if adopted else b'QPRFAA01')+len(self.initial).to_bytes(2,'big'))
        for entry in self.initial:body.extend(entry.application+entry.root.raw+entry.roster)
        body.extend(len(self.replacements).to_bytes(2,'big'))
        for record in self.replacements:
            plan=record.expectation.wire()
            bound=b'' if record.phase in (ADOPTING,ADOPTED) else record.bound
            body.extend(record.application+record.revision.to_bytes(8,'big')+bytes([record.phase])
                        +len(plan).to_bytes(4,'big')+plan+len(bound).to_bytes(4,'big')+bound)
            if record.original_operation is not None:body.extend(fixed(record.original_operation,32))
        require(len(body)<=MAX_IMAGE,'authority image capacity');return bytes(body)

    @classmethod
    def read(cls,wire,family,pin):
        require(type(wire) is bytes and len(wire)<=MAX_IMAGE,'authority image capacity')
        r=Reader(wire);schema=r.take(8);require(schema in (b'QPRFAA01',b'QPRFAA02'),'authority image schema')
        count=r.integer(2);require(count<=MAX_ACCOUNTS,'authority association capacity')
        initial=tuple(Initial(r.take(32),VerificationKey(r.take(1985)),checkpoint(r)) for _ in range(count))
        count=r.integer(2);require(count<=MAX_REPLACEMENTS,'authority operation capacity')
        records=[]
        for _ in range(count):
            application,revision,phase=r.take(32),r.integer(8),r.integer(1)
            adopted=phase in (ADOPTING,ADOPTED)
            require(not adopted or schema==b'QPRFAA02','adoption requires authority image version two')
            size=r.integer(4);require(0<size<=(65536 if adopted else 8192),'authority expectation capacity')
            expectation=(RetainedWinner if adopted else RetainedPlan)(pin,r.take(size))
            size=r.integer(4);require(size<=65536,'authority decision capacity')
            bound=r.take(size);original=r.take(32) if adopted else None
            require(not adopted or not bound,'adopted decision is stored once')
            records.append(Replacement(application,revision,expectation,phase,
                                       expectation.original if adopted else bound,original))
        r.finish();result=cls(initial,tuple(records))
        require(result.encode(family,pin)==wire,'noncanonical authority image');return result
