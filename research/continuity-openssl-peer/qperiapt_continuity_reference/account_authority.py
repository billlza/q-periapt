"""Original application/root registry outside replaceable session backups.

The host selects and retains identity, wrapping key, family and witness pin.
Fresh plans require independent host approval; network bytes cannot create one.
Registry selection is not live device/policy permission or delivery evidence.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import os
import threading
import weakref

from .account_authority_state import (Checkpoint,Image,Initial,Replacement,MAX_IMAGE,
    MAX_ACCOUNTS,MAX_REPLACEMENTS,PREPARING,PENDING,CLOSED_PLAN,CLOSED_DECISION,COMMITTED)
from .account_root_protocol import Plan
from .account_root_record import RetainedPlan
from .identity import credential,roster
from .journal import Journal,Scope,Conflict
from .owner_guard import coordinated
from .wire import digest,ldh,require
from .witness import fixed

DOMAIN=b'Q-PERIAPT-REFERENCE-ACCOUNT-AUTHORITY/v1/'
STATES=('Preparing','Pending','Closed','Closed','Committed')


class AuthorityJournal(Journal):
    max_payload=MAX_IMAGE
    reserved_creation=True


class Lease:
    def __init__(self,owner,expected,epoch):
        self._owner=weakref.ref(owner);self.expected=expected;self._epoch=epoch
        from .account_binding import Binding
        self.binding=Binding(owner._journal.scope.wire(),expected.application,expected.revision,expected.account)

    def check_account(self,account,family,witness=None):
        self.check();owner=self._owner()
        require(owner is not None and account==self.expected.account and family==owner.family
                and (witness is None or witness==owner.witness),'account root lease differs from original identity')
        self.check()

    def check(self):
        owner=self._owner();require(owner is not None,'closed account authority owner')
        with owner._lock:
            owner._admit(self.expected)
            require(owner._epochs.get(self.expected.application,0)==self._epoch,'revoked account authority lease')


class _RecoveryAccess:
    """Original-operation metadata access; deliberately not a live Lease."""
    def __init__(self,owner,binding,operation):
        self._owner=weakref.ref(owner);self.binding=binding;self.operation=operation
        self.check()

    def check(self):
        owner=self._owner();require(owner is not None,'closed account authority recovery owner')
        with owner._lock:
            _,record=owner._record(self.operation)
            require(self.binding.registry==owner._journal.scope.wire()
                    and (record.application,record.revision,digest(b'ACCOUNT',record.plan.target.previous.raw))
                    ==(self.binding.application,self.binding.revision,self.binding.account),
                    'root recovery differs from original operation')

    def observation(self):
        self.check();owner=self._owner()
        require(owner is not None,'closed account authority recovery owner')
        result=owner.operation(self.operation);self.check();return result

    def check_scope(self,account,family,witness):
        self.check();owner=self._owner()
        require(owner is not None and account==self.binding.account and family==owner.family
                and witness==owner.witness,'root recovery original account/family/witness differs')
        self.check()


class AccountAuthority:
    def __init__(self,journal,identity,family,pin):
        self._lock=threading.RLock();self._busy=False;self._mutating=None
        self._journal=journal;self.identity=identity;self.family=family;self.witness=pin
        self._epochs={};self._snapshot=journal.read();self._image=Image.read(self._snapshot.payload,family,pin)
        self._current=self._image.current(family,pin)
        self._finalizer=weakref.finalize(self,journal.close)

    @staticmethod
    def scope(path,identity,family,pin):
        fixed(identity,32);fixed(family,32)
        require(path.is_absolute() and '..' not in path.parts,'original authority path required')
        location=ldh(DOMAIN+b'path',os.fsencode(path))
        return Scope(identity,ldh(DOMAIN+b'owner',family+pin.binding),ldh(DOMAIN+b'configuration',location+family+pin.binding))

    @classmethod
    def provision(cls,path,key,identity,family,pin,*,observer=None):
        scope=cls.scope(path,identity,family,pin);validate=lambda raw:Image.read(raw,family,pin)
        journal=AuthorityJournal.create(path,scope,key,Image().encode(family,pin),validate,observer)
        try:return cls(journal,identity,family,pin)
        except BaseException:journal.close();raise

    @classmethod
    def open(cls,path,key,identity,family,pin,*,observer=None,initial=False):
        """Initial=True is only explicit original revision-zero intent recovery."""
        scope=cls.scope(path,identity,family,pin);validate=lambda raw:Image.read(raw,family,pin)
        journal=AuthorityJournal.open(path,scope,key,validate,creation=initial,observer=observer)
        try:return cls(journal,identity,family,pin)
        except BaseException:journal.close();raise

    def _alive(self):require(self._journal is not None,'closed account authority owner')

    def _admit(self,expected):
        self._alive();require(type(expected) is Checkpoint,'exact account authority checkpoint required')
        current=self._current.get(expected.application)
        require(current is not None and current.checkpoint==expected,'account authority checkpoint differs')
        require(not current.pending and self._mutating!=expected.application,'account authority suspended')

    def admit(self,expected):
        with self._lock:
            self._admit(expected)
            return Lease(self,expected,self._epochs.get(expected.application,0))

    @coordinated
    def _recovery_access(self,binding,operation):
        from .account_binding import Binding
        require(type(binding) is Binding,'original root binding required')
        binding.wire()
        return _RecoveryAccess(self,binding,operation)

    @coordinated
    def current(self,application):
        """Select an active mapping; original-operation history uses operation()."""
        self._alive();fixed(application,32)
        require(application in self._current,'original account association absent')
        expected=self._current[application].checkpoint;self._admit(expected)
        return expected

    def _save(self,image,application):
        # Validate and reserve the exact bounded target before revoking leases.
        raw=image.encode(self.family,self.witness);current=image.current(self.family,self.witness)
        self._epochs[application]=self._epochs.get(application,0)+1;self._mutating=application
        try:
            journal=self._journal;self._alive()
            snapshot=journal.update(self._snapshot.digest,raw)
            require(self._journal is journal,'authority closed during persistence')
            self._snapshot=snapshot;self._image=image;self._current=current;self._mutating=None
        except BaseException:self.close();raise

    @coordinated
    def associate(self,application,pin,certificate,listing):
        """An independently selected historical device identifies the original root."""
        self._alive();fixed(application,32)
        cert=credential(pin,certificate,self.family);members=roster(pin,listing,expected=pin.checkpoint())
        require(members.contains(pin,cert.digest) and not pin.root.shares_component(self.witness.key),'original root association scope')
        if application in self._current:
            current=self._current[application];require(current.root==pin.root,'original association root differs')
            self._admit(current.checkpoint)
            return current.checkpoint
        require(len(self._image.initial)<MAX_ACCOUNTS,'authority association capacity')
        entry=Initial(application,pin.root,members.checkpoint())
        image=replace(self._image,initial=tuple(sorted((*self._image.initial,entry),key=lambda item:item.application)))
        self._save(image,application);return self._current[application].checkpoint

    def _record(self,operation):
        self._alive();fixed(operation,32)
        for index,record in enumerate(self._image.replacements):
            if record.plan.target.operation==operation:return index,record
        raise Conflict('original account root operation absent')

    def _replace(self,index,record):
        rows=list(self._image.replacements);rows[index]=record
        self._save(replace(self._image,replacements=tuple(rows)),record.application)

    @coordinated
    def begin_preparation(self,expected,plan):
        self._alive();require(type(expected) is Checkpoint and type(plan) is Plan,'fresh independently approved root plan required')
        retained=RetainedPlan(self.witness,plan.wire())
        require(plan.witness==self.witness and retained.target.family==self.family,'original root policy or witness differs')
        for record in self._image.replacements:
            if record.plan.target.operation==plan.operation:
                require(record.application==expected.application and record.revision==expected.revision
                        and digest(b'ACCOUNT',retained.target.previous.raw)==expected.account
                        and record.plan.original==retained.original,'original root approval differs')
                return STATES[record.phase]
        require(expected.application in self._current and self._current[expected.application].checkpoint==expected,
                'original account checkpoint differs')
        require(len(self._image.replacements)<MAX_REPLACEMENTS,'authority operation capacity')
        record=Replacement(expected.application,expected.revision,retained,PREPARING)
        self._save(replace(self._image,replacements=(*self._image.replacements,record)),expected.application)
        return STATES[record.phase]

    @coordinated
    def operation(self,operation):
        _,record=self._record(operation)
        return (Checkpoint(record.application,record.revision,digest(b'ACCOUNT',record.plan.target.previous.raw)),
                STATES[record.phase],record.plan.original,record.bound)

    @coordinated
    def bind_freeze(self,operation,receipt):
        index,record=self._record(operation)
        require(record.phase not in (CLOSED_PLAN,CLOSED_DECISION),'original root operation closed')
        decision=record.plan.bind(receipt);bound=decision.wire()
        if record.bound:
            require(record.bound==bound,'original root freeze differs');return record.bound
        require(record.phase==PREPARING,'original root preparation differs')
        self._replace(index,replace(record,bound=bound,phase=PENDING));return bound

    @coordinated
    def commit_retirement(self,operation,decision,receipt):
        index,record=self._record(operation)
        require(record.phase not in (CLOSED_PLAN,CLOSED_DECISION),'original root operation closed')
        record.plan.verify_retirement(decision,receipt)
        require(not record.bound or record.bound==decision,'retirement changes original frozen decision')
        if record.phase!=COMMITTED:self._replace(index,replace(record,bound=decision,phase=COMMITTED))
        # Historical result remains the original selected revision after later work.
        return Checkpoint(record.application,record.revision+1,record.plan.target.account)

    @coordinated
    def close_plan(self,operation,receipt):
        index,record=self._record(operation);record.plan.verify_closed(receipt)
        require(record.phase!=COMMITTED,'committed root operation cannot close')
        if record.phase not in (CLOSED_PLAN,CLOSED_DECISION):self._replace(index,replace(record,phase=CLOSED_PLAN))
        return 'Closed'

    @coordinated
    def close_decision(self,operation,decision,receipt):
        index,record=self._record(operation)
        require(record.bound and record.bound==decision,'exact closure requires original bound preparation')
        record.plan.verify_decision_closure(decision,receipt)
        require(record.phase!=COMMITTED,'committed root operation cannot close')
        if record.phase not in (CLOSED_PLAN,CLOSED_DECISION):self._replace(index,replace(record,phase=CLOSED_DECISION))
        return 'Closed'

    def close(self):
        with self._lock:
            journal,self._journal=self._journal,None
            self._current={};self._image=None;self._snapshot=None;self._mutating=None
            if journal is not None:self._finalizer()

    def __enter__(self):self._alive();return self
    def __exit__(self,*_error):self.close()
