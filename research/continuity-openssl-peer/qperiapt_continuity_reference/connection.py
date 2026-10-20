"""Owned original-session connection operations over an untrusted bounded carrier.

The EnrollmentClient retains the signer and owns this borrowed capability.
Errors close the entire client; reopen original state and retain the same ID.
No method infers remote liveness, retries I/O implicitly or selects a new epoch.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from . import connection_wire as wire
from .connection_run import Run, ExchangeLimit
from .control import inspect
from .traffic import PendingDelivery, PreviouslyConsumed
from .wire import MAX_U64, require


class Consumption(Enum):
    CONFIRMED='Confirmed'
    PREFIX_PENDING='PrefixPending'


@dataclass(frozen=True)
class RekeyCompleted:
    epoch: int
    exchanges: int


@dataclass(frozen=True,repr=False)
class PreparedMessage:
    """Committed public ciphertext, not an owner or a fresh dispatch permission."""
    journal: bytes
    session: bytes
    message: bytes
    request: bytes


@dataclass(frozen=True)
class RekeyConfirmed:
    """Authenticated local target, not remote receipt or secrecy recovery."""
    epoch: int


@dataclass(frozen=True,repr=False)
class PreparedRekey:
    """Original committed public control flight, without a private owner."""
    journal: bytes
    session: bytes
    target: int
    request: bytes


def exchange(parent,child,transport,request,run):
    parent._alive(); child.__enter__(); run.check()
    require(callable(transport),'connection carrier')
    response=transport(request,run.deadline,run.cancellation)
    parent._alive(); child.__enter__(); run.check()
    require(type(response) is bytes and 10<=len(response)<=wire.MAX_FRAME,'connection response bound')
    return response


class Connection:
    def __init__(self,parent,child,identity):
        self._parent,self._child,self._identity=parent,child,identity
        self._journal=parent._registration.status()['journal']
        require(type(self._journal) is bytes and len(self._journal)==32,'original connection journal')

    @classmethod
    def _open(cls,parent,run,witness_transport):
        require(isinstance(run,Run),'connection invocation')
        child=parent._registration.connection_session(run.now(),transport=witness_transport)
        try:
            identity=child.connection_identity(run.now()); run.check(); parent._alive()
            return cls(parent,child,identity)
        except BaseException:
            child.close(); raise

    @classmethod
    def _connect(cls,parent,transport,run,witness_transport):
        require(isinstance(run,Run) and callable(transport),'connection invocation or carrier'); run.check()
        if parent._registration.connection_confirmation() is not None:
            return cls._open(parent,run,witness_transport)
        child=parent._registration.session(run.now(),transport=witness_transport)
        try:
            initial=child.initial(run.now())
            reply=exchange(parent,child,transport,wire.frame(wire.INITIAL,initial),run)
            final=child.finish(wire.payload(reply,wire.REPLY),run.now())
            # Release the same original initial flight with fresh admission.
            initial=child.initial(run.now())
            ready=exchange(parent,child,transport,wire.frame(wire.FINAL,wire.pair(initial,final)),run)
            identity,proof=wire.split(wire.payload(ready,wire.READY))
        finally: child.close()
        parent._registration.confirm_connection(identity,proof,run.now(),transport=witness_transport)
        return cls._open(parent,run,witness_transport)

    def _alive(self):
        self._parent._alive(); require(self._child is not None,'closed connection')
        self._child.__enter__()

    @contextmanager
    def _operation(self,run=None,*,historical=False):
        parent=self._parent
        with parent._lock:
            require(not parent._busy,'connection operation already in progress')
            parent._busy=True
            try:
                self._alive()
                if not historical:
                    require(isinstance(run,Run),'connection invocation'); run.check()
                yield
                self._alive()
                if not historical: run.check()
            except BaseException:
                parent.close(); raise
            finally: parent._busy=False

    def _admit(self,run):
        require(self._child.connection_identity(run.now())==self._identity,'original connection identity differs')
        self._alive(); run.check()

    @property
    def identity(self):
        """Historical identity, not a permission or liveness check."""
        with self._operation(historical=True): return self._identity

    def next_id(self,run):
        with self._operation(run): return self._child.next_id(run.now())

    def status(self,message):
        """Historical original-message disposition; no replacement-input promise."""
        with self._operation(historical=True): return self._child.status(message)

    def deliver(self,message,plaintext,ad,transport,run):
        with self._operation(run):
            require(type(message) is bytes and len(message)==32 and type(plaintext) is bytes
                    and type(ad) is bytes,'connection submission types')
            ciphertext=self._child.send(message,plaintext,ad,run.now())
            return self._deliver(message,ciphertext,ad,transport,run)

    def resume(self,message,ad,transport,run):
        """Resume the original reservation/outbox; host retains original AD and ID."""
        with self._operation(run):
            require(type(message) is bytes and len(message)==32 and type(ad) is bytes and len(ad)<=1024,
                    'connection resume inputs')
            ciphertext=self._child.resume(message,run.now())
            return self._deliver(message,ciphertext,ad,transport,run)

    def _deliver(self,message,ciphertext,ad,transport,run):
        prepared=self._prepared(message,ciphertext,ad,run)
        reply=exchange(self._parent,self._child,transport,prepared.request,run)
        return self._complete(prepared,reply,run)

    def _prepared(self,message,ciphertext,ad,run):
        self._admit(run)
        return PreparedMessage(self._journal,self._identity,message,wire.frame(wire.MESSAGE,wire.pair(ad,ciphertext)))

    def prepare_delivery(self,message,plaintext,ad,run):
        """Commit original input/outbox before the host closes this owner for I/O."""
        with self._operation(run):
            require(type(message) is bytes and len(message)==32 and type(plaintext) is bytes
                    and type(ad) is bytes,'connection submission types')
            return self._prepared(message,self._child.send(message,plaintext,ad,run.now()),ad,run)

    def prepare_resume(self,message,ad,run):
        """Release only the exact original reservation/outbox before bounded I/O."""
        with self._operation(run):
            require(type(message) is bytes and len(message)==32 and type(ad) is bytes and len(ad)<=1024,
                    'connection resume inputs')
            return self._prepared(message,self._child.resume(message,run.now()),ad,run)

    def complete_delivery(self,prepared,reply,run):
        """Recheck current original owner and authenticate consumption after I/O.

        Preparation carries no private owner across transport. The authenticated
        ACK concerns the original ID, never replacement plaintext after erasure.
        """
        with self._operation(run):
            return self._complete(prepared,reply,run)

    def _complete(self,prepared,reply,run):
        require(type(prepared) is PreparedMessage and prepared.journal==self._journal
                and prepared.session==self._identity,'prepared message belongs to another original owner')
        message=prepared.message
        require(self._child.status(message) in ('Committed','Acknowledged'),'prepared original message is not committed')
        self._admit(run); proof=wire.payload(reply,wire.ACK)
        require(wire.acknowledgement_epoch(proof)==int.from_bytes(message[:8],'big'),'delivery acknowledgement epoch differs')
        self._child.accept_acknowledgement(proof,run.now())
        status=self._child.status(message)
        require(status in ('Acknowledged','Committed'),'delivery result is not a consumption disposition')
        self._admit(run)
        return Consumption.CONFIRMED if status=='Acknowledged' else Consumption.PREFIX_PENDING

    def rekey(self,target,transport,run,*,exchanges=8):
        with self._operation(run):
            require(type(target) is int and 0<target<MAX_U64 and type(exchanges) is int and 1<=exchanges<=128,
                    'connection rekey target or allowance')
            step=self._prepare_rekey(target,run);attempted=0
            while True:
                self._admit(run)
                if isinstance(step,RekeyConfirmed):return RekeyCompleted(step.epoch,attempted)
                if attempted==exchanges: raise ExchangeLimit('connection rekey request allowance')
                attempted+=1
                reply=exchange(self._parent,self._child,transport,step.request,run)
                step=self._complete_rekey(step,reply,run)

    def prepare_rekey(self,target,run):
        """Prepare/resume the original target, including a retained final receipt."""
        with self._operation(run):return self._prepare_rekey(target,run)

    def _prepare_rekey(self,target,run):
        require(type(target) is int and 0<target<MAX_U64,'connection rekey target')
        self._admit(run)
        return self._rekey_step(target,self._child.start_rekey_control(target,now=run.now()),run)

    def complete_rekey(self,prepared,reply,run):
        """Admit a reply after reopening the original owner under current authority."""
        with self._operation(run):return self._complete_rekey(prepared,reply,run)

    def _complete_rekey(self,prepared,reply,run):
        require(type(prepared) is PreparedRekey and prepared.journal==self._journal
                and prepared.session==self._identity,'prepared control belongs to another original owner')
        target=prepared.target
        require(type(target) is int and 0<target<MAX_U64,'prepared control target')
        self._admit(run);body=wire.payload(reply,wire.CONTROL_REPLY)
        if body==b'\0':
            step=self._child.advance_rekey_control(target,now=run.now())
            require(step==(target,None),'unauthenticated control completion')
        else:
            require(body[:1]==b'\1' and inspect(body[1:])[1]==target,'connection control response target')
            step=self._child.receive_rekey_control(body[1:],now=run.now())
        return self._rekey_step(target,step,run)

    def _rekey_step(self,target,step,run):
        epoch,output=step;self._admit(run)
        require(epoch==target,'connection control target differs')
        if output is None:return RekeyConfirmed(target)
        epoch,original=self._child.replay_rekey_control(output,run.now())
        require(epoch==target,'connection replay target differs');self._admit(run)
        return PreparedRekey(self._journal,self._identity,target,wire.frame(wire.CONTROL,original))

    def serve_message(self,request,consumer,run):
        """Consume authenticated input, or replay only original consumption ACK.

        consumer(session, message, plaintext) must atomically commit its effect
        and deduplication before returning None. Errors/unknown effects must raise.
        Host copies of plaintext are outside SDK erasure and encryption guarantees.
        """
        with self._operation(run):
            require(callable(consumer),'connection application consumer')
            ad,ciphertext=wire.split(wire.payload(request,wire.MESSAGE)); self._admit(run)
            delivery=self._child.receive_delivery(ciphertext,ad,run.now())
            if isinstance(delivery,PendingDelivery):
                self._admit(run)
                result=consumer(self._identity,delivery.message,delivery.plaintext)
                self._alive(); run.check(); require(result is None,'application consumer did not confirm durable commit')
                self._admit(run); self._child.consume(delivery.message,run.now())
            else:
                require(isinstance(delivery,PreviouslyConsumed),'unknown connection delivery disposition')
            self._admit(run)
            proof=self._child.acknowledgement_for_epoch(int.from_bytes(delivery.message[:8],'big'),run.now())
            self._admit(run); return wire.frame(wire.ACK,proof)

    def serve_control(self,request,run):
        """Authenticate one peer control flight and replay only original output."""
        with self._operation(run):
            control=wire.payload(request,wire.CONTROL); target=inspect(control)[1]; self._admit(run)
            epoch,output=self._child.receive_rekey_control(control,now=run.now())
            require(epoch==target,'received control target differs')
            if output is None: body=b'\0'
            else:
                epoch,output=self._child.replay_rekey_control(output,run.now())
                require(epoch==target,'response control target differs'); body=b'\1'+output
            self._admit(run); return wire.frame(wire.CONTROL_REPLY,body)

    def __enter__(self):
        with self._parent._lock: self._alive(); return self

    def __exit__(self,*_error): self.close()

    def close(self):
        """Release this borrow; explicitly closing the client also revokes it."""
        with self._parent._lock:
            child,self._child=self._child,None
            try:
                if child is not None: child.close()
            except BaseException:
                self._parent.close(); raise
