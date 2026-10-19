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
from .wire import MAX_U64, require


class Consumption(Enum):
    CONFIRMED='Confirmed'
    PREFIX_PENDING='PrefixPending'


@dataclass(frozen=True)
class RekeyCompleted:
    epoch: int
    exchanges: int


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
        self._admit(run)
        reply=exchange(self._parent,self._child,transport,wire.frame(wire.MESSAGE,wire.pair(ad,ciphertext)),run)
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
            epoch,output=self._child.start_rekey_control(target,now=run.now()); attempted=0
            while True:
                self._admit(run); require(epoch==target,'connection control target differs')
                if output is None: return RekeyCompleted(target,attempted)
                if attempted==exchanges: raise ExchangeLimit('connection rekey request allowance')
                epoch,original=self._child.replay_rekey_control(output,run.now())
                require(epoch==target,'connection replay target differs'); self._admit(run)
                attempted+=1
                reply=exchange(self._parent,self._child,transport,wire.frame(wire.CONTROL,original),run)
                self._admit(run); body=wire.payload(reply,wire.CONTROL_REPLY)
                if body==b'\0':
                    epoch,output=self._child.advance_rekey_control(target,now=run.now())
                    require(epoch==target and output is None,'unauthenticated control completion')
                else:
                    require(body[:1]==b'\1' and inspect(body[1:])[1]==target,'connection control response target')
                    epoch,output=self._child.receive_rekey_control(body[1:],now=run.now())

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
