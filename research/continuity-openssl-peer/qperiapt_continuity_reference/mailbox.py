"""Reference host effect: encrypted, durable delivery storage for one session.

The existing exact-target journal supplies commit/recovery, private-file checks
and a process lease. This is separate from protocol state and never produces an
ACK. Retained plaintext and backups remain part of the host's compromise scope.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import os
import threading
from .journal import Journal, Scope, MissingState, locked
from .private_files import PrivateDirectory
from .traffic import message_id
from .wire import Reader, ldh, require

TAG=b'QPHINB01'
DOMAIN=b'Q-PERIAPT-INDEPENDENT-HOST-INBOX/v1/'
MAX_DELIVERIES=1024


def identity(value):
    require(type(value) is bytes and len(value)==32 and any(value),'host inbox identity')


def scope(client,journal,session):
    for value in (client,journal,session):identity(value)
    return Scope(journal,ldh(DOMAIN+b'owner',client),ldh(DOMAIN+b'session',session))


def correlation(session,message):
    identity(message)
    epoch,index=int.from_bytes(message[:8],'big'),int.from_bytes(message[8:16],'big')
    require(message==message_id(session,2,index,epoch),'host inbox incoming message scope')


def decode(raw,session):
    require(type(raw) is bytes and 10<=len(raw)<=Journal.max_payload,'host inbox image bound')
    reader=Reader(raw);require(reader.take(8)==TAG,'host inbox schema')
    count=reader.integer(2);require(count<=MAX_DELIVERIES,'host inbox capacity')
    rows={};previous=None
    for _ in range(count):
        key=reader.take(32);correlation(session,key)
        require(previous is None or previous<key,'host inbox order or duplicate')
        size=reader.integer(2);require(size<=16384,'host inbox message bound')
        rows[key]=reader.take(size);previous=key
    require(reader.offset==len(raw),'host inbox trailing bytes')
    return rows


def encode(rows):
    require(len(rows)<=MAX_DELIVERIES,'host inbox capacity')
    size=10+sum(34+len(body) for body in rows.values())
    require(size<=Journal.max_payload,'host inbox byte capacity')
    return TAG+len(rows).to_bytes(2,'big')+b''.join(key+len(body).to_bytes(2,'big')+body for key,body in sorted(rows.items()))


class _MailboxJournal(Journal):
    reserved_creation=True


class Mailbox:
    """One original client/journal/session; absent state is never a fresh inbox."""
    def __init__(self,store,session,observer):
        self._store,self.session,self._observer=store,session,observer
        self._lock=threading.RLock()

    @classmethod
    def provision(cls,path,client,journal,session,key,*,observer=None):
        selected=scope(client,journal,session)
        directory=PrivateDirectory(path)
        try:require(not os.listdir(directory.fd),'new host inbox directory is not empty')
        finally:directory.close()
        store=_MailboxJournal.create(path,selected,key,encode({}),lambda raw:decode(raw,session),observer)
        return cls(store,session,observer)

    @classmethod
    def open(cls,path,client,journal,session,key,*,recover_initial=False,observer=None):
        selected=scope(client,journal,session);validate=lambda raw:decode(raw,session)
        try:store=_MailboxJournal.open(path,selected,key,validate,observer=observer)
        except MissingState:
            if not recover_initial:raise
            # Only the original authenticated revision-zero intent can recover
            # initialization. No empty image or new identifier is synthesized.
            store=_MailboxJournal.open(path,selected,key,validate,creation=True,observer=observer)
        return cls(store,session,observer)

    @locked
    def commit(self,session,message,plaintext):
        require(session==self.session,'host inbox session differs');correlation(session,message)
        require(type(plaintext) is bytes and len(plaintext)<=16384,'host inbox delivery bound')
        try:
            snapshot=self._store.read();rows=decode(snapshot.payload,self.session)
            require(message not in rows or rows[message]==plaintext,'conflicting original host delivery')
            rows[message]=plaintext
            # An exact retry also crosses the durable commit boundary. A former
            # caller may have lost the result of its original sync/commit.
            self._store.update(snapshot.digest,encode(rows))
            if self._observer is not None:self._observer('inbox:effect-committed')
            self._store.read()
        except BaseException:
            self.close();raise

    @locked
    def delivery(self,message):
        correlation(self.session,message)
        rows=decode(self._store.read().payload,self.session)
        require(message in rows,'original host delivery is absent')
        return rows[message]

    @locked
    def count(self):
        return len(decode(self._store.read().payload,self.session))

    @locked
    def close(self):
        self._store.close()

    def __enter__(self):return self
    def __exit__(self,*_error):self.close()
