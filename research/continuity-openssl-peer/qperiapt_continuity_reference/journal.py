"""Independent encrypted exact-target journal; a local-only storage primitive.

It never constructs trust inputs, repairs missing active state, or authorizes
protocol output. The protocol codec must validate every authenticated payload.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from __future__ import annotations

import hashlib
import hmac
import functools
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from .kem import hkdf
from .private_files import PrivateDirectory
from .storage_budget import MAX_STATE, MAX_POLICY_STATE
from .wire import MAX_U64, Reader, require
from . import account_binding

DOMAIN = b"Q-PERIAPT-INDEPENDENT-JOURNAL/v1/"


def locked(function):
    @functools.wraps(function)
    def call(self, *args, **kwargs):
        with self._lock:
            return function(self, *args, **kwargs)
    return call


class Conflict(ValueError):
    """The original prior/target or creation scope differs; no mutation allowed."""


class MissingState(ValueError):
    """The original formal state is absent; this is not first use."""


@dataclass(frozen=True)
class Scope:
    identity: bytes
    owner: bytes
    context: bytes

    def __post_init__(self):
        require(all(type(x) is bytes and len(x) == 32 and any(x)
                    for x in (self.identity, self.owner, self.context)), "journal scope")

    def wire(self) -> bytes:
        return self.identity + self.owner + self.context


@dataclass(frozen=True, repr=False)
class Snapshot:
    revision: int
    digest: bytes
    payload: bytes


class Journal:
    image_overhead = 128
    image_capacity_error = 'encrypted image capacity'
    image_scope_error = 'journal identity/owner/context'
    image_revision_error = 'journal revision'
    payload_capacity_error = 'journal payload capacity'
    max_payload = MAX_STATE
    reserved_creation = False

    def __init__(self, path: Path, scope: Scope, wrapping_key: bytes, validate, observer=None, *, root_lease=None):
        require(type(wrapping_key) is bytes and len(wrapping_key) == 32, "wrapping key size")
        self._lock = threading.RLock()
        account_binding.check(root_lease);self._root_lease=root_lease
        self.scope, self.validate = scope, validate
        self._cipher = AESSIV(hkdf(wrapping_key, scope.identity, DOMAIN + b"image-key/" + scope.wire(), 64))
        self._intent_key = hkdf(wrapping_key, scope.identity, DOMAIN + b"intent-key/" + scope.wire())
        self._directory = PrivateDirectory(path, observer, max_file=self.max_payload + 4096)
        try: self._admit_root_fence()
        except BaseException:
            self.close(); raise

    def _admit_root_fence(self):
        # The exclusive directory lease prevents a coordinator from adding a
        # fence while this owner is alive; avoid rereading it on every operation.
        require(self._directory.read('root-fence') is None, 'original account root is fenced')

    @classmethod
    def create(cls, path: Path, scope: Scope, key: bytes, initial: bytes, validate, observer=None, *, root_lease=None):
        owner, _snapshot = cls._create(path, scope, key, initial, validate, observer,root_lease=root_lease)
        return owner

    @classmethod
    def _create(cls, path: Path, scope: Scope, key: bytes, initial: bytes, validate, observer=None, *, root_lease=None):
        owner = cls(path, scope, key, validate, observer,root_lease=root_lease)
        try:
            if any(owner._directory.read(name) is not None for name in ("head", "intent", "authority")):
                raise Conflict("existing state is not new creation")
            if owner.reserved_creation and owner._directory.read_initial_intent() is not None:
                raise Conflict("existing initial intent requires original creation recovery")
            snapshot = owner._commit(0, bytes(32), initial)
            return owner, snapshot
        except BaseException:
            owner.close()
            raise

    @classmethod
    def open(cls, path: Path, scope: Scope, key: bytes, validate, *, creation=False, observer=None,root_lease=None):
        owner, _snapshot = cls._open(path, scope, key, validate, creation=creation, observer=observer,root_lease=root_lease)
        return owner

    @classmethod
    def _open(cls, path: Path, scope: Scope, key: bytes, validate, *, creation=False, observer=None,root_lease=None):
        owner = cls(path, scope, key, validate, observer,root_lease=root_lease)
        try:
            snapshot = owner._recover(creation)
            owner._check_root()
            return owner, snapshot
        except BaseException:
            owner.close()
            raise

    def _admit(self) -> PrivateDirectory:
        require(self._directory is not None, "closed journal")
        self._check_root()
        self._directory.check()
        return self._directory

    def _check_root(self):
        require(self._directory is not None,'closed journal')
        account_binding.check(self._root_lease)

    def _image_prefix(self):return b'QPREFJ01'+self.scope.wire()

    def _seal(self, revision: int, payload: bytes) -> bytes:
        require(type(payload) is bytes and len(payload) <= self.max_payload and 0 < revision < MAX_U64,
                "journal payload/revision capacity")
        self.validate(payload)
        header = account_binding.header(self._image_prefix(),revision,self._root_lease)
        return header + self._cipher.encrypt(payload, [header])

    def _decode(self, wire: bytes) -> Snapshot:
        return self._decode_with_root(wire,self._root_lease)

    def _decode_with_root(self,wire,lease):
        require(self.image_overhead <= len(wire) <= self.max_payload + self.image_overhead + account_binding.SIZE,
                self.image_capacity_error)
        header,revision=account_binding.read_header(wire,self._image_prefix(),lease,scope_error=self.image_scope_error)
        return self._decode_envelope(wire,header,revision)

    def _decode_envelope(self,wire,header,revision):
        """Decrypt only after the owning reader has authenticated its header scope."""
        require(self.image_overhead <= len(wire) <= self.max_payload + self.image_overhead + account_binding.SIZE,
                self.image_capacity_error)
        require(0 < revision < MAX_U64,self.image_revision_error)
        payload = self._cipher.decrypt(wire[len(header):], [header])
        require(len(payload)<=self.max_payload,self.payload_capacity_error)
        self.validate(payload)
        return Snapshot(revision, hashlib.sha256(wire).digest(), payload)

    def _decode_unbound_source(self,wire):
        """Authenticated original source only; never changes this owner's live guard."""
        require(self._root_lease is not None and wire[:8]==self._image_prefix()[:8],'original unbound adoption source required')
        self._check_root();source=self._decode_with_root(wire,None);self._check_root();return source

    def _opening_head(self,wire,pending):
        if self._root_lease is None or wire[:8]!=self._image_prefix()[:8]:return self._decode(wire)
        require(pending is not None and pending.startswith(b'QPREFI01'),'missing original root binding intent')
        revision,prior,_target,result=self._decode_intent(pending)
        source=self._decode_unbound_source(wire)
        require(revision>0 and (source.revision,source.digest)==(revision,prior) and source.payload==result.payload,
                'root binding intent changes original business state')
        return source

    def _intent(self, revision: int, prior: bytes, target: bytes) -> bytes:
        body = b"QPREFI01" + revision.to_bytes(8, "big") + prior + len(target).to_bytes(4, "big") + target
        return body + hmac.digest(self._intent_key, DOMAIN + b"intent/" + self.scope.wire() + body, "sha256")

    def _intent_parts(self,wire):
        require(84 + self.image_overhead <= len(wire) <= self.max_payload + 84 + self.image_overhead + account_binding.SIZE, "write-intent capacity")
        expected = hmac.digest(self._intent_key, DOMAIN + b"intent/" + self.scope.wire() + wire[:-32], "sha256")
        require(hmac.compare_digest(expected, wire[-32:]), "write-intent authentication")
        r = Reader(wire[:-32])
        require(r.take(8) == b"QPREFI01", "write-intent schema")
        revision, prior = r.integer(8), r.take(32)
        target = r.take(r.integer(4))
        r.finish()
        return revision,prior,target

    def _decode_intent(self, wire: bytes) -> tuple[int, bytes, bytes, Snapshot]:
        revision,prior,target=self._intent_parts(wire)
        snapshot = self._decode(target)
        require(revision < MAX_U64 - 1 and snapshot.revision == revision + 1
                and (prior == bytes(32)) == (revision == 0), "write-intent predecessor")
        return revision, prior, target, snapshot

    def _recover(self, creation: bool) -> Snapshot:
        directory = self._admit()
        wire = directory.read("head")
        pending = directory.read("intent")
        head = self._opening_head(wire,pending) if wire is not None else None
        if head is None and not creation:
            raise MissingState("missing active image")
        if creation and head is not None and head.revision != 1:
            raise Conflict("creation reader cannot admit an advanced store")
        if pending is None and head is None and creation and self.reserved_creation:
            pending = directory.read_initial_intent()
            if pending is not None:
                revision, prior, _target, result = self._decode_intent(pending)
                if revision != 0 or prior != bytes(32) or result.revision != 1:
                    raise Conflict("not the original creation transition")
                # Authenticate the complete original transaction before making
                # it formal. Reuse its reserved slot and exact bytes; do not
                # generate a new image or inspect other staging files.
                directory.publish("intent", pending, fixed_slot="initial-intent")
        if pending is None:
            if head is None:
                raise MissingState("no original creation intent")
            return head
        revision, prior, target, result = self._decode_intent(pending)
        if creation and (revision != 0 or result.revision != 1):
            raise Conflict("not the original creation transition")
        if head is not None and head.digest == result.digest:
            pass  # A reachable file-publication cut; apply no second increment.
        elif ((head is None and creation and revision == 0 and prior == bytes(32))
              or (head is not None and head.revision == revision and head.digest == prior)):
            directory.publish("head", target)
        else:
            raise Conflict("write intent does not name the current image")
        directory.remove_intent()
        return result

    @locked
    def read(self) -> Snapshot:
        try:
            result=self._recover(False);self._check_root();return result
        except BaseException:
            self.close()
            raise

    def _commit(self, revision: int, digest: bytes, payload: bytes) -> Snapshot:
        directory = self._admit()
        target = self._seal(revision + 1, payload)
        intent = self._intent(revision, digest, target)
        # Ensure both staged publications fit before making an irrevocable
        # exact-target intent. Recoveries still retain all failed staging files.
        directory.quota(len(intent) + len(target), 2)
        directory.publish("intent", intent,
                          fixed_slot="initial-intent" if revision == 0 and self.reserved_creation else None)
        directory.publish("head", target)
        directory.remove_intent()
        return self._decode(target)

    @locked
    def update(self, expected: bytes, payload: bytes) -> Snapshot:
        try:
            current = self._recover(False)
        except BaseException:
            self.close()
            raise
        if current.digest != expected:
            raise Conflict("stale expected image")
        try:
            return self._commit(current.revision, current.digest, payload)
        except BaseException:
            self.close()
            raise

    @locked
    def close(self) -> None:
        if self._directory is not None:
            directory, self._directory = self._directory, None
            self._cipher, self._intent_key = None, None
            directory.close()


class LocalSessionJournal(Journal):
    """Same transaction engine; the codec enforces each schema's own allocation."""
    max_payload = MAX_POLICY_STATE
