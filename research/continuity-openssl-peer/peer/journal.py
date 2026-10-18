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
from .wire import MAX_U64, Reader, require

DOMAIN = b"Q-PERIAPT-INDEPENDENT-JOURNAL/v1/"
MAX_STATE = 2 * 1024 * 1024


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

    def __init__(self, path: Path, scope: Scope, wrapping_key: bytes, validate, observer=None):
        require(type(wrapping_key) is bytes and len(wrapping_key) == 32, "wrapping key size")
        self._lock = threading.RLock()
        self.scope, self.validate = scope, validate
        self._cipher = AESSIV(hkdf(wrapping_key, scope.identity, DOMAIN + b"image-key/" + scope.wire(), 64))
        self._intent_key = hkdf(wrapping_key, scope.identity, DOMAIN + b"intent-key/" + scope.wire())
        self._directory = PrivateDirectory(path, observer)

    @classmethod
    def create(cls, path: Path, scope: Scope, key: bytes, initial: bytes, validate, observer=None):
        owner, _snapshot = cls._create(path, scope, key, initial, validate, observer)
        return owner

    @classmethod
    def _create(cls, path: Path, scope: Scope, key: bytes, initial: bytes, validate, observer=None):
        owner = cls(path, scope, key, validate, observer)
        try:
            if any(owner._directory.read(name) is not None for name in ("head", "intent", "authority")):
                raise Conflict("existing state is not new creation")
            snapshot = owner._commit(0, bytes(32), initial)
            return owner, snapshot
        except BaseException:
            owner.close()
            raise

    @classmethod
    def open(cls, path: Path, scope: Scope, key: bytes, validate, *, creation=False, observer=None):
        owner, _snapshot = cls._open(path, scope, key, validate, creation=creation, observer=observer)
        return owner

    @classmethod
    def _open(cls, path: Path, scope: Scope, key: bytes, validate, *, creation=False, observer=None):
        owner = cls(path, scope, key, validate, observer)
        try:
            snapshot = owner._recover(creation)
            return owner, snapshot
        except BaseException:
            owner.close()
            raise

    def _admit(self) -> PrivateDirectory:
        require(self._directory is not None, "closed journal")
        self._directory.check()
        return self._directory

    def _seal(self, revision: int, payload: bytes) -> bytes:
        require(type(payload) is bytes and len(payload) <= MAX_STATE and 0 < revision < MAX_U64,
                "journal payload/revision capacity")
        self.validate(payload)
        header = b"QPREFJ01" + self.scope.wire() + revision.to_bytes(8, "big")
        return header + self._cipher.encrypt(payload, [header])

    def _decode(self, wire: bytes) -> Snapshot:
        require(128 <= len(wire) <= MAX_STATE + 128, "encrypted image capacity")
        require(wire[:104] == b"QPREFJ01" + self.scope.wire(), "journal identity/owner/context")
        revision = int.from_bytes(wire[104:112], "big")
        require(0 < revision < MAX_U64, "journal revision")
        payload = self._cipher.decrypt(wire[112:], [wire[:112]])
        self.validate(payload)
        return Snapshot(revision, hashlib.sha256(wire).digest(), payload)

    def _intent(self, revision: int, prior: bytes, target: bytes) -> bytes:
        body = b"QPREFI01" + revision.to_bytes(8, "big") + prior + len(target).to_bytes(4, "big") + target
        return body + hmac.digest(self._intent_key, DOMAIN + b"intent/" + self.scope.wire() + body, "sha256")

    def _decode_intent(self, wire: bytes) -> tuple[int, bytes, bytes, Snapshot]:
        require(84 + self.image_overhead <= len(wire) <= MAX_STATE + 84 + self.image_overhead, "write-intent capacity")
        expected = hmac.digest(self._intent_key, DOMAIN + b"intent/" + self.scope.wire() + wire[:-32], "sha256")
        require(hmac.compare_digest(expected, wire[-32:]), "write-intent authentication")
        r = Reader(wire[:-32])
        require(r.take(8) == b"QPREFI01", "write-intent schema")
        revision, prior = r.integer(8), r.take(32)
        target = r.take(r.integer(4))
        r.finish()
        snapshot = self._decode(target)
        require(revision < MAX_U64 - 1 and snapshot.revision == revision + 1
                and (prior == bytes(32)) == (revision == 0), "write-intent predecessor")
        return revision, prior, target, snapshot

    def _recover(self, creation: bool) -> Snapshot:
        directory = self._admit()
        wire = directory.read("head")
        head = self._decode(wire) if wire is not None else None
        if head is None and not creation:
            raise MissingState("missing active image")
        if creation and head is not None and head.revision != 1:
            raise Conflict("creation reader cannot admit an advanced store")
        pending = directory.read("intent")
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
            return self._recover(False)
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
        directory.publish("intent", intent)
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
