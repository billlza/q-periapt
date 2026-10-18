"""Witnessed exact-target journal; inactive provisioning grants no output owner."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import hashlib
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from .journal import Journal, Snapshot, Conflict, MissingState, MAX_STATE, locked
from .kem import hkdf
from .private_files import PrivateDirectory
from .witness import Head, Operation
from .wire import MAX_U64, require

DOMAIN = b"Q-PERIAPT-INDEPENDENT-WITNESSED-JOURNAL/v1/"


@dataclass(frozen=True)
class Genesis:
    subject: bytes
    image_digest: bytes

    def wire(self):
        return self.subject + self.image_digest


class WitnessJournal(Journal):
    image_overhead = 264

    def __init__(self, path, scope, key, validate, profile, client, observer=None):
        require(type(key) is bytes and len(key) == 32, "wrapping key size")
        self._lock = threading.RLock()
        self.scope, self.validate, self.profile, self.client = scope, validate, profile, client
        self.subject = profile.subject(scope.identity)
        if client is not None:
            require(client.subject == self.subject and client.pin == profile.pin, "witness client scope")
        self._binding = scope.wire() + profile.pin.binding + self.subject + (1).to_bytes(8, "big")
        self._cipher = AESSIV(hkdf(key, scope.identity, DOMAIN + b"image-key/" + self._binding, 64))
        self._intent_key = hkdf(key, scope.identity, DOMAIN + b"intent-key/" + self._binding)
        self._directory = PrivateDirectory(path, observer)

    @classmethod
    def provision(cls, path, scope, key, initial, validate, profile, observer=None):
        owner = cls(path, scope, key, validate, profile, None, observer)
        try:
            directory = owner._admit()
            require(directory.read("head") is None and directory.read("intent") is None, "existing witnessed creation")
            # Original first image has no enrolled witness yet. No Session or
            # bootstrap output is returned from this explicitly inactive operation.
            target = owner._seal(1, initial)
            intent = owner._intent(0, bytes(32), target)
            directory.quota(len(target) + len(intent), 2)
            directory.publish("intent", intent); directory.publish("head", target); directory.remove_intent()
            return Genesis(owner.subject, owner._decode(target).digest)
        finally:
            owner.close()

    @classmethod
    def recover_genesis(cls, path, scope, key, validate, profile, observer=None):
        owner = cls(path, scope, key, validate, profile, None, observer)
        try:
            # Only this explicit inactive path may reconcile the original
            # revision-zero intent; it cannot advance an enrolled lineage.
            snapshot = Journal._recover(owner, True)
            require(snapshot.revision == 1, "advanced state is not genesis")
            return Genesis(owner.subject, snapshot.digest)
        finally:
            owner.close()

    @classmethod
    def open(cls, path, scope, key, validate, profile, client, observer=None):
        owner, _snapshot = cls._open(path, scope, key, validate, profile, client, observer)
        return owner

    @classmethod
    def _open(cls, path, scope, key, validate, profile, client, observer=None):
        owner = cls(path, scope, key, validate, profile, client, observer)
        try:
            snapshot = owner._recover(False)
            return owner, snapshot
        except BaseException:
            owner.close()
            raise

    def _seal(self, revision, payload):
        require(type(payload) is bytes and len(payload) <= MAX_STATE and 0 < revision < MAX_U64, "journal payload/revision capacity")
        self.validate(payload)
        header = b"QPREFW01" + self._binding + revision.to_bytes(8, "big")
        return header + self._cipher.encrypt(payload, [header])

    def _decode(self, wire):
        require(self.image_overhead <= len(wire) <= MAX_STATE + self.image_overhead, "witnessed image capacity")
        require(wire[:240] == b"QPREFW01" + self._binding, "witnessed image identity/protection")
        revision = int.from_bytes(wire[240:248], "big")
        require(0 < revision < MAX_U64, "witnessed revision")
        payload = self._cipher.decrypt(wire[248:], [wire[:248]])
        self.validate(payload)
        return Snapshot(revision, hashlib.sha256(wire).digest(), payload)

    def _query(self, snapshot):
        require(self.client is not None, "inactive witnessed journal")
        expected = Head(1, snapshot.revision, snapshot.digest)
        reply = self.client.exchange(Operation.query())
        require(reply.head == expected, "witness head differs from original local image")
        self._admit()

    def _advance(self, revision, prior, target):
        require(self.client is not None and revision > 0, "inactive witnessed journal")
        operation = Operation.advance(Head(1, revision, prior), target.digest)
        reply = self.client.exchange(operation)
        require(reply.outcome in (2, 3), "witness exact advance conflicts")
        self._admit().observe("witness:advanced")

    def _recover(self, creation):
        require(not creation, "use explicit witnessed genesis recovery")
        directory = self._admit(); wire = directory.read("head")
        if wire is None:
            raise MissingState("missing original witnessed image")
        head = self._decode(wire); pending = directory.read("intent")
        if pending is not None:
            require(not pending.startswith(b"QPRFLI01"), "local renewal coordination remains pending")
            revision, prior, target, result = self._decode_intent(pending)
            require(revision > 0, "inactive creation requires explicit genesis recovery")
            if head.digest != result.digest and (head.revision != revision or head.digest != prior):
                raise Conflict("witness intent does not name the current local image")
            self._advance(revision, prior, result)
            if head.digest != result.digest:
                directory.publish("head", target)
            directory.remove_intent(); head = result
        self._query(head)
        return head

    def _commit(self, revision, digest, payload):
        directory = self._admit(); target = self._seal(revision + 1, payload)
        intent = self._intent(revision, digest, target)
        directory.quota(len(intent) + len(target), 2)
        directory.publish("intent", intent)
        snapshot = self._decode(target)
        self._advance(revision, digest, snapshot)
        directory.publish("head", target); directory.remove_intent()
        self._query(snapshot)
        return snapshot

    def _authorize(self, snapshot, authority=None):
        expected = Head(1, snapshot.revision, snapshot.digest)
        reply = self.client.exchange(Operation.authority(self.profile.authority if authority is None else authority))
        require(reply.outcome == 5 and reply.head == expected, "witness current authority denied")
        self._admit()

    @locked
    def admit(self, snapshot, operational, authority=None):
        try:
            if operational:
                self._authorize(snapshot, authority)
        except BaseException:
            self.close()
            raise

    @locked
    def release(self, operational, authority=None):
        try:
            snapshot = self._recover(False)
            if operational:
                self._authorize(snapshot, authority)
        except BaseException:
            self.close()
            raise

    @locked
    def close(self):
        if self.client is not None:
            self.client.close()
        super().close()
