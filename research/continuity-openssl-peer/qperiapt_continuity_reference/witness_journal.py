"""Witnessed exact-target journal; inactive provisioning grants no output owner."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import dataclass
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

from .journal import Journal, Conflict, MissingState, locked
from .kem import hkdf
from .private_files import PrivateDirectory
from .witness import Head, Operation
from .wire import require
from .storage_budget import MAX_POLICY_STATE
from . import account_binding

DOMAIN = b"Q-PERIAPT-INDEPENDENT-WITNESSED-JOURNAL/v1/"


@dataclass(frozen=True)
class Genesis:
    subject: bytes
    image_digest: bytes

    def wire(self):
        return self.subject + self.image_digest


class WitnessJournal(Journal):
    image_overhead = 264
    image_capacity_error = 'witnessed image capacity'
    image_scope_error = 'witnessed image identity/protection'
    image_revision_error = 'witnessed revision'
    payload_capacity_error = 'witnessed payload capacity'
    max_payload = MAX_POLICY_STATE

    def __init__(self, path, scope, key, validate, profile, client, observer=None, *, root_lease=None):
        require(type(key) is bytes and len(key) == 32, "wrapping key size")
        self._lock = threading.RLock()
        account_binding.check(root_lease);self._root_lease=root_lease
        self.scope, self.validate, self.profile, self.client = scope, validate, profile, client
        self.subject = profile.subject(scope.identity)
        if client is not None:
            require(client.subject == self.subject and client.pin == profile.pin, "witness client scope")
        self._binding = scope.wire() + profile.pin.binding + self.subject + (1).to_bytes(8, "big")
        self._cipher = AESSIV(hkdf(key, scope.identity, DOMAIN + b"image-key/" + self._binding, 64))
        self._intent_key = hkdf(key, scope.identity, DOMAIN + b"intent-key/" + self._binding)
        self._directory = PrivateDirectory(path, observer, max_file=self.max_payload + 4096)

    @classmethod
    def provision(cls, path, scope, key, initial, validate, profile, observer=None, *, root_lease=None):
        owner = cls(path, scope, key, validate, profile, None, observer,root_lease=root_lease)
        try:
            directory = owner._admit()
            require(all(directory.read(name) is None for name in ("head", "intent", "authority")), "existing witnessed creation")
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
    def recover_genesis(cls, path, scope, key, validate, profile, observer=None, *, root_lease=None):
        owner = cls(path, scope, key, validate, profile, None, observer,root_lease=root_lease)
        try:
            # Only this explicit inactive path may reconcile the original
            # revision-zero intent; it cannot advance an enrolled lineage.
            snapshot = Journal._recover(owner, True)
            require(snapshot.revision == 1, "advanced state is not genesis")
            return Genesis(owner.subject, snapshot.digest)
        finally:
            owner.close()

    @classmethod
    def open(cls, path, scope, key, validate, profile, client, observer=None, *, root_lease=None):
        owner, _snapshot = cls._open(path, scope, key, validate, profile, client, observer,root_lease=root_lease)
        return owner

    @classmethod
    def _open(cls, path, scope, key, validate, profile, client, observer=None, *, root_lease=None):
        owner = cls(path, scope, key, validate, profile, client, observer,root_lease=root_lease)
        try:
            snapshot = owner._recover(False)
            owner._check_root()
            return owner, snapshot
        except BaseException:
            owner.close()
            raise

    def _image_prefix(self):return b'QPREFW01'+self._binding

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
        head = self._recover_image(creation)
        self._query(head)
        return head

    def _recover_image(self, creation):
        # Reconcile only the exact authenticated local intent. The caller must
        # still authenticate this recovered head through _query or _authorize
        # before returning a snapshot or releasing an operation's result.
        require(not creation, "use explicit witnessed genesis recovery")
        directory = self._admit(); wire = directory.read("head")
        if wire is None:
            raise MissingState("missing original witnessed image")
        pending = directory.read("intent");head = self._opening_head(wire,pending)
        if pending is not None:
            require(pending[:8] not in (b"QPRFLI01", b"QPRFLI02"), "local renewal coordination remains pending")
            require(not pending.startswith(b"QPRFRI01"), "roster coordination remains pending")
            require(not pending.startswith(b"QPRFPI01"), "policy coordination remains pending")
            revision, prior, target, result = self._decode_intent(pending)
            require(revision > 0, "inactive creation requires explicit genesis recovery")
            if head.digest != result.digest and (head.revision != revision or head.digest != prior):
                raise Conflict("witness intent does not name the current local image")
            self._advance(revision, prior, result)
            if head.digest != result.digest:
                directory.publish("head", target)
            directory.remove_intent(); head = result
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
        from .local_authority_control import read
        expected = Head(1, snapshot.revision, snapshot.digest)
        authority = self.profile.authority if authority is None else authority
        control = read(self)
        require(control is None or control.ready(), "authority coordination remains pending")
        policy = None if control is None else control.policy
        operation = (Operation.authority(authority) if policy is None or policy.active is None
                     else Operation.policy_authority(authority, policy.active[40:]))
        reply = self.client.exchange(operation)
        require(reply.head == expected, "witness head differs from original local image")
        require(reply.outcome == 5, "witness current authority denied")
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
            if operational:
                # The fresh signed authority reply authenticates both the exact
                # recovered head and current permission. A preceding Query
                # repeats the head check; it does not add authorization. This
                # is one fresh exchange, not a cached permission or reply.
                snapshot = self._recover_image(False)
                self._authorize(snapshot, authority)
            else:
                self._recover(False)
        except BaseException:
            self.close()
            raise

    @locked
    def close(self):
        if self.client is not None:
            self.client.close()
        super().close()
