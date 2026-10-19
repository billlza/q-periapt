"""Original protected device registration, independent approval and child ownership."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import os
import threading
from .authority import authenticate_policy
from .identity import verify_device
from .journal import Journal, locked
from .owner_guard import coordinated
from .registration_protocol import request_body
from .registration_state import Admission, Image, PHASES, seed_from, signer
from .wire import SigningKey, require


class Registration:
    def __init__(self, journal, key, intent, observer):
        self._journal, self._key, self._intent, self._observer = journal, key, intent, observer
        self._lock = threading.RLock(); self._busy = False; self._child = None

    @staticmethod
    def _store_observer(observer):
        if observer is None: return None
        return lambda stage: observer(stage if stage.startswith('registration:') else 'registration-store:' + stage)

    def _child_observer(self, stage):
        if self._observer is not None:
            storage = stage.startswith(('stage-synced:', 'published:', 'committed:', 'removed:'))
            self._observer(('session-store:' if storage else '') + stage)

    @staticmethod
    def _validator(intent):
        return lambda wire: Image.decode(wire, intent)

    @classmethod
    def provision(cls, path, registration_id, key, intent, *, observer=None):
        # First use is explicit. A missing/failed open never selects this method.
        value = Image(os.urandom(32), seed_from(SigningKey()))
        journal = Journal.create(path, intent.scope(registration_id), key, value.encode(intent), cls._validator(intent), cls._store_observer(observer))
        return cls(journal, key, intent, observer)

    @classmethod
    def open(cls, path, registration_id, key, intent, *, recover_initial=False, observer=None):
        journal = Journal.open(path, intent.scope(registration_id), key, cls._validator(intent), creation=recover_initial, observer=cls._store_observer(observer))
        return cls(journal, key, intent, observer)

    def _alive(self):
        require(self._journal is not None, 'closed registration owner')
        self._journal._admit()

    def _image(self):
        self._alive(); snapshot = self._journal.read()
        return snapshot, Image.decode(snapshot.payload, self._intent)

    def _save(self, snapshot, image, stage):
        self._alive(); result = self._journal.update(snapshot.digest, image.encode(self._intent))
        self._observe(stage)
        current, saved = self._image(); require(current.digest == result.digest, 'registration durable readback')
        return current, saved

    def _observe(self, stage):
        self._alive(); self._journal._admit().observe('registration:' + stage); self._alive()

    @coordinated
    def status(self):
        try:
            _, image = self._image()
            result = {'phase': PHASES[image.phase()], 'signing_id': image.identity,
                      'public_key': signer(image.seed).public().raw,
                      'journal': None if image.admission is None else image.admission.journal}
            self._alive(); return result
        except BaseException: self.close(); raise

    @coordinated
    def request(self, now):
        try:
            self._intent.validity.check(now); snapshot, image = self._image()
            if not image.request:
                key = signer(image.seed)
                image.request = key.sign(14, request_body(self._intent, image.identity, key.public()))
                snapshot, image = self._save(snapshot, image, 'request-committed')
            require(self._intent.verify_request(image.request, now) == (image.identity, signer(image.seed).public()),
                    'registration original signing owner differs')
            self._alive(); return image.request
        except BaseException: self.close(); raise

    @coordinated
    def accept(self, certificate, roster, pin, policy_pins, policy_materials, now, *, witness_pin=None):
        try:
            snapshot, image = self._image(); require(bool(image.request), 'registration request not committed')
            public = signer(image.seed).public()
            require(self._intent.verify_request(image.request, now) == (image.identity, public), 'registration original request')
            policy = authenticate_policy(policy_pins, policy_materials, now, witness_pin=witness_pin)
            require(policy.family == self._intent.family, 'registration approved policy family differs')
            device = verify_device(pin, certificate, roster, policy.family, now); self._intent.admit_device(device, public)
            require(not public.shares_component(policy_pins.policy_root) and public.raw[:1952] != policy_pins.sdk_root,
                    'registration device/policy key separation')
            if witness_pin is not None:
                require(not witness_pin.key.shares_component(public) and not witness_pin.key.shares_component(self._intent.root),
                        'registration witness/device/account key separation')
            policy_head = policy.version.to_bytes(8, 'big') + policy.digest
            if image.admission is not None:
                previous = image.admission.validate(self._intent, public)
                require(image.admission.checkpoint == pin.checkpoint() and image.admission.policy == policy_head
                        and previous.digest == device.credential, 'conflicting original registration admission')
            else:
                image.admission = Admission(pin.checkpoint(), policy_head, os.urandom(32), certificate, roster)
                snapshot, image = self._save(snapshot, image, 'acceptance-committed')
            self._alive(); return image.admission.journal
        except BaseException: self.close(); raise

    @coordinated
    def prepare(self, path, inputs, now):
        try:
            from .registration_session import prepare
            return prepare(self, path, inputs, now)
        except BaseException: self.close(); raise

    @coordinated
    def session(self, now, *, transport=None):
        try:
            from .registration_session import open_child
            return open_child(self, 'session', now, transport=transport)
        except BaseException: self.close(); raise

    @coordinated
    def credential_renewal(self, operation, now, *, transport=None):
        try:
            from .registration_session import open_child
            return open_child(self, 'credential', now, operation=operation, transport=transport)
        except BaseException: self.close(); raise

    @coordinated
    def pending_write_recovery(self, now, *, transport):
        try:
            from .registration_session import open_child
            return open_child(self, 'pending', now, transport=transport)
        except BaseException: self.close(); raise

    @locked
    def close(self):
        # All exposed child calls acquire this lease before their protocol lock.
        # Reentrant close can revoke the result before it leaves a callback.
        child, self._child = self._child, None
        journal, self._journal = self._journal, None; self._key = None
        try:
            if child is not None: child._close()
        finally:
            if journal is not None: journal.close()
