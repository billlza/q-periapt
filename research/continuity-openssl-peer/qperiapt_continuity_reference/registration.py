"""Original protected device registration, independent approval and child ownership."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import os
import threading
from dataclasses import replace
from .authority import authenticate_policy
from .identity import verify_device
from .journal import Journal, locked
from .owner_guard import coordinated
from .registration_protocol import request_body
from .registration_state import Admission, Image, PHASES, seed_from, signer
from .wire import SigningKey, require


class RegistrationJournal(Journal):
    # Opt in only for original device creation. Session/configuration journals
    # retain their existing publication/discovery contract.
    reserved_creation = True


class Registration:
    def __init__(self, journal, key, intent, observer, parent=None):
        self._journal, self._key, self._intent, self._observer = journal, key, intent, observer
        self._parent = parent
        self._lock = threading.RLock() if parent is None else parent._lock
        self._busy = False; self._child = None

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
    def provision(cls, path, registration_id, key, intent, *, observer=None, _parent=None):
        # First use is explicit. A missing/failed open never selects this method.
        value = Image(os.urandom(32), seed_from(SigningKey()))
        journal = RegistrationJournal.create(path, intent.scope(registration_id), key, value.encode(intent), cls._validator(intent), cls._store_observer(observer))
        return cls(journal, key, intent, observer, _parent)

    @classmethod
    def open(cls, path, registration_id, key, intent, *, recover_initial=False, observer=None, _parent=None):
        journal = RegistrationJournal.open(path, intent.scope(registration_id), key, cls._validator(intent), creation=recover_initial, observer=cls._store_observer(observer))
        return cls(journal, key, intent, observer, _parent)

    def _alive(self):
        if self._parent is not None: self._parent._alive()
        require(self._journal is not None, 'closed registration owner')
        self._journal._admit()

    def _close_after_error(self):
        # A borrowed operation must revoke the whole owning client, including
        # its configuration lease. Both layers use the same reentrant lock.
        if self._parent is not None: self._parent.close()
        else: self.close()

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
            if image.extension is not None:
                approved = image.extension.approval
                result['credential_extension'] = {'request_id':approved.identity, 'enrollment':approved.enrollment,
                    'previous_extension':approved.previous, 'valid_until':approved.until,
                    'roster_checkpoint':image.extension.admission.checkpoint, 'policy_checkpoint':image.extension.admission.policy}
            self._alive(); return result
        except BaseException: self._close_after_error(); raise

    @coordinated
    def verify_original_credential(self, certificate):
        """Compare historical issuer input with the retained original admission.

        No time-based authorization or state mutation occurs. The original
        credential survives extensions and child policy/credential renewals.
        """
        try:
            from .identity import credential
            _, image = self._image()
            require(image.admission is not None, 'original registration is not accepted')
            expected = image.admission.validate(self._intent, signer(image.seed).public())
            received = credential(image.admission.pin(self._intent), certificate, self._intent.family)
            require(received.digest == expected.digest, 'issuance changes original accepted credential')
            self._alive()
        except BaseException: self._close_after_error(); raise

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
        except BaseException: self._close_after_error(); raise

    @coordinated
    def accept(self, certificate, roster, pin, policy_pins, policy_materials, now, *, witness_pin=None):
        try:
            snapshot, image = self._image(); require(bool(image.request), 'registration request not committed')
            require(image.extension is None, 'registration already adopted a credential extension')
            public = signer(image.seed).public()
            require(self._intent.verify_request(image.request, now) == (image.identity, public), 'registration original request')
            policy = authenticate_policy(policy_pins, policy_materials, now, witness_pin=witness_pin)
            require(policy.family == self._intent.family, 'registration approved policy family differs')
            device = verify_device(pin, certificate, roster, policy.family, now); self._intent.admit_device(device, public)
            self._check_policy_keys(public, policy_pins, witness_pin)
            policy_head = policy.version.to_bytes(8, 'big') + policy.digest
            if image.admission is not None:
                previous = image.admission.validate(self._intent, public)
                require(image.admission.checkpoint == pin.checkpoint() and image.admission.policy == policy_head
                        and previous.digest == device.credential, 'conflicting original registration admission')
            else:
                image.admission = Admission(pin.checkpoint(), policy_head, os.urandom(32), certificate, roster)
                snapshot, image = self._save(snapshot, image, 'acceptance-committed')
            self._alive(); return image.admission.journal
        except BaseException: self._close_after_error(); raise

    def _check_policy_keys(self, public, policy_pins, witness_pin):
        require(not public.shares_component(policy_pins.policy_root) and public.raw[:1952] != policy_pins.sdk_root,
                'registration device/policy key separation')
        if witness_pin is not None:
            require(not witness_pin.key.shares_component(public) and not witness_pin.key.shares_component(self._intent.root),
                    'registration witness/device/account key separation')

    @coordinated
    def adopt_extension(self, approval, issued, roster, pin, policy, now):
        try:
            from .registration_extension import adopt
            return adopt(self, approval, issued, roster, pin, policy, now)
        except BaseException: self._close_after_error(); raise

    @coordinated
    def refresh_roster(self, roster, pin, policy_pins, policy_materials, now, *, witness_pin=None):
        """Adopt a current same-credential roster before an original child exists."""
        try:
            snapshot, image = self._image()
            require(image.admission is not None, 'registration is not accepted')
            require(image.child is None and not image.active, 'registration child was already prepared')
            intent, admission = image.effective(self._intent)
            policy = authenticate_policy(policy_pins, policy_materials, now, witness_pin=witness_pin)
            require(policy.family == intent.family
                    and policy.version.to_bytes(8, 'big') + policy.digest == admission.policy,
                    'roster refresh cannot change the admitted policy')
            public = signer(image.seed).public()
            device = verify_device(pin, admission.certificate, roster, policy.family, now)
            intent.admit_device(device, public)
            previous = admission.pin(intent)
            require(pin.roster_version >= previous.roster_version, 'roster checkpoint cannot roll back')
            if pin.roster_version == previous.roster_version:
                require(pin.checkpoint() == previous.checkpoint(), 'different roster at the retained version')
                self._alive(); return previous.checkpoint()
            updated = replace(admission, checkpoint=pin.checkpoint(), roster=roster)
            if image.extension is None: image.admission = updated
            else: image.extension = replace(image.extension, admission=updated)
            _, image = self._save(snapshot, image, 'roster-refreshed')
            self._alive(); return image.effective(self._intent)[1].checkpoint
        except BaseException: self._close_after_error(); raise

    @coordinated
    def prepare(self, path, inputs, now):
        try:
            from .registration_session import prepare
            return prepare(self, path, inputs, now)
        except BaseException: self._close_after_error(); raise

    @coordinated
    def session(self, now, *, transport=None):
        try:
            from .registration_session import open_child
            return open_child(self, 'session', now, transport=transport)
        except BaseException: self._close_after_error(); raise

    @coordinated
    def confirm_connection(self, session, proof, now, *, transport=None):
        """Verify READY and persist its exact original evidence before success."""
        try:
            from .registration_connection import confirm
            return confirm(self,session,proof,now,transport)
        except BaseException: self._close_after_error(); raise

    @coordinated
    def connection_confirmation(self):
        """Historical recorded session ID, or None when no proof was recorded."""
        try:
            _,image=self._image()
            result=None if image.confirmation is None else image.confirmation.session
            self._alive(); return result
        except BaseException: self._close_after_error(); raise

    @coordinated
    def connection_session(self, now, *, transport=None):
        """Reopen only recorded peer-confirmed traffic, with current admission."""
        try:
            from .registration_session import open_child
            return open_child(self,'connection',now,transport=transport)
        except BaseException: self._close_after_error(); raise

    @coordinated
    def credential_renewal(self, operation, now, *, transport=None):
        try:
            from .registration_session import open_child
            return open_child(self, 'credential', now, operation=operation, transport=transport)
        except BaseException: self._close_after_error(); raise

    @coordinated
    def policy_renewal(self, operation, now, *, transport=None):
        try:
            from .registration_session import open_child
            return open_child(self, 'policy', now, operation=operation, transport=transport)
        except BaseException: self._close_after_error(); raise

    @coordinated
    def roster_refresh(self, operation, now, *, transport=None):
        try:
            from .registration_session import open_child
            return open_child(self, 'roster', now, operation=operation, transport=transport)
        except BaseException: self._close_after_error(); raise

    @coordinated
    def pending_write_recovery(self, now, *, transport):
        try:
            from .registration_session import open_child
            return open_child(self, 'pending', now, transport=transport)
        except BaseException: self._close_after_error(); raise

    @locked
    def close(self):
        # All exposed child calls acquire this lease before their protocol lock.
        # Reentrant close can revoke the result before it leaves a callback.
        child, self._child = self._child, None
        journal, self._journal = self._journal, None; self._key = None
        self._parent = None
        try:
            if child is not None: child._close()
        finally:
            if journal is not None: journal.close()
