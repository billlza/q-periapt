"""Explicit original-parent/child root migration; no traffic facade while pending."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import threading
import weakref
from .account_authority import AccountAuthority
from .client_configuration import Configuration
from .client_root import selected as select_root
from .client_root_recovery import _close_owners
from .journal import Journal
from .owner_guard import coordinated
from .private_files import PrivateDirectory
from .registered_owner import _Signer
from .registration import RegistrationJournal
from .registration_session import selected, validate_context
from .registration_state import Image
from .root_adoption_journal import finish, preflight
from .wire import require
from .witness import Client


def _retained(journal):
    """Authenticate an ordinary retained target without publishing or removing it."""
    directory = journal._admit(); wire = directory.read('head'); pending = directory.read('intent')
    require(wire is not None, 'missing original client configuration')
    snapshot = journal._decode(wire)
    if pending is not None:
        revision, prior, _target, result = journal._decode_intent(pending)
        require(snapshot.digest == result.digest or (snapshot.revision, snapshot.digest) == (revision, prior),
                'root adoption configuration intent differs')
        snapshot = result
    return snapshot


def _configuration(journal):
    """Authenticate the retained target before registry selection or any write."""
    value = Configuration.read(_retained(journal).payload)
    require(value.ready and value.root_adoption and value.root_binding is not None,
            'no original client root adoption')
    return value


def _child(parent, image, now, transport):
    require(image.child is not None, 'root adoption requires original child')
    context = image.child.inputs.original(image.child.context, now)
    validate_context(parent, image, context)
    scope, key = selected(parent, image, context)
    if context.witness is None:
        require(transport is None, 'local root adoption has no witness carrier'); client = None
    else:
        require(transport is not None, 'required witness carrier is missing')
        client = Client(context.witness.pin, context.witness.subject(scope.identity), _Signer(parent), transport)
    return image.child.path, scope, key, context, client


class RootAdoption:
    """Original migration metadata and exact pending recovery, never a Session.

    `commit` returns a normal EnrollmentClient only after child, registration
    and configuration agree. Each call uses its supplied witness carrier.
    A fully committed child may finish parent metadata after expiry; subsequent
    communication still performs normal current credential/policy admission.
    """
    def __init__(self):
        self._lock = threading.RLock(); self._busy = False; self._owners = []
        self._root = None; self._root_lease = None; self._configuration = None
        self._journal = None; self._key = None
        self._finalizer = weakref.finalize(self, _close_owners, self._owners)

    @classmethod
    def open(cls, path, client_id, key, registry, *, observer=None, _genesis=None):
        from .enrollment_client import scope
        require(type(registry) is AccountAuthority, 'original account registry required')
        owner = cls()
        try:
            owner._root = PrivateDirectory(path); owner._owners.append(owner._root)
            owner._configuration = Journal(path / 'configuration', scope(client_id), key, Configuration.read)
            owner._owners.append(owner._configuration)
            configuration = _configuration(owner._configuration)
            owner._root_lease = select_root(configuration, registry)
            owner._registry = weakref.ref(registry); owner._observer = observer; owner._genesis = _genesis
            owner._authority, invitation = configuration.inputs(); owner._intent = invitation.intent
            owner._key = key; owner._ready = configuration.root_ready
            owner._configuration._directory.observer = owner._observe('client-config:')
            require(Configuration.read(owner._configuration.read().payload) == configuration,
                    'original root adoption configuration changed')
            intent = owner._intent
            journal, _snapshot = RegistrationJournal._open(path / 'registration', intent.scope(configuration.registration),
                key, lambda raw: Image.decode(raw, intent), observer=owner._observe('client-device:registration-store:'))
            owner._journal = journal; owner._owners.append(journal)
            owner._image(); owner._alive(); return owner
        except BaseException:
            owner.close(); raise

    def _observe(self, prefix):
        reference = weakref.ref(self); observer = self._observer
        def observe(stage):
            if observer is not None: observer(prefix + stage)
            owner = reference(); require(owner is not None, 'closed original root adoption')
            owner._alive()
        return observe

    def _alive(self):
        require(self._root is not None and self._root_lease is not None, 'closed original root adoption')
        self._root.check(); self._root_lease.check()

    def _image(self):
        self._alive(); snapshot = self._journal.read(); image = Image.decode(snapshot.payload, self._intent)
        require(image.admission is not None and image.child is not None, 'original accepted child absent')
        binding = self._root_lease.binding
        require(image.root_binding == binding if self._ready else image.root_binding in (None, binding),
                'original registration root binding differs')
        self._alive(); return snapshot, image

    @coordinated
    def status(self):
        try:
            _, image = self._image()
            value = {'root_ready': self._ready, 'registration_bound': image.root_binding is not None,
                     'binding': self._root_lease.binding, 'signing_id': image.identity,
                     'journal': image.admission.journal, 'child_path': image.child.path}
            self._alive(); return value
        except BaseException:
            self.close(); raise

    @coordinated
    def commit(self, now, *, transport=None):
        from .enrollment_client import EnrollmentClient
        try:
            snapshot, image = self._image()
            path, scope, key, context, client = _child(self, image, now, transport)
            try:
                binding = finish(path, scope, key, context, now, root_lease=self._root_lease, client=client,
                    observer=self._observe('client-root-child:'), registration_bound=image.root_binding is not None,
                    expected_genesis=self._genesis)
            finally:
                if client is not None: client.close()
            require(binding == self._root_lease.binding, 'original child binding differs')
            self._alive()
            current, retained = self._image()
            require(current == snapshot and retained == image, 'registration changed during root adoption')
            if image.root_binding is None:
                self._journal.update(snapshot.digest, replace(image, root_binding=binding).encode(self._intent))
            require(self._image()[1].root_binding == binding, 'registration binding durable readback')
            current = self._configuration.read(); configuration = Configuration.read(current.payload)
            require(configuration.root_adoption and configuration.root_binding == binding,
                    'original client root adoption changed')
            if not configuration.root_ready:
                self._configuration.update(current.digest, replace(configuration, root_ready=True).wire())
            require(Configuration.read(self._configuration.read().payload) == replace(configuration, root_ready=True),
                    'client root adoption readiness readback')
            self._ready = True; self._alive()
            registry = self._registry(); require(registry is not None, 'closed account authority owner')
            path, client_id, key, observer = self._root.path, self._configuration.scope.identity, self._key, self._observer
            self.close()
            return EnrollmentClient.open(path, client_id, key, account_authority=registry, observer=observer)
        except BaseException:
            self.close(); raise

    def _pending(self, now, transport, action):
        from .pending_recovery import PendingWriteRecovery
        _, image = self._image()
        path, scope, key, context, client = _child(self, image, now, transport)
        require(client is not None, 'pending root adoption recovery requires original witness')
        owner = None
        try:
            owner = PendingWriteRecovery.open(path, scope, key, context, client=client,
                observer=self._observe('client-root-child:'), root_lease=self._root_lease)
            result = action(owner); self._alive(); return result
        finally:
            if owner is not None: owner.close()
            client.close()

    @coordinated
    def pending_write_request(self, now, *, transport):
        try: return self._pending(now, transport, lambda owner: owner.request())
        except BaseException: self.close(); raise

    @coordinated
    def confirm_pending_write(self, proposal, metadata, now, *, transport):
        try: return self._pending(now, transport, lambda owner: owner.confirm(proposal, metadata))
        except BaseException: self.close(); raise

    def close(self):
        with self._lock:
            self._root = None; self._root_lease = None; self._journal = None
            self._configuration = None; self._key = None
            self._finalizer()

    def __enter__(self): self._alive(); return self
    def __exit__(self, *_error): self.close()


def begin(client, registry, now, *, transport=None, expected_genesis=None):
    """Preflight the actual old child before retaining a parent migration marker."""
    client._alive(); require(type(registry) is AccountAuthority, 'original account registry required')
    require(client._registration._child is None, 'close borrowed child before root adoption')
    snapshot = client._configuration.read(); configuration = Configuration.read(snapshot.payload)
    require(configuration.root_binding is None, 'client already associated; resume original root adoption explicitly')
    _, image = client._registration._image()
    require(image.admission is not None and image.child is not None, 'root adoption requires original accepted child')
    intent, admission = image.effective(client._registration._intent)
    expected = registry.associate(client._authority.application, admission.pin(intent), admission.certificate, admission.roster)
    lease = registry.admit(expected); lease.check_account(expected.account, intent.family)
    path, scope, key, context, witness = _child(client._registration, image, now, transport)
    client._root_lease = lease
    try:
        with preflight(path, scope, key, context, now, root_lease=lease, client=witness,
                       observer=client._registration._child_observer, expected_genesis=expected_genesis):
            updated = replace(configuration, root_binding=lease.binding, root_ready=False, root_adoption=True)
            client._configuration.update(snapshot.digest, updated.wire())
            require(Configuration.read(client._configuration.read().payload) == updated, 'root adoption preparation readback')
    finally:
        if witness is not None: witness.close()
    path, client_id, key, observer = client._root.path, client._configuration.scope.identity, client._registration._key, client._observer
    client.close()
    return RootAdoption.open(path, client_id, key, registry, observer=observer, _genesis=expected_genesis)
