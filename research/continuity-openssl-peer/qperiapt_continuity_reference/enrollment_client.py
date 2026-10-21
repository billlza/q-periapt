"""Durable local enrollment coordination; account authorization remains external.

The host retains a stable client ID and wrapping key. The existing journal stores
the original trusted authority/invitation, and Registration owns the device key.
No private signing material is copied into configuration or returned to callers.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from dataclasses import replace
import os
import threading
import time

from .enrollment_exchange import (HostInvitation, CurrentMembership,
                                 IssuedEnrollment, PolicyInputs, accept_issued)
from .journal import Journal, MissingState, Scope, locked
from .owner_guard import coordinated
from .private_files import PrivateDirectory, DirectoryBusy
from .registration import Registration
from .wire import ldh, require
from .account_binding import check as check_root
from .client_configuration import Configuration

DOMAIN = b'Q-PERIAPT-REFERENCE-CLIENT/v1/'


def root_lease(path, run):
    if run is None: return PrivateDirectory(path)
    from .connection_run import Run
    require(isinstance(run, Run), 'bounded original owner admission')
    while True:
        run.check()
        try:
            lease = PrivateDirectory(path)
        except DirectoryBusy:
            time.sleep(min(.025, max(0, run.deadline - time.monotonic())))
        else:
            try:
                run.check()
                return lease
            except BaseException:
                lease.close()
                raise


def scope(client_id):
    return Scope(client_id, ldh(DOMAIN + b'owner', b''), ldh(DOMAIN + b'configuration', b''))


class EnrollmentClient:
    """One original device enrollment, serialized across processes and threads.

    `begin` requires an empty, existing private directory. `open` only recovers
    authenticated original journals; it never calls `Registration.provision`.
    After acceptance, prepare the original child and borrow its existing
    session or recovery operations. Closing this client revokes every child.
    """
    def __init__(self, path, observer, run=None):
        self._lock = threading.RLock(); self._busy = False
        self._root = root_lease(path, run)
        self._configuration = None; self._registration = None
        self._observer = observer
        self._original = None; self._authority = None
        self._root_lease=None

    def _observe(self, prefix):
        def observe(stage):
            if self._observer is not None: self._observer(prefix + stage)
            self._alive()
        return observe

    def _alive(self):
        require(self._root is not None, 'closed enrollment client')
        self._root.check()
        check_root(self._root_lease)

    @classmethod
    def begin(cls, path, client_id, key, authority, invitation, now, *, observer=None):
        require(type(key) is bytes and len(key) == 32, 'client wrapping key size')
        configuration = Configuration(authority, invitation, os.urandom(32), False)
        _, original = configuration.inputs()
        original.intent.validity.check(now)
        require(now < original.deadline, 'new client invitation approval deadline expired')
        context = scope(client_id)
        owner = cls(path, observer)
        try:
            require(not os.listdir(owner._root.fd), 'new client directory is not empty')
            for name in ('configuration', 'registration'):
                os.mkdir(name, 0o700, dir_fd=owner._root.fd)
            os.fsync(owner._root.fd)
            owner._configuration = Journal.create(path / 'configuration', context, key, configuration.wire(),
                                                 Configuration.read, owner._observe('client-config:'))
            owner._registration = Registration.provision(path / 'registration', configuration.registration,
                                                        key, original.intent, observer=owner._observe('client-device:'), _parent=owner)
            owner._finish(configuration)
            return owner
        except BaseException:
            owner.close(); raise

    @classmethod
    def open(cls, path, client_id, key, *, observer=None, run=None,account_authority=None):
        """Open original state; an optional Run bounds only initial lease contention.

        Admission polls every 25 ms within the original Run (at most 120 seconds)
        and cancellation. Configuration recovery and protocol work never retry.
        """
        owner = cls(path, observer, run)
        try:
            arguments = (path / 'configuration', scope(client_id), key, Configuration.read)
            try:
                owner._configuration = Journal.open(*arguments, observer=owner._observe('client-config:'))
            except MissingState:
                # Only an authenticated revision-zero intent can recover first
                # publication. This never creates a missing configuration.
                owner._configuration = Journal.open(*arguments, creation=True, observer=owner._observe('client-config:'))
            configuration = Configuration.read(owner._configuration.read().payload)
            _, original = configuration.inputs()
            if configuration.root_binding is not None:
                from .client_root import selected
                owner._root_lease=selected(configuration,account_authority)
            else:require(account_authority is None,'client has no retained root association; bind it explicitly')
            owner._registration = Registration.open(path / 'registration', configuration.registration,
                                                    key, original.intent, recover_initial=not configuration.ready,
                                                    observer=owner._observe('client-device:'), _parent=owner,
                                                    root_lease=owner._root_lease,
                                                    _pending_binding=configuration.root_binding if not configuration.root_ready else None)
            owner._finish(configuration)
            if configuration.root_binding is not None:
                from .client_root import finish
                finish(owner,configuration)
            if run is not None: run.check()
            return owner
        except BaseException:
            owner.close(); raise

    def _finish(self, configuration):
        if not configuration.ready:
            snapshot = self._configuration.read()
            require(Configuration.read(snapshot.payload) == configuration, 'client preparation changed')
            self._configuration.update(snapshot.digest, replace(configuration, ready=True).wire())
        current = Configuration.read(self._configuration.read().payload)
        require(current == replace(configuration, ready=True), 'client readiness readback differs')
        self._authority, self._original = current.inputs()
        self._alive()

    @coordinated
    def bind_account_root(self,registry):
        """Retain the original application registry before preparing a session."""
        try:
            from .client_root import bind
            return bind(self,registry)
        except BaseException:self.close();raise

    @coordinated
    def prepare_account_root(self,registry,plan):
        """Consume this client's live facade and retain the original approved operation."""
        try:
            from .client_root_recovery import begin
            return begin(self,registry,plan)
        except BaseException:self.close();raise

    @coordinated
    def request(self, now):
        try:
            self._alive(); result = self._registration.request(now); self._alive()
            return result
        except BaseException:
            self.close(); raise

    @coordinated
    def status(self):
        try:
            self._alive(); result = self._registration.status(); self._alive()
            configuration = Configuration.read(self._configuration.read().payload)
            issued = None if configuration.issuance is None else HostInvitation.decode(configuration.issuance, self._authority).operation
            return dict(result, application=self._authority.application, operation=self._original.operation, issued_operation=issued)
        except BaseException:
            self.close(); raise

    @coordinated
    def accept(self, approved, issued, current, policy_pins, policy_materials, now):
        try:
            self._alive()
            result = accept_issued(self._registration, self._original,
                                   HostInvitation.decode(approved, self._authority), IssuedEnrollment.decode(issued),
                                   CurrentMembership.from_trusted(current, self._authority),
                                   PolicyInputs.from_trusted(policy_pins, policy_materials), now)
            self._bind_issuance(approved, issued)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    def _issued(self):
        configuration = Configuration.read(self._configuration.read().payload)
        require(configuration.issuance is not None,
                'original issuance association missing; bind approved enrollment metadata')
        return HostInvitation.decode(configuration.issuance, self._authority)

    def _bind_issuance(self, approved, issued):
        invitation = HostInvitation.decode(approved, self._authority)
        self._original.same_device(invitation)
        received = IssuedEnrollment.decode(issued); received.verify_history(invitation)
        self._registration.verify_original_credential(received.certificate)
        snapshot = self._configuration.read(); configuration = Configuration.read(snapshot.payload)
        if configuration.issuance is not None:
            require(HostInvitation.decode(configuration.issuance, self._authority) == invitation,
                    'conflicting original issuance association')
        else:
            self._configuration.update(snapshot.digest, replace(configuration, issuance=approved).wire())
        require(self._issued() == invitation, 'issuance association durable readback differs')
        return invitation.operation

    @coordinated
    def bind_issuance(self, approved, issued):
        """Recover historical issuer correlation without changing live authority.

        Supply the independently approved invitation and its original issued
        credential. This also upgrades accepted v1 configurations, including
        expired owners; it neither accepts credentials nor prepares a child.
        """
        try:
            self._alive(); result = self._bind_issuance(approved, issued)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def refresh_roster(self, current, policy_pins, policy_materials, now):
        """Refresh independent membership before preparing this device's child."""
        try:
            self._alive()
            membership = CurrentMembership.from_trusted(current, self._authority)
            policy = PolicyInputs.from_trusted(policy_pins, policy_materials)
            result = self._registration.refresh_roster(
                membership.wire, membership.pin(self._original), policy.pins, policy.materials,
                now, witness_pin=policy.witness)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def adopt_extension(self, approved_enrollment, approved_extension, issued, current,
                        policy_pins, policy_materials, now):
        """Explicit same-key extension before selecting any child installation."""
        try:
            from .enrollment_extension import ExtensionApproval, IssuedExtension
            self._alive()
            enrollment = HostInvitation.decode(approved_enrollment, self._authority)
            self._original.same_device(enrollment)
            require(enrollment == self._issued(), 'extension differs from retained issued enrollment')
            approval = ExtensionApproval.from_trusted(approved_extension)
            received = IssuedExtension.decode(issued)
            require(approval.enrollment == enrollment.operation and received.revision == self._authority.revision,
                    'extension differs from independently approved enrollment or root revision')
            membership = CurrentMembership.from_trusted(current, self._authority)
            policy = PolicyInputs.from_trusted(policy_pins, policy_materials)
            result = self._registration.adopt_extension(approval, received, membership.wire, membership.pin(enrollment), policy, now)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def prepare(self, path, inputs, now):
        """Prepare or recover the same accepted child with independent trust inputs."""
        try:
            self._alive()
            # Keep the child outside configuration and device ownership. Each
            # journal has its own lease and fixed on-disk record inventory.
            require(path != self._root.path and not path.is_relative_to(self._root.path)
                    and not self._root.path.is_relative_to(path),
                    'client and session directories must be separate')
            result = self._registration.prepare(path, inputs, now)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def session(self, now, *, transport=None):
        """Borrow the original session; the owning client must remain open."""
        try:
            self._alive(); result = self._registration.session(now, transport=transport)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def confirm_connection(self, session, proof, now, *, transport=None):
        """Record actual authenticated peer confirmation in the original owner."""
        try:
            self._alive(); result=self._registration.confirm_connection(session,proof,now,transport=transport)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def connection_confirmation(self):
        """Historical peer-confirmation metadata, never current permission."""
        try:
            self._alive(); result=self._registration.connection_confirmation()
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def connection_session(self, now, *, transport=None):
        """Borrow recorded peer-confirmed traffic without a new bootstrap."""
        try:
            self._alive(); result=self._registration.connection_session(now,transport=transport)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def connect(self,transport,run,*,witness_transport=None):
        """Establish/reconcile this original child and its authenticated READY."""
        try:
            from .connection import Connection
            self._alive(); result=Connection._connect(self,transport,run,witness_transport)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def reopen_connection(self,run,*,witness_transport=None):
        """Open recorded original traffic; performs no network or bootstrap."""
        try:
            from .connection import Connection
            self._alive(); result=Connection._open(self,run,witness_transport)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def credential_renewal_request(self, operation, now, *, transport=None):
        """Public issuer request from the original enrollment and current journal."""
        try:
            from .credential_request import for_host
            self._alive()
            with self._registration.credential_renewal(operation, now, transport=transport) as child:
                result = for_host(self._issued(), child.request())
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def prepare_credential_renewal(self, operation, issued, current, now, *, transport=None, companion_grants=None):
        """Prepare original credential maintenance; commitment remains separate.

        The original profile chooses local Pending or a witnessed proposal.
        Explicit companion_grants selects the complete-account path. An empty
        supplied set is valid only if retained membership needs no companions.
        """
        try:
            from .credential_inputs import selected, companions
            self._alive()
            identity = self._registration.status()['journal']
            chosen, wire, target, statement = selected(issued, current, self._authority, self._issued(), identity, now)
            require(chosen == operation, 'credential issuance differs from selected operation')
            account = None if companion_grants is None else companions(companion_grants, self._authority, target)
            with self._registration.credential_renewal(operation, now, transport=transport) as child:
                if account is not None:
                    wires, expected = account
                    if transport is None:
                        result = child.stage_account(wire, wires, target, now,
                                                     expected_statement=statement, expected_companions=expected)
                    else:
                        child.prepare_account(wire, wires, target, now,
                                              expected_statement=statement, expected_companions=expected)
                        result = child.preparation()
                elif transport is None:
                    result = child.stage(wire, target, now, expected_statement=statement)
                else:
                    child.prepare(wire, target, now, expected_statement=statement)
                    result = child.preparation()
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def credential_renewal(self, operation, now, *, transport=None):
        """Borrow local/joint renewal without creating a replacement registration."""
        try:
            self._alive()
            result = self._registration.credential_renewal(operation, now, transport=transport)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def policy_renewal_request(self, operation, now, *, transport=None):
        """Export issuer context from the original owned session, including expiry.

        This observes protected state; it grants no account permission, signature,
        reservation or traffic authority. Keep the original export across retries.
        """
        try:
            from .policy_request import for_host
            self._alive()
            with self._registration.policy_renewal(operation, now, transport=transport) as child:
                result = for_host(self._issued(), child.request())
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def policy_renewal(self, operation, now, *, transport=None):
        """Borrow original policy-only maintenance; target trust stays explicit."""
        try:
            self._alive()
            result = self._registration.policy_renewal(operation, now, transport=transport)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @coordinated
    def pending_write_recovery(self, now, *, transport):
        """Borrow original witnessed recovery; this does not renew authority."""
        try:
            self._alive(); result = self._registration.pending_write_recovery(now, transport=transport)
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @locked
    def close(self):
        root, self._root = self._root, None
        configuration, self._configuration = self._configuration, None
        registration, self._registration = self._registration, None
        self._root_lease=None
        try:
            if registration is not None: registration.close()
        finally:
            try:
                if configuration is not None: configuration.close()
            finally:
                if root is not None: root.close()
