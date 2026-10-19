"""Durable local enrollment coordination; account authorization remains external.

The host retains a stable client ID and wrapping key. The existing journal stores
the original trusted authority/invitation, and Registration owns the device key.
No private signing material is copied into configuration or returned to callers.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import base64
from dataclasses import dataclass, replace
import json
import os
import threading

from .enrollment_exchange import (HostAuthority, HostInvitation, CurrentMembership,
                                 IssuedEnrollment, PolicyInputs, accept_issued,
                                 decode, encoded, identifier)
from .journal import Journal, MissingState, Scope, locked
from .owner_guard import coordinated
from .private_files import PrivateDirectory
from .registration import Registration
from .wire import ldh, require

DOMAIN = b'Q-PERIAPT-REFERENCE-CLIENT/v1/'


def scope(client_id):
    return Scope(client_id, ldh(DOMAIN + b'owner', b''), ldh(DOMAIN + b'configuration', b''))


@dataclass(frozen=True)
class Configuration:
    authority: bytes
    invitation: bytes
    registration: bytes
    ready: bool

    def inputs(self):
        authority = HostAuthority.from_trusted(self.authority)
        return authority, HostInvitation.decode(self.invitation, authority)

    def wire(self):
        b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b'=').decode()
        return json.dumps({'schema':'qperiapt-client-configuration/1',
                           'authority':b64(self.authority), 'invitation':b64(self.invitation),
                           'registration':list(self.registration), 'ready':self.ready},
                          separators=(',', ':')).encode()

    @classmethod
    def read(cls, raw):
        value = decode(raw, 'schema authority invitation registration ready', 48 * 1024)
        require(value['schema'] == 'qperiapt-client-configuration/1' and type(value['ready']) is bool,
                'client configuration schema or phase')
        result = cls(encoded(value['authority'], 16384), encoded(value['invitation'], 16384),
                     identifier(value['registration']), value['ready'])
        result.inputs()
        return result


class EnrollmentClient:
    """One original device enrollment, serialized across processes and threads.

    `begin` requires an empty, existing private directory. `open` only recovers
    authenticated original journals; it never calls `Registration.provision`.
    After acceptance, session/bootstrap operations remain on the Registration
    API; this wrapper does not yet expose the complete session lifecycle.
    """
    def __init__(self, path, observer):
        self._lock = threading.RLock(); self._busy = False
        self._root = PrivateDirectory(path)
        self._configuration = None; self._registration = None
        self._observer = observer
        self._original = None; self._authority = None

    def _observe(self, prefix):
        def observe(stage):
            if self._observer is not None: self._observer(prefix + stage)
            self._alive()
        return observe

    def _alive(self):
        require(self._root is not None, 'closed enrollment client')
        self._root.check()

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
                                                        key, original.intent, observer=owner._observe('client-device:'))
            owner._finish(configuration)
            return owner
        except BaseException:
            owner.close(); raise

    @classmethod
    def open(cls, path, client_id, key, *, observer=None):
        owner = cls(path, observer)
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
            owner._registration = Registration.open(path / 'registration', configuration.registration,
                                                    key, original.intent, recover_initial=not configuration.ready,
                                                    observer=owner._observe('client-device:'))
            owner._finish(configuration)
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
            return dict(result, application=self._authority.application, operation=self._original.operation)
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
            self._alive(); return result
        except BaseException:
            self.close(); raise

    @locked
    def close(self):
        root, self._root = self._root, None
        configuration, self._configuration = self._configuration, None
        registration, self._registration = self._registration, None
        try:
            if registration is not None: registration.close()
        finally:
            try:
                if configuration is not None: configuration.close()
            finally:
                if root is not None: root.close()
