"""Policy-only continuation under the original local registered journal lease."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import contextmanager
from dataclasses import replace
import threading
from .authority import authenticate_policy
from .durable import Session
from .enrollment_exchange import PolicyInputs
from .identity_state import local_view
from .journal import LocalSessionJournal, locked
from .local_authority_control import admit_snapshot
from .owner_guard import coordinated
from .policy_record import Grant, Record, retained_device
from .policy_snapshot import current_device, original, validate
from .renewal import field
from .state_codec import decode, encode
from .wire import Reader, require
from .witness import fixed


class LocalPolicyRenewal:
    def __init__(self, journal, context, operation, inputs):
        self._journal, self._context, self.operation, self._inputs = journal, context, operation, inputs
        self._lock, self._busy = threading.RLock(), False

    @classmethod
    def open(cls, path, scope, key, context, operation, inputs, *, observer=None):
        require(context.witness is None, "required policy renewal needs its witness coordinator")
        Session._scope(context, scope)
        fixed(operation, 32)
        original(context)
        first = retained_device(context.devices[0], inputs.materials.initiator_credential,
                                inputs.materials.initiator_roster, context.devices[0].pin.checkpoint(), context.family)
        require(first == context.devices[0], "policy original credential inputs differ")
        journal = LocalSessionJournal.open(path, scope, key, Session._validator(context), observer=observer)
        owner = cls(journal, context, operation, inputs)
        try:
            with owner._state():
                pass
            return owner
        except BaseException:
            owner.close()
            raise

    @contextmanager
    def _state(self):
        snapshot = self._journal.read()
        state = decode(snapshot.payload, self._context)
        try:
            require(state.traffic is not None, "policy renewal requires original established session")
            # A P coordinator may inspect its own Pending but cannot bypass G/R.
            admit_snapshot(self._journal, replace(state, policy_renewal=None, policy_journal=None))
            if state.policy_renewal is not None:
                validate(state, self._context, self._journal.scope.identity)
            record = state.policy_renewal or Record()
            current = current_device(state, self._context)
            yield snapshot, state, record, current
        finally:
            state.close()

    def _arguments(self, current):
        return original(self._context), self._context.devices[0], self._journal.scope.identity, current

    @staticmethod
    def _time(state, now):
        for record in (state.account_renewal, state.local_renewal):
            if record is not None:
                record.current_time(now)

    def _certificate(self, state, current):
        view = local_view(state, self._context)
        if view is None or view.renewal is None:
            wire = self._inputs.materials.initiator_credential
        else:
            reader = Reader(view.renewal.wire)
            require(reader.take(8) == b"QPRNB001", "retained credential grant tag")
            signed, first, prior, wire = (field(reader) for _ in range(4))
        checked = retained_device(self._context.devices[0], wire, current.roster_wire,
                                  current.pin.checkpoint(), self._context.family)
        require(checked == current, "policy current credential differs from actual journal")
        return wire

    def _save(self, snapshot, state, record, label):
        state.policy_renewal, state.policy_journal = record, self._journal.scope.identity
        if state.format_version < 5:
            state.format_version = 5
        sealed = self._journal.update(snapshot.digest, encode(state))
        self._journal._admit().observe("local-policy:" + label)
        require(self._journal.read().digest == sealed.digest, "policy transition durable readback")

    @coordinated
    def request(self):
        try:
            with self._state() as (_, state, record, current):
                scope = record.request(self.operation, *self._arguments(current))
                previous = original(self._context) if record.active is None else record.active.target
                return {"scope": scope.wire(), "original_policy": original(self._context).wire,
                        "previous_policy": previous.wire,
                        "original_credential": self._inputs.materials.initiator_credential,
                        "original_roster": self._inputs.materials.initiator_roster,
                        "current_credential": self._certificate(state, current), "current_roster": current.roster_wire}
        except BaseException:
            self.close()
            raise

    @coordinated
    def stage(self, approval, policy_pins, policy_materials, now):
        try:
            inputs = PolicyInputs.from_trusted(policy_pins, policy_materials)
            require(inputs.witness is None, "local policy cannot introduce a witness")
            target = authenticate_policy(inputs.pins, inputs.materials, now)
            with self._state() as (snapshot, state, record, current):
                self._time(state, now)
                args = self._arguments(current)
                known = record.known(self.operation)
                if known is not None:
                    require(known["status"] != "ExpiredUncommitted", "abandoned policy cannot be restaged")
                    held = record.pending if known["status"] == "Pending" else record.active
                    scope, previous = held.approval.scope, held.previous
                else:
                    scope = record.request(self.operation, *args)
                    previous = args[0] if record.active is None else record.active.target
                grant = Grant.current_inputs(approval, scope, args[0], previous, target, args[1],
                                             self._certificate(state, current), current.roster_wire, now)
                pending = record.stage(grant, *args, now)
                if pending is not record:
                    # Preflight the committed representation before reserving
                    # Pending; business cannot drain while this operation waits.
                    committed = pending.commit(self.operation, *args, now)
                    encode(replace(state, policy_renewal=committed, policy_journal=args[2]))
                    self._save(snapshot, state, pending, "staged")
                return pending.status(self.operation)
        except BaseException:
            self.close()
            raise

    @coordinated
    def commit(self, now):
        try:
            with self._state() as (snapshot, state, record, current):
                if record.status(self.operation)["status"] == "Pending":
                    self._time(state, now)
                committed = record.commit(self.operation, *self._arguments(current), now)
                if committed is not record:
                    self._save(snapshot, state, committed, "committed")
                return committed.status(self.operation)
        except BaseException:
            self.close()
            raise

    @coordinated
    def reconcile_expired(self, now):
        try:
            with self._state() as (snapshot, state, record, current):
                if record.status(self.operation)["status"] == "Pending":
                    self._time(state, now)
                expired = record.reconcile_expired(self.operation, *self._arguments(current), now,
                                                   snapshot.revision, snapshot.digest)
                if expired is not record:
                    self._save(snapshot, state, expired, "expired-uncommitted")
                return expired.status(self.operation)
        except BaseException:
            self.close()
            raise

    @coordinated
    def status(self):
        try:
            with self._state() as (_, _, record, _):
                return record.status(self.operation)
        except BaseException:
            self.close()
            raise

    @locked
    def close(self):
        self._journal.close()
