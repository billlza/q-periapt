"""Original local-policy credential coordination in one authenticated journal."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import contextmanager
from dataclasses import replace
import threading
from .durable import Session
from .identity_state import IdentityState
from .journal import Journal, locked
from .local_renewal_record import Record, Expired
from .owner_guard import coordinated
from .renewal import verify
from .state_codec import decode, encode
from .wire import require


class LocalCredentialRenewal:
    def __init__(self, journal, context, operation):
        self._journal, self._context, self.operation = journal, context, operation
        self._lock = threading.RLock(); self._busy = False

    @classmethod
    def open(cls, path, scope, key, context, operation, *, observer=None):
        require(context.witness is None, "local credential coordinator requires original local-only policy")
        Session._scope(context, scope)
        require(type(operation) is bytes and len(operation) == 32 and any(operation), "original local renewal operation")
        journal = Journal.open(path, scope, key, Session._validator(context), observer=observer)
        owner = cls(journal, context, operation)
        try:
            with owner._state():
                pass
            return owner
        except BaseException:
            owner.close(); raise

    @contextmanager
    def _state(self):
        require(self._journal._admit().read("authority") is None, "witness coordination in local-only store")
        snapshot = self._journal.read(); state = decode(snapshot.payload, self._context)
        try:
            require(state.traffic is not None, "local renewal requires original established session")
            current = state.local_authority or IdentityState.initial(self._context, role=0)
            record = state.local_renewal or Record()
            yield snapshot, state, current, record
        finally:
            state.close()

    def _save(self, snapshot, state, label):
        result = self._journal.update(snapshot.digest, encode(state))
        self._journal._admit().observe("local-credential:" + label)
        require(self._journal.read().digest == result.digest, "local credential transition durable readback")

    @coordinated
    def status(self):
        try:
            with self._state() as (_snapshot, _state, current, record):
                return record.status(current, self.operation)
        except BaseException:
            self.close(); raise

    @coordinated
    def stage(self, wire, target, now):
        try:
            with self._state() as (snapshot, state, current, record):
                grant = verify(wire, current.original, self._context.family, self._context.policy_digest, target)
                require(grant.operation == self.operation, "local renewal original operation differs")
                known = ((record.pending is not None and record.pending.operation == self.operation)
                         or (current.renewal is not None and current.renewal.operation == self.operation)
                         or (record.expired is not None and record.expired.operation == self.operation))
                if known:
                    result = record.status(current, self.operation)
                    require(result['statement'] == grant.statement.hex() and result['target'] == target.hex(),
                            "conflicting original local renewal")
                    return result
                require(record.pending is None, "another local credential renewal remains pending")
                record.current_time(now); self._context.intervals[0].check(now)
                successor = current.renew(self._context, wire, self.operation, target, now)
                # Stage must reserve the completed identity/roster too. For a
                # first grant it can be larger than the pending grant alone;
                # no ordinary traffic can drain space while coordination waits.
                preview = replace(state, local_authority=successor,
                                  local_renewal=replace(record, pending=None, expired=None), format_version=7)
                encode(preview)
                state.local_renewal = replace(record, pending=grant); state.format_version = 7
                self._save(snapshot, state, "staged")
                return state.local_renewal.status(current, self.operation)
        except BaseException:
            self.close(); raise

    @coordinated
    def commit(self, now):
        try:
            with self._state() as (snapshot, state, current, record):
                result = record.status(current, self.operation)
                if result['status'] == 'Committed':
                    return result
                require(result['status'] == 'Pending', "expired uncommitted renewal cannot commit")
                record.current_time(now); self._context.intervals[0].check(now)
                grant = record.pending
                next_identity = current.renew(self._context, grant.wire, self.operation,
                                              grant.successor_roster.checkpoint(), now)
                require(next_identity is not current, "local pending target is already current")
                state.local_authority = next_identity
                state.local_renewal = replace(record, pending=None, expired=None)
                self._save(snapshot, state, "committed")
                return state.local_renewal.status(next_identity, self.operation)
        except BaseException:
            self.close(); raise

    @coordinated
    def reconcile_expired(self, now):
        try:
            with self._state() as (snapshot, state, current, record):
                result = record.status(current, self.operation)
                if result['status'] in ('Committed', 'ExpiredUncommitted'):
                    return result
                record.current_time(now)
                grant = record.pending
                require(grant.successor.validity.end <= now or grant.successor_roster.validity.end <= now,
                        "local renewal target is not expired")
                # Canonical state validation retains the exact current predecessor
                # while Pending. No missing receipt or unknown error is this proof.
                record.validate(current)
                terminal = Expired(self.operation, grant.statement, grant.successor_roster.checkpoint(),
                                   snapshot.revision, snapshot.digest, now)
                state.local_renewal = Record(now, None, terminal)
                self._save(snapshot, state, "expired-uncommitted")
                return state.local_renewal.status(current, self.operation)
        except BaseException:
            self.close(); raise

    @locked
    def close(self):
        self._journal.close()
