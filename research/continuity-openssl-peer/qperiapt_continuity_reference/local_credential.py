"""Original local-policy credential coordination in one authenticated journal."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from contextlib import contextmanager
from dataclasses import replace
import threading
from .durable import Session
from .identity_state import IdentityState
from .account_snapshot import initialize, shared
from .account_request import AccountRequest
from .journal import LocalSessionJournal, locked
from .local_renewal_record import Record, Expired
from .owner_guard import root_coordinated as coordinated
from .renewal import verify
from .state_codec import decode, encode
from .wire import require
from .policy_snapshot import admit as admit_policy, validate as validate_policy


class LocalCredentialRenewal:
    def __init__(self, journal, context, operation, inputs=None):
        self._journal, self._context, self.operation = journal, context, operation
        self._inputs = inputs
        self._lock = threading.RLock(); self._busy = False

    @classmethod
    def open(cls, path, scope, key, context, operation, *, observer=None, inputs=None,root_lease=None):
        require(context.witness is None, "local credential coordinator requires original local-only policy")
        Session._scope(context, scope,root_lease)
        require(type(operation) is bytes and len(operation) == 32 and any(operation), "original local renewal operation")
        journal = LocalSessionJournal.open(path, scope, key, Session._validator(context), observer=observer,root_lease=root_lease)
        owner = cls(journal, context, operation, inputs)
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
            require(state.policy_renewal is None or state.policy_renewal.pending is None,
                    "policy renewal remains pending")
            if state.policy_renewal is not None:
                validate_policy(state, self._context, self._journal.scope.identity)
            if shared(self._context):
                if state.format_version == 5:
                    initialize(state)
                require(state.format_version in (9, 10) and state.account_authority is not None
                        and state.account_renewal is not None, "original common account state absent")
                current = state.account_authority.view(self._context.devices[0], local=True)
                record = state.account_renewal
            else:
                current = state.local_authority or IdentityState.initial(self._context, role=0)
                record = state.local_renewal or Record()
            yield snapshot, state, current, record
            self._journal._check_root()
        finally:
            state.close()

    def _save(self, snapshot, state, label):
        result = self._journal.update(snapshot.digest, encode(state))
        self._journal._admit().observe("local-credential:" + label)
        require(self._journal.read().digest == result.digest, "local credential transition durable readback")

    @coordinated
    def request(self):
        """Historical issuer inputs; raw owners must supply original inputs at open."""
        try:
            from .credential_request import retained
            with self._state() as (_, state, _, _):
                return retained(state, self._context, self._inputs, self.operation, self._journal.scope.identity)
        except BaseException:
            self.close(); raise

    @coordinated
    def status(self):
        try:
            with self._state() as (_snapshot, state, current, record):
                if state.account_authority is not None:
                    return record.status(self.operation)
                return record.status(current, self.operation)
        except BaseException:
            self.close(); raise

    @coordinated
    def stage(self, wire, target, now, *, expected_statement=None):
        try:
            with self._state() as (snapshot, state, current, record):
                require(state.account_authority is None, "shared account requires stage_account")
                grant = verify(wire, current.original, self._context.family, self._context.policy_digest, target)
                require(expected_statement is None or grant.statement == expected_statement,
                        'credential issuance statement differs from signed grant')
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
                record.current_time(now); admit_policy(state, self._context, now)
                successor = current.renew(self._context, wire, self.operation, target, now)
                # Stage must reserve the completed identity/roster too. For a
                # first grant it can be larger than the pending grant alone;
                # no ordinary traffic can drain space while coordination waits.
                preview = replace(state, local_authority=successor,
                                  local_renewal=replace(record, pending=None, expired=None), format_version=8)
                encode(preview)
                state.local_renewal = replace(record, pending=grant); state.format_version = 8
                self._save(snapshot, state, "staged")
                return state.local_renewal.status(current, self.operation)
        except BaseException:
            self.close(); raise

    @coordinated
    def stage_account(self, wire, companions, target, now, *, expected_statement=None, expected_companions=None):
        try:
            with self._state() as (snapshot, state, _current, record):
                require(state.account_authority is not None, "account renewal requires common account state")
                request = AccountRequest.parse(wire, companions, self._context.devices[0],
                                               self._context.family, self._context.policy_digest, target,
                                               expected_companions=expected_companions)
                require(expected_statement is None or request.local.statement == expected_statement,
                        'credential issuance statement differs from signed grant')
                require(request.local.operation == self.operation, "local renewal original operation differs")
                if record.known(self.operation) is None:
                    admit_policy(state, self._context, now)
                pending = record.stage(state.account_authority, request, now)
                if pending is record:
                    return record.status(self.operation)
                # Preflight both representations before persisting Pending.
                # Business bytes retain their prior budget even for 32 grants.
                account, completion = pending.commit(state.account_authority, self.operation, now)
                encode(replace(state, account_authority=account, account_renewal=completion))
                state.account_renewal = pending
                self._save(snapshot, state, "staged")
                return pending.status(self.operation)
        except BaseException:
            self.close(); raise

    @coordinated
    def commit(self, now):
        try:
            with self._state() as (snapshot, state, current, record):
                if state.account_authority is not None:
                    if record.status(self.operation)["status"] == "Pending":
                        admit_policy(state, self._context, now)
                    account, completed = record.commit(state.account_authority, self.operation, now)
                    if completed is not record:
                        state.account_authority, state.account_renewal = account, completed
                        self._save(snapshot, state, "committed")
                    return completed.status(self.operation)
                result = record.status(current, self.operation)
                if result['status'] == 'Committed':
                    return result
                require(result['status'] == 'Pending', "expired uncommitted renewal cannot commit")
                record.current_time(now); admit_policy(state, self._context, now)
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
                if state.account_authority is not None:
                    expired = record.reconcile_expired(state.account_authority, self.operation, now,
                                                       snapshot.revision, snapshot.digest)
                    if expired is not record:
                        state.account_renewal = expired
                        self._save(snapshot, state, "expired-uncommitted")
                    return expired.status(self.operation)
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
