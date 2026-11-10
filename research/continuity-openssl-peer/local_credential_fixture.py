"""Fresh local-policy session with genuine native grants and retained private state."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
from pathlib import Path
import tempfile
from fixture_inputs import load
from qperiapt_continuity_reference.durable import Session, owner_binding
from qperiapt_continuity_reference.journal import Scope
from qperiapt_continuity_reference.local_credential import LocalCredentialRenewal
from qperiapt_continuity_reference.wire import SigningKey, require
from run import Counterpart
from session_driver import SessionDriver
from signing_fixture import write


class Fixture:
    def __init__(self, args, label, *, short_roster=False, combined=False, account_members=None, archived_five=False):
        self.out = args.output.resolve() / label; self.out.mkdir(); (self.out / 'native').mkdir()
        self.private = Path(tempfile.mkdtemp(prefix='qperiapt-local-credential-')).resolve()
        require(not self.private.is_relative_to(self.out), 'private fixture inside public output')
        (self.out / 'private-fixture-path').write_text(str(self.private) + '\n')
        require(not archived_five or account_members in (3, 32), 'archived common-account fixture')
        self.native = Counterpart(args.native.resolve(), self.out / 'native', local_lifecycle=account_members is None,
                                  peer_lifecycle=combined, short_roster=short_roster, account_members=account_members)
        self.driver = None; self.refusals = []
        try:
            self.signer = SigningKey(); require(self.native.transfer(self.signer.public().raw) == b'\1ready', 'native ready')
            self.public = self.out / 'native/public'; _, _, self.context = load(self.public, 150)
            self.key = os.urandom(32); self.scope = Scope(os.urandom(32), owner_binding(self.context), self.context.digest)
            config = self.private / 'configuration'
            with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
                stream.write(self.key + self.scope.wire()); stream.flush(); os.fsync(stream.fileno())
            signer_path = self.private / 'signer'; write(signer_path, self.signer)
            self.path = self.private / 'session'; self.path.mkdir(mode=0o700)
            if archived_five:
                import importlib
                from archived_fixture import load_version
                from local_budget_controls import authenticate_archived
                self.archived, self.archived_hash = load_version(self.private, 7)
                self.archived_context = authenticate_archived(self.public, self.archived)
                require(self.archived_context.digest == self.context.digest, 'archived common context differs')
                wire = importlib.import_module(self.archived.__package__ + '.wire')
                original_signer = self.signer
                class ArchivedSigner:
                    def public(self):
                        return wire.VerificationKey(original_signer.public().raw)
                    def sign(self, purpose, body):
                        return original_signer.sign(purpose, body)
                self.archived_session = importlib.import_module(self.archived.__package__ + '.durable').Session
                owner = self.archived_session.create(self.path, self.scope, self.key, self.archived_context, ArchivedSigner(), 150)
                require(owner.storage_format() == 5, 'archived writer did not create version five')
            else:
                owner = Session.create(self.path, self.scope, self.key, self.context, self.signer, 150)
            owner.close()
            self.driver = SessionDriver(self.out, args.provider_root.resolve(), self.public, config, self.path, signer_path)
            initial = self.value('initial', 'initial', now=150)
            reply = self.call('bootstrap-reply', 4, initial)
            final = self.value('finish', 'finish', (reply,), now=150)
            self.session = self.call('complete', 5, final)
            require(self.value('activate', 'activate') == self.session, 'original local session')
            self.call('native-activate', 6, expected=self.session)
        except BaseException:
            self.close(); raise

    def worker(self, name, action, arguments=(), **options):
        return self.driver.run(name, action, arguments, **options)

    def value(self, name, action, arguments=(), **options):
        return bytes.fromhex(self.worker(name, action, arguments, **options))

    def call(self, name, command, wire=b'', expected=None, status=1):
        return self.native.command(name, command, wire, status, expected)

    def materials(self, suffix, *, peer=False):
        prefix = ('peer' if peer else 'local') + '-renewal-' + str(suffix)
        return tuple((self.public / name).read_bytes() for name in (prefix + '-operation', prefix, 'pin-' + prefix + '-target'))

    def open_session(self, observer=None):
        return Session.open(self.path, self.scope, self.key, self.context, observer=observer)

    def coordinator(self, operation, observer=None):
        return LocalCredentialRenewal.open(self.path, self.scope, self.key, self.context, operation, observer=observer)

    def refuses(self, name, action, reason=None):
        from cryptography.exceptions import InvalidSignature, InvalidTag
        try:
            action()
        except (ValueError, OSError, InvalidSignature, InvalidTag) as error:
            require(reason is None or reason in str(error), 'wrong local credential refusal: ' + name + ': ' + str(error))
            self.refusals.append({'case': name, 'type': type(error).__name__, 'error': str(error)})
        else:
            raise ValueError('missing local credential refusal: ' + name)

    def check_codec(self, now):
        from dataclasses import replace
        from qperiapt_continuity_reference.local_renewal import LocalRenewal
        from qperiapt_continuity_reference.local_renewal_record import Expired
        from qperiapt_continuity_reference.state_codec import encode, decode
        owner = self.open_session()
        try:
            path = self.private / 'retained-authority-create'; path.mkdir(mode=0o700)
            marker = b'retained coordination'
            with os.fdopen(os.open(path / 'authority', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
                stream.write(marker); stream.flush(); os.fsync(stream.fileno())
            fresh_scope = Scope(os.urandom(32), owner_binding(self.context), self.context.digest)
            self.refuses('retained-authority-is-not-new-creation',
                         lambda: Session.create(path, fresh_scope, self.key, self.context, self.signer, 150), 'existing state')
            require(not (path / 'head').exists() and not (path / 'intent').exists()
                    and (path / 'authority').read_bytes() == marker, 'creation changed retained coordination')
            with owner._state(operational=False) as (snapshot, state):
                require(state.format_version == 8 and state.local_authority is not None, 'current local coordination absent')
                require(encode(state) == snapshot.payload, 'canonical local coordination')
                version, record = state.format_version, state.local_renewal
                try:
                    for legacy in range(1, 7):
                        state.format_version = legacy
                        self.refuses('local-coordination-downgrade-' + str(legacy), lambda: encode(state))
                    state.format_version = version
                    state.local_renewal = None
                    self.refuses('missing-local-coordination', lambda: encode(state), 'local coordination requires')
                    state.local_renewal = replace(record, pending=state.local_authority.renewal)
                    self.refuses('committed-target-cannot-be-pending', lambda: encode(state), 'pending renewal predecessor differs')
                    current = state.local_authority.renewal
                    terminal = Expired(current.operation, current.statement, current.successor_roster.checkpoint(),
                                       snapshot.revision, snapshot.digest, now)
                    state.local_renewal = replace(record, floor=max(now, record.floor), expired=terminal)
                    self.refuses('committed-target-cannot-be-abandoned', lambda: encode(state), 'already current')
                finally:
                    state.format_version, state.local_renewal = version, record
                self.refuses('negative-time-floor', lambda: replace(record, floor=-1), 'time range')
                self.refuses('boolean-time-floor', lambda: replace(record, floor=False), 'time range')
                peer_size = len(state.peer_authority.encode()) if state.peer_authority is not None else 0
                local_flag = 42 + peer_size
                record_start = local_flag + 1 + len(state.local_authority.encode())
                require(snapshot.payload[local_flag] == 1 and snapshot.payload[record_start + 8:record_start + 10] == b'\0\0',
                        'exact local metadata offsets')
                for label, offset in [('identity', local_flag), ('pending', record_start + 8), ('expiry', record_start + 9)]:
                    changed = snapshot.payload[:offset] + b'\2' + snapshot.payload[offset + 1:]
                    self.refuses('invalid-local-' + label + '-discriminator', lambda changed=changed: decode(changed, self.context))
            self.refuses('local-policy-cannot-use-witness-coordinator',
                         lambda: LocalRenewal.open(self.path, self.scope, self.key, self.context, current.operation, client=None),
                         'requires original witness')
        finally:
            owner.close()

    def cancelled_stage(self, materials, now):
        operation, wire, target = materials
        owner = None
        def observer(stage):
            if stage == 'local-credential:staged':
                self.refuses('nested-local-commit-refused', lambda: owner.commit(now), 'operation already in progress')
                owner.close()
        owner = self.coordinator(operation, observer)
        try:
            self.refuses('closed-local-stage-withholds-result', lambda: owner.stage(wire, target, now), 'closed store directory')
        finally:
            owner.close()

    def report(self, observations):
        report = dict(observations, worker_operations=self.driver.operations,
                      native_commands=self.native.commands, refusals=self.refusals,
                      process_kills=sum(row.get('signal') == 'SIGKILL' for row in self.driver.operations),
                      session=self.session.hex(),
                      scope='Actual local-only native provider and independent original store. Native traffic clock stays170; supplied independent times exercise root credential/roster expiry. No witness downgrade, same-account, installed/cross-host, power-loss, physical erasure or PCS claim.')
        (self.out / 'RESULT.json').write_text(json.dumps(report, indent=2) + '\n')
        return {k: report[k] for k in ('process_kills', 'scope')}

    def close(self):
        if self.driver is not None:
            (self.out / 'WORKERS.json').write_text(json.dumps(self.driver.operations, indent=2) + '\n')
        (self.out / 'NATIVE.json').write_text(json.dumps(self.native.commands, indent=2) + '\n')
        (self.out / 'REFUSALS.json').write_text(json.dumps(self.refusals, indent=2) + '\n')
        self.native.close()
