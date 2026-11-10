#!/usr/bin/env python3
"""Original local-image adoption, adversarial transitions and actual process cuts.

Uses authenticated explicit test issuers and real files. Tagged opaque payloads
exercise the storage boundary; native session semantics have a separate test.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import enrollment_exchange as fixture
from qperiapt_continuity_reference.account_authority import AccountAuthority
from qperiapt_continuity_reference.journal import LocalSessionJournal, Scope
from qperiapt_continuity_reference.root_adoption_journal import _Local
from qperiapt_continuity_reference.wire import SigningKey, require
from qperiapt_continuity_reference.witness import Pin

STAGES = ('stage-synced:intent', 'published:intent', 'committed:intent', 'stage-synced:head',
          'published:head', 'committed:head', 'removed:intent', 'committed:removal')
cuts = []; refusals = []


class AdoptionChecks(unittest.TestCase):
    issue_for = fixture.ExchangeChecks.issue_for
    roster = fixture.ExchangeChecks.roster

    def setUp(self):
        fixture.ExchangeChecks.setUp(self)
        self.registry_path = fixture.args.private_output / (self._testMethodName + '.registry')
        self.registry_path.mkdir(mode=0o700)
        self.registry_key, self.registry_id = os.urandom(32), os.urandom(32)
        self.pin = Pin(os.urandom(32), SigningKey().public())
        self.registry = AccountAuthority.provision(self.registry_path, self.registry_key,
                                                   self.registry_id, self.family, self.pin)
        self.checkpoint = self.registry.associate(self.authority.application, self.current.pin(self.offer),
                                                  self.certificate, self.current.wire)
        self.scope = Scope(os.urandom(32), os.urandom(32), os.urandom(32))
        self.payload = b'QPTEST01original secret, pending randomness, ciphertext and message identities'
        with os.fdopen(os.open(fixture.args.private_output / (self._testMethodName + '.storage-keys'),
                              os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
            out.write(self.registry_key + self.registry_id + self.key + self.scope.wire())
            out.flush(); os.fsync(out.fileno())

    def tearDown(self):
        self.registry.close(); self.owner.close()

    @staticmethod
    def validate(raw):
        require(type(raw) is bytes and raw.startswith(b'QPTEST01'), 'tagged test state')

    def create(self, suffix='original'):
        path = fixture.args.private_output / (self._testMethodName + '.' + suffix)
        path.mkdir(mode=0o700)
        owner = LocalSessionJournal.create(path, self.scope, self.key, self.payload, self.validate)
        snapshot = owner.read(); owner.close()
        return path, snapshot

    def reopen_registry(self):
        self.registry = AccountAuthority.open(self.registry_path, self.registry_key,
                                              self.registry_id, self.family, self.pin)

    def normal(self, path, *, bound=True, observer=None):
        return LocalSessionJournal.open(path, self.scope, self.key, self.validate, observer=observer,
                                        root_lease=self.registry.admit(self.checkpoint) if bound else None)

    def adapter(self, path, observer=None):
        return _Local(path, self.scope, self.key, self.validate, observer,
                      root_lease=self.registry.admit(self.checkpoint))

    def bind(self, path, observer=None):
        owner = self.adapter(path, observer)
        try:
            return owner.bind(lambda _journal, snapshot: self.validate(snapshot.payload))
        finally:
            owner.close()

    def files(self, path):
        return {p.name: p.read_bytes() for p in path.iterdir() if p.is_file()}

    def refuse(self, name, action, reason):
        with self.assertRaisesRegex(ValueError, reason): action()
        refusals.append(name)

    def interrupt_intent(self, path):
        def stop(stage):
            if stage == 'committed:intent': raise OSError('retained original intent')
        with self.assertRaisesRegex(OSError, 'retained original intent'): self.bind(path, stop)

    def test_explicit_adoption_preserves_payload_and_is_idempotent(self):
        path, source = self.create()
        before = self.files(path)
        self.refuse('normal-open-does-not-start-adoption', lambda: self.normal(path), 'missing original root binding intent')
        self.assertEqual(self.files(path), before)
        result = self.bind(path)
        self.assertEqual(result.payload, source.payload); self.assertEqual(result.revision, source.revision + 1)
        self.assertNotEqual(result.digest, source.digest)
        self.assertEqual((path / 'head').read_bytes()[:8], b'QPREFJ02')
        bound = self.files(path); self.assertEqual(self.bind(path), result); self.assertEqual(self.files(path), bound)
        self.refuse('bound-head-requires-original-registry', lambda: self.normal(path, bound=False), 'original root registry lease required')
        owner = self.normal(path)
        try: self.assertEqual(owner.read(), result)
        finally: owner.close()

    def test_normal_recovery_requires_original_registry_before_writing(self):
        path, source = self.create(); self.interrupt_intent(path); before = self.files(path)
        self.refuse('bound-pending-requires-original-registry', lambda: self.normal(path, bound=False), 'original root registry lease required')
        self.assertEqual(self.files(path), before)
        other_path = fixture.args.private_output / (self._testMethodName + '.other'); other_path.mkdir(mode=0o700)
        other = AccountAuthority.provision(other_path, os.urandom(32), os.urandom(32), self.family, self.pin)
        try:
            checkpoint = other.associate(self.authority.application, self.current.pin(self.offer), self.certificate, self.current.wire)
            self.refuse('substitute-registry-before-recovery', lambda: LocalSessionJournal.open(path, self.scope, self.key,
                         self.validate, root_lease=other.admit(checkpoint)), 'original root registry lease required')
        finally: other.close()
        self.assertEqual(self.files(path), before)
        owner = self.normal(path)
        try:
            result = owner.read(); self.assertEqual(result.payload, source.payload)
            self.assertEqual(result.revision, source.revision + 1)
        finally: owner.close()

    def test_existing_ordinary_transition_finishes_before_binding(self):
        path, source = self.create(); target_payload = self.payload + b'; original next operation'
        def stop(stage):
            if stage == 'committed:intent': raise OSError('unknown ordinary write')
        owner = self.normal(path, bound=False, observer=stop)
        with self.assertRaisesRegex(OSError, 'unknown ordinary write'): owner.update(source.digest, target_payload)
        owner.close(); original_intent = (path / 'intent').read_bytes()
        result = self.bind(path)
        self.assertEqual(result.payload, target_payload); self.assertEqual(result.revision, source.revision + 2)
        self.assertTrue(original_intent.startswith(b'QPREFI01'))

    def test_authenticated_adoption_cannot_change_business_state(self):
        path, source = self.create(); owner = self.adapter(path)
        try:
            target = owner._seal(source.revision + 1, self.payload + b'; forbidden change')
            owner._admit().publish('intent', owner._intent(source.revision, source.digest, target))
        finally: owner.close()
        before = self.files(path)
        self.refuse('normal-adoption-changes-business-state', lambda: self.normal(path), 'changes original business state')
        self.refuse('explicit-adoption-changes-business-state', lambda: self.bind(path), 'changes original business state')
        self.assertEqual(self.files(path), before)

    def test_bound_head_cannot_replay_a_legacy_target(self):
        path, source = self.create(); source_wire = (path / 'head').read_bytes(); result = self.bind(path)
        # Authenticated hostile transition, constructed with this test's original
        # wrapping key. Even the explicit adapter cannot remove the binding.
        owner = self.adapter(path)
        try: owner._admit().publish('intent', owner._intent(result.revision, result.digest, source_wire))
        finally: owner.close()
        before = self.files(path)
        self.refuse('root-binding-removal', lambda: self.bind(path), 'root binding cannot be removed')
        self.assertEqual(self.files(path), before)

    def test_root_closure_withholds_result_and_original_state_reopens(self):
        path, source = self.create(); reached = []
        def stop(stage):
            if stage == 'committed:intent': reached.append(stage); self.registry.close()
        self.refuse('registry-close-during-binding', lambda: self.bind(path, stop), 'closed account authority owner')
        self.assertEqual(reached, ['committed:intent']); self.reopen_registry()
        owner = self.normal(path)
        try:
            snapshot = owner.read(); self.assertEqual(snapshot.payload, source.payload)
            self.assertEqual(snapshot.revision, source.revision + 1)
        finally: owner.close()

    def test_original_authority_intents_are_never_reinterpreted_as_binding(self):
        for index, tag in enumerate((b'QPRFLI01', b'QPRFLI02', b'QPRFRI01', b'QPRFPI01')):
            path, _source = self.create('authority-' + str(index))
            owner = self.normal(path, bound=False)
            try: owner._admit().publish('intent', tag + b'original opaque coordination')
            finally: owner.close()
            before = self.files(path)
            self.refuse('preserved-authority-intent-' + tag.decode(), lambda: self.bind(path),
                        'finish original authority coordination before root binding')
            self.assertEqual(self.files(path), before)

    def test_actual_process_cuts_retain_original_payload_and_exact_revision(self):
        for index, stage in enumerate(STAGES):
            path, source = self.create('cut-' + str(index)); self.registry.close()
            marker = fixture.args.private_output / (path.name + '.cut')
            pid = os.fork()
            if pid == 0:
                def stop(value):
                    if value != stage: return
                    with os.fdopen(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
                        json.dump({'stage': stage, 'pid': os.getpid()}, out); out.flush(); os.fsync(out.fileno())
                    os.kill(os.getpid(), signal.SIGKILL)
                try:
                    self.reopen_registry(); self.bind(path, stop)
                except BaseException:
                    import traceback
                    traceback.print_exc(); os._exit(71)
                os._exit(72)
            deadline = time.monotonic() + 30
            while True:
                finished, status = os.waitpid(pid, os.WNOHANG)
                if finished: break
                if time.monotonic() >= deadline:
                    os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0); self.fail('process cut timed out: ' + stage)
                time.sleep(.01)
            self.assertTrue(os.WIFSIGNALED(status), str(status)); self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
            self.assertEqual(json.loads(marker.read_bytes()), {'stage': stage, 'pid': pid})
            retained = self.files(path); self.reopen_registry()
            if index == 0: result = self.bind(path)
            else:
                owner = self.normal(path)
                try: result = owner.read()
                finally: owner.close()
            self.assertEqual(result.payload, source.payload); self.assertEqual(result.revision, source.revision + 1)
            self.assertEqual(self.bind(path), result)
            for name, value in retained.items():
                if name == '.stage-head':
                    self.assertEqual((path / 'head').read_bytes(), value)
                    self.assertFalse((path / name).exists())
                elif name.startswith('.'): self.assertEqual((path / name).read_bytes(), value)
            cuts.append({'stage': stage, 'pid': pid, 'signal': 'SIGKILL', 'revision': result.revision})


sources = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
           for path in (fixture.implementation / 'qperiapt_continuity_reference').glob('*.py')}
sources.update({str(Path(path)): hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in (__file__, fixture.__file__)})
result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AdoptionChecks))
unchanged = all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected for path, expected in sources.items())
report = {'completed': result.wasSuccessful() and unchanged, 'tests': result.testsRun,
          'failures': len(result.failures), 'errors': len(result.errors), 'refusals': refusals,
          'process_cuts': cuts, 'source_files': sources, 'private_fixtures': str(fixture.args.private_output),
          'scope': 'Local encrypted storage adoption with tagged payloads and real process cuts; not session/native/device acceptance.'}
with (fixture.args.private_output / 'RESULT.json').open('x') as out: json.dump(report, out, indent=2); out.write('\n')
print(json.dumps({key: report[key] for key in ('completed', 'tests', 'failures', 'errors', 'private_fixtures')}))
raise SystemExit(0 if report['completed'] else 1)
