#!/usr/bin/env python3
"""Real private files, process kills and CLI processes; explicit test issuers.

Reuse the existing exchange fixture/signatures, not a second policy builder.
All state and failed files are retained. No real host login is claimed.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from pathlib import Path
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import enrollment_exchange as fixture
from qperiapt_continuity_reference import enrollment_client as implementation
from qperiapt_continuity_reference.enrollment_client import EnrollmentClient
from qperiapt_continuity_reference.journal import Journal, MissingState, Conflict
from qperiapt_continuity_reference.registration import Registration
from cryptography.exceptions import InvalidTag
from qperiapt_continuity_reference.connection_run import Run, Cancelled
from qperiapt_continuity_reference.private_files import DirectoryBusy

wire = fixture.wire


class ClientChecks(unittest.TestCase):
    issue_for = fixture.ExchangeChecks.issue_for
    roster = fixture.ExchangeChecks.roster

    def setUp(self):
        fixture.ExchangeChecks.setUp(self)
        self.client_path = fixture.args.private_output / (self._testMethodName + '.client')
        self.client_path.mkdir(mode=0o700)
        self.client = None; self.cut_count = 0

    def tearDown(self):
        if self.client is not None: self.client.close()
        self.owner.close()

    def begin(self, observer=None):
        return EnrollmentClient.begin(self.client_path, self.local_id, self.key,
                                      wire(self.authority_json), wire(self.offer_json), self.now, observer=observer)

    def reopen(self, observer=None):
        return EnrollmentClient.open(self.client_path, self.local_id, self.key, observer=observer)

    def accept(self):
        return self.client.accept(wire(self.offer_json), wire(self.issued_json), wire(self.membership_json),
                                  wire(self.policy_pins), wire(self.policy_materials), self.now)

    def state(self):
        return {str(p.relative_to(self.client_path)):hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.client_path.rglob('*') if p.is_file()}

    def kill_at(self, stage, occurrence=1, *, request=False, open_existing=False, membership=None, extension=None, acceptance=None, association=None):
        self.cut_count += 1
        marker = fixture.args.private_output / (self._testMethodName + '.cut-' + stage.replace(':','-') + str(self.cut_count))
        pid = os.fork()
        if pid == 0:
            count = 0
            def cut(observed):
                nonlocal count
                if observed != stage: return
                count += 1
                if count != occurrence: return
                # Preserve the exact original target outside the formal store.
                directory = self.client_path / 'registration'
                intent, head = directory / 'intent', directory / 'head'
                target = None
                if intent.exists():
                    raw = intent.read_bytes(); target = raw[52:52+int.from_bytes(raw[48:52], 'big')]
                elif head.exists(): target = head.read_bytes()
                elif observed == 'client-device:registration-store:stage-synced:intent':
                    # This is a test observation of the write being killed, not
                    # a production rule for discovering arbitrary staging files.
                    candidates = list(directory.glob('.stage-*'))
                    if len(candidates) != 1: os._exit(73)
                    raw = candidates[0].read_bytes(); target = raw[52:52+int.from_bytes(raw[48:52], 'big')]
                with os.fdopen(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
                    json.dump({'stage':observed, 'target':None if target is None else hashlib.sha256(target).hexdigest()}, out)
                    out.flush(); os.fsync(out.fileno())
                os.kill(os.getpid(), signal.SIGKILL)
            try:
                child = self.reopen(cut) if request or open_existing else self.begin(cut)
                if request: child.request(self.now)
                if membership is not None:
                    child.refresh_roster(wire(membership), wire(self.policy_pins), wire(self.policy_materials), self.now)
                if extension is not None: child.adopt_extension(*extension)
                if acceptance is not None: child.accept(*acceptance)
                if association is not None: child.bind_issuance(*association)
                child.close()
            except BaseException:
                os._exit(71)
            os._exit(72)  # Reaching this is a missing kill, not a passed scenario.
        _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFSIGNALED(status), f'child did not stop at cut: {status}')
        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
        return json.loads(marker.read_text())

    def test_original_configuration_request_and_acceptance_reopen(self):
        self.client = self.begin(); identity = self.client.status()
        proof = self.client.request(self.now); self.issue_for(proof)
        first = self.accept(); self.client.close(); self.client = self.reopen()
        self.assertEqual(self.client.request(self.now), proof)
        self.assertEqual(self.accept(), first)
        self.assertEqual(self.client.status()['public_key'], identity['public_key'])
        self.assertEqual(self.client.status()['operation'], bytes(self.offer_json['operation']))
        self.assertEqual(self.client.status()['phase'], 'Accepted')

    def successor(self):
        approved = dict(self.offer_json, operation=list(os.urandom(32)), request_id=list(os.urandom(32)))
        issued = dict(self.issued_json, operation=approved['operation'])
        return wire(approved), wire(issued), bytes(approved['operation'])

    def legacy_configuration(self):
        # Exercise an actual authenticated v1 store, not a default-filled v2.
        snapshot = self.client._configuration.read()
        config = implementation.Configuration.read(snapshot.payload)
        raw = wire({'schema':'qperiapt-client-configuration/1', 'authority':fixture.b64(config.authority),
                    'invitation':fixture.b64(config.invitation), 'registration':list(config.registration), 'ready':True})
        self.client._configuration.update(snapshot.digest, raw)

    def test_reapproved_issuance_survives_reopen_and_conflicting_rebind_is_read_only(self):
        self.client = self.begin(); proof = self.client.request(self.now); self.issue_for(proof)
        approved, issued, operation = self.successor()
        journal = self.client.accept(approved, issued, wire(self.membership_json),
                                    wire(self.policy_pins), wire(self.policy_materials), self.now)
        self.client.close(); self.client = self.reopen()
        status = self.client.status()
        self.assertEqual(status['operation'], bytes(self.offer_json['operation']))
        self.assertEqual(status['issued_operation'], operation)
        self.assertEqual(status['journal'], journal)
        before = self.state()
        self.assertEqual(self.client.bind_issuance(approved, issued), operation)
        self.assertEqual(self.state(), before)
        other, other_issued, _ = self.successor()
        with self.assertRaisesRegex(ValueError, 'conflicting original issuance association'):
            self.client.bind_issuance(other, other_issued)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.assertEqual(self.client.status(), status)
        self.assertEqual(self.client.request(self.now), proof)

    def test_legacy_association_requires_original_accepted_credential_and_grants_no_authority(self):
        self.client = self.begin(); self.issue_for(self.client.request(self.now))
        approved, issued, operation = self.successor(); before = self.state()
        with self.assertRaisesRegex(ValueError, 'not accepted'):
            self.client.bind_issuance(approved, issued)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.client.accept(approved, issued, wire(self.membership_json),
                           wire(self.policy_pins), wire(self.policy_materials), self.now)
        self.legacy_configuration(); self.client.close(); self.client = self.reopen()
        self.assertIsNone(self.client.status()['issued_operation'])
        before = self.state()
        self.issue_for(self.request)  # Same trusted issuer and intent; another actual device key.
        bad = dict(self.issued_json, operation=list(operation))
        with self.assertRaisesRegex(ValueError, 'original accepted credential'):
            self.client.bind_issuance(approved, wire(bad))
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.assertEqual(self.client.bind_issuance(approved, issued), operation)
        after = self.state()
        self.assertEqual({k:v for k,v in before.items() if k.startswith('registration/')},
                         {k:v for k,v in after.items() if k.startswith('registration/')})
        with self.assertRaisesRegex(ValueError, 'expired or premature authority'):
            self.client.request(self.end + 1)
        self.client = self.reopen(); before = self.state()
        self.assertEqual(self.client.bind_issuance(approved, issued), operation)
        self.assertEqual(self.state(), before)

    def test_acceptance_crash_leaves_recoverable_issuance_gap(self):
        self.client = self.begin(); self.issue_for(self.client.request(self.now))
        approved, issued, operation = self.successor(); self.client.close()
        self.kill_at('client-device:registration:acceptance-committed', open_existing=True,
                     acceptance=(approved, issued, wire(self.membership_json), wire(self.policy_pins),
                                 wire(self.policy_materials), self.now))
        self.client = self.reopen(); status = self.client.status()
        self.assertEqual(status['phase'], 'Accepted'); self.assertIsNone(status['issued_operation'])
        self.assertEqual(self.client.bind_issuance(approved, issued), operation)
        self.assertEqual(self.client.status()['journal'], status['journal'])
        self.client.close(); self.client = self.reopen()
        self.assertEqual(self.client.status()['issued_operation'], operation)

    def test_issuance_commit_reply_loss_recovers_exact_original_association(self):
        self.client = self.begin(); self.issue_for(self.client.request(self.now)); self.accept()
        approved, issued = wire(self.offer_json), wire(self.issued_json)
        self.legacy_configuration(); journal = self.client.status()['journal']; self.client.close()
        self.kill_at('client-config:committed:intent', open_existing=True, association=(approved, issued))
        self.client = self.reopen(); before = self.state()
        self.assertEqual(self.client.bind_issuance(approved, issued), bytes(self.offer_json['operation']))
        self.assertEqual(self.state(), before); self.assertEqual(self.client.status()['journal'], journal)

    def membership(self, version, include=True):
        roster, digest = self.roster(version, include)
        return dict(self.membership_json, roster={'checkpoint':{'version':version, 'digest':list(digest)},
                                                 'bytes':fixture.b64(roster)})

    def refresh(self, membership, now=None):
        return self.client.refresh_roster(wire(membership), wire(self.policy_pins), wire(self.policy_materials),
                                          self.now if now is None else now)

    def test_unprepared_roster_refresh_preserves_identity_and_original_journal(self):
        self.client = self.begin(); proof = self.client.request(self.now); self.issue_for(proof)
        self.accept(); original = self.client.status()
        target = self.membership(3)
        expected = (3).to_bytes(8, 'big') + bytes(target['roster']['checkpoint']['digest'])
        self.assertEqual(self.refresh(target), expected)
        self.assertEqual(self.client.status(), original)
        self.client.close(); self.client = self.reopen(); before = self.state()
        # A freshly signed representation of the same checkpoint is a read-only retry.
        self.assertEqual(self.refresh(self.membership(3)), expected)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.client.request(self.now), proof)
        self.assertEqual(self.client.status()['journal'], original['journal'])

    def test_unprepared_roster_refresh_rejects_rollback_and_same_version_fork(self):
        self.client = self.begin(); self.issue_for(self.client.request(self.now)); self.accept()
        self.refresh(self.membership(3)); before = self.state()
        with self.assertRaisesRegex(ValueError, 'roster checkpoint cannot roll back'):
            self.refresh(self.membership_json)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.start -= 1
        fork = self.membership(3)
        self.start += 1
        with self.assertRaisesRegex(ValueError, 'different roster at the retained version'):
            self.refresh(fork)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.assertEqual(self.refresh(self.membership(3))[:8], (3).to_bytes(8, 'big'))

    def test_roster_refresh_cannot_restore_revocation_or_extend_credential_validity(self):
        self.client = self.begin(); self.issue_for(self.client.request(self.now)); self.accept()
        before = self.state()
        with self.assertRaisesRegex(ValueError, 'device absent from current roster'):
            self.refresh(self.membership(3, False))
        self.assertEqual(self.state(), before); self.client = self.reopen()
        with self.assertRaisesRegex(ValueError, 'expired or premature authority'):
            self.refresh(self.membership(3), self.end + 1)
        self.assertEqual(self.state(), before); self.client = self.reopen()

    def test_roster_refresh_kill_recovers_exact_committed_target(self):
        self.client = self.begin(); proof = self.client.request(self.now); self.issue_for(proof)
        self.accept(); identity = self.client.status(); self.client.close()
        target = self.membership(3)
        marker = self.kill_at('client-device:registration:roster-refreshed', open_existing=True, membership=target)
        self.client = self.reopen()
        self.assertEqual(hashlib.sha256((self.client_path / 'registration/head').read_bytes()).hexdigest(), marker['target'])
        before = self.state()
        self.assertEqual(self.refresh(target)[:8], (3).to_bytes(8, 'big'))
        self.assertEqual(self.state(), before)
        self.assertEqual(self.client.status(), identity)
        self.assertEqual(self.client.request(self.now), proof)

    def test_roster_refresh_cannot_change_policy_even_with_valid_new_signature(self):
        self.client = self.begin(); self.issue_for(self.client.request(self.now)); self.accept()
        before = self.state()
        original = self.policy_root.public().open(self.policy.materials.policy, 4, 200)
        body = original[:40] + (2).to_bytes(8, 'big') + original[48:]
        pins = dict(self.policy_pins, policy_version=2,
                    policy_digest=list(fixture.digest(b'SESSION-POLICY', body)))
        materials = dict(self.policy_materials, policy=fixture.b64(self.policy_root.sign(4, body)))
        with self.assertRaisesRegex(ValueError, 'cannot change the admitted policy'):
            self.client.refresh_roster(wire(self.membership(3)), wire(pins), wire(materials), self.now)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.assertEqual(self.refresh(self.membership(3))[:8], (3).to_bytes(8, 'big'))

    def test_exclusive_owner_wrong_key_id_and_second_begin_preserve_state(self):
        self.client = self.begin()
        with self.assertRaises(BlockingIOError): self.reopen()
        self.client.close(); before = self.state()
        with self.assertRaisesRegex(ValueError, 'not empty'): self.begin()
        with self.assertRaises(InvalidTag): EnrollmentClient.open(self.client_path, self.local_id, bytes(32))
        with self.assertRaisesRegex(ValueError, 'identity/owner/context'):
            EnrollmentClient.open(self.client_path, bytes([9])*32, self.key)
        self.assertEqual(self.state(), before)
        self.client = self.reopen()

    def test_bounded_root_lease_waits_without_retrying_recovery_or_other_errors(self):
        self.client = self.begin(); original = self.client.status(); before = self.state()
        with self.assertRaises(TimeoutError):
            EnrollmentClient.open(self.client_path, self.local_id, self.key, run=Run(.04))
        cancelled = Run(5)
        timer = threading.Timer(.04, cancelled.cancellation.cancel); timer.start()
        try:
            with self.assertRaises(Cancelled):
                EnrollmentClient.open(self.client_path, self.local_id, self.key, run=cancelled)
        finally: timer.join(timeout=1)
        with self.assertRaises(DirectoryBusy):
            EnrollmentClient.open(self.client_path, self.local_id, self.key)
        self.assertEqual(self.state(), before)
        results = []; failures = []; started = threading.Event()
        def waiting():
            started.set()
            try:
                owner = EnrollmentClient.open(self.client_path, self.local_id, self.key, run=Run(5))
                try: results.append(owner.status())
                finally: owner.close()
            except BaseException as error: failures.append(error)
        worker = threading.Thread(target=waiting); worker.start()
        self.assertTrue(started.wait(timeout=1))
        # Real account renewal can keep an original owner busy beyond the old
        # 64 x 25 ms admission cap. The enclosing five-second run still has time.
        time.sleep(2.25); self.client.close(); worker.join(timeout=6)
        self.assertFalse(worker.is_alive())
        if failures: raise BaseExceptionGroup('bounded root admission failed', failures)
        self.assertEqual(results, [original]); self.assertEqual(self.state(), before)
        with self.assertRaises(InvalidTag):
            EnrollmentClient.open(self.client_path, self.local_id, bytes(32), run=Run(5))
        with self.assertRaises(FileNotFoundError):
            EnrollmentClient.open(self.client_path / 'absent', self.local_id, self.key, run=Run(5))
        self.assertEqual(self.state(), before)
        self.client = self.reopen()

    def test_configuration_cleanup_error_releases_outer_client_lease(self):
        self.client = self.begin()
        original = self.client.status()
        close_configuration = self.client._configuration.close
        def fail_after_configuration_cleanup():
            close_configuration()
            raise OSError('injected error after real configuration cleanup')
        self.client._configuration.close = fail_after_configuration_cleanup
        with self.assertRaisesRegex(OSError, 'after real configuration cleanup'):
            self.client.close()
        with self.assertRaisesRegex(ValueError, 'closed enrollment client'):
            self.client.status()
        # A fresh owner must acquire all original leases despite that error.
        self.client = self.reopen()
        self.assertEqual(self.client.status(), original)

    def test_ready_missing_device_state_is_never_recreated(self):
        self.client = self.begin(); self.client.request(self.now); self.client.close()
        original = self.client_path / 'registration/head'
        original.rename(fixture.args.private_output / (self._testMethodName + '.retained-head'))
        before = self.state()
        with self.assertRaises(MissingState): self.reopen()
        self.assertEqual(self.state(), before)

    def test_response_cannot_replace_retained_authority_or_invitation(self):
        self.client = self.begin(); proof = self.client.request(self.now); self.issue_for(proof)
        altered = dict(self.offer_json, application=list(os.urandom(32)))
        with self.assertRaisesRegex(ValueError, 'independent host authority'):
            self.client.accept(wire(altered), wire(self.issued_json), wire(self.membership_json),
                               wire(self.policy_pins), wire(self.policy_materials), self.now)
        self.client = self.reopen()
        self.assertEqual(self.client.request(self.now), proof)
        self.assertEqual(self.client.status()['operation'], bytes(self.offer_json['operation']))
        self.accept()

    def test_device_first_intent_kill_recovers_exact_original_target(self):
        marker = self.kill_at('client-device:registration-store:committed:intent')
        self.client = self.reopen()
        self.assertEqual(hashlib.sha256((self.client_path / 'registration/head').read_bytes()).hexdigest(), marker['target'])
        self.assertEqual(self.client.status()['phase'], 'Preparing')

    def test_ready_intent_kill_recovers_original_device(self):
        marker = self.kill_at('client-config:committed:intent', 2)
        self.client = self.reopen()
        self.assertEqual(hashlib.sha256((self.client_path / 'registration/head').read_bytes()).hexdigest(), marker['target'])
        self.assertEqual(self.client.status()['phase'], 'Preparing')

    def test_request_commit_kill_preserves_exact_signed_request(self):
        self.client = self.begin(); self.client.close()
        marker = self.kill_at('client-device:registration:request-committed', request=True)
        self.client = self.reopen(); proof = self.client.request(self.now)
        self.assertEqual(hashlib.sha256((self.client_path / 'registration/head').read_bytes()).hexdigest(), marker['target'])
        self.offer.intent.verify_request(proof, self.now)
        self.client.close(); self.client = self.reopen()
        self.assertEqual(self.client.request(self.now), proof)

    def test_synced_initial_device_intent_recovers_exact_original_identity(self):
        marker = self.kill_at('client-device:registration-store:stage-synced:intent')
        self.client = self.reopen()
        self.assertEqual(hashlib.sha256((self.client_path / 'registration/head').read_bytes()).hexdigest(), marker['target'])
        proof = self.client.request(self.now)
        self.client.close(); self.client = self.reopen()
        self.assertEqual(self.client.request(self.now), proof)

    def test_corrupt_reserved_creation_is_rejected_before_publication(self):
        self.kill_at('client-device:registration-store:stage-synced:intent')
        path = self.client_path / 'registration/.stage-initial-intent'
        original = path.read_bytes()
        retained = fixture.args.private_output / (self._testMethodName + '.original-intent')
        with os.fdopen(os.open(retained, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out: out.write(original)
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        before = self.state()
        with self.assertRaisesRegex(ValueError, 'write-intent authentication'): self.reopen()
        self.assertEqual(self.state(), before)

    def test_truncated_reserved_creation_is_retained_without_new_key(self):
        self.kill_at('client-device:registration-store:stage-synced:intent')
        path = self.client_path / 'registration/.stage-initial-intent'
        retained = fixture.args.private_output / (self._testMethodName + '.original-intent')
        original = path.read_bytes(); path.rename(retained)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out: out.write(original[:64])
        before = self.state()
        with self.assertRaisesRegex(ValueError, 'write-intent capacity'): self.reopen()
        self.assertEqual(self.state(), before)

    def test_arbitrary_authenticated_orphan_is_not_selected(self):
        self.kill_at('client-device:registration-store:stage-synced:intent')
        path = self.client_path / 'registration/.stage-initial-intent'
        path.rename(path.with_name('.stage-unknown-original'))
        before = self.state()
        with self.assertRaises(MissingState): self.reopen()
        self.assertEqual(self.state(), before)

    def registration_id(self):
        config = Journal.open(self.client_path / 'configuration', implementation.scope(self.local_id),
                              self.key, implementation.Configuration.read)
        try: return implementation.Configuration.read(config.read().payload).registration
        finally: config.close()

    def test_reserved_creation_cannot_change_scope_or_wrapping_key(self):
        self.kill_at('client-device:registration-store:stage-synced:intent')
        original_id = self.registration_id(); before = self.state()
        for identity, key in ((original_id, bytes(32)), (bytes([9])*32, self.key)):
            with self.assertRaisesRegex(ValueError, 'write-intent authentication'):
                Registration.open(self.client_path / 'registration', identity, key, self.offer.intent, recover_initial=True)
            self.assertEqual(self.state(), before)
        with self.assertRaisesRegex(Conflict, 'initial intent requires original creation recovery'):
            Registration.provision(self.client_path / 'registration', original_id, self.key, self.offer.intent)
        self.assertEqual(self.state(), before)
        self.client = self.reopen()

    def test_ready_owner_and_creation_reader_reject_reserved_advanced_transition(self):
        self.client = self.begin(); self.client.close()
        self.kill_at('client-device:registration-store:committed:intent', request=True)
        directory = self.client_path / 'registration'
        (directory / 'head').rename(fixture.args.private_output / (self._testMethodName + '.original-head'))
        (directory / 'intent').rename(directory / '.stage-initial-intent')
        original_id = self.registration_id(); before = self.state()
        with self.assertRaises(MissingState): self.reopen()
        with self.assertRaisesRegex(Conflict, 'not the original creation transition'):
            Registration.open(directory, original_id, self.key, self.offer.intent, recover_initial=True)
        self.assertEqual(self.state(), before)

    def test_repeated_creation_recovery_kills_keep_one_exact_reserved_target(self):
        original = self.kill_at('client-device:registration-store:stage-synced:intent')
        before = self.state()
        for _ in range(3):
            current = self.kill_at('client-device:registration-store:stage-synced:intent', open_existing=True)
            self.assertEqual(current['target'], original['target'])
            self.assertEqual(self.state(), before)
        self.client = self.reopen()
        self.assertEqual(hashlib.sha256((self.client_path / 'registration/head').read_bytes()).hexdigest(), original['target'])

    def test_configuration_without_original_device_intent_stays_explicit_failure(self):
        self.kill_at('client-config:committed:removal')
        before = self.state()
        with self.assertRaises(MissingState): self.reopen()
        self.assertEqual(self.state(), before)

    def test_cli_original_request_export_no_overwrite_and_real_acceptance(self):
        public = fixture.args.private_output / (self._testMethodName + '.inputs'); public.mkdir(mode=0o700)
        def save(name, value):
            path = public / name
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
                out.write(value)
            return str(path)
        key = save('key', self.key)
        authority, invitation = save('authority.json', wire(self.authority_json)), save('invitation.json', wire(self.offer_json))
        base = [sys.executable, '-I', '-S', '-B', '-c',
                "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('qperiapt_continuity_reference.enrollment_cli',run_name='__main__')",
                str(fixture.implementation), '--provider-root', str(fixture.args.provider_root),
                '--directory', str(self.client_path), '--client-id', self.local_id.hex(), '--key-file', key]
        count = 0
        def cli(arguments, expected=0):
            nonlocal count
            result = subprocess.run(base + arguments, capture_output=True, timeout=30, check=False)
            save(str(count)+'.stdout', result.stdout); save(str(count)+'.stderr', result.stderr); count += 1
            self.assertEqual(result.returncode, expected, result.stderr.decode())
            return json.loads(result.stdout) if result.returncode == 0 else result
        initial = cli(['begin', '--authority', authority, '--invitation', invitation])
        first_path, second_path = public / 'request-1.bin', public / 'request-2.bin'
        cli(['request', '--output', str(first_path)])
        cli(['request', '--output', str(first_path)], 1)
        cli(['request', '--output', str(second_path)])
        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
        self.issue_for(first_path.read_bytes())
        accepted = cli(['accept', '--approved', invitation, '--issued', save('issued.json', wire(self.issued_json)),
                        '--current', save('current.json', wire(self.membership_json)),
                        '--policy-pins', save('pins.json', wire(self.policy_pins)),
                        '--policy-materials', save('materials.json', wire(self.policy_materials))])
        self.assertEqual(accepted['phase'], 'Accepted')
        bound = cli(['bind-issuance', '--approved', invitation, '--issued', str(public / 'issued.json')])
        self.assertEqual(bound, {'issued_operation':fixture.b64(bytes(self.offer_json['operation'])),
                                 'current_permission_granted':False})
        target = self.membership(3)
        refreshed = cli(['refresh-roster', '--current', save('current-3.json', wire(target)),
                         '--policy-pins', str(public / 'pins.json'), '--policy-materials', str(public / 'materials.json')])
        self.assertEqual(refreshed['phase'], 'Accepted')
        self.assertEqual(refreshed['roster_checkpoint'], fixture.b64((3).to_bytes(8, 'big') + bytes(target['roster']['checkpoint']['digest'])))
        final = cli(['status'])
        self.assertEqual(final['public_key'], initial['public_key'])
        self.assertEqual(final['journal'], accepted['journal'])


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ClientChecks))
    print(json.dumps({'tests':result.testsRun,'successful':result.wasSuccessful(),
                      'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
                      'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),
                      'provider_version':fixture.provider.__version__,'openssl':fixture.backend.openssl_version_text(),
                      'implementation':str(Path(implementation.__file__).resolve()),
                      'private_fixtures_retained':str(fixture.args.private_output)}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
