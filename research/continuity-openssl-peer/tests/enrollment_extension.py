#!/usr/bin/env python3
"""Real signatures and journals for explicit pre-child credential adoption.

Test roots and clocks are explicit fixtures. No real account grant is selected.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from enrollment_client import ClientChecks, fixture, wire
from qperiapt_continuity_reference import enrollment_extension as implementation


class ExtensionChecks(unittest.TestCase):
    begin = ClientChecks.begin
    reopen = ClientChecks.reopen
    state = ClientChecks.state
    issue_for = ClientChecks.issue_for
    roster = ClientChecks.roster
    accept = ClientChecks.accept
    kill_at = ClientChecks.kill_at
    tearDown = ClientChecks.tearDown

    def setUp(self):
        ClientChecks.setUp(self)
        self.client = self.begin(); self.proof = self.client.request(self.now)
        self.issue_for(self.proof)
        self.accepted_offer = self.offer_json
        if self._testMethodName == 'test_reapproved_enrollment_is_bound_explicitly_instead_of_initial_invitation_id':
            self.accepted_offer = dict(self.offer_json, operation=list(os.urandom(32)), request_id=list(os.urandom(32)))
            issued = dict(self.issued_json, operation=self.accepted_offer['operation'])
            self.client.accept(wire(self.accepted_offer), wire(issued), wire(self.membership_json),
                               wire(self.policy_pins), wire(self.policy_materials), self.now)
        else: self.accept()
        self.original_status = self.client.status()
        self.original_admission = self.client._registration._image()[1].admission.wire()

    def renew_policy(self, version=2, until=None):
        original = self.policy_root.public().open(self.policy.materials.policy, 4, 200)
        body = (original[:40] + version.to_bytes(8, 'big') + self.start.to_bytes(8, 'big')
                + (self.end + 20000 if until is None else until).to_bytes(8, 'big') + original[64:])
        self.policy_pins = dict(self.policy_pins, policy_version=version,
                                policy_digest=list(fixture.digest(b'SESSION-POLICY', body)))
        self.policy_materials = dict(self.policy_materials, policy=fixture.b64(self.policy_root.sign(4, body)))

    def bundle(self, *, predecessor=None, previous=None, until=None, public=None, enrollment=None):
        before = self.membership_json['roster']['checkpoint'] if predecessor is None else predecessor
        until = self.end + 3600 if until is None else until
        approval = {'request_id':list(os.urandom(32)), 'enrollment':self.offer_json['operation'] if enrollment is None else enrollment,
                    'previous_extension':previous, 'predecessor':before, 'valid_until':until}
        body = (b'QPCERT01' + self.account + self.offer.intent.device + (1).to_bytes(8, 'big')
                + self.start.to_bytes(8, 'big') + until.to_bytes(8, 'big') + self.family
                + (self.public.raw if public is None else public))
        certificate = self.root.sign(1, body); commitment = fixture.digest(b'CREDENTIAL', body)
        version = before['version'] + 1
        roster_body = (b'QPROST01' + self.account + version.to_bytes(8, 'big') + self.start.to_bytes(8, 'big')
                       + until.to_bytes(8, 'big') + (1).to_bytes(2, 'big') + self.offer.intent.device
                       + (1).to_bytes(8, 'big') + commitment)
        listing = self.root.sign(2, roster_body)
        head = {'version':version, 'digest':list(fixture.digest(b'ROSTER', roster_body))}
        issued = {'request':approval, 'root_revision':1, 'certificate':fixture.b64(certificate),
                  'roster':fixture.b64(listing), 'checkpoint':head}
        current = dict(self.membership_json, roster={'checkpoint':head, 'bytes':fixture.b64(listing)})
        return approval, issued, current

    def arguments(self, bundle, *, now=None, enrollment=None):
        approval, issued, current = bundle
        return (wire(self.offer_json if enrollment is None else enrollment), wire(approval), wire(issued), wire(current),
                wire(self.policy_pins), wire(self.policy_materials), self.now if now is None else now)

    def adopt(self, bundle, **kw): return self.client.adopt_extension(*self.arguments(bundle, **kw))

    def original_preserved(self):
        status = self.client.status()
        for key in ('signing_id', 'public_key', 'journal', 'application', 'operation'):
            self.assertEqual(status[key], self.original_status[key])
        image = self.client._registration._image()[1]
        self.assertEqual(image.request, self.proof)
        self.assertEqual(image.admission.wire(), self.original_admission)

    def session_inputs(self, target, now):
        """Signed peer publication fixture for actual child preparation/initial flight."""
        from qperiapt_continuity_reference.authority import Pins, Materials, SUITE
        from qperiapt_continuity_reference.enrollment_exchange import CurrentMembership, PolicyInputs, encoded
        from qperiapt_continuity_reference.identity import DevicePin
        from qperiapt_continuity_reference.kem import HybridPrivate
        from qperiapt_continuity_reference.registration_inputs import Inputs
        peer_root, peer = fixture.SigningKey(), fixture.SigningKey()
        account = fixture.digest(b'ACCOUNT', peer_root.public().raw); device = os.urandom(16)
        validity = self.start.to_bytes(8, 'big') + (self.end+30000).to_bytes(8, 'big')
        cert_body = b'QPCERT01' + account + device + (1).to_bytes(8, 'big') + validity + self.family + peer.public().raw
        cert = peer_root.sign(1, cert_body); cert_id = fixture.digest(b'CREDENTIAL', cert_body)
        roster_body = b'QPROST01' + account + (1).to_bytes(8, 'big') + validity + b'\0\1' + device + (1).to_bytes(8, 'big') + cert_id
        listing = peer_root.sign(2, roster_body); roster_id = fixture.digest(b'ROSTER', roster_body)
        peer_pin = DevicePin(peer_root.public(), account, 1, roster_id, device, 1)
        local = CurrentMembership.from_trusted(wire(target[2]), self.authority)
        policy = PolicyInputs.from_trusted(wire(self.policy_pins), wire(self.policy_materials)); p = policy.pins
        directory = os.urandom(32); interval = now.to_bytes(8, 'big') + (now+600).to_bytes(8, 'big')
        scope = (account + device + (1).to_bytes(8, 'big') + cert_id + (1).to_bytes(8, 'big') + roster_id
                 + (1).to_bytes(8, 'big') + p.sdk_state[4:] + SUITE + directory + interval)
        public = HybridPrivate().public()
        leaves = [b'QPLEAF01\1'+interval+public[1184:], b'QPLEAF01\3'+interval+public[:1184]]
        identities = [fixture.digest(b'PREKEY-LEAF', scope+leaf) for leaf in leaves]
        ordered = sorted(identities); root = fixture.digest(b'PREKEY-NODE', b''.join(ordered))
        proofs = [(ordered.index(identity)).to_bytes(2,'big')+len(leaf).to_bytes(2,'big')+leaf+b'\1'+identities[1-index]
                  for index,(identity,leaf) in enumerate(zip(identities,leaves,strict=True))]
        manifest = peer.sign(3, b'QPMANF01'+scope+b'\0\2'+root)
        pins = Pins(p.sdk_root,p.sdk_state,p.policy_root,p.policy_version,p.policy_digest,
                    local.pin(self.offer),peer_pin,directory)
        m = policy.materials
        materials = Materials(m.sdk_document,m.sdk_signature,m.policy,encoded(target[1]['certificate'],8192),
                              local.wire,cert,listing,manifest,*proofs)
        return Inputs(pins,materials,None)

    def test_adopted_identity_prepares_original_child_and_replays_initial_after_reopen(self):
        self.renew_policy(); target = self.bundle(); now = self.end+120; self.adopt(target,now=now)
        inputs = self.session_inputs(target,now)
        path = fixture.args.private_output/(self._testMethodName+'.session'); path.mkdir(mode=0o700)
        scope = self.client.prepare(path,inputs,now)
        self.assertEqual(scope[:32],self.original_status['journal'])
        with self.client.session(now) as child: first = child.initial(now=now)
        self.client.close(); self.client = self.reopen(); self.original_preserved()
        with self.client.session(now) as child: self.assertEqual(child.initial(now=now),first)
        before = self.state()
        next_target = self.bundle(predecessor=target[1]['checkpoint'],previous=target[0]['request_id'],until=self.end+7200)
        with self.assertRaisesRegex(ValueError,'child was already prepared'): self.adopt(next_target,now=now)
        self.assertEqual(self.state(),before)

    def test_expired_original_adopts_current_extension_and_policy_without_recreating_identity(self):
        self.renew_policy(); target = self.bundle(); now = self.end + 120
        self.assertEqual(self.adopt(target, now=now), self.original_status['journal'])
        self.original_preserved()
        self.client.close(); self.client = self.reopen(); before = self.state()
        self.assertEqual(self.adopt(target, now=now), self.original_status['journal'])
        self.assertEqual(self.state(), before); self.original_preserved()
        self.assertEqual(self.client.status()['credential_extension']['request_id'], bytes(target[0]['request_id']))
        self.assertTrue(self.client._registration._image()[1].encode(self.offer.intent).startswith(b'QPREGS02'))

    def test_repeated_extensions_require_exact_predecessor_and_keep_original_history(self):
        self.renew_policy(); first = self.bundle(); self.adopt(first)
        second = self.bundle(predecessor=first[1]['checkpoint'], previous=first[0]['request_id'], until=self.end+7200)
        self.adopt(second); self.original_preserved(); before = self.state()
        with self.assertRaisesRegex(ValueError, 'rollback or same-version fork'): self.adopt(first)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.adopt(second); self.assertEqual(self.state(), before)
        branch = self.bundle(predecessor=second[1]['checkpoint'], previous=first[0]['request_id'], until=self.end+10800)
        with self.assertRaisesRegex(ValueError, 'retained predecessor'): self.adopt(branch)
        self.assertEqual(self.state(), before)

    def check_confirmation_codec(self, extended):
        """Crafted records test decoding only; they are not authenticated READY."""
        from dataclasses import replace
        from qperiapt_continuity_reference.connection_confirmation import Confirmation, TAG, OVERHEAD
        from qperiapt_continuity_reference.registration_state import Image, MAX_EXTENDED_IMAGE
        if extended:
            self.renew_policy(); target=self.bundle(); self.adopt(target)
        else: target=(None,self.issued_json,self.membership_json)
        path=fixture.args.private_output/(self._testMethodName+'.session'); path.mkdir(mode=0o700)
        self.client.prepare(path,self.session_inputs(target,self.now),self.now)
        with self.client.session(self.now) as child: original_initial=child.initial(self.now)
        registration=self.client._registration
        snapshot,image=registration._image(); original=image.encode(self.offer.intent)
        self.assertEqual(original[:8],b'QPREGS02' if extended else b'QPREGS01')
        self.assertIsNone(Image.decode(original,self.offer.intent).confirmation)
        self.assertEqual(Image.decode(original,self.offer.intent).encode(self.offer.intent),original)
        session=os.urandom(32); record=Confirmation(session,b'QPCMACK1'+session+b'\1'+bytes(40))
        image.confirmation=record; encoded=image.encode(self.offer.intent)
        self.assertEqual(len(encoded),len(original)+OVERHEAD)
        self.assertEqual(encoded[12:-113],original)
        self.assertEqual(Image.decode(encoded,self.offer.intent).confirmation,record)
        self.assertEqual(Image.decode(encoded,self.offer.intent).encode(self.offer.intent),encoded)
        bad=[encoded[:-1],encoded+b'\0',TAG+len(encoded).to_bytes(4,'big')+encoded+record.wire(),
             TAG+(MAX_EXTENDED_IMAGE+1).to_bytes(4,'big')+original+record.wire(),
             TAG+len(original).to_bytes(4,'big')+original+record.wire()[:32]+bytes(81)]
        inactive=replace(image,active=False,confirmation=None).encode(self.offer.intent)
        bad.append(TAG+len(inactive).to_bytes(4,'big')+inactive+record.wire())
        for value in bad:
            with self.subTest(size=len(value)),self.assertRaises(ValueError): Image.decode(value,self.offer.intent)
        # Model a retained parent receipt with a child rolled back to pretraffic.
        # Opening a connection must never activate that child to hide the loss.
        registration._save(snapshot,image,'test-crafted-historical-confirmation')
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir() if p.is_file()}
        with self.assertRaisesRegex(ValueError,'original traffic state is not active'):
            self.client.connection_session(self.now)
        self.assertEqual({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir() if p.is_file()},before)
        self.client=self.reopen()
        with self.client.session(self.now) as child: self.assertEqual(child.initial(self.now),original_initial)

    def test_ordinary_confirmation_codec_preserves_old_payload_and_refuses_missing_traffic(self):
        self.check_confirmation_codec(False)

    def test_extended_confirmation_codec_preserves_old_payload_and_refuses_missing_traffic(self):
        self.check_confirmation_codec(True)

    def test_roster_refresh_after_adoption_preserves_original_and_issued_history(self):
        from qperiapt_continuity_reference.enrollment_exchange import encoded
        self.renew_policy(); target = self.bundle(); now = self.end+120; self.adopt(target,now=now)
        body = self.root.public().open(encoded(target[1]['certificate'],8192),1,2097)
        listing = (b'QPROST01'+self.account+(4).to_bytes(8,'big')+self.start.to_bytes(8,'big')
                   +(self.end+3600).to_bytes(8,'big')+b'\0\1'+self.offer.intent.device
                   +(1).to_bytes(8,'big')+fixture.digest(b'CREDENTIAL',body))
        head = {'version':4,'digest':list(fixture.digest(b'ROSTER',listing))}
        current = dict(target[2],roster={'checkpoint':head,'bytes':fixture.b64(self.root.sign(2,listing))})
        self.client.refresh_roster(wire(current),wire(self.policy_pins),wire(self.policy_materials),now)
        self.original_preserved(); self.client.close(); self.client = self.reopen(); before = self.state()
        self.adopt((target[0],target[1],current),now=now); self.assertEqual(self.state(),before)
        next_target = self.bundle(predecessor=head,previous=target[0]['request_id'],until=self.end+7200)
        self.adopt(next_target,now=now); self.original_preserved()

    def test_extension_cannot_choose_approval_key_revision_or_revoked_membership(self):
        self.renew_policy(); good = self.bundle(); before = self.state()
        def copy(value): return json.loads(wire(value))
        wrong_approval = copy(good); wrong_approval[1]['request']['valid_until'] += 1
        wrong_revision = copy(good); wrong_revision[1]['root_revision'] = 2
        wrong_key = self.bundle(public=fixture.SigningKey().public().raw)
        revoked = copy(good)
        body = b'QPROST01' + self.account + (4).to_bytes(8, 'big') + self.start.to_bytes(8, 'big') + (self.end+3600).to_bytes(8, 'big') + bytes(2)
        revoked[2]['roster'] = {'checkpoint':{'version':4,'digest':list(fixture.digest(b'ROSTER', body))},'bytes':fixture.b64(self.root.sign(2, body))}
        for target, reason in [(wrong_approval,'independent approval'), (wrong_revision,'root revision'),
                               (wrong_key,'signing key'), (revoked,'device absent')]:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason): self.adopt(target)
            self.assertEqual(self.state(), before); self.client = self.reopen()

    def test_extension_rejects_expired_target_policy_rollback_and_same_version_fork(self):
        self.renew_policy(); first = self.bundle(); self.adopt(first); before = self.state()
        second = self.bundle(predecessor=first[1]['checkpoint'], previous=first[0]['request_id'], until=self.end+7200)
        with self.assertRaisesRegex(ValueError, 'expired or premature authority'): self.adopt(second, now=self.end+7200)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.renew_policy(version=1)
        with self.assertRaisesRegex(ValueError, 'extension policy rollback'): self.adopt(second)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.renew_policy(version=2, until=self.end+19000)
        with self.assertRaisesRegex(ValueError, 'same-version fork'): self.adopt(second)
        self.assertEqual(self.state(), before)

    def test_reapproved_enrollment_is_bound_explicitly_instead_of_initial_invitation_id(self):
        # The approved issuance may have a different operation after host reapproval.
        approved = self.accepted_offer
        self.renew_policy(); target = self.bundle(enrollment=approved['operation']); before = self.state()
        with self.assertRaisesRegex(ValueError, 'approved enrollment'): self.adopt(target)
        self.assertEqual(self.state(), before); self.client = self.reopen()
        self.adopt(target, enrollment=approved); self.original_preserved()
        self.assertEqual(self.client.status()['credential_extension']['enrollment'], bytes(approved['operation']))

    def test_extension_intent_and_commit_kills_recover_one_exact_reserved_target(self):
        self.renew_policy()
        for version, stage in enumerate(('client-device:registration-store:committed:intent',
                                         'client-device:registration:extension-adopted'), 3):
            prior = None if version == 3 else target[0]['request_id']
            head = None if version == 3 else target[1]['checkpoint']
            target = self.bundle(predecessor=head, previous=prior, until=self.end+(version-2)*3600)
            self.client.close()
            marker = self.kill_at(stage, open_existing=True, extension=self.arguments(target))
            self.client = self.reopen(); self.original_preserved()
            self.assertEqual(hashlib.sha256((self.client_path/'registration/head').read_bytes()).hexdigest(), marker['target'])
            before = self.state(); self.adopt(target); self.assertEqual(self.state(), before)

    def test_old_acceptance_cannot_replace_an_adopted_extension(self):
        self.renew_policy(); self.adopt(self.bundle()); before = self.state()
        with self.assertRaisesRegex(ValueError, 'already adopted a credential extension'): self.accept()
        self.assertEqual(self.state(), before)

    def test_cli_adopts_exact_approved_extension_with_real_os_time(self):
        self.renew_policy(); target = self.bundle(); arguments = self.arguments(target); self.client.close()
        inputs = fixture.args.private_output/(self._testMethodName+'.inputs'); inputs.mkdir(mode=0o700)
        def save(name, data):
            path = inputs/name
            with os.fdopen(os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'wb') as file: file.write(data)
            return str(path)
        key = save('key', self.key)
        command = [sys.executable, '-I', '-S', '-B', '-c',
                   "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('qperiapt_continuity_reference.enrollment_cli',run_name='__main__')",
                   str(fixture.implementation), '--provider-root', str(fixture.args.provider_root),
                   '--directory', str(self.client_path), '--client-id', self.local_id.hex(), '--key-file', key, 'adopt-extension']
        for name, data in zip(('approved-enrollment','approved-extension','issued','current','policy-pins','policy-materials'), arguments[:-1], strict=True):
            command += ['--'+name, save(name+'.json', data)]
        result = subprocess.run(command, capture_output=True, timeout=30)
        save('stdout',result.stdout); save('stderr',result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertFalse(result.stderr)
        self.client = self.reopen(); self.original_preserved()
        self.assertEqual(json.loads(result.stdout)['phase'], 'Accepted')


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ExtensionChecks))
    print(json.dumps({'tests':result.testsRun,'successful':result.wasSuccessful(),
        'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
        'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),
        'provider_version':fixture.provider.__version__,'openssl':fixture.backend.openssl_version_text(),
        'implementation':str(Path(implementation.__file__).resolve()),'private_fixtures_retained':str(fixture.args.private_output)}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
