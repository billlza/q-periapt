#!/usr/bin/env python3
"""Exchange adapter checks with real signatures/journals and explicit test issuers.

These are not host-account authorization, browser, native interop or elapsed-time
expiry claims. The implementation/provider paths are selected explicitly.
"""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--implementation-root', type=Path, required=True)
parser.add_argument('--provider-root', type=Path, required=True)
parser.add_argument('--private-output', type=Path, required=True)
args = parser.parse_args()
implementation = args.implementation_root.resolve(strict=True)
sys.path.insert(0, str(implementation))
from qperiapt_continuity_reference.provider import load_provider
provider, backend = load_provider(args.provider_root)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa
from qperiapt_continuity_reference import enrollment_exchange as exchange
from qperiapt_continuity_reference.authority import SUITE
from qperiapt_continuity_reference.registration import Registration
from qperiapt_continuity_reference.wire import SigningKey, digest
assert Path(exchange.__file__).resolve().is_relative_to(implementation)
args.private_output.mkdir(mode=0o700)

b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b'=').decode()
wire = lambda value: json.dumps(value, separators=(',', ':')).encode()

def sdk_document():
    return b'schema_version=1\npolicy_version=1\nmin_nist_level=3\ndefault_profile="ContextBound"\nallowed_kems=["ML-KEM-768","X25519"]\nallowed_sigs=["ML-DSA-65"]\ndeprecated=[]\n'

class ExchangeChecks(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time()); self.start, self.end = self.now - 60, self.now + 3600
        self.root, self.policy_root = SigningKey(), SigningKey()
        self.sdk_root = mldsa.MLDSA65PrivateKey.generate()
        sdk_public = self.sdk_root.public_key().public_bytes_raw(); document = sdk_document()
        sdk_state = (1).to_bytes(4, 'big') + hashlib.sha3_256(document).digest()
        signature = self.sdk_root.sign(b'Q-PERIAPT-SIGNED-POLICY/v1' + len(document).to_bytes(8, 'big') + document)
        family = digest(b'POLICY-AUTHORITY', self.policy_root.public().raw)
        self.family = family
        body = (b'QPSESP03' + family + (1).to_bytes(8, 'big') + self.start.to_bytes(8, 'big')
                + (self.end + 60).to_bytes(8, 'big') + SUITE + hashlib.sha256(sdk_public).digest() + sdk_state
                + b'\2\0' + bytes(32) + (100).to_bytes(2, 'big'))
        assert len(body) == 200
        self.policy_pins = {'schema':'qperiapt-policy-pins/1','sdk_root':b64(sdk_public),'sdk_state':b64(sdk_state),
                            'policy_root':b64(self.policy_root.public().raw),'policy_version':1,
                            'policy_digest':list(digest(b'SESSION-POLICY', body)),'witness':None}
        self.policy_materials = {'schema':'qperiapt-policy-materials/1','sdk_document':b64(document),
                                 'sdk_signature':b64(signature),'policy':b64(self.policy_root.sign(4, body))}
        self.policy = exchange.PolicyInputs.from_trusted(wire(self.policy_pins), wire(self.policy_materials))
        self.authority_json = {'schema':'qperiapt-host-authority/1','application':list(os.urandom(32)),
                               'root_revision':1,'root':b64(self.root.public().raw),'family':list(family)}
        self.authority = exchange.HostAuthority.from_trusted(wire(self.authority_json))
        self.offer_json = {'operation':list(os.urandom(32)),'request_id':list(os.urandom(32)),
                           'application':self.authority_json['application'],'root_revision':1,
                           'root':self.authority_json['root'],'family':list(family),'device':list(os.urandom(16)),
                           'generation':1,'valid_from':self.start,'valid_until':self.end,'deadline':self.now+300,'predecessor':None}
        self.offer = exchange.HostInvitation.decode(wire(self.offer_json), self.authority)
        self.path = args.private_output / self._testMethodName; self.path.mkdir(mode=0o700)
        self.key, self.local_id = os.urandom(32), os.urandom(32)
        config = args.private_output / (self._testMethodName + '.configuration')
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
            file.write(self.key + self.local_id + self.offer.intent.wire()); file.flush(); os.fsync(file.fileno())
        self.owner = Registration.provision(self.path, self.local_id, self.key, self.offer.intent)
        self.request = self.owner.request(self.now)
        self.issue_for(self.request)
        retained = args.private_output / (self._testMethodName + '.public.json')
        with os.fdopen(os.open(retained, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as file:
            file.write(wire({'authority':self.authority_json,'invitation':self.offer_json,
                             'policy_pins':self.policy_pins,'policy_materials':self.policy_materials,
                             'issued':self.issued_json,'current':self.membership_json})); file.flush(); os.fsync(file.fileno())

    def issue_for(self, request):
        self.signing, self.public = self.offer.intent.verify_request(request, self.now)
        self.account = digest(b'ACCOUNT', self.root.public().raw)
        cert_body = (b'QPCERT01' + self.account + self.offer.intent.device + (1).to_bytes(8, 'big')
                     + self.start.to_bytes(8, 'big') + self.end.to_bytes(8, 'big') + self.family + self.public.raw)
        self.certificate = self.root.sign(1, cert_body)
        self.certificate_digest = digest(b'CREDENTIAL', cert_body)
        first, first_digest = self.roster(1, True)
        self.issued_json = {'operation':self.offer_json['operation'],'root_revision':1,'certificate':b64(self.certificate),
                            'roster':b64(first),'checkpoint':{'version':1,'digest':list(first_digest)}}
        current, current_digest = self.roster(2, True)
        self.membership_json = {'revision':1,'account':list(self.account),'public_key':self.authority_json['root'],
                                'family':list(self.family),'suspended':False,
                                'roster':{'checkpoint':{'version':2,'digest':list(current_digest)},'bytes':b64(current)}}
        self.issued = exchange.IssuedEnrollment.decode(wire(self.issued_json))
        self.current = exchange.CurrentMembership.from_trusted(wire(self.membership_json), self.authority)

    def roster(self, version, include):
        body = (b'QPROST01' + self.account + version.to_bytes(8, 'big') + self.start.to_bytes(8, 'big')
                + self.end.to_bytes(8, 'big') + int(include).to_bytes(2, 'big'))
        if include: body += self.offer.intent.device + (1).to_bytes(8, 'big') + self.certificate_digest
        return self.root.sign(2, body), digest(b'ROSTER', body)

    def tearDown(self):
        self.owner.close()  # Retain every private fixture directory; no reset on failure.

    def accept(self, approved=None, issued=None, current=None, policy=None, now=None):
        return exchange.accept_issued(self.owner, self.offer, approved or self.offer,
                                      issued or self.issued, current or self.current, policy or self.policy,
                                      self.now if now is None else now)

    def test_independent_current_roster_and_original_reopen(self):
        first = self.accept(); self.assertEqual(self.owner.status()['phase'], 'Accepted')
        self.owner.close(); self.owner = Registration.open(self.path, self.local_id, self.key, self.offer.intent)
        self.assertEqual(self.owner.request(self.now), self.request)
        self.assertEqual(self.accept(), first)
        self.assertEqual(self.owner.status()['public_key'], self.public.raw)
        self.assertEqual(self.current.version, 2); self.assertEqual(self.issued.version, 1)

    def test_current_revocation_cannot_be_overridden_by_historical_issuance(self):
        removed, commitment = self.roster(3, False)
        value = dict(self.membership_json, roster={'checkpoint':{'version':3,'digest':list(commitment)},'bytes':b64(removed)})
        current = exchange.CurrentMembership.from_trusted(wire(value), self.authority)
        with self.assertRaisesRegex(ValueError, 'device absent'): self.accept(current=current)
        self.owner = Registration.open(self.path, self.local_id, self.key, self.offer.intent)
        self.assertEqual(self.owner.status()['phase'], 'Requested')

    def test_issuer_suspension_is_not_mislabelled_as_device_revocation(self):
        value = dict(self.membership_json, suspended=True)
        current = exchange.CurrentMembership.from_trusted(wire(value), self.authority)
        self.assertTrue(current.issuance_suspended)
        self.assertEqual(len(self.accept(current=current)), 32)

    def test_host_deadline_does_not_expire_an_already_issued_valid_credential(self):
        value = dict(self.offer_json, deadline=self.now-1)
        original = exchange.HostInvitation.decode(wire(value), self.authority)
        result = exchange.accept_issued(self.owner, original, original, self.issued, self.current, self.policy, self.now)
        self.assertEqual(len(result), 32)

    def test_response_cannot_select_its_own_operation_or_successor_intent(self):
        value = dict(self.issued_json, operation=list(os.urandom(32)))
        with self.assertRaisesRegex(ValueError, 'approved operation'): self.accept(issued=exchange.IssuedEnrollment.decode(wire(value)))
        successor_json = dict(self.offer_json, operation=list(os.urandom(32)), request_id=list(os.urandom(32)))
        successor = exchange.HostInvitation.decode(wire(successor_json), self.authority)
        self.offer.same_device(successor)
        value = dict(self.issued_json, operation=successor_json['operation'])
        self.assertEqual(len(self.accept(approved=successor, issued=exchange.IssuedEnrollment.decode(wire(value)))), 32)
        changed = dict(successor_json, valid_until=self.end+1)
        with self.assertRaisesRegex(ValueError, 'original device intent'):
            self.offer.same_device(exchange.HostInvitation.decode(wire(changed), self.authority))

    def test_live_policy_pins_and_signature_required(self):
        material = dict(self.policy_materials, sdk_signature=b64(bytes(3309)))
        bad = exchange.PolicyInputs.from_trusted(wire(self.policy_pins), wire(material))
        with self.assertRaises(InvalidSignature): self.accept(policy=bad)
        pins = dict(self.policy_pins, policy_digest=list(os.urandom(32)))
        bad = exchange.PolicyInputs.from_trusted(wire(pins), wire(self.policy_materials))
        with self.assertRaisesRegex(ValueError, 'digest pin'): self.accept(policy=bad)
        with self.assertRaisesRegex(ValueError, 'expired'): self.accept(now=self.end+60)
        self.assertEqual(self.owner.status()['phase'], 'Requested')

    def test_current_pin_and_historical_roster_are_individually_verified(self):
        bad = dict(self.membership_json, roster={'checkpoint':{'version':2,'digest':list(os.urandom(32))},'bytes':self.membership_json['roster']['bytes']})
        with self.assertRaisesRegex(ValueError, 'checkpoint pin'):
            self.accept(current=exchange.CurrentMembership.from_trusted(wire(bad), self.authority))
        self.owner = Registration.open(self.path, self.local_id, self.key, self.offer.intent)
        bad = dict(self.issued_json, checkpoint={'version':1,'digest':list(os.urandom(32))})
        with self.assertRaisesRegex(ValueError, 'checkpoint pin'): self.accept(issued=exchange.IssuedEnrollment.decode(wire(bad)))
        self.assertEqual(self.owner.status()['phase'], 'Requested')

    def test_json_types_scope_bounds_and_duplicates(self):
        for key in ['root_revision','generation','valid_from','valid_until','deadline']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                exchange.HostInvitation.decode(wire(dict(self.offer_json, **{key:True})), self.authority)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            exchange.HostAuthority.from_trusted(b'{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError, 'exact integers'):
            exchange.HostAuthority.from_trusted(b'{"schema":1.5}')
        with self.assertRaisesRegex(ValueError, 'identity shape'):
            exchange.HostInvitation.decode(wire(dict(self.offer_json, application=[True]*32)), self.authority)
        with self.assertRaisesRegex(ValueError, 'independent host authority'):
            exchange.HostInvitation.decode(wire(dict(self.offer_json, application=list(os.urandom(32)))), self.authority)
        with self.assertRaises(ValueError): exchange.IssuedEnrollment.decode(b' '*(32768+1))
        for encoded in ['AQ==','AR','AA+']:
            with self.assertRaises(ValueError): exchange.encoded(encoded, 1)
        maximum = (1 << 64) - 1
        trusted = exchange.HostAuthority.from_trusted(wire(dict(self.authority_json, root_revision=maximum)))
        self.assertEqual(exchange.HostInvitation.decode(wire(dict(self.offer_json, root_revision=maximum)), trusted).revision, maximum)

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ExchangeChecks))
    print(json.dumps({'tests':result.testsRun,'successful':result.wasSuccessful(),
                      'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),
                      'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses),
                      'provider_version':provider.__version__,'openssl':backend.openssl_version_text(),
                      'implementation':str(Path(exchange.__file__).resolve()),'private_fixtures_retained':str(args.private_output)}))
    raise SystemExit(0 if result.wasSuccessful() else 1)
