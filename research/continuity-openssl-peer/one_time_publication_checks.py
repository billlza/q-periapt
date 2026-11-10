#!/usr/bin/env python3
"""Real OpenSSL signatures and four-leaf selection; no one-time session admission."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import base64
import dataclasses
import hashlib
import json
from pathlib import Path
import sys
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    args = parser.parse_args()
    peer = Path(__file__).resolve().parent
    sys.path.append(str(peer))
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem, x25519
    from qperiapt_continuity_reference.authority import (
        SUITE, PolicyPins, PolicyMaterials, authenticate_policy)
    from qperiapt_continuity_reference.identity import DevicePin
    from qperiapt_continuity_reference.kem import SdkBinding
    from qperiapt_continuity_reference.one_time_publication import (
        OneTimePublication, OneTimePublicationExpectation)
    from qperiapt_continuity_reference.publication import Publication
    from qperiapt_continuity_reference.wire import Interval, SigningKey, digest, ldh, lp, require

    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b'=').decode()

    def wire(value):
        return json.dumps(value, separators=(',', ':')).encode()

    def u16(value):
        return value.to_bytes(2, 'big')

    def u64(value):
        return value.to_bytes(8, 'big')

    account, policy_owner, device = SigningKey(), SigningKey(), SigningKey()
    sdk_owner = mldsa.MLDSA65PrivateKey.generate()
    sdk_root = sdk_owner.public_key().public_bytes_raw()
    document = (b'schema_version = 1\npolicy_version = 1\nmin_nist_level = 3\n'
                b'default_profile = "ContextBound"\nallowed_kems = ["ML-KEM-768", "X25519"]\n'
                b'allowed_sigs = ["ML-DSA-65"]\ndeprecated = []\n')
    signature = sdk_owner.sign(b'Q-PERIAPT-SIGNED-POLICY/v1' + u64(len(document)) + document, b'')
    sdk = SdkBinding(1, hashlib.sha3_256(document).digest(), hashlib.sha256(sdk_root).digest())
    family = digest(b'POLICY-AUTHORITY', policy_owner.public().raw)
    account_id = digest(b'ACCOUNT', account.public().raw)
    device_id, directory, journal = b'R' * 16, b'D' * 32, b'J' * 32
    # Retain the caller's operation and plan before producing or parsing public bytes.
    publication_id = u64(1) + ldh(
        b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ID/v1', journal + u64(1))[:24]
    expectation = OneTimePublicationExpectation(journal, publication_id, Interval(110, 190))
    certificate_body = (b'QPCERT01' + account_id + device_id + u64(1) + u64(100) + u64(200)
                        + family + device.public().raw)
    certificate = account.sign(1, certificate_body)
    credential = digest(b'CREDENTIAL', certificate_body)
    roster_body = (b'QPROST01' + account_id + u64(1) + u64(100) + u64(200) + u16(1)
                   + device_id + u64(1) + credential)
    roster = account.sign(2, roster_body)
    roster_digest = digest(b'ROSTER', roster_body)
    responder = DevicePin(account.public(), account_id, 1, roster_digest, device_id, 1)
    public = {1: x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
              2: x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
              3: mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw(),
              4: mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw()}
    checks = []

    def policy(modes, *, start=100, end=200):
        body = (b'QPSESP03' + family + u64(1) + u64(start) + u64(end) + SUITE + sdk.wire()
                + bytes([modes, 0]) + bytes(32) + u16(1024))
        return (PolicyPins(sdk_root, sdk.state(), policy_owner.public(), 1, digest(b'SESSION-POLICY', body)),
                PolicyMaterials(document, signature, policy_owner.sign(4, body)))

    def fixture(*, alias=None, reverse=False, epoch=1, roles=(1, 2, 3, 4), policy_pin=None):
        selected_policy = pins if policy_pin is None else policy_pin
        keys = dict(public)
        if alias == 'classical':
            keys[2] = keys[1]
        if alias == 'pq':
            keys[4] = keys[3]
        scope = (account_id + device_id + u64(1) + credential + u64(1) + roster_digest
                 + u64(epoch) + sdk.policy_digest + SUITE + directory + u64(110) + u64(190))
        leaves = {kind: b'QPLEAF01' + bytes([kind]) + u64(110) + u64(190) + keys[kind] for kind in roles}
        ids = {kind: digest(b'PREKEY-LEAF', scope + leaf) for kind, leaf in leaves.items()}
        order = sorted(roles, key=lambda kind: ids[kind], reverse=reverse)
        levels = [[ids[kind] for kind in order]]
        while len(levels[-1]) > 1:
            last = levels[-1]
            levels.append([digest(b'PREKEY-NODE', last[i] + last[i + 1]) for i in range(0, len(last), 2)])
        manifest = device.sign(3, b'QPMANF01' + scope + u16(len(roles)) + levels[-1][0])
        proofs = []
        for index, kind in enumerate(order):
            siblings = b''.join(level[(index >> height) ^ 1] for height, level in enumerate(levels[:-1]))
            leaf = leaves[kind]
            proofs.append(u16(index) + u16(len(leaf)) + leaf + bytes([len(levels) - 1]) + siblings)
        ordinal = u64(1)
        identity = ordinal + ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ID/v1', journal + ordinal)[:24]
        plan_time = u64(110) + u64(190)
        plan = directory + plan_time + u16(len(roles)) + b''.join(
            bytes([kind]) + plan_time + bytes(33) for kind in roles)
        intent = ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-INTENT/v1',
                     sdk.wire() + u64(selected_policy.policy_version) + selected_policy.policy_digest + scope + plan)
        commitment = ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ARTIFACT/v1',
                         intent + manifest + b''.join(keys[kind] for kind in roles))
        requests = [ldh(b'Q-PERIAPT-CONTINUITY-PUBLICATION-PREKEY/v1', identity + u16(index))
                    for index in range(len(roles))]
        def artifact(selected=proofs, request_ids=requests):
            return (b'QPPUBA01' + identity + intent + commitment + len(manifest).to_bytes(4, 'big')
                    + manifest + u16(len(roles)) + b''.join(request_ids)
                    + b''.join(u16(len(proof)) + proof for proof in selected))
        value = {'schema': 'qperiapt-native-one-time-publication/1',
                 'journal': list(journal), 'publication': list(identity), 'artifact': b64(artifact()),
                 'certificate': b64(certificate), 'roster': b64(roster),
                 'checkpoint': {'version': 1, 'digest': list(roster_digest)}}
        return value, proofs, requests, artifact, ids, keys

    pins, materials = policy(1)
    value, proofs, requests, artifact, ids, keys = fixture()
    original = OneTimePublication.decode(wire(value))
    result = original.verify_selection(pins, materials, responder, directory, 150,
                                       expectation=expectation, required_quality=1)
    expected = b''.join(lp(field) for field in (
        b'Q-PERIAPT-CONTINUITY-PREKEY-SELECTION/v1', b'\0\1', SUITE, account_id, device_id, u64(1),
        credential, u64(1), directory, digest(b'MANIFEST', original.manifest[4:294]),
        b'\1', ids[1], ids[2], b'\1', ids[3], ids[4]))
    require(result.record == expected and len(result.record) == 492
            and result.quality == 1 and result.responder_prekey == keys[4] + keys[2]
            and result.digest == ldh(b'Q-PERIAPT-CONTINUITY-PREKEY-SELECTION-DIGEST/v1', expected),
            'signed independent OneTimeBoth selection')
    result.check(150)
    checks.append('signed-four-role-selection')

    def refused(name, action):
        try:
            action()
        except (ValueError, InvalidSignature):
            checks.append(name)
        else:
            raise AssertionError('accepted negative control: ' + name)

    def verify(raw=value, *, selected_pins=pins, selected_materials=materials, selected_responder=responder,
               selected_directory=directory, selected_expectation=expectation, now=150, quality=1):
        return OneTimePublication.decode(wire(raw)).verify_selection(
            selected_pins, selected_materials, selected_responder, selected_directory, now,
            expectation=selected_expectation, required_quality=quality)

    refused('old-schema-rejects-one-time', lambda: Publication.decode(wire(value)))
    reused, _, _, _, _, _ = fixture(roles=(1, 3))
    reused['schema'] = 'qperiapt-native-publication/1'
    Publication.decode(wire(reused))
    refused('new-schema-rejects-old', lambda: OneTimePublication.decode(wire(reused)))
    refused('closed-field-set', lambda: OneTimePublication.decode(wire(dict(value, lease='untrusted'))))
    refused('no-implicit-downgrade', lambda: verify(quality=2))
    refused('boolean-quality', lambda: verify(quality=True))
    refused('default-policy-stays-reusable', lambda: authenticate_policy(pins, materials, 150))
    legacy_pins, legacy_materials = policy(3)
    authenticate_policy(legacy_pins, legacy_materials, 150)
    forbidden_pins, forbidden_materials = policy(2)
    refused('signed-policy-forbids-one-time', lambda: verify(
        selected_pins=forbidden_pins, selected_materials=forbidden_materials))
    short_pins, short_materials = policy(1, end=180)
    short_value, _, _, _, _, _ = fixture(policy_pin=short_pins)
    refused('signed-policy-does-not-contain-manifest', lambda: verify(
        short_value, selected_pins=short_pins, selected_materials=short_materials))
    refused('missing-independent-expectation', lambda: verify(selected_expectation=None))
    refused('wrong-journal-expectation', lambda: verify(
        selected_expectation=dataclasses.replace(expectation, journal=b'K' * 32)))
    other_operation = u64(2) + ldh(
        b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLICATION-ID/v1', journal + u64(2))[:24]
    refused('wrong-operation-expectation', lambda: verify(
        selected_expectation=dataclasses.replace(expectation, publication=other_operation)))
    refused('wrong-plan-interval-expectation', lambda: verify(
        selected_expectation=dataclasses.replace(expectation, validity=Interval(111, 189))))
    refused('independent-directory-mismatch', lambda: verify(selected_directory=b'E' * 32))
    refused('independent-roster-mismatch', lambda: verify(
        selected_responder=dataclasses.replace(responder, roster_digest=b'Z' * 32)))
    refused('selected-leaf-expiry', lambda: verify(now=190))
    refused('retained-selection-expiry', lambda: result.check(190))
    for name in ('classical', 'pq'):
        alias_value, _, _, _, _, _ = fixture(alias=name)
        refused('signed-' + name + '-public-alias', lambda raw=alias_value: verify(raw))
    reversed_value, _, _, _, _, _ = fixture(reverse=True)
    refused('signed-noncanonical-merkle-order', lambda: verify(reversed_value))
    epoch_value, _, _, _, _, _ = fixture(epoch=2)
    refused('signed-manifest-ordinal-mismatch', lambda: verify(epoch_value))
    refused('proof-order', lambda: verify(dict(value, artifact=b64(artifact(list(reversed(proofs)))))))
    duplicates = list(requests); duplicates[1] = duplicates[0]
    refused('duplicate-inventory-correlation', lambda: verify(dict(value, artifact=b64(artifact(request_ids=duplicates)))))
    unrelated = list(requests); unrelated[1] = b'U' * 32
    refused('unrelated-generated-inventory-identity', lambda: verify(
        dict(value, artifact=b64(artifact(request_ids=unrelated)))))
    zeros = list(requests); zeros[1] = bytes(32)
    refused('zero-inventory-correlation', lambda: verify(dict(value, artifact=b64(artifact(request_ids=zeros)))))
    grafted = list(proofs); changed = bytearray(grafted[0]); changed[-1] ^= 1; grafted[0] = bytes(changed)
    refused('proof-graft', lambda: verify(dict(value, artifact=b64(artifact(grafted)))))
    duplicate_roles = list(proofs)
    source = bytearray(proofs[0]); source[:2] = u16(1); duplicate_roles[1] = bytes(source)
    refused('duplicate-role', lambda: verify(dict(value, artifact=b64(artifact(duplicate_roles)))))
    mutated = bytearray(artifact()); mutated[72] ^= 1
    refused('artifact-commitment', lambda: verify(dict(value, artifact=b64(mutated))))
    refused('trailing-artifact', lambda: verify(dict(value, artifact=b64(artifact() + b'\0'))))
    for name in ('certificate', 'roster'):
        raw = bytearray(certificate if name == 'certificate' else roster); raw[-1] ^= 1
        refused(name + '-signature', lambda raw=raw, name=name: verify(dict(value, **{name: b64(raw)})))
    bad_manifest = bytearray(original.manifest); bad_manifest[-1] ^= 1
    refused('manifest-signature', lambda: dataclasses.replace(original, manifest=bytes(bad_manifest)).verify_selection(
        pins, materials, responder, directory, 150, expectation=expectation, required_quality=1))
    refused('sdk-signature', lambda: verify(selected_materials=dataclasses.replace(materials, sdk_signature=bytes(3309))))
    refused('policy-signature', lambda: verify(selected_materials=dataclasses.replace(materials, policy=materials.policy[:-1] + bytes([materials.policy[-1] ^ 1]))))

    output = args.output.resolve()
    output.mkdir()
    public_case = {'schema': 'qperiapt-one-time-publication-fixture/1', 'now': 150,
                   'publication': value, 'directory': list(directory),
                   'expected_journal': list(expectation.journal),
                   'expected_publication': list(expectation.publication),
                   'expected_validity': [expectation.validity.start, expectation.validity.end],
                   'sdk_root': b64(pins.sdk_root), 'sdk_state': b64(pins.sdk_state),
                   'policy_root': b64(pins.policy_root.raw), 'policy_version': pins.policy_version,
                   'policy_digest': list(pins.policy_digest), 'sdk_document': b64(materials.sdk_document),
                   'sdk_signature': b64(materials.sdk_signature), 'policy': b64(materials.policy),
                   'account_root': b64(responder.root.raw), 'account': list(account_id),
                   'device': list(device_id), 'generation': 1,
                   'selection': b64(result.record), 'selection_digest': list(result.digest)}
    (output / 'PUBLIC_CASE.json').write_text(json.dumps(public_case, sort_keys=True, indent=2) + '\n')
    fields = (u64(150), u64(expectation.validity.start) + u64(expectation.validity.end),
              directory, expectation.journal, expectation.publication, family,
              u64(pins.policy_version) + pins.policy_digest,
              account_id + u64(1) + roster_digest + device_id + u64(1), pins.sdk_state,
              document, signature, sdk_root, pins.policy_root.raw, materials.policy,
              responder.root.raw, certificate, roster, artifact())
    native_fixture = b'QPOPTF01' + b''.join(len(field).to_bytes(4, 'big') + field for field in fields)
    (output / 'PUBLIC_CASE.bin').write_bytes(native_fixture)
    native = args.native.resolve(strict=True)
    observed = subprocess.run([str(native), '--verify-one-time-publication', str(output / 'PUBLIC_CASE.bin')],
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
    (output / 'native.stdout').write_bytes(observed.stdout)
    (output / 'native.stderr').write_bytes(observed.stderr)
    require(observed.returncode == 0 and not observed.stderr
            and observed.stdout == result.record + result.digest, 'Rust signed publication selection differs')
    checks.append('rust-same-publication-record-and-digest')
    files = [Path(__file__), peer / 'qperiapt_continuity_reference/one_time_publication.py',
             peer / 'qperiapt_continuity_reference/authority.py']
    report = {'schema': 'qperiapt-one-time-publication-checks/1', 'checks': checks,
              'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()},
              'source_sha256': {str(path.relative_to(peer)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in files},
              'public_case_sha256': hashlib.sha256((output / 'PUBLIC_CASE.json').read_bytes()).hexdigest(),
              'native_sha256': hashlib.sha256(native.read_bytes()).hexdigest(),
              'native_publication_selection_matched': True,
              'one_time_session_or_directory_lease_qualified': False,
              'private_keys_exported': False}
    (output / 'RESULT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'checks': len(checks), 'selection_bytes': len(result.record),
                      'scope': 'independent signed publication selection only'}))


if __name__ == '__main__':
    main()
