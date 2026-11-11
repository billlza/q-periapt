#!/usr/bin/env python3
"""Independent OpenSSL history/conflict checks and real Rust receipt readback."""
# SPDX-License-Identifier: Apache-2.0 OR MIT
import argparse
import base64
import dataclasses
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-root', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--publication-case', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    peer = Path(__file__).resolve().parent
    sys.path.append(str(peer))
    from qperiapt_continuity_reference.provider import load_provider
    crypto, backend = load_provider(args.provider_root)
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
    from qperiapt_continuity_reference.directory_lease import (
        BODY_BYTES, CONFLICT_BYTES, LEASE_BYTES, PURPOSE, DirectoryPin,
        DirectoryLeaseConflict, LeaseStatement, key_fingerprint)
    from qperiapt_continuity_reference.enrollment_exchange import encoded, identifier
    from qperiapt_continuity_reference.wire import ORDER, Interval, SigningKey, VerificationKey, ldh, require

    def read(path, maximum, exact=None):
        require(path.is_file() and not path.is_symlink(), 'public fixture file')
        with path.open('rb') as stream:
            data = stream.read(maximum + 1)
        require(len(data) <= maximum and (exact is None or len(data) == exact), 'public fixture capacity')
        return data

    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b'=').decode()

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate public fixture field')
            result[key] = value
        return result

    output = args.output.resolve()
    output.mkdir()
    native = args.native.resolve(strict=True)
    publication = args.publication_case.resolve(strict=True)
    public_case = json.loads(read(publication.with_suffix('.json'), 65536), object_pairs_hook=unique)
    require(public_case['schema'] == 'qperiapt-one-time-publication-fixture/1', 'original publication fixture')
    expected_selection = encoded(public_case['selection'], 492, 492)
    expected_digest = identifier(public_case['selection_digest'])
    original_bytes = read(publication, 128 * 1024)
    native_output = output / 'native'
    executed = subprocess.run([str(native), '--directory-lease-fixture', str(publication), str(native_output)],
                              stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
    (output / 'native.stdout').write_bytes(executed.stdout)
    (output / 'native.stderr').write_bytes(executed.stderr)
    require(executed.returncode == 0 and not executed.stderr
            and executed.stdout == expected_selection + expected_digest, 'Rust lease fixture command failed')
    require(read(publication, 128 * 1024) == original_bytes, 'original public fixture changed')
    # The test controller explicitly provisions this identity separately from any receipt.
    require(read(native_output / 'service-id', 32, 32) == b'\xd1' * 32, 'native service identity')
    native_pin = DirectoryPin(b'\xd1' * 32,
        VerificationKey(read(native_output / 'service-key', 1985, 1985)))
    require(native_pin.binding == read(native_output / 'service-binding', 32, 32), 'native service binding')
    first_wire = read(native_output / 'first', LEASE_BYTES, LEASE_BYTES)
    second_wire = read(native_output / 'second', LEASE_BYTES, LEASE_BYTES)
    resigned_wire = read(native_output / 'resigned-first', LEASE_BYTES, LEASE_BYTES)
    first = native_pin.verify_historical_lease(first_wire)
    second = native_pin.verify_historical_lease(second_wire)
    resigned = native_pin.verify_historical_lease(resigned_wire)
    require(first.statement_digest == read(native_output / 'statement-digest-first', 32, 32)
            and first.statement.selection == second.statement.selection == expected_digest
            and first.statement.operation == b'\xa1' * 32 and second.statement.operation == b'\xa2' * 32
            and first.statement.requester == b'\xb1' * 32 and second.statement.requester == b'\xb2' * 32
            and first.statement.checkpoint == identifier(public_case['directory'])
            and first.statement.account == identifier(public_case['account'])
            and first.statement.device == identifier(public_case['device'], 16)
            and first.statement.validity == Interval(*public_case['expected_validity'])
            and first.statement.sdk.state() == encoded(public_case['sdk_state'], 36, 36),
            'Rust receipt differs from independently retained publication')
    require(first.statement == resigned.statement and first_wire != resigned_wire,
            'Rust same-body randomized signatures control')
    native_conflict = read(native_output / 'conflict', CONFLICT_BYTES, CONFLICT_BYTES)
    proof = DirectoryLeaseConflict.from_bytes(native_pin, native_conflict)
    require(proof.classical and proof.pq and proof.to_bytes() == native_conflict
            and DirectoryLeaseConflict.verify(native_pin, second_wire, first_wire).to_bytes() == native_conflict,
            'Rust canonical conflict differs')
    checks = ['rust-signed-history', 'rust-statement-digest', 'rust-canonical-conflict']

    def refused(name, action):
        try:
            action()
        except (ValueError, InvalidSignature):
            checks.append(name)
        else:
            raise AssertionError('accepted negative control: ' + name)

    refused('native-exact-replay-is-not-conflict',
            lambda: DirectoryLeaseConflict.verify(native_pin, first_wire, first_wire))
    refused('native-randomized-resigning-is-not-conflict',
            lambda: DirectoryLeaseConflict.verify(native_pin, first_wire, resigned_wire))

    owner = SigningKey()
    pin = DirectoryPin(b'S' * 32, owner.public())
    base = dataclasses.replace(first.statement, service=pin.binding)
    def signed(statement):
        return owner.sign(PURPOSE, statement.encode())
    a = signed(base)
    b = signed(dataclasses.replace(base, operation=b'O' * 32, requester=b'R' * 32))
    verified = pin.verify_historical_lease(a)
    require(verified.statement == base and verified.statement.encode() == a[4:4 + BODY_BYTES],
            'independent historical receipt roundtrip')
    both = DirectoryLeaseConflict.verify(pin, a, b)
    require(both.classical and both.pq, 'independent two-key conflict')
    checks += ['openssl-signed-history', 'openssl-two-key-conflict']
    new_classical = x25519.X25519PrivateKey.generate().public_key().public_bytes_raw()
    new_pq = mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw()
    classical_only = dataclasses.replace(base, operation=b'C' * 32, pq=new_pq,
                                         pq_fingerprint=key_fingerprint(2, new_pq))
    pq_only = dataclasses.replace(base, operation=b'P' * 32, classical=new_classical,
                                  classical_fingerprint=key_fingerprint(1, new_classical))
    one = DirectoryLeaseConflict.verify(pin, a, signed(classical_only))
    two = DirectoryLeaseConflict.verify(pin, a, signed(pq_only))
    require(one.classical and not one.pq and two.pq and not two.classical, 'single-algorithm conflict')
    checks.append('single-algorithm-key-reuse')
    historical = dataclasses.replace(base, operation=b'H' * 32, manifest=b'M' * 32,
                                    selection=b'V' * 32, epoch=base.epoch + 1,
                                    validity=Interval(210, 220))
    # Historical evidence has no wall-clock argument: disjoint windows do not recycle a key.
    later = pin.verify_historical_lease(signed(historical))
    require(base.validity.end < later.statement.validity.start
            and DirectoryLeaseConflict.verify(pin, a, later.wire).classical,
            'historical conflict lost across expired window or manifest')
    checks.append('disjoint-historical-interval-and-manifest')
    different = dataclasses.replace(classical_only, classical=new_classical,
                                     classical_fingerprint=key_fingerprint(1, new_classical))
    refused('different-keys-are-not-conflict', lambda: DirectoryLeaseConflict.verify(pin, a, signed(different)))
    refused('exact-replay-is-not-conflict', lambda: DirectoryLeaseConflict.verify(pin, a, a))
    resigned_a = signed(base)
    require(a != resigned_a, 'independent randomized signing control')
    refused('same-body-resigning-is-not-conflict', lambda: DirectoryLeaseConflict.verify(pin, a, resigned_a))
    other_pin = DirectoryPin(b'T' * 32, owner.public())
    other = signed(dataclasses.replace(base, service=other_pin.binding, operation=b'Q' * 32))
    other_pin.verify_historical_lease(other)
    refused('different-service-identity', lambda: DirectoryLeaseConflict.verify(pin, a, other))
    other_owner = SigningKey()
    key_pin = DirectoryPin(pin.identity, other_owner.public())
    other_key = other_owner.sign(PURPOSE, dataclasses.replace(base, service=key_pin.binding).encode())
    key_pin.verify_historical_lease(other_key)
    refused('different-service-key', lambda: pin.verify_historical_lease(other_key))
    refused('wrong-signature-purpose', lambda: pin.verify_historical_lease(owner.sign(3, base.encode())))
    for name, index in (('pq-signature', 4 + BODY_BYTES), ('classical-signature', LEASE_BYTES - 1),
                        ('unsigned-body-mutation', 44)):
        changed = bytearray(a); changed[index] ^= 1
        refused(name, lambda changed=changed: pin.verify_historical_lease(bytes(changed)))
    high_s = a[:-32] + (ORDER - int.from_bytes(a[-32:], 'big')).to_bytes(32, 'big')
    refused('noncanonical-high-s-signature', lambda: pin.verify_historical_lease(high_s))
    for name, changed in (
        ('statement-tag', b'QPDLSE02' + base.encode()[8:]),
        ('zero-operation', base.encode()[:40] + bytes(32) + base.encode()[72:]),
        ('zero-generation', base.encode()[:184] + bytes(8) + base.encode()[192:]),
        ('exhausted-epoch', base.encode()[:320] + b'\xff' * 8 + base.encode()[328:]),
        ('zero-policy-version', base.encode()[:360] + bytes(8) + base.encode()[368:]),
        ('zero-sdk-authority', base.encode()[:400] + bytes(32) + base.encode()[432:]),
        ('zero-sdk-version', base.encode()[:432] + bytes(4) + base.encode()[436:]),
        ('wrong-suite', base.encode()[:468] + b'Z' * 32 + base.encode()[500:]),
        ('empty-interval', dataclasses.replace(base, validity=Interval(110, 110)).encode()),
        ('exhausted-interval', dataclasses.replace(base, validity=Interval(110, (1 << 64) - 1)).encode()),
        ('zero-classical-public', dataclasses.replace(base, classical=bytes(32)).encode()),
        ('zero-pq-public', dataclasses.replace(base, pq=bytes(1184)).encode()),
        ('wrong-classical-fingerprint', dataclasses.replace(base, classical_fingerprint=b'F' * 32).encode()),
        ('wrong-pq-fingerprint', dataclasses.replace(base, pq_fingerprint=b'F' * 32).encode()),
        ('wrong-algorithm-domain', dataclasses.replace(base, classical_fingerprint=ldh(
            b'Q-PERIAPT-CONTINUITY-PREKEY-PUBLIC-CANDIDATE/v1', b'\2' + base.classical)).encode()),
    ):
        refused('signed-' + name, lambda changed=changed: pin.verify_historical_lease(owner.sign(PURPOSE, changed)))
    for index, raw in enumerate((a[:-1], a + b'\0', bytes(4) + a[4:])):
        refused('receipt-framing-' + str(index), lambda raw=raw: pin.verify_historical_lease(raw))
    canonical = both.to_bytes()
    reversed_proof = b'QPDLCF01' + both.second.wire + both.first.wire
    require(DirectoryLeaseConflict.verify(pin, b, a).to_bytes() == canonical,
            'receipt-pair verification must canonicalize')
    checks.append('pair-order-independent')
    refused('reversed-archive-container', lambda: DirectoryLeaseConflict.from_bytes(pin, reversed_proof))
    for name, raw in (('truncated-conflict', canonical[:-1]), ('trailing-conflict', canonical + b'\0'),
                      ('conflict-tag', b'QPDLCF02' + canonical[8:]), ('duplicate-receipt', b'QPDLCF01' + a + a),
                      ('randomized-same-body-container', b'QPDLCF01' + a + resigned_a)):
        refused(name, lambda raw=raw: DirectoryLeaseConflict.from_bytes(pin, raw))

    (output / 'openssl-service-key').write_bytes(pin.key.raw)
    (output / 'openssl-service-id').write_bytes(pin.identity)
    (output / 'openssl-first').write_bytes(a)
    (output / 'openssl-second').write_bytes(b)
    (output / 'openssl-conflict').write_bytes(canonical)
    sources = [Path(__file__), peer / 'qperiapt_continuity_reference/directory_lease.py',
               peer / 'qperiapt_continuity_reference/wire.py']
    report = {
        'schema': 'qperiapt-independent-directory-lease-checks/1',
        'checks': checks,
        'provider': {'cryptography': crypto.__version__, 'openssl': backend.openssl_version_text()},
        'source_sha256': {str(path.relative_to(peer)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sources},
        'native_sha256': hashlib.sha256(native.read_bytes()).hexdigest(),
        'publication_case_sha256': hashlib.sha256(original_bytes).hexdigest(),
        'public_files': {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in sorted(output.rglob('*')) if path.is_file()},
        'rust_signed_receipts_verified': 3,
        'rust_canonical_conflict_matched': True,
        'receipt_bytes': LEASE_BYTES,
        'conflict_bytes': CONFLICT_BYTES,
        'historical_only': True,
        'durable_allocation_or_session_qualified': False,
        'private_keys_exported': False,
        'release_claim_eligible': False,
    }
    (output / 'RESULT.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'checks': len(checks), 'scope': 'historical signed leases and attributable conflicts',
                      'rust_receipts': 3, 'receipt_bytes': LEASE_BYTES, 'conflict_bytes': CONFLICT_BYTES}))


if __name__ == '__main__':
    main()
