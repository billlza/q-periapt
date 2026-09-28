#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Public-only witness oracle, run alongside the bootstrap enrollment oracle.

Run through artifact/python-run.sh. This checks independently encoded commands,
attempt freshness, full signed replies and monotonic transitions. It is not a
production enrollment API or evidence of protection against witness-store rollback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

# The repository runner dispatches through runpy rather than adding this script's directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_public_vectors import Oracle, Reader, bootstrap_hash, digest, require, save


def commit(domain: str, body: bytes) -> bytes:
    name = domain.encode('ascii')
    return hashlib.sha3_256(len(name).to_bytes(8, 'big') + name
                           + len(body).to_bytes(8, 'big') + body).digest()


def public_body(oracle: Oracle, name: str, length: int) -> bytes:
    # The companion verifier authenticates these same enrollment/policy fixtures.
    wire = Reader(oracle.read(name))
    require(wire.integer(4) == length, 'enrollment body width')
    body = wire.take(length)
    wire.take(3373)
    wire.finish()
    return body


def head(reader: Reader) -> tuple[int, int, bytes]:
    fence, revision, digest_bytes = reader.integer(8), reader.integer(8), reader.take(32)
    require(0 < fence < 2**64 - 1 and 0 < revision < 2**64 - 1 and any(digest_bytes), 'invalid head')
    return fence, revision, digest_bytes


def verify(oracle: Oracle) -> dict:
    witness = oracle.read('anchor-witness.pub', 1985)
    instance = oracle.read('anchor-instance.id', 32)
    require(any(instance), 'zero witness identity')
    authority = commit('Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1', instance + witness)
    require(authority == oracle.read('anchor-authority.digest', 32), 'witness binding')
    device = oracle.read('bootstrap-r-device.pub', 1985)
    certificate = public_body(oracle, 'bootstrap-r-credential.bin', 2097)
    require(certificate[:8] == b'QPCERT01' and certificate[112:] == device, 'device public binding')
    owner = bootstrap_hash(b'storage-owner', certificate[8:64] + digest('CREDENTIAL', certificate))
    policy = public_body(oracle, 'bootstrap-policy.bin', 198)
    subject = oracle.read('anchor-journal.id', 32) + owner + digest('SESSION-POLICY', policy)
    initial = (1, 1, oracle.read('anchor-genesis.digest', 32))
    observed = initial
    last = None
    challenges = set()
    commands = []
    request_digests = []
    outcomes = []
    for index, expected_kind in enumerate([1, 2, 2, 3, 2, 1]):
        request = oracle.envelope(f'anchor-{index}-request', 7, device)
        require(len(request) == 297, 'request body width')
        r = Reader(request)
        require(r.take(8) == b'QPANRQ01' and r.take(32) == authority and r.take(96) == subject, 'request scope')
        command, challenge = r.take(32), r.take(32)
        require(any(challenge) and challenge not in challenges, 'attempt challenge reused')
        challenges.add(challenge)
        kind = r.integer(1)
        require(kind == expected_kind, 'command order')
        if kind == 1:
            require(r.take(96) == bytes(96), 'noncanonical query')
            expected_outcome = 1
        else:
            prior, target = head(r), head(r)
            if kind == 2:
                require(target[0] == prior[0] and target[1] == prior[1] + 1
                        and target[2] != prior[2], 'noncanonical state advance')
            else:
                require(target[0] == prior[0] + 1 and target[1:] == prior[1:], 'noncanonical fence advance')
            if observed == target and last == command:
                expected_outcome = 3
            elif observed != prior:
                expected_outcome = 4
            else:
                observed, last = target, command
                expected_outcome = 2
        r.finish()
        require(command == commit('Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1',
                                  authority + subject + request[200:]), 'immutable command identity')
        attempt = commit('Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1', request)
        commands.append(command)
        request_digests.append(attempt)
        response = oracle.envelope(f'anchor-{index}-reply', 8, witness)
        require(len(response) == 282, 'reply body width')
        r = Reader(response)
        require(r.take(8) == b'QPANRS01' and r.take(32) == authority and r.take(96) == subject, 'reply scope')
        require(r.take(32) == attempt and r.take(32) == command, 'reply attempt/command binding')
        outcome = r.integer(1)
        require(outcome == expected_outcome, 'witness outcome')
        require(head(r) == observed, 'observed full head')
        present, last_bytes = r.integer(1), r.take(32)
        require((present, last_bytes) == (0, bytes(32)) if last is None
                else (present, last_bytes) == (1, last), 'last transition binding')
        r.finish()
        outcomes.append(outcome)
    require(outcomes == [1, 2, 3, 2, 4, 1], 'transition results')
    require(commands[1] == commands[2] and request_digests[1] != request_digests[2], 'retry freshness')
    require(commands[0] == commands[5] and request_digests[0] != request_digests[5], 'query freshness')
    require(observed == (2, 2, bytes([42]) * 32), 'final witness head')
    return {'schema_version': 1, 'signed_envelopes': 12, 'signature_negative_controls': 60,
            'requests': 6, 'outcomes': outcomes, 'command_binding': 'verified',
            'fresh_attempt_binding': 'verified', 'fence_and_state_advance': 'verified',
            'enrollment': 'validated separately by verify_public_vectors.py over the same fixtures',
            'scope': 'public wire oracle; storage crashes and witness trust are separate checks',
            'inputs_sha256': oracle.inputs, 'openssl_commands': oracle.commands}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--openssl', required=True)
    args = parser.parse_args()
    args.output.mkdir()
    oracle = Oracle(args.fixtures, args.output, args.openssl)
    result = verify(oracle)
    save(args.output / 'result.json', (json.dumps(result, indent=2) + '\n').encode())
    print('ANCHOR_PUBLIC_VECTORS_PASS envelopes=12 signature_negative_controls=60 transitions=6')


if __name__ == '__main__':
    main()
