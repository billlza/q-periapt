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
    policy = public_body(oracle, 'bootstrap-policy.bin', 200)
    require(policy[:8] == b'QPSESP03' and int.from_bytes(policy[198:], 'big') == 1024,
            'explicit signed fixture send budget')
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


def verify_joint(oracle: Oracle) -> dict:
    root = oracle.read('bootstrap-r-root.pub', 1985)
    device = oracle.read('bootstrap-r-device.pub', 1985)
    grant = Reader(oracle.read('anchor-renewal-grant.bin'))
    require(grant.take(8) == b'QPRNB001', 'renewal container tag')
    fields = []
    for _ in range(6):
        size = grant.integer(2)
        require(0 < size <= 8192, 'renewal field bound')
        fields.append(grant.take(size))
    grant.finish()
    signed, original, previous, successor, old_roster, next_roster = fields
    require(original == previous == oracle.read('bootstrap-r-credential.bin'),
            'renewal original and predecessor differ')
    require(old_roster == oracle.read('bootstrap-r-roster.bin'), 'renewal predecessor roster')
    bodies = []
    for name, wire, purpose in [('statement', signed, 15), ('original', original, 1),
                                ('successor', successor, 1), ('previous-roster', old_roster, 2),
                                ('successor-roster', next_roster, 2)]:
        bodies.append(oracle.envelope_bytes('joint-' + name, wire, purpose, root))
    statement, original, successor, old_roster, next_roster = bodies
    one, two = (1).to_bytes(8, 'big'), (2).to_bytes(8, 'big')
    interval = (100).to_bytes(8, 'big') + (200).to_bytes(8, 'big')
    extended = (100).to_bytes(8, 'big') + (300).to_bytes(8, 'big')
    family = oracle.read('bootstrap-family.bin', 32)
    account, identity = digest('ACCOUNT', root), bytes([2]) * 16
    require(original == b'QPCERT01' + account + identity + one + interval + family + device,
            'original credential grammar')
    require(successor == b'QPCERT01' + account + identity + one + extended + family + device,
            'successor same-key extension')
    old_digest, next_digest = digest('CREDENTIAL', original), digest('CREDENTIAL', successor)
    require(old_roster == b'QPROST01' + account + one + interval + b'\0\1'
            + identity + one + old_digest, 'old roster membership')
    require(next_roster == b'QPROST01' + account + two + extended + b'\0\1'
            + identity + one + next_digest, 'new roster membership')
    policy = public_body(oracle, 'bootstrap-policy.bin', 200)
    policy_digest = digest('SESSION-POLICY', policy)
    operation = oracle.read('anchor-renewal-operation.id', 32)
    require(any(operation), 'renewal operation identity')
    require(statement == b'QPCRNW01' + operation + account + identity + one + family
            + commit('Q-PERIAPT-CREDENTIAL-RENEWAL-KEY/v1', device)
            + old_digest + old_digest + next_digest + policy_digest
            + one + digest('ROSTER', old_roster) + two + digest('ROSTER', next_roster) + b'\x01',
            'complete root-approved statement')
    statement_digest = commit('Q-PERIAPT-CREDENTIAL-RENEWAL-STATEMENT/v1', statement)
    owner = bootstrap_hash(b'storage-owner', account + identity + one + old_digest)
    results = {}
    challenges = set()
    for flow, terminal, transition, target_byte in [('applied', 8, 5, 51), ('closed', 9, 7, 52)]:
        prefix = 'joint-' + flow
        witness = oracle.read(prefix + '-witness.pub', 1985)
        instance = oracle.read(prefix + '-instance.id', 32)
        authority = commit('Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1', instance + witness)
        journal = oracle.read(prefix + '-journal.id', 32)
        require(any(instance) and any(journal), 'joint identity')
        subject = journal + owner + policy_digest
        initial = (1, 1, oracle.read(prefix + '-genesis.digest', 32))
        target = (1, 2, bytes([target_byte]) * 32)
        proposal = oracle.read(prefix + '-proposal.bin', 296)
        p = Reader(proposal)
        require(p.take(8) == b'QPCRNP01' and p.take(32) == authority
                and p.take(96) == subject and p.take(32) == operation
                and p.take(32) == statement_digest, 'complete proposal scope')
        require(head(p) == initial and head(p) == target and initial[2] != target[2],
                'adjacent proposal expectations')
        p.finish()
        binding = commit('Q-PERIAPT-ANCHOR-CREDENTIAL-PROPOSAL/v1', proposal)
        require(binding == oracle.read(prefix + '-proposal.digest', 32), 'proposal binding')
        commit_command = commit('Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1',
                                authority + subject + bytes([5]) + binding + bytes(64))
        kinds = [6, 6, transition, transition, 12 - transition, 6, 8, 8, 6, 5]
        outcomes = [10, 7, terminal, terminal, terminal, terminal, 11, 11, 10, 10]
        attempts = {}
        for index, (kind, outcome) in enumerate(zip(kinds, outcomes, strict=True)):
            name = prefix + '-' + str(index)
            request = oracle.envelope(name + '-request', 7, device)
            r = Reader(request)
            require(len(request) == 297 and r.take(8) == b'QPANRQ01'
                    and r.take(32) == authority and r.take(96) == subject, 'joint request scope')
            command, challenge = r.take(32), r.take(32)
            require(any(challenge) and challenge not in challenges, 'joint attempt freshness')
            challenges.add(challenge)
            require(r.take(97) == bytes([kind]) + binding + bytes(64), 'joint command grammar')
            r.finish()
            require(command == commit('Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1',
                                      authority + subject + request[200:]), 'joint command identity')
            attempt = commit('Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1', request)
            if kind in attempts:
                old_command, old_attempt = attempts[kind]
                require(command == old_command and attempt != old_attempt, 'joint exact fresh retry')
            attempts[kind] = command, attempt
            reply = oracle.envelope(name + '-reply', 8, witness)
            r = Reader(reply)
            require(len(reply) == 282 and r.take(8) == b'QPANRS01'
                    and r.take(32) == authority and r.take(96) == subject, 'joint reply scope')
            require(r.take(32) == attempt and r.take(32) == command and r.integer(1) == outcome,
                    'joint reply exact observation')
            applied = flow == 'applied' and index >= 2
            require(head(r) == (target if applied else initial), 'joint observed head')
            require((r.integer(1), r.take(32)) == ((1, commit_command) if applied else (0, bytes(32))),
                    'joint last commit identity')
            r.finish()
        results[flow] = {'requests': len(kinds), 'outcomes': outcomes}
    return {'flows': results, 'signed_envelopes': 45, 'signature_negative_controls': 225,
            'scope': 'Independent public grammar, root statement and dual signatures; fixture targets are opaque expectations, not local apply or an independent protocol implementation'}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--openssl', required=True)
    args = parser.parse_args()
    args.output.mkdir()
    oracle = Oracle(args.fixtures, args.output, args.openssl)
    result = verify(oracle)
    result["joint_renewal"] = verify_joint(oracle)
    result["signed_envelopes"] += result["joint_renewal"]["signed_envelopes"]
    result["signature_negative_controls"] += result["joint_renewal"]["signature_negative_controls"]
    save(args.output / 'result.json', (json.dumps(result, indent=2) + '\n').encode())
    print('ANCHOR_PUBLIC_VECTORS_PASS envelopes=57 signature_negative_controls=285 requests=26')


if __name__ == '__main__':
    main()
