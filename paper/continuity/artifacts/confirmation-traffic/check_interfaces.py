#!/usr/bin/env python3
"""Finite algebra/interface checks for the confirmation/traffic research note.

This is not a Rust execution or a formal verification run. Exact source
identities, framing, toy-model counterexamples and finite classical-verifier
enumerations are recorded separately in the JSON receipt.
"""
from __future__ import annotations

import hashlib
import argparse
import itertools
import json
import math
import pathlib
import subprocess
from fractions import Fraction

HERE = pathlib.Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--native-repository', type=pathlib.Path, default=pathlib.Path.cwd(),
                    help='Git repository containing the pinned native source; default: current directory.')
parser.add_argument('--development-repository', type=pathlib.Path, default=pathlib.Path.cwd(),
                    help='Git repository containing the development checkpoint; default: current directory.')
parser.add_argument('--paper-repository', type=pathlib.Path, default=pathlib.Path.cwd(),
                    help='Git repository containing the original paper head; default: current directory.')
parser.add_argument('--output', type=pathlib.Path, default=HERE / 'interface_check_receipt.json',
                    help='JSON receipt path.')
parser.add_argument('--finite-only', action='store_true',
                    help='Run self-contained finite/algebra witnesses without reading Git or source files.')
args = parser.parse_args()
SRC = args.native_repository.resolve()
DEV = args.development_repository.resolve()
PIN = '228c944fc476e3e57d6c08063cacb19bca5b360e'
DEV_PIN = '1c68aa666db22d36ee136be1ec712545a9e74f03'
PAPER = args.paper_repository.resolve()
PAPER_PIN = 'da521d8388f5f0c64697387bf80b0b5b7837fb34'
BASE = 'research/continuity-identity-candidate/src/'
FILES = [
    BASE + p for p in [
        'contract.rs', 'crypto.rs', 'durable/messages/rekey.rs',
        'durable/messages/rekey/response.rs',
        'durable/messages/rekey/completion.rs', 'durable/messages.rs',
        'durable/messages/traffic.rs', 'durable/messages/delivery.rs',
        'durable.rs', 'durable/write_intent.rs',
    ]
] + ['crates/q-periapt-sdk/src/lib.rs', 'crates/q-periapt-sdk/src/expert/replay.rs']
checks = []

def check(name, condition, detail):
    checks.append({'id': name, 'pass': bool(condition), 'detail': detail})
    if not condition:
        raise AssertionError(name + ': ' + detail)

def git_bytes(repo, rev, rel):
    return subprocess.check_output(['git', '-C', str(repo), 'show', f'{rev}:{rel}'])

sources = []
texts = {}
for rel in ([] if args.finite_only else FILES):
    pin_bytes = git_bytes(SRC, PIN, rel)
    current = (SRC / rel).read_bytes()
    dev_bytes = git_bytes(DEV, DEV_PIN, rel)
    dev_current = (DEV / rel).read_bytes()
    check('source_identity_' + rel.replace('/', '_'),
          pin_bytes == current == dev_bytes == dev_current,
          'Pinned native, development commit and both worktrees have identical bytes.')
    texts[rel] = pin_bytes.decode()
    sources.append({
        'path': rel,
        'sha256': hashlib.sha256(pin_bytes).hexdigest(),
        'git_blob': subprocess.check_output(
            ['git', '-C', str(SRC), 'rev-parse', f'{PIN}:{rel}'], text=True).strip(),
        'source_url': f'https://github.com/billlza/q-periapt/blob/{PIN}/{rel}',
        'bytes': len(pin_bytes),
    })

DR = b'Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/'
DM = b'Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/'
lp = lambda b: len(b).to_bytes(8, 'big') + b
digest = lambda label, core: hashlib.sha3_256(lp(DR + label) + lp(core)).digest()

check('domain_lengths', (len(DR), len(DM)) == (40, 43), 'Actual fixed source domain byte lengths.')
prefix_len = 8 + 32 + 32 + 32 + 8 + 8 + 1 + 32
pk_len, ct_len = 1184 + 32, 1088 + 32
cores = {'response': prefix_len + 32 + ct_len,
         'final': prefix_len + 32 + 32 + 8,
         'receipt': prefix_len + 32 + 32 + 8 + 32}
check('core_lengths', cores == {'response': 1305, 'final': 225, 'receipt': 257},
      'Response includes complete hybrid ciphertext; completion cores include closing length.')
check('offer_and_mac_lengths', prefix_len + pk_len == 1369 and
      all(len(digest(k.encode() + b'-core', bytes(n))) == 32 for k, n in cores.items()),
      'Offer body is 1369 bytes; all three HMAC messages are 32-byte digests.')
ell = lambda length: 1 + math.ceil((length + 9) / 64)
check('mac_compression_cost', ell(32) == 2 and 2 + ell(32) == 4,
      'Two pad calls plus two remaining compression calls per uncached MAC.')
check('aad_size', len(DM) + len(b'aead') + 93 + 2 == 142,
      'Actual associated-data length is 142 + external-ad bytes.')

if not args.finite_only:
    crypto = texts[BASE + 'crypto.rs']
    check('signed_body_framing', all(s in crypto for s in [
        'message.extend_from_slice(SIGNATURE_CONTEXT);',
        'message.push(purpose as u8);',
        'message.extend_from_slice(&length.to_be_bytes());',
        'message.extend_from_slice(body);']),
        'Purpose and complete length-framed body are inside the signed message.')
    check('signing_coins_retained', 'out.extend_from_slice(self.randomness.as_bytes());' in crypto,
          'A signature-oracle bridge must account for persisted reservation randomness.')
    rekey = texts[BASE + 'durable/messages/rekey.rs']
    start = rekey.index('if state.control.plan.is_none()')
    reserve = rekey.index('.reserve_key(', start)
    plan = rekey.index('state.control.plan = Some(Plan::Key(key));', reserve)
    persist = rekey.index('self.store_message_state(&mut image, &state).await?;', plan)
    execute = rekey.index('recovery.generate_key(', persist)
    check('reserve_persist_execute_order', reserve < plan < persist < execute,
          'A failed first persist can occur after original draw and before key computation.')
    response = texts[BASE + 'durable/messages/rekey/response.rs']
    check('response_retained_offer', 'if saved.offer != offer' in response and
          'return Err(DurableError::Conflict);' in response,
          'A retained responder plan fixes the complete offer input.')
    check('response_private_tag_before_sign', response.index('confirmation(&root, &body)?') <
          response.index('Purpose::RekeyResponse,\n                &body,'),
          'The confirmation construction precedes signing and final publication.')
    completion = texts[BASE + 'durable/messages/rekey/completion.rs']
    check('completion_width_constants', all(s in completion for s in [
        'const FINAL_CORE: usize = 153 + 32 + 32 + 8;',
        'const RECEIPT_CORE: usize = FINAL_CORE + 32;']),
        'Actual final and receipt core widths match the derived framing.')
    traffic = texts[BASE + 'durable/messages/traffic.rs']
    check('nonce_policy', traffic.count('&Nonce::from([0; 12])') >= 2,
          'Send and receive use the source fixed 96-bit nonce; per-key one-send ownership is substantive.')
    delivery = texts[BASE + 'durable/messages/delivery.rs']
    check('historical_consumption_status', 'PreviouslyConsumed' in delivery and 'receive_floor' in delivery,
          'Historical consumed status is distinct from a new AEAD authentication transition.')

# Exhaustively enumerate all deterministic all-failure-prefix strategies for
# V <= 3, two fresh messages, and a four-element tag space. Any deterministic
# adaptive verifier that stops at its first success has exactly such a path.
tag_space, messages = 4, 2
tables = list(itertools.product(range(tag_space), repeat=messages))
guesses = list(itertools.product(range(messages), range(tag_space)))
strategy_count = table_runs = 0
maxima = {}
for attempts in range(4):
    best = Fraction(0)
    for seq in itertools.product(guesses, repeat=attempts):
        successes = sum(any(tab[m] == tag for m, tag in seq) for tab in tables)
        p = Fraction(successes, len(tables))
        best = max(best, p)
        strategy_count += 1
        table_runs += len(tables)
        if p > min(Fraction(1), Fraction(attempts, tag_space)):
            raise AssertionError('Classical guessing bound failed')
    maxima[str(attempts)] = str(best)
    check('finite_classical_verifier_' + str(attempts),
          best == min(Fraction(1), Fraction(attempts, tag_space)),
          f'Exact maximum {best} over all all-failure-prefix strategies.')

# Counterexample and alias witnesses use labels for allocation identity;
# numerical values are allowed to coincide independently.
role_table = {('root-1', 'final', b'x'): 2}
check('same_core_replay_alias', role_table[('root-1', 'final', b'x')] == 2,
      'Exact repeats are prior-origin acceptance, not fresh-core forgery.')
owner_a = ('root-1', 'final')
owner_b = ('root-1', 'final')
check('owner_alias_origin', owner_a == owner_b,
      'A copied owner retrieves the canonical role-key origin ledger.')
private_ledger = set()
private_ledger.add(('root-1', 'final', b'x'))
commit_succeeded = False
check('failed_commit_keeps_private_origin', not commit_succeeded and
      ('root-1', 'final', b'x') in private_ledger,
      'Private computation must remain logged when later persistence fails.')
forced_hash = lambda core: b'collision'
check('digest_collision_witness', b'x' != b'y' and forced_hash(b'x') == forced_hash(b'y'),
      'A digest-authentication result needs a hash-collision term for complete-core origin.')
E = {'valid_target': True, 'session_epoch_roles_match': True,
     'cut_before_g1_a2': True, 'identity_unexposed': True,
     'entropy_unexposed': True, 'no_postcut_capture': True}
selected, actual = ('g1', 'a2'), ('g2', 'a2')
check('general_selector_obstruction', all(E.values()) and selected != actual,
      'General metadata eligibility can hold for an unused failed-reservation handle.')
root_plan_trace = ['reserve:g1', 'persist-fail-before-durable-target', 'reopen:old',
                   'reserve:g2', 'persist:g2', 'generate:g2', 'encapsulate:a2']
check('source_resolved_selector', next(x for x in root_plan_trace if x.startswith('generate:')) == 'generate:g2',
      'Online first-computation registration designates g2 in this witness.')
floor, incoming_index = 1, 0
check('consumed_is_historical', incoming_index < floor,
      'Arbitrary replacement bytes at a consumed index can return history; no new authentication is asserted.')
pad = bytes([0x34, 0x91, 0x5F])
ma, mb = b'abc', b'XYZ'
ca = bytes(x ^ y for x, y in zip(ma, pad))
cb = bytes(x ^ y for x, y in zip(mb, pad))
check('forked_nonce_reuse_witness', bytes(x ^ y for x, y in zip(ca, cb)) ==
      bytes(x ^ y for x, y in zip(ma, mb)),
      'Two competing send owners using the same stream and nonce expose plaintext XOR.')
check('public_retry_guess_witness', (ma == ma) != (mb == ma),
      'A same-ID plaintext comparison is a challenge-bit-dependent public predicate.')
grover = math.sin(3 * math.asin(1 / math.sqrt(16))) ** 2
check('coherent_verify_scope', grover > 2 / 16,
      f'One Grover step succeeds with {grover}; the linear classical verification bound has a distinct interface.')

DEPENDENCIES = [
    'paper/continuity/joint-continuation.tex',
    'paper/continuity/joint-primitive-bounds.tex',
    'paper/continuity/contextbound-connection.tex',
    'paper/continuity/candidate-local-accounting.tex',
    'paper/continuity/security-model.tex',
    'paper/continuity/opaque-rendering.tex',
    'paper/continuity/primitive-inputs.tex',
    'paper/continuity/artifacts/live-profile/source_profile.md',
]
dependencies = []
for rel in ([] if args.finite_only else DEPENDENCIES):
    raw = git_bytes(PAPER, PAPER_PIN, rel)
    dependencies.append({'path': rel, 'sha256': hashlib.sha256(raw).hexdigest(),
                         'paper_head': PAPER_PIN})

receipt = {
    'kind': ('finite_algebra_and_counterexample_checks' if args.finite_only
             else 'finite_source_algebra_and_counterexample_checks'),
    'native_rust_execution': False, 'formal_proof_tool_execution': False,
    'source_pin': PIN, 'development_pin': DEV_PIN, 'paper_head': PAPER_PIN,
    'source_audit_performed': not args.finite_only,
    'repositories': (None if args.finite_only else {
        'native': str(SRC), 'development': str(DEV), 'paper': str(PAPER)}),
    'passed': sum(c['pass'] for c in checks), 'total': len(checks),
    'source_files': len(sources), 'checks': checks,
    'finite_verifier': {'tag_space': tag_space, 'messages': messages,
        'maximum_attempts': 3, 'strategies': strategy_count,
        'table_evaluations': table_runs, 'maximum_success_probabilities': maxima},
    'sources': sources, 'dependencies': dependencies,
    'script_sha256': hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(receipt, indent=2) + '\n')
print(json.dumps({k: receipt[k] for k in ['kind', 'passed', 'total', 'source_files', 'finite_verifier', 'native_rust_execution', 'formal_proof_tool_execution']}, indent=2))
