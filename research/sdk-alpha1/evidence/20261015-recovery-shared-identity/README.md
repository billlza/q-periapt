# Shared identity scope and proof-runner decoding

This checkpoint checks a concrete limit of the earlier independent-identity
recovery theorem. It also retains the first hosted failure of that theorem's CI
replay and a locally validated UTF-8 correction. It is not release qualification.

## Shared signing identities

The separate [`shared-identity.spthy`](../../../continuity-recovery-symbolic/shared-identity.spthy)
model allocates one signing-key pair and lets multiple independently initialized
sessions use it. Its SHA-256 is
`02e731a4d97a5fbdf64bea4c1ecee304c03686a9231f7eea73150821c1c06653`.
Wrapping keys remain per session. All rules after Setup, equations, restrictions
and five original full query declarations are unchanged. Two proof observations
bind the signing keys and sessions to their shared identity owner.

| Property | Search | Independent replay | Result |
| --- | ---: | ---: | --- |
| `other_session_identity_leak_breaks_session_scoped_recovery` | 30 steps | 53 steps | Verified existential trace |
| `shared_identity_key_origin` | 356 steps | 356 steps | Verified universal provenance property |

Both replays use fresh Tamarin 1.12.0 / Maude 3.5.1 processes, without `--prove`,
at two threads and a 4 GiB heap limit. Neither property has a reusable premise.
`experiments/VERIFIED_15.json` checks complete parsed declarations, normalized
expanded signatures/equations, operational rules and restrictions, and the
concrete witness graph. The checked trace has:

- Two different session IDs with the same identity owner.
- Exactly one responder identity leak, labelled with the sibling session.
- Both target-session KEM reservations after the target Cut.
- No Snapshot or EntropyLeak anywhere in the trace.
- Knowledge of the exact initiator application payload emitted in the target
  session, with the required causal ordering.

The attacker can use the shared responder key to authenticate a substituted
response with a known contribution. The trace does not require both honest peers
to confirm that root. It refutes extending the original session-scoped secrecy
formula unchanged to shared identities. It does not contradict the theorem for
independently generated identities, and is not an executed SDK decryption attack.

The key-origin property places a signing-key disclosure in a session using the
same identity pair; it establishes no timing bound. A positive recovery theorem
for reused device keys remains open. Arbitrary one-sided key overlap between
different pairs, shared journals, multiple epochs, computational primitives and
SDK refinement remain outside this variant.

The implementation motivates this scope: [`DeviceEnrollment::signer`](../../../continuity-identity-candidate/src/enrollment.rs)
reopens the original signer file, and [`DeviceJournal::initiate`](../../../continuity-identity-candidate/src/durable/initiator.rs)
uses separate request identities while taking an existing device signer.
Rekey [offer](../../../continuity-identity-candidate/src/durable/messages/rekey.rs)
and [response](../../../continuity-identity-candidate/src/durable/messages/rekey/response.rs)
preparation compare that signer's public key to the authenticated device key.
The existing device-level revocation/replacement requirement remains appropriate.

## Retained non-successful attempts

Direct automatic search of the original universal secrecy query on the shared
model reached its 300-second deadline and returned no accepted result. The
explicit stronger existential witness, rather than that timeout, establishes the
counterexample. The initial certificate comparator also rejected Tamarin's
builtin-to-expanded-function metadata formatting. The corrected comparator
validates that metadata against the unchanged full function signature before
comparing equations, rules, restrictions and complete declarations. The rejected
attempt and its correction are retained; no proof input was weakened.

## CI decoding failure and local correction

Push run [38755817078](https://github.com/billlza/q-periapt/actions/runs/38755817078),
job `116493820155`, completes the existing handshake/migration proof step, then
fails the new recovery replay on source `74cbb2c0`. Its retained artifact
`11984496181` contains `positive.stderr` and `RESULT.json`: Linux GHC rejects
a certificate byte sequence starting with 226 under `LC_ALL=C`. The prover exits
1 before proof evaluation; this is not a failed secrecy theorem or heap exhaustion.

Commit `28a226813f2351ad5e49458aef7008d264c96413` selects an explicit UTF-8 locale
for the bounded prover subprocess: `C.UTF-8` on Linux, `en_US.UTF-8` on macOS.
Ambient RTS overrides remain excluded. All 190 related tests pass in the clean
validation clone, and source admission passes. A complete local replay under the
new environment verifies the unchanged 20-property group and three separate
witnesses; `utf8-replay-16/RESULT.json` binds the actual checker and certificate
digests. Hosted Linux validation of the fix remains pending. The current Rust
CodeQL analysis is preserved; these local commits have not been pushed over it.

## Archive

`CAPTURE.zip` contains 121 public members, all reopened and rehashed. Its SHA-256
is `58f406770e1f5f601325798eb48002d29d80845e391a66299813a4eb21db9005`.
`CAPTURE.json` lists each member digest; `READBACK.json` records the readback.
The archive includes both search/replay certificates and terminal receipts,
source copies, semantic comparisons, the direct-search timeout, CI diagnostics,
the UTF-8 replay, and regression/source-gate results. No private SDK runtime
cohort, key store or device state was reopened or selected.
