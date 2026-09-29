# Durable reservation disclosure experiment

This experiment tests one necessary recovery boundary in the actual v4 candidate.
It is a finite passive-disclosure counterexample, not a proof of continuous PQ
recovery or an attack on the SDK's stated sealed-operation contract. Replaying
exact reserved entropy after a crash is intentional; classifying that replay as
new secret entropy after a disclosure would be incorrect.

## Actual cuts and attacker inputs

Each case starts from a real confirmed bootstrap and encrypted device journals.
A bounded child process starts target epoch 1, commits its first reservation,
and stops at the existing pre-computation barrier. The parent kills and reaps
that child, reopens the persisted journal and checks the exact pending phase:

| Cut | Disclosed reservation | Reconstructed future contribution |
| --- | --- | --- |
| `rekey-key-reserved` | 277-byte SDK key-generation token, before key computation or offer publication | Exact offered hybrid public/private key and the combined secret from the later public response ciphertext |
| `rekey-response-kem-reserved` | 245-byte SDK encapsulation token, after offer authentication but before encapsulation computation or response publication | Exact response ciphertext and combined secret |

The predictor receives the prior rekey root, journal identity, host wrapping key
and exact sealed token captured at that cut. It does not receive device signing
owners, an installed future root, future traffic keys or later reservations.
After capture, its method accepts only the verified public policy configuration
and the later public offer/response wires. It has no journal or filesystem
parameter. This is a code-level input boundary, not an instrumented operating
system noninterference proof.

The predictor uses the SDK's actual sealed-operation owner to recover the saved
KEM computation. A token opened under a different wrapping key must return
`InvalidPrivateKey`. With the disclosed key, the generated public key or
ciphertext must equal the honest later wire exactly. The predictor independently
assembles the documented operation scopes, pending-root KDF and epoch-traffic
KDF from the captured root and public bytes. It constructs separate intercepting
traffic owners for the two directions; it never reads the honest future owners.

Both honest peers finish final/receipt confirmation, report epoch 1, close and
reopen their journals. The driver then generates fresh random 128-byte application
payloads, commits three messages in each direction and checks actual honest
delivery. Each intercepted frame also passes AEAD authentication and returns the
same plaintext using only the predictor's derived owners. The predictor is not
given the expected plaintext.

## Observation and meaning

Both reservation cuts recover all six tested future application messages: twelve
actual decryptions across two independent cases, after completed rekey and
restart. The public logs record the cut, confirmed epoch and recovered-message
count, with no secret bytes or private-state hashes. The tests are
`disclosed_key_reservation_exposes_traffic_computed_after_restart` and
`disclosed_encapsulation_reservation_exposes_traffic_computed_after_restart` in
[`src/durable/messages/tests/reservation_disclosure.rs`](src/durable/messages/tests/reservation_disclosure.rs).

The fixed Rust 1.98.1 run passes all 153 release tests, with no failures or ignored
tests, in 226.86 seconds. Strict all-target Clippy, formatting, Rust 1.90 locked
all-target compilation and 45 standalone source-contract tests also pass. The
research source inventory is 183 tracked Rust files across the repository.
These local checks do not qualify installed product bindings or replace hosted
execution on other platforms.

This falsifies a recovery rule based only on execution time, completed epoch or
post-restart confirmation. The contribution's ancestry starts when its entropy
reservation becomes recoverable, before the KEM function runs. A future recovery
analysis must follow those descendants and identify a later authenticated
contribution that was not exposed at the relevant disclosure cut.

No later epoch is labelled secure because this predictor stops. The experiment
does not search all attacks, exercise active impersonation, quantify recovery
delay, test every pending phase or establish the product scheduling policy.
Both signatures remain enforced by the honest protocol. Continuous-recovery and
hybrid-combiner arguments remain separate requirements.

The disclosed host key is especially consequential: if the attacker can also read
later encrypted journal images or reservations protected by that same key, this
one-snapshot model no longer applies. New randomness alone does not protect those
later records from a known wrapping key. Host-key replacement, independent
keystore protection and any claimed erasure/backup guarantees require their own
explicit lifecycle. Logical removal of old tokens cannot revoke copies already
captured by the attacker.
