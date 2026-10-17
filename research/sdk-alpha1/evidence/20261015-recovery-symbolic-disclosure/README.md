# Two checked disclosure traces in the unchanged recovery model

The protected-state theory now has checked witnesses for both specified leakage
conditions. The pre-cut witness captures exactly one phase-1 generation record
before Cut exposes wrapping keys. The response uses newly reserved encapsulation
material after Cut; both endpoints then confirm and emit a message. The attacker
recovers the generation key from the captured record, decapsulates the public
response and decrypts the message. No later root snapshot, identity leak or
separate entropy leak is allowed. Tamarin verifies this witness in **80 steps**.

The later-access witness places both reservations after Cut and captures exactly
one phase-8 record after the application event. That record contains the new
root, so the attacker derives the traffic key and decrypts the message. Identity
and separate entropy leaks are again excluded. This witness verifies in **45
steps**. It shows why stopping access to new state is a distinct recovery
condition; it does not prove that the positive recovery conditions suffice.

A fresh Tamarin 1.12.0 / Maude 3.5.1 process replays all stored witness methods,
without `--prove`, on `proof/export-36.spthy`. It verifies the two disclosure
traces and the existing **59-step honest execution** witness. A second successful
invocation on the same exact input searches only for `generation_secret_origin`,
verifies it in **182 steps**, and retains all three checked witnesses. The
all-traces `clean_reservation_recovers_symbolic_message_secrecy` result is still
**analysis incomplete (1 steps)**; it is not accepted.

The first combined invocation, capped at a 2 GiB heap, failed with exit code 251
and explicit heap exhaustion. Its command, stdout and stderr are retained. The
separate witness replay succeeds within its 300-second bound at 2 GiB. The
combined invocation succeeds within its 600-second bound at 4 GiB. These are
resource-bounded proof checks, not controlled performance comparisons. No model,
formula, primitive equation or proof-depth bound changed to obtain success.

There are 67 recorded proof-method applications: 24 for later access and 43 for
the pre-cut capture. All model rules, equations, restrictions and all five full
lemma declarations match the original closed theory, including quantifier kinds,
annotations and leak exclusions. The canonical bare model is unchanged. One
helper navigated to an unused branch of the existing honest proof; no mutation
was applied there. The subsequent helper restricts selection to its named query.
The complete request record confirms mutations only on the two disclosure proofs.

Six controls reject changes to a lemma name, quantifier kind, reuse annotation,
signature equation, leak condition or lemma inventory. Removing both disclosure
proof scripts while retaining every declaration causes both results to become
incomplete, despite process exit zero; the verifier rejects them. Generated
certificates include placeholders for other queries and unused existential
branches. Only exact verified terminal results are admitted.

`CAPTURE.zip` contains **495 public members**, SHA-256
`0ef55c5d5a2e85ae3e34b06ee9f1713f4e51fb06bbad198f62b17ec291b2d7f2`.
The certificate SHA-256 is
`3e217d9c6d535739826799f46078137328dda6bbc23d984ca88556095eacb8d2`.
Readback verifies every member hash, accepted terminal receipts, the rejected
missing-proof control and owned-server cleanup. The archive retains the pinned
arm64 toolchain contract, raw interactive requests/responses, failed combined
attempt and its diagnostic sample. The short sample does not establish the
prover's internal performance cause; the heap-exhaustion terminal does establish
that the first combined attempt exceeded its configured memory limit.

The [research scope](../../../continuity-recovery-symbolic/README.md) remains one
exchange per independently initialized identity pair, ideal KEM/hash/signature
primitives and protected-state confidentiality. It omits shared device journals,
concrete message chains and deletion, lifecycle policy transitions, exposed
ML-DSA coins and a computational/refinement argument for the Rust implementation.
These witnesses do not prove continuous PQ recovery, a maximum exposure bound or
the explicit nested-encryption alternative. Actual SDK disclosure experiments
retain their separate empirical status.

Base commit: `232ca85a32c555f8769deeba1fb14c455195ac2c`. This checkpoint changes
research status and evidence only. Private SDK cohorts and device state were not
opened; no global tool installation, protocol or product runtime changed. The
owned proof server and all local proof processes have terminated. The full 0.2.0
goal and current-source hosted checks remain open.
