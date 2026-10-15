# Continuity recovery transition research

Status: **two checked statements: generated-key provenance and an honest
execution witness.** Recovery secrecy and the two specified disclosure witnesses
remain unproved. This directory is not a release proof gate; the full 0.2.0
construction, shared-device lifecycle, computational argument and external
review remain open.

[`protected-state.spthy`](protected-state.spthy) is an unchanged symbolic projection
of one identity-authenticated rekey exchange. `generation_secret_origin` is
verified by Tamarin 1.12.0 / Maude 3.5.1 using induction: 182 steps. It gives a
necessary condition for knowing an honest generated decapsulation key: modeled
generation-entropy leakage or acquisition of a phase-1/2/3 record. It is not a
causal timing bound or a recovery-secrecy theorem. The lemma is not marked
`reuse`; no unproved lemma is imported as an assumption.

`recovery_is_executable` now has a checked 59-step witness: Cut precedes fresh
reservations, both endpoints confirm, and an application event follows both
confirmations, with no extra snapshot, identity or entropy leakage anywhere.
Interactive proof-method selection follows genuine signed-flight sources. A
fresh process then replays the exported methods **without `--prove`** and verifies
the witness. Initial and final closed-theory exports have identical rules,
equations, restrictions and all five complete lemma declarations, including
quantifier kinds and annotations. No model or hypothesis was weakened.

A combined invocation on that same exported input verifies both provenance and
execution. It reports **analysis incomplete** for
`clean_reservation_recovers_symbolic_message_secrecy`,
`pre_cut_generation_reservation_remains_exposed`, and
`later_storage_access_defeats_fresh_reservations`. Those three are not accepted.
The [execution checkpoint](../sdk-alpha1/evidence/20261015-recovery-symbolic-execution/README.md)
retains proof methods, independent replays, six rejected semantic substitutions
and a missing-proof control: removing the witness still exits zero, but its
terminal result is incomplete and is rejected. The
[preceding checkpoint](../sdk-alpha1/evidence/20261015-recovery-symbolic/README.md)
preserves the earlier one-lemma result and failed automated searches.

The exported certificate has placeholders for unselected lemmas and unused
alternative branches. One fully solved trace suffices for this `exists-trace`
claim; it does not discharge an `all-traces` secrecy claim. Acceptance is based
on the exact terminal lemma results, not a grep for a word or a successful exit.
The original bare model remains the editable source; the generated certificate
is evidence, not additional production code.

## Modeled boundaries

The old root is public from setup. Cut exposes both endpoints' wrapping keys.
Snapshot acquisition and unsealing are distinct rules: a captured protected
record becomes readable only after the matching wrapping capability is exposed.
Old records remain available, and later records can also be captured. Identity
and entropy leakage remain explicit adversary actions. A captured signer file
combined with that wrapping capability discloses the signing key too.

The ten plan phases follow the source-derived
[dependency map](../../docs/continuity/RECOVERY_DEPENDENCIES_V1.md): phases 1–3 retain
generation material, phase 4 encapsulation material, phases 5–7 and 9 the pending
root, and phase 8 the newly installed active root while local confirmation lags.
Receipt completion produces phase zero with the new root. Setup omits a redundant
initial phase-zero snapshot because its old root is already public.

Public flights contain ideal signatures and direction-separated confirmation
values. Later bodies bind hashes of preceding wires; the Equality restriction
represents signature and confirmation validation. The network still controls
message delivery. No restriction prohibits the disclosure rules. The positive
query explicitly requires fresh reservations after Cut, uncompromised identity
and entropy, and no captured record created after Cut.

The honest executable query requires no additional leakage anywhere. Each
negative query permits exactly one Snapshot event at its named phase and excludes
additional identity/entropy leaks. This prevents a supposed reservation attack
from passing only because the model also disclosed a later traffic root.

## Assumptions and uncovered obligations

- Protected state is an ideal confidentiality boundary. The alternative
  [`explicit-storage.spthy`](explicit-storage.spthy) retains nested symbolic
  encryption for journals and replay tokens; no lemma is accepted for it yet.
  No equivalence/refinement between the two theories has been proved.
- Each instance has independent signing and wrapping keys. Shared device owners,
  several sessions in one journal, identity reuse, multi-device authorization,
  policy expiry and revocation are not modeled.
- The ideal KEM equation and hash constructors do not prove the concrete hybrid
  combiner, ML-KEM, HKDF or confirmation-MAC assumptions. Perfect signatures omit
  the auxiliary information in exposed ML-DSA signing coins. That gap is not
  resolved by the signer-file disclosure rule.
- A message is a fresh symbolic payload under a direction-bound epoch key.
  Concrete message chains, nonce handling, ACKs, consumption floors, old-epoch
  records and application effects require separate correspondence and analysis.
- Durable phases assume atomic admitted transitions. Real fsync, witness checks,
  process faults, rollback resistance and serialization are not proved.
- This is one exchange per independently initialized pair. It proves no maximum
  exposure bound, multi-epoch recovery, epoch-three secrecy or continuous PQ
  recovery for the product.

## Reproduction

Use the pinned Tamarin 1.12.0 and Maude 3.5.1 identities. The checkpoint records
official macOS arm64 archive URLs, exact SHA-256 values, local extraction and the
repository toolchain-contract result; no global installation or Intel target was
added. The original provenance run can be reproduced on the bare model. To reproduce
the execution witness, extract `proof/export-19.spthy` from the execution
checkpoint's `CAPTURE.zip` and replay it:

```sh
tamarin-prover --with-maude=/absolute/path/to/maude \
  export-19.spthy --derivcheck-timeout=60 --quit-on-warning \
  +RTS -N2 -M2G -RTS
```

Adding `--prove=generation_secret_origin --heuristic=s` also verifies provenance
on the same input. Neither accepted invocation uses a proof-depth bound. Parse
success, process exit zero, incomplete analysis, timeout and heap exhaustion
remain distinct from a verified terminal lemma. The `no_precomp` annotations
change when sources are expanded; they do not remove rule premises. See the
Tamarin manual on [precomputation](https://tamarin-prover.com/manual/master/book/009_precomputation.html)
and [lemma annotations](https://tamarin-prover.com/manual/master/book/007_property-specification.html#lemma-annotations).
