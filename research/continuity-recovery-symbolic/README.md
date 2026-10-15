# Continuity recovery transition research

Status: **four checked statements: generated-key provenance, an honest execution
witness, and two specified disclosure witnesses.** The all-traces recovery-secrecy
claim remains unproved. This directory is not a release proof gate; the full
0.2.0 construction, shared-device lifecycle, computational argument and external
review remain open.

[`protected-state.spthy`](protected-state.spthy) is an unchanged symbolic projection
of one identity-authenticated rekey exchange. `generation_secret_origin` is
verified by Tamarin 1.12.0 / Maude 3.5.1 using induction: 182 steps. It gives a
necessary condition for knowing an honest generated decapsulation key: modeled
generation-entropy leakage or acquisition of a phase-1/2/3 record. It is not a
causal timing bound or a recovery-secrecy theorem. The lemma is not marked
`reuse`; no unproved lemma is imported as an assumption.

The checked existential statements are:

| Statement | Checked steps | What the trace establishes |
| --- | ---: | --- |
| `recovery_is_executable` | 59 | Cut precedes both fresh reservations; both peers confirm before an application event, with no additional leakage. |
| `pre_cut_generation_reservation_remains_exposed` | 80 | One phase-1 capture precedes Cut; after wrapping-key exposure and a fresh response, the captured generation key permits decryption after both peers confirm. |
| `later_storage_access_defeats_fresh_reservations` | 45 | Both reservations follow Cut; one phase-8 capture after the application event exposes the new root and permits decryption. |

Each disclosure witness permits exactly one Snapshot globally and excludes
additional identity/entropy leaks. The pre-cut trace does not obtain a later
root snapshot: it obtains the generation key from the earlier record, decapsulates
the public response and reconstructs the root. These are two distinct failures of
insufficient recovery conditions, not proofs of recovery under sufficient ones.
They also do not establish a multi-epoch exposure bound for the actual SDK.

The [disclosure checkpoint](../sdk-alpha1/evidence/20261015-recovery-symbolic-disclosure/README.md)
retains 67 proof-method applications, unchanged rules/equations/restrictions and
all five full lemma declarations. A fresh process replays all three witnesses
without `--prove` using a 2 GiB heap limit. A combined invocation verifies all
four statements on that same input; only provenance uses automatic proof search.
The 2 GiB combined attempt failed with heap exhaustion and is retained. The
successful combined run uses 4 GiB without changing the model or a query. Removing
both disclosure proof scripts leaves their queries incomplete despite exit zero;
six substitutions of semantic declarations are also rejected.

`clean_reservation_recovers_symbolic_message_secrecy` remains **analysis
incomplete**, and is not accepted. The historical
[execution checkpoint](../sdk-alpha1/evidence/20261015-recovery-symbolic-execution/README.md)
and [initial checkpoint](../sdk-alpha1/evidence/20261015-recovery-symbolic/README.md)
retain their earlier results and failed searches. Generated certificates contain
placeholders for unselected lemmas and unused existential branches. Acceptance
uses exact terminal lemma results, not exit zero or a search for a word. The bare
model remains editable source; the certificate is evidence.

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
added. The original provenance run can be reproduced on the bare model. To
reproduce the three witnesses, extract `proof/export-36.spthy` from the disclosure
checkpoint's `CAPTURE.zip` and replay its stored proof methods:

```sh
tamarin-prover --with-maude=/absolute/path/to/maude \
  export-36.spthy --derivcheck-timeout=60 --quit-on-warning \
  +RTS -N2 -M2G -RTS
```

The accepted combined invocation adds
`--prove=generation_secret_origin --heuristic=s`, and uses `-M4G -s` in place of
`-M2G`, to verify provenance on the same input and retain runtime statistics.
Neither successful invocation uses a proof-depth bound. See the checkpoint for
separate replay and resource-limited attempt outcomes. Parse success, process
exit zero, incomplete analysis, timeout and heap exhaustion
remain distinct from a verified terminal lemma. The `no_precomp` annotations
change when sources are expanded; they do not remove rule premises. See the
Tamarin manual on [precomputation](https://tamarin-prover.com/manual/master/book/009_precomputation.html)
and [lemma annotations](https://tamarin-prover.com/manual/master/book/007_property-specification.html#lemma-annotations).
