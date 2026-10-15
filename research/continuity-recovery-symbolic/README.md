# Continuity recovery transition research

Status: **the original positive recovery-secrecy query is verified through a
20-property dependency group.** Generated-key provenance, honest execution and
two disclosure witnesses retain their separate checked evidence. This is a
single-exchange symbolic result. The full construction, shared-device lifecycle,
computational argument and external review remain open.

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

The [positive recovery checkpoint](../sdk-alpha1/evidence/20261015-recovery-positive-symbolic/README.md)
verifies `clean_reservation_recovers_symbolic_message_secrecy` in nine steps with
all 19 auxiliary properties checked in the same fresh replay. Its unchanged
formula requires both reservations after Cut, no target-session identity or
entropy disclosure anywhere in the trace, and no acquired revision saved after
Cut. Other-session leakage remains allowed. Six observation actions erase to
the unchanged canonical model. The historical
[execution checkpoint](../sdk-alpha1/evidence/20261015-recovery-symbolic-execution/README.md)
and [initial checkpoint](../sdk-alpha1/evidence/20261015-recovery-symbolic/README.md)
retain their earlier results and failed searches. Generated certificates contain
placeholders for unselected lemmas and unused existential branches. Acceptance
uses exact terminal results and complete required dependencies, not exit zero or
a word search. The three original witnesses are checked separately and are not
reusable premises of the positive theorem. The bare model remains editable
source; the certificate is evidence.

## Retained-record proof obligations

A separate [provenance checkpoint](../sdk-alpha1/evidence/20261015-recovery-record-provenance/README.md)
checks two auxiliary statements on a lemma-only extension: every Snapshot has an
earlier Saved event (13 steps), and fresh reservations after Cut put every record
of that exchange after Cut (42 steps). Its operational rules and the original
five complete declarations are unchanged. A third, observational extension
checks that the exact content read matches an earlier write (16 steps). Erasing
its 12 observer labels recovers the preceding model byte for byte. These labels
are proof observations, not additional network outputs or SDK logging.

Fresh processes replay the three helper proofs without automatic search. A
control removes the 13-step proof while retaining the 42-step proof: exit zero
and one verified helper do not admit the incomplete helper group. Ordinary,
inductive and helper-assisted searches at that checkpoint did not close the main
query. Two bounded oracle diagnostics returned incomplete proof trees, not attacks
or security proofs. All failed attempts remain recorded. These auxiliary results
are separate from the four original checked statements and do not extend their
product or computational scope.

## Authenticated KEM and session-root proof obligations

The [crypto-provenance checkpoint](../sdk-alpha1/evidence/20261015-recovery-crypto-provenance/README.md)
adds checked signing-key and generation-key derivation helpers, accepted-offer
authentication and encapsulation-contribution provenance. Six related
obligations, including the original public generated-key property, verify in
one certificate and replay without automatic search. A removed-dependency
control is rejected even though the remaining helpers display verified.
An executable identity leak and a deliberately untracked-leak countermodel
also distinguish successful execution from a false provenance statement.

Three observation actions are removable; operational rules and all original
five declarations remain unchanged under the checked projection. The internal
`KU` helpers supplement the public `K` queries. These properties require
modeled disclosure events but do not establish causal timing or message
exposure bounds.

The [session-root authentication checkpoint](../sdk-alpha1/evidence/20261015-recovery-root-authentication/README.md)
extends the independently replayed group to eight obligations: an accepted root
has an earlier authenticated response origin, and a message uses a root with
that origin. Three more removable observations express those connections.
A separate honest witness is independently replayed, and a missing-authentication
proof is rejected. An 8 GiB replay succeeds after the identical 4 GiB input
exhausts its heap. Authentication alone does not establish secrecy.

The positive checkpoint completes the remaining symbolic composition through
causal root, traffic-key and message-knowledge properties. The original query and
all 19 dependencies replay together at 12 GiB after an 8 GiB heap-exhaustion
failure. Controls reject removing the main theorem, narrowing other-session
leakage, adding a snapshot prohibition and admitting incomplete dependencies.
A separate single-responder-identity-disclosure witness illustrates the need for
the identity condition. No unproved helper is admitted. The computational and
implementation boundaries below remain open.

## Identity reuse across sessions

[`shared-identity.spthy`](shared-identity.spthy) is a separate research variant.
It allocates one signing-key pair and allows multiple independently initialized
sessions to use that pair. Wrapping keys remain per session. All transitions after
Setup, equations, restrictions and the original five complete queries are unchanged.
The [shared-identity checkpoint](../sdk-alpha1/evidence/20261015-recovery-shared-identity/README.md)
retains a checked counterexample (30 search steps, 53 replay steps): exactly one
responder identity leak in a sibling session permits knowledge of an initiator
application payload in the target session. Both target KEM reservations follow
Cut, with no Snapshot or EntropyLeak anywhere in the trace. The sibling and target
have different session IDs and the same identity owner. The witness does not
require both honest peers to confirm the attacked root.

This refutes extending the session-scoped secrecy formula unchanged to reused
identities. It does not contradict the positive theorem on `protected-state.spthy`,
where every session receives independent signing keys. Direct automatic search of
the original universal query on the shared variant timed out at 300 seconds;
the stronger, independently replayed existential witness establishes the failure,
not that timeout. No changed shared-identity secrecy theorem is accepted yet.

`shared_identity_key_origin` verifies and independently replays in 356 steps:
knowledge of a signing key implies a modeled identity disclosure in some session
belonging to that identity pair. It has no reusable premise and establishes no
disclosure timing bound. A future positive argument must bind its exclusions to
the actual device keys across their uses, including one-sided identity overlap
between different pairs. This variant does not model that broader overlap,
shared journals, multiple epochs or concrete SDK decryption. Its evidence is
separate from the current 20-property CI gate.

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

The repository CI `tamarin-proof` job runs the bounded
[`continuity_recovery_proof.py`](../../artifact/continuity_recovery_proof.py)
gate with the same pinned Tamarin 1.12.0 / Maude 3.5.1 toolchain as the existing
handshake and migration checks:

```sh
sh artifact/python-run.sh artifact/continuity_recovery_proof.py \
  --output target/continuity-recovery-proof
```

The output directory must be fresh. The gate checks the canonical model and
both certificate digests against the reviewed checkpoint, then replays the
20-property group and the three witnesses in separate fresh prover processes,
without `--prove`. Each process has a 900-second deadline and 4 MiB limits on
each standard stream. Heap limits are 12 GiB for the positive group and 2 GiB
for the witnesses. Every required verdict, trace quantifier and inventory entry
must match; a zero exit code alone cannot pass. Results and checked certificates
are retained as the `continuity-recovery-proof` CI artifact.
The prover uses an explicit UTF-8 locale (`C.UTF-8` on Linux and `en_US.UTF-8`
on macOS), because exported certificates contain Unicode quantifiers and arrows.
The first hosted invocation exposed a Linux decoding failure under `LC_ALL=C`;
it failed before proof evaluation and retained its stderr and failure receipt.

The exact byte pins deliberately reject source edits, including deleted queries,
stronger secrecy antecedents and new restrictions. Updating them requires a new
reviewed checkpoint that re-establishes the original query declarations and the
observer-erasure relationship; a hash update alone is not a new security argument.
The gate's unit tests exercise these rejection paths using retained real terminal
output. Hosted Linux replay remains a separate observation from local macOS
replay; wiring this command into CI does not itself establish a passing CI run.

For manual inspection, extract `proof/final-positive-53-proof.spthy` from the
[positive checkpoint](../sdk-alpha1/evidence/20261015-recovery-positive-symbolic/README.md)
and replay without `--prove`, using `+RTS -N2 -M12G -s -RTS`. Require every member
of its 20-property group to be verified; the three original witnesses keep the
separate reproduction path below.

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
