# Continuity recovery transition research

Status: **single-exchange recovery is checked with reused identity and wrapping
keys and explicit per-record ciphertext disclosure.** Its 20-property group
verifies together, and a separate witness exercises the same identity/storage
owner across roles. Earlier independent-identity and per-session wrapping-key
results remain valid in their own models. Whole-journal image/restore
correspondence, multi-epoch recovery, computational security, SDK correspondence
and external review remain open.

An experimental [multi-epoch projection](multi-epoch.spthy) now preserves stable
session/context, inherited roots, completed transcript parents, alternating
proposers and asymmetric local confirmation across unbounded rounds. Its
[model checkpoint](../sdk-alpha1/evidence/20261015-recovery-multi-epoch-model/README.md)
retains six bounded searches, exact search-annotation controls and a source map.
Those initial searches time out without a terminal verdict. A later
[inheritance checkpoint](../sdk-alpha1/evidence/20261015-recovery-multi-epoch-inheritance/README.md)
independently replays one structural property: every reservation inherits an
earlier local Ready root and parent at the predecessor epoch. The two witnesses
and multi-epoch message secrecy remain unproved. This research is separate from
the three checked CI profiles.

A separate [initial-traffic checkpoint](../sdk-alpha1/evidence/20261027-recovery-initial-traffic/README.md)
extends the natural-number/private-position model to permit application traffic
before the first rekey. Ten auxiliary properties and a 414-step execution witness
pass a joint independent replay. The old zero-counter helper is not reused:
it applies only to the preceding model, which excluded initial traffic. All
original queries remain visible, and the multi-epoch secrecy and SDK-refinement
obligations remain open. Earlier checkpoints retain their original model scope.

The [tagged-parent checkpoint](../sdk-alpha1/evidence/20261027-recovery-parent-origin/README.md)
independently verifies the parent transcript's tag and epoch shape in 12 steps
without reused premises. The complete operational prefix and all 26 baseline
queries remain unchanged. Its generation-origin searches remain incomplete:
one reaches a depth frontier, and a different goal order reaches the existing
900-second deadline. The retained oracle inputs identify an unresolved
self-peer contradiction before an expensive state expansion; they do not close
the main origin or multi-epoch secrecy obligations.

The [peer-source diagnostic](../sdk-alpha1/evidence/20261027-recovery-peer-order/README.md)
preserves two controlled ordering comparisons on that identical model. They
resolve the self-peer branch and then bind A/B roles, but both still time out.
A separately marked diagnostic exports a 40-step incomplete origin proof;
all ordinary rankings, stopping inputs and unchanged model/query identities
are read back. Its first frontier remains in application-message source analysis
and recursive phase history. It establishes no new security theorem.

The [application-source continuation](../sdk-alpha1/evidence/20261027-recovery-application-source/README.md)
checks one closed subtree of that origin conjecture: finite A/B role
classification followed by an existing deduction-chain constraint closes the
application-message source case. The role-only control leaves both children
open. An automatic role-priority search still times out because that chain is
not offered to the oracle. All queries, lemma attributes and operational rules
remain unchanged; eleven auxiliary proofs and the initial-traffic witness
recheck. The overall origin proof remains incomplete; at that checkpoint,
continuation from the checked partial certificate was prepared but not yet run.

The [wrapping-source checkpoint](../sdk-alpha1/evidence/20261027-recovery-wrapping-sources/README.md)
continues that partial proof while retaining the total depth cutoff of 16.
Resolving existing wrapping-key sources before recursive state history closes
both Cut cases and an additional Offer case. An independent replay checks the
four closed source subtrees, eleven auxiliary proofs and initial-traffic
witness. The 197-step origin proof remains incomplete, with depth-cut,
callback-budget and unvisited nodes retained. Its remaining scope projections
and state dependencies need analysis before further search.

The [reservation and wire-origin checkpoint](../sdk-alpha1/evidence/20261028-recovery-wire-scope-origins/README.md)
closes the existing reservation-inheritance obligation in the initial-traffic
model and adds proved session/key separation and signed-envelope scope origins.
Independent replay checks these 14-, 1- and 47-step proofs, all earlier helpers
and the initial-traffic witness. The unguarded first formula and two incomplete
search-order controls remain visible. All original queries and operational rules
are retained. The new helpers have not yet been applied to the unchanged,
incomplete generation-origin proof; multi-epoch secrecy and SDK correspondence
remain open.

The [counter-invariant checkpoint](../sdk-alpha1/evidence/20261016-recovery-counter-invariants/README.md)
adds seven deterministic observations of produced send-state counters. Checked
erasure preserves the original execution model and all four complete queries.
The produced-state counter shape has a 35-step proof; the application-message
counter shape has a 17-step proof using that fully verified dependency. Both
independently replay. Removing only the dependency proof leaves a conditional
target success, which the complete acceptance check rejects. The bare model has
no reusable assumptions. These are constructor-shape properties, not counter
uniqueness, nonce safety or recovery secrecy. The added generation-secret origin
conjecture and the original reachability/secrecy obligations remain unproved.

The [structural-invariant checkpoint](../sdk-alpha1/evidence/20261016-recovery-structural-invariants/README.md)
independently checks two more facts: produced send-state roles are `A` or `B`
and their epochs have outer form `zero` or `succ`; a non-initial Ready root has
outer constructor `h`. Both are proved without prior reusable premises. Their
certificates have the same execution model as the counter proofs, and the full
four-property dependency graph is discharged. A combined replay timed out;
the independent root replay and the complete state/counter replay are retained
separately. No new observation, restriction or protocol round bound is added.
The subsequent generation-origin search still times out, so these structural
results do not establish authentication, root secrecy or multi-epoch recovery.

The [private-position checkpoint](../sdk-alpha1/evidence/20261016-recovery-position-invariant/README.md)
independently replays a 29-step induction proof: a private phase owner and step
identify at most one event. Its composition also replays the 285-step Ready
helper, with all 19 complete queries retained. A real unproved-dependency control
is rejected. The unbounded companion step counts internal transitions; it does
not prove application-counter or nonce uniqueness, two-round executability or
recovery secrecy. The original protocol model and SDK remain unchanged.

The [first-Ready checkpoint](../sdk-alpha1/evidence/20261016-recovery-ready-invariant/README.md)
checks a 285-step uniqueness proof for role B's Ready event at epoch one, with
independent replays in the isolated phase representation and its wire-observation
extension. Rule/query comparisons and mutation controls support the explicit
representation argument, which is not a machine-checked equivalence theorem.
The canonical model is unchanged; the result does not establish arbitrary-epoch
uniqueness, two-round executability or recovery secrecy.

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
not that timeout. The key-scoped formulation below now has a checked positive
result; the old session-scoped formulation remains refuted in this shared model.

`shared_identity_key_origin` verifies and independently replays in 356 steps:
knowledge of a signing key implies a modeled identity disclosure in some session
belonging to that identity pair. It has no reusable premise and establishes no
disclosure timing bound. The subsequent key-scoped model binds its exclusions to
the actual device keys across their uses, including one-sided identity overlap
between different pairs. This earlier pair-based variant does not model that broader overlap,
shared journals, multiple epochs or concrete SDK decryption. Its evidence is
separate from the current 20-property CI gate.

## Recovery with reused keys

[`key-scoped.spthy`](key-scoped.spthy) allocates independent signing keys that may
be selected in either role by any number of sessions. The
[key-scoped checkpoint](../sdk-alpha1/evidence/20261015-recovery-key-scoped/README.md)
checks `key_scoped_reservations_recover_symbolic_message_secrecy` in eight steps
with all 19 dependencies verified in the same fresh, no-search replay. Its
conditions require fresh target KEM reservations after Cut, no modeled exposure
of either target identity key anywhere in the trace, no target entropy leak, and
no acquisition of a target record saved after Cut. Other keys may be disclosed.

`IdentityKeyLeak` conservatively marks both direct key release and signer-file
capture, including capture before unsealing. Thus these are sufficient conditions,
not a proof that every excluded capture already reveals the key. A later identity
exposure also falls outside this entire-trace theorem. The events are proof
observations, not runtime key logging or detection that an attacker is gone.

Two separate fresh processes replay a cross-role target-key disclosure attack
(55 steps) and a normal execution satisfying the recovery premises despite actual
knowledge of a third identity key (72 steps). The normal trace includes both
target confirmations and use of the shared key to sign in another session's
opposite role. It shows that the premises admit useful executions; the universal
20-property group supplies the secrecy result. Neither trace is an SDK exploit.

This model still performs one exchange per session. Setup samples and publicly
reveals an initial old root, and allocates separate wrapping keys per session.
Arbitrary inherited-root correlations, shared journals/wrapping ownership and
multiple epochs are not established by this result. Its explicit CI profile is
described below; a hosted pass still requires the actual terminal run.

## Shared wrapping-key disclosure

[`shared-storage.spthy`](shared-storage.spthy) replaces per-session wrapping-key
allocation and ideal unsealing flags with reusable wrapping keys and explicit
record/signer-file ciphertexts. Its original query declarations are unchanged.
The [shared-storage checkpoint](../sdk-alpha1/evidence/20261015-recovery-shared-storage/README.md)
checks a sibling-key disclosure trace (36 search / 85 replay steps), an
independent-allocation control that rejects the same trace, and normal execution
with the shared key actually used by both sessions (50 / 171).

This identifies a storage-owner boundary relevant to the SDK's whole-device
journal. It is not a counterexample to the earlier main theorem's premises.
The initial transfer of old scripts left required helpers incomplete. The
[positive follow-up](../sdk-alpha1/evidence/20261015-recovery-shared-storage-positive/README.md)
now replays all 20 universal properties together in 739.706 seconds with the
unchanged operational model and main formula. A new normal witness (47 / 168)
requires the same signing key and wrapping key in the target initiator and sibling
responder roles, a sibling response commit and both target confirmations. Scope
mutation and missing-dependency controls are rejected. Whole-image storage
correspondence, multiple epochs and computational/SDK refinement remain open.
The CI profiles retain the earlier models and now include an explicit
`shared-storage` profile for the new certificate. Hosted qualification remains
required for the new profile.

## Original independent-identity model boundaries

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

- The earlier protected-state models use an ideal confidentiality boundary.
  Shared-storage checks explicit per-record encryption; whole-image and replay-token
  correspondence remain unproved. The alternative
  [`explicit-storage.spthy`](explicit-storage.spthy) retains nested symbolic
  encryption for journals and replay tokens; no lemma is accepted for it yet.
  No equivalence/refinement between the two theories has been proved.
- The original model allocates independent signing keys; the key-scoped model
  permits their reuse while retaining per-session wrapping keys. Shared-storage
  also permits wrapping-key reuse and checks a combined identity/storage owner
  witness. Several sessions in an actual journal, multi-device authorization,
  policy expiry and revocation remain outside the checked scope.
- The ideal KEM equation and hash constructors do not prove the concrete hybrid
  combiner, ML-KEM, HKDF or confirmation-MAC assumptions. Perfect signatures omit
  the auxiliary information in exposed ML-DSA signing coins. That gap is not
  resolved by the signer-file disclosure rule.
- A message is a fresh symbolic payload under a direction-bound epoch key.
  Concrete message chains, nonce handling, ACKs, consumption floors, old-epoch
  records and application effects require separate correspondence and analysis.
- Durable phases assume atomic admitted transitions. Real fsync, witness checks,
  process faults, rollback resistance and serialization are not proved.
- Each session has one exchange after a freshly sampled old root is disclosed.
  These results prove no maximum exposure bound, multi-epoch recovery,
  epoch-three secrecy or continuous PQ
  recovery for the product.

## Reproduction

### CI profiles

The repository CI `tamarin-proof` job checks all three models through the bounded
[`continuity_recovery_proof.py`](../../artifact/continuity_recovery_proof.py)
gate with the same pinned Tamarin 1.12.0 / Maude 3.5.1 toolchain as the existing
handshake and migration checks. The independent profile remains the CLI default;
CI selects each profile explicitly:

```sh
sh artifact/python-run.sh artifact/continuity_recovery_proof.py \
  --profile independent --output target/continuity-recovery-proof/independent
sh artifact/python-run.sh artifact/continuity_recovery_proof.py \
  --profile key-scoped --output target/continuity-recovery-proof/key-scoped
sh artifact/python-run.sh artifact/continuity_recovery_proof.py \
  --profile shared-storage --output target/continuity-recovery-proof/shared-storage
```

Each output directory must be fresh. The independent profile verifies its
20-property group and three disclosure/execution witnesses in two processes;
the key-scoped profile verifies its own 20-property group and the attack and
normal-execution witnesses in three processes. The shared-storage profile checks
its 20-property group, sibling-wrapping-key attack and combined identity/storage
owner execution witness in 22 processes: one per universal property and one per
witness. No process uses `--prove`.
Each process has a 900-second deadline and 4 MiB limits on both standard streams and
certificate files. Positive groups use a 12 GiB heap; independent witnesses use
2 GiB, and the other witnesses use 6 GiB. The key-scoped and shared-storage
profiles use one thread. The existing 50-minute shared-storage CI step bounds
the aggregate work; the positive group no longer has a single 900-second process
budget. A timeout still fails the profile and does not skip a property.

The shared-storage positive certificate uses
[`continuity_recovery_composition.py`](../../artifact/continuity_recovery_composition.py).
Each part preserves the pinned operational theory, every complete declaration,
their source order and the selected original proof body. Other proof bodies are
explicitly incomplete. An individual part is conditional because Tamarin permits
earlier reuse declarations as premises without checking their proof status.
The gate reconstructs those dependencies from the original pinned certificate,
verifies every original universal property, and requires each dependency to have
verified earlier in that same source order. This closes the conjunction by
induction over an acyclic proof graph. Missing properties, incomplete helpers,
different source/input identities and cycles are rejected. Global source lemmas
are not supported by this composition and cause failure. The final manifest and
all checked parts are retained; a single successful part never qualifies the
group. The witness checks and model/archive/certificate pins are unchanged.
The [composition qualification](../sdk-alpha1/evidence/20261015-recovery-composed-replay/README.md)
retains both hosted whole-group timeouts, the rejected allocation experiment,
all twenty conditional replays, the complete production profile and independent
readbacks. It passes locally on `72587c2a`; hosted Linux qualification remains open.

[`continuity_recovery_profiles.py`](../../artifact/continuity_recovery_profiles.py)
keeps each model, archive, certificate and complete verdict inventory together.
The archive-read limits are 4 MiB for independent/shared-storage and 8 MiB for
key-scoped; only the named small certificates are read, and routine CI does not
export diagnostic graphs. Every
required verdict, trace quantifier and inventory entry must match. The checker,
composition helper and profile-catalog digests are recorded and rechecked after replay. Results and
checked certificates are retained in separate profile directories inside the
`continuity-recovery-proof` CI artifact.

Key-scoped and shared-storage positive results have the same theorem names and
verdict inventory. Their distinct model, archive and certificate byte pins bind
each result to its reviewed theory; names alone do not identify that scope.

The key-scoped and shared-storage steps can run after another proof step fails,
provided pinned tools were verified and the job was not cancelled. All proof
steps remain hard gates; a successful later profile does not turn an earlier
failure into success.
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

### Key-scoped certificate

Extract `experiments/final-37-proof.spthy` from the key-scoped checkpoint and
replay without `--prove`, using pinned Tamarin 1.12.0 / Maude 3.5.1 and
`+RTS -N1 -M12G -s -RTS`. Require every member of its 20-property group to be
verified. The two separate witness certificates and their declarations are listed
in that checkpoint. Use an explicit UTF-8 locale for Unicode certificate input.
A recorded parallel GHC runtime abort motivates the retained single-thread
reproduction; its underlying cause is not established.
