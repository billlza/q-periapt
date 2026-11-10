# Connection A: an explicit opaque renderer for private images and intents

Version: 1.2, 2026-11-07. Source snapshot: `228c944fc476e3e57d6c08063cacb19bca5b360e`.

## Result and scope

This note constructs a finite renderer for protected images and write intents **without receiving the selected reservation coins**. It handles exact copies, fresh resealing, byte-equality queries between retained object handles, public commitments, metadata, storage outcomes and crash recovery. After the named commitment replacement, its only additional representation loss is at most `binom(M,2) * 2^-192` for an observable bit. When no private-wire equality is exposed, that additional loss is zero.

The construction explicitly separates designated private objects from fully renderable atom-free objects. The latter retain their real digests and permitted raw-byte outputs. Unknown bytes are represented by immutable origin handles. A fixed-candidate computation stops before an unknown raw output only when a mapped ledger event has already made its original eligibility permanently false.

This is a hand-proved finite-interface result. The previous manuscript already establishes alias normalization with a trusted renderer and a safe fixed-target acquisition stop; those are used here and are not counted as new. This note's increment is the explicit simulator and its byte-equality argument. Its native use requires mapping call sites to the stated interface. Section 9 records a separate next theorem rather than a completed result.

---

# Completed finite lemma: an explicit opaque renderer for private images and intents

**Status.** The following is a hand proof about a fully specified finite interface. It constructs the renderer; its existence is not a premise. Applying it to every native call site is a source-correspondence task. The result is stronger than the previous alias lemma in one precise respect: this renderer never receives the selected reservation's unknown bytes. The statement begins *after* the named record-commitment replacement and charges that replacement separately below.

## 1. Interface and the two experiments

Fix public finite budgets: at most `M` fresh image-sealing invocations and at most `K_i` original intent headers for image invocation `i`. In this finite interface the intent-digest domain `d` ranges over exactly the five domains enumerated in `HIDDEN_RECORD_COMMITMENTS_V1.md`; the image-head domain is its separate sixth domain. Exact retry does not spend a fresh invocation; a genuinely fresh sealing attempt does, including an attempt followed by a persistence failure. Set `n = 192` for the current image format.

A private atom is a fixed-length string identified by an immutable origin handle `o`. The materialized machine knows the atom's bytes. The opaque machine receives its handle and length, but not its bytes. An atom may occur in multiple records. Image-encryption and intent-authentication keys are known local inputs in this finite interface; their secrecy is not used. Mark an image as designated private exactly when its recipe contains an opaque atom. Atom-free images and their intents are fully materializable and keep their real digests. All images, private or atom-free, count toward `M` for the equality comparison. Public protocol results that depend on an atom are supplied through a separately specified, common functional interface `F`. For the selected KEM operations, `F` is the original-operation KEM adapter, including its exact challenge-ciphertext replay rule. The lemma preserves `F` without asserting its security.

The interface admits the following operations and nothing else on private bytes:

* `Seal(p, meta)`: `p` is a bounded private recipe consisting of known literals and atom references. Its length and all branch-driving metadata are computable without opening an atom. Private encryption and intent authentication are fixed deterministic local byte functions, as in the existing record-commitment module; they do not make extra calls to the public SHA3 oracle used for the commitments. A joint idealization of additional primitive oracles needs its own query/interface accounting. Before drawing the sealing nonce, the recipe and non-nonce fields are fixed. The materialized image has the form `B_i = Hdr_i || N_i || C_i`, where `N_i` is an independent uniform `n`-bit value, at the same fixed image offset for all admitted tags. `C_i` may be any prescribed deterministic encryption of the recipe with its authentication tag. The result of this internal operation is the opaque image handle `i`, its length and known metadata; no raw `N_i`, ciphertext or plaintext is returned.
* `Intent(i,P)`: `P` is the complete canonical fixed prefix, including its tag, binding, predecessor and this game's image-head value. An admitted tag determines the prefix length. The private bytes are `W_(i,P) = P || B_i || MAC_(k_i)(P || B_i)`, with one fixed intent-authentication key `k_i` for a given image. Repeating exactly `(i,P)` returns the original intent. Changing `P` creates a new intent identity. The MAC is private inside the intent. The equality proof uses determinism under that fixed key; the renderer knows local authentication keys, although it cannot evaluate this MAC without an opaque target's bytes.
* `Head(i)` and `Digest(d,i,P)`: for a **designated private image** in the materialized **ideal-commitment** experiment, return independently uniform 256-bit values cached by image invocation, or by the tuple `(domain d, image invocation i, complete prefix P)`. The same original image/intent and domain always receive the same reply. Atom-free images and intents are hashed normally in the shared oracle. This is the invocation-indexed ideal game specified by the existing multi-record commitment hop, applied only to designated private images. A later use of a digest, including a zero-value check, consumes its actual sampled value.
* `Equal(x,y)`: compare complete private image/intent bytes named by two retained handles. This is a classical query. Cross comparisons between image and intent formats are false because their tags are disjoint. There is no direct comparison of the unknown atom bytes and no comparison against an arbitrary supplied raw byte string in this version of the lemma.
* `Copy`, `Retain`, `Persist`, `Delete`, `Crash` and `Resume`: maintain references to immutable handles and an explicit durable-state directory. A storage response or partial-commit choice comes from the same external scheduler or a rule on available metadata, length, digests and handles. Failure does not overwrite a commit that has already occurred. Deletion removes host references; it does not remove the adversary's acquisition ledger or previously returned public values.
* Ordinary public computation may use known inputs, the replies above and the common functional interface `F`. It may call the shared public oracles, with exactly the same calls in both experiments. Its branches are functions of these available inputs. It may not inspect private recipe bytes, private nonces, ciphertext fragments, private MACs or atoms through another channel.
* `Acquire(x)` is handled by an explicit public event ledger. A successful acquisition containing an opaque atom must, **before its raw bytes are returned**, trigger a computable permanent-failure flag for the fixed-candidate score. This flag is determined by the admitted provenance/acquisition rule, not by testing adversary knowledge or unknown atom values. The compared stopped experiments then return score zero. Unavailable-object errors and permitted acquisitions of atom-free objects retain their ordinary behavior. Atom-free objects can be rendered normally from their known recipes; every fresh sealing invocation, including such an object, is included in `M`.

The last rule is the already-proved acquisition-stopping operation applied to an actual metadata-mapped event. It is not permission to create an extra security exclusion. For example, in the current fixed-target experiment a complete post-cut selected-session image containing the selected reservation supplies the required event. A projection that does not establish that event is not admitted by this atom-bearing acquisition rule.

The materialized ideal-commitment machine `I` constructs the actual private `B_i` and `W_(i,P)` and answers `Equal` by byte comparison. The opaque machine `S` is defined by the algorithm below. They share the same public-oracle model and functional interface `F`. No theorem about the entropy, KEM security or message security of `F` is used in this lemma.

## 2. Explicit simulator

The simulator maintains four finite tables:

1. `Images[i] = (recipe handles, known metadata, length, nonce N_i, durable status)`. Sampling `N_i` does not require any private atom. The simulator never computes `C_i` for an image whose recipe contains an opaque atom.
2. `Intents[(i,P)] = (i, complete known prefix P, length, durable status)`. The key is the actual prefix bytes, not an operation ID or revision number. The simulator never computes the private intent MAC for an opaque image.
3. `Digests[key]`, with keys `('image', i)` or `('intent', d, i, P)`. For a designated private image, on first use sample an independent uniform 256-bit reply; on repeat return it. For an atom-free image, materialize and hash its actual bytes, preserving required real validation calls. All downstream checks use their reply unchanged, including the zero-digest error branch.
4. The physical-object directory, retained-handle map, acquisition history and semantic event ledger. Copies share immutable image/intent entries. New seals allocate a new entry; failed persistence leaves the actual reached durable state in the directory. Resume reads that state.

For `Equal`, return true exactly for two image references with the same `i`, or two intent references with the same `(i,P)`; return false for different formats. For permitted atom-free acquisitions, materialize using the locally known recipe and the already sampled nonce. For an atom-bearing acquisition, evaluate the stipulated permanent-failure event before serialization and terminate the fixed-candidate computation with zero when it fires. All other actions execute the same public code and the same `F` calls.

This is an executable table algorithm. It uses origins, lengths, public inputs and locally sampled coins. It does not call a trusted renderer that possesses the unknown atoms, infer the KEM challenger's hidden bit, or guess the challenged reservation tape.

## 3. Equality lemma

Let `GoodNonce` mean that the nonces of all fresh image invocations are pairwise distinct. On `GoodNonce`, complete byte equality for the admitted private objects is exactly structural equality:

\[
 B_i = B_j \iff i=j,
 \qquad
 W_{i,P}=W_{j,P'} \iff (i,P)=(j,P').
\]

**Proof.** An immutable image handle always refers to the same bytes. If `i != j`, their distinct nonces occupy the same explicit offset, so the image wires differ, regardless of their private plaintexts, encryption keys or ciphertexts. For intents, distinct tags differ in their first eight bytes. With the same tag the canonical prefix lengths coincide. Distinct prefix bytes then make the wires unequal before the target, and equal prefixes followed by different image nonces make the wires unequal inside the target. If image handle and full prefix coincide, the fixed key and deterministic MAC give the identical complete intent. Image and intent tags are disjoint. No encryption injectivity, MAC unforgeability, collision resistance, or source-byte inequality is assumed. ∎

This supplies the equality mapping that the multi-record commitment note explicitly requires. In particular, it applies when two independent reservation invocations accidentally contain equal source bytes: they need not be merged or inspected to decide these image/intent equalities.

## 4. Opaque-rendering theorem and proof

Define

\[
 \delta_{\rm nonce}=\min\{1,\binom M2\,2^{-n}\}.
\]

A terminal test in this theorem is the same efficient computation in both experiments, using only the common public view, available metadata/event ledger, functional-interface outputs and its own independent test coins. An application challenge bit used in the centered score is an explicitly retained test coin. The test has no additional access to a designated private nonce, unknown atom or private materialized wire. For any adaptive classical-interface adversary, including one with quantum private state and quantum access to the common public oracles, and any such terminal bit `D`,

\[
 \left|\Pr[I:D=1]-\Pr[S:D=1]\right|
 \le \delta_{\rm nonce}.
\]

For any terminal score `Z` in `[-1,1]` evaluated from those same available inputs, including the fixed-candidate centered eligibility score,

\[
 \left|\mathbb E_I Z-\mathbb E_S Z\right|
 \le 2\delta_{\rm nonce}.
\]

Both experiments include their specified zero-score stopping rule. There is no division by eligibility probability.

**Proof.** Couple fresh nonces, ideal-digest samples, scheduler choices, public-oracle transformations and the state of `F`. Until the first nonce collision, prove the following invariant by induction on the adaptive interaction: the physical directories and immutable recipe references agree; all public bytes and statuses agree; their original-source, persistence and acquisition ledgers agree; and the opaque structural equality relation equals the materialized byte relation.

`Seal` extends the corresponding directories with the same metadata, length and nonce. The materialized encryption is private, so it introduces no public discrepancy. `Intent` installs the same known prefix and target reference; its private MAC is not an additional output. A first designated-private digest query uses the coupled fresh reply, while every replay uses the same tuple-keyed cache. Atom-free digests use the identical materialized bytes and shared oracle in both games. Equality agrees by the preceding lemma. Public computation uses identical available inputs and therefore has the same outcomes and oracle calls. Reference copying, deletion, successful writes, failures after commit, crash and resume preserve the invariant by their explicit directory transitions; none samples replacement reservation atoms. Permitted atom-free acquisitions can be materialized identically. For a successful atom-bearing acquisition, the two ledgers trigger the same permanent-failure event before any unknown bytes are needed; both stop with zero. Thus every adaptive response and the final score are identical until a nonce collision.

At each fresh sealing invocation its nonce is independent uniform, even when the decision to invoke it is adaptive. With at most `M` invocations, the union bound gives probability at most `binom(M,2)/2^n` for any collision. Unused slots do not contribute. A coupling whose outputs differ only on that event bounds each terminal-bit probability difference by its probability. A score in `[-1,1]` can differ by at most two on that event, giving the second bound.

For a quantum adversary, the same classical replies and public-oracle transformations induce the same quantum state at every coupled good prefix. The proof neither measures a quantum query nor reasons from classical oracle transcripts. The collision event concerns locally sampled classical nonces. ∎

The simulator does not need to detect a collision to run; the coupling simply charges the executions on which its structural equality answer could cease to match byte equality. The nonce term is a statistical representation loss for these extra raw-handle equality observations. The existing digest-hiding theorem itself does not require an extra nonce-collision exclusion.

## 5. Composition with the established commitment hop

Let `R` be the corresponding materialized real-digest experiment **with exactly the admitted confinement/interface conditions**. Use the existing multi-record commitment bound

\[
 \varepsilon_{\rm rec}
 =\min\left\{1,\sum_{i=1}^{M}
 \left[4\sqrt{2q_i^2 Q_i2^{-192}}
       +4\sqrt{2Q_i^2q_i2^{-192}}\right]\right\},
 \qquad q_i\le1+5K_i,
\]

where `q_i=0` for an atom-free image whose digest is not replaced, and each `Q_i` counts the complete hybrid reduction's shared-SHA3 work, including honest operations, permitted atom-free acquisitions and the final distinguisher. If the original commitment lemma uses the per-image outer minimum, retain that convention; the displayed sum is a conservative bound. Its fixed-input injectivity, per-nonce confinement and distinct-input conditions must hold for the admitted interface.

**Important composition restriction.** The commitment hop's published interface excludes extra raw-nonce-dependent outputs. Therefore the direct use of `epsilon_rec` above applies when `Equal` is absent from the externally observable interface, or when it has first been compiled to structural equality and the materialized-vs-structural equality replacement is charged separately. To cover equality, first compare `R` with the real-digest game whose `Equal` answers are structural; this costs at most `delta_nonce` for a bit. The latter game has no additional raw-nonce-dependent equality channel, so apply the commitment hop there. Finally its ideal-digest form is simulated **exactly** by the table algorithm, because structural equality is already its rule. Consequently,

\[
 |\Pr[R:D=1]-\Pr[S:D=1]|
 \le \min\{1,\delta_{\rm nonce}+\varepsilon_{\rm rec}\}.
\]

For an unconditional score in `[-1,1]`, apply the binary-output indistinguishability bound to a randomized test which returns one with probability `(1+Z)/2`. This gives

\[
 |\mathbb E_R Z-\mathbb E_S Z|
 \le \min\{2,\,2(\delta_{\rm nonce}+\varepsilon_{\rm rec})\}.
\]

When all observations are commitment/metadata observations and no private-wire equality is used, the simulation of the existing invocation-indexed ideal game is exact, and the additional `delta_nonce` term can be omitted. Exact replay still uses the original cache.

The commitment replacement is applied before the KEM challenge embedding, while the real source experiment can construct its real record inputs. The opaque-renderer algorithm then supplies the coin-free implementation required for the subsequent KEM-adapter step. This order avoids assuming the ability to construct the very unknown inputs that the adapter is meant to eliminate. The bound is for the stipulated fixed-candidate interface; adaptive pair accounting must preserve its own per-pair events and costs.

The commitments and score are evaluated in each experiment's own execution. A changed head is used in that experiment's intent prefix and all its downstream values. The construction does not replace bytes afterward in a fixed real transcript.

## 6. Necessary interface boundaries: short distinguishing executions

These are interface-separation examples, not attacks on the declared recovery theorem.

**Copy cache.** Seal once, copy the original, and compare the two head replies. They are equal with probability one in the correct experiment. Independently resampling the copied head makes them equal with probability `2^-256`. Thus merely labeling two physical positions as separate objects cannot implement the ideal renderer.

**Fresh seal.** Seal the same private recipe twice. Their private complete wires differ whenever their nonces differ. If a simulator keys equality only by recipe or reservation origin, it answers true with probability one, whereas the real equality probability is at most `2^-192`. The simulator must keep sealing origins distinct from reservation origins.

**Unknown-byte projection.** Add an otherwise unrestricted operation returning the first bit of an opaque atom. Two same-length atoms whose first bits differ give different output bits, while an algorithm receiving only the common shape/length has no information from which to produce both outputs. This is why the typed prohibition on such a projection is a necessary condition of coin-free rendering. Actual public protocol output is instead routed through the explicit functional interface `F`.

**Adaptive-target stopping.** If candidate 1 becomes permanently invalid but candidate 2 remains selectable and eligible, globally stopping would erase candidate 2's contribution. The theorem's early termination is attached to a fixed-candidate score with fixed session/cut/epoch coordinates. For an adaptive origin-pair event `F_j = Eligible AND Attr AND (I=j)`, a reduction may stop only after a computable ledger event proves `F_j` false for **every continuation and every still-admissible final coordinate choice** attributed to `j`. For example, unique session attribution plus `cut < reservation(j) <= save(v)` for the captured target-session version supplies the required permanence. If pair ownership or coordinates are ambiguous, the fixed-target stopping rule has not by itself justified that adaptive halt. A failed candidate does not stop the full multi-candidate experiment.

## 7. What this closes for connection A

The previous alias lemma supplied a byte-faithful renderer with access to the private atom table. This lemma supplies the next, algorithmic step for a finite, explicit subinterface: after the permitted digest replacement, image/intent handling, exact copies, fresh reseals, handle equality, metadata, storage outcomes and crash recovery can be implemented from immutable origin handles without the unknown reservation coins. The equality lemma resolves an explicit premise in `MULTI_RECORD_COMMITMENTS_V1.md`, with the stated nonce term where observable equality is admitted.

It leaves a concrete source question rather than a generic simulation assumption: does each native call on an opaque selected source compile to this operation list or to another already specified cryptographic interface? Direct report MACs over unknown private state are not an `Intent` MAC hidden inside a digest; they need their own output treatment. A permitted atom-bearing partial acquisition needs its actual projection rule. Neither is silently declared invalid by this lemma.

## 8. Source mapping checked at the fixed snapshot

| Interface element | Fixed-snapshot source/evidence | Status |
|---|---|---|
| Image nonce at fixed offset; encode/size-check before fresh nonce | `research/continuity-identity-candidate/src/durable.rs`, `seal`, `unseal_image`; tags `QPVLT021`–`QPVLT024`; nonce offsets `[80,104)` | Direct source read; matches the equality lemma's image premise |
| Intent fixed tag-dependent prefix and complete original target | `research/continuity-identity-candidate/src/durable/write_intent.rs`; eight target-bearing `QPWINT` forms enumerated by `HIDDEN_RECORD_COMMITMENTS_V1.md` | Existing exact-format inventory; the per-image fixed-key condition remains part of the admitted interface |
| Fresh invocation versus replay cache and `q_i <= 1+5K_i` | `docs/continuity/MULTI_RECORD_COMMITMENTS_V1.md` | Existing proven conditional hop; the current lemma resolves its structural equality subproblem |
| Original gen/enc handles, preplay/repeat of the challenge ciphertext | `docs/continuity/KEM_CHALLENGE_ADAPTER_V1.md` | Existing common functional interface retained, with its own security bound |
| Fixed-candidate acquisition stop and adaptive original-pair scores | `work/previous_draft/security-model.tex`; `docs/continuity/ADAPTIVE_TARGET_ACCOUNTING_V1.md` | Existing results used, not counted as new |
| Public closure/fanout/resolution report identifiers | `docs/continuity/CLEANUP_REPORT_MAC_V1.md` | Separate explicit output interface; single-report hop already exists |

## 9. Next narrow theorem, not claimed completed here

The cleanup report note records that a later closure/fanout MAC may include an earlier resolution key and tag. A useful next theorem is a reverse-creation-order composition for immutable report transcripts: replace later report rows first, then replace an earlier key after all later outputs depending on it have become cached ideal tags. Earlier immutable transcripts predate that key, so they are simulable from known inputs. The opaque renderer above would handle the private storage of the unknown report key. A proof still has to state the permitted key-acquisition interface and preserve all changed-transcript rejection paths; in particular, a batch-only report-key fragment does not automatically imply acquisition of a target-session record. This prospective result is not included in the proved bounds above.
