# Immutable report families: reverse-order composition

Version: 0.3 — completed finite-interface proof, incorporating independent review. 2026-11-07.
Source snapshot: `228c944fc476e3e57d6c08063cacb19bca5b360e`.

## Result and scope

This note proves a bounded composition theorem for immutable report transcripts. A later report may authenticate an earlier report key and tag. The construction replaces protected report rows in **reverse creation order** and uses an explicit private-handle table, so a reduction never needs the selected row's unknown key bytes to build a later MAC transcript.

The result preserves independent key draws even when their resulting values happen to coincide. Exact original-report retries share one row and tag. Fresh attempts keep separate invocation indices. Permitted report-key fragments remain genuine outputs of the full real experiment: the theorem accounts for those that coexist with an eligible target through an explicit exposure residual, rather than adding a new freshness exclusion.

The existing one-report replacement is used as a cryptographic lemma. The new part is its composition across dependent transcripts, the reduction algorithm, the distinction between origin aliases and accidental key equality, and the treatment of actual disclosures. The previous source/one-report note and the frozen opaque renderer v1.2 are not counted as new results here.

## 1. Existing primitive lemma and notation

Let `h` be the same public ideal SHA-256 compression oracle throughout all report computations and all adversarial quantum queries. Use the HMAC encoding and quantitative functions of `docs/continuity/SHARED_ROOT_HMAC_V1.md` and `docs/continuity/CLEANUP_REPORT_MAC_V1.md`.

The existing one-row lemma compares:

* a uniform independent 256-bit hidden key `K` and `HMAC_h(K,m)`;
* one independent uniform 256-bit tag, cached for the same immutable transcript `m`.

The surrounding algorithm chooses `m` without knowing `K`; all subsequent row calls use that same `m`. It may compare arbitrary supplied tags to the retained tag. It has arbitrary counted quantum access to `h`, and it executes the complete oracle-dependent preparation. Its direct uses of `K` are confined to that row. For a public transcript bound `L <= 2^61 - 65`, put

\[
 \ell=1+\left\lceil\frac{L+9}{64}\right\rceil.
\]

With `T >= 1` bounding the row calls and `q` bounding all other ordinary compression queries, the bit-distinguishing error is

\[
 \epsilon_{\rm row}(T,q,L)
 =\min\{1,\operatorname{DFH}(2,q+\ell T)
                + E_{\rm NMAC}(T,q,\ell)\}.
\]

`DFH` and `E_NMAC` mean exactly the already stated functions, including their parameter ranges and constants. The theorem below does not replace them with an asserted numerical security level.

All application scores are **unconditional**. A terminal score is the same efficient function in the compared experiments of the available public view, semantic event ledger, common protocol-interface outputs and independent application/test coins. It has no extra read access to a protected report key or private materialized transcript. For message indistinguishability use

\[
 Z=\mathbf 1_{\mathsf{Eligible}}(-1)^{b\oplus b'},\qquad |Z|\le1.
\]

The retained application challenge bit `b` is a test coin. Eligibility has its original definition.

## 2. A finite typed report interface

Fix a public lifetime budget `N` for fresh report-key draws, indexed in actual chronological invocation order. Slots include attempts which later fail, return a zero-ID error, fail encoding, or fail persistence. Unused slots do not occur. A retry of an already retained original report keeps its original slot. A new draw after definite absence consumes a new slot even if its session, batch, epoch or application identifier is reused.

### 2.1 Transcript recipes and causal dependencies

There is a fixed set `X` of private source-atom handles whose byte values the later KEM reduction will not possess. During the present real-to-ideal report argument the surrounding source experiment still knows those values. This ordering is essential: a row-reduction challenge must be supplied a genuine classical transcript before that transcript is eliminated.

For slot `i`, the honest machine fixes a bounded transcript recipe `m_i`. It may contain:

* known literals, metadata and available protocol outputs;
* source atoms from `X`;
* the raw bytes of report keys `K_j` for `j < i`;
* previously returned tags `t_j` and other known public values.

The recipe may use deterministic encodings and already specified common-oracle computations. Its length, static dependency set and ordinary admission/encoding errors are computable from the recipe metadata without inspecting an unavailable key. Every direct or computed use of a private key in the recipe retains its key-origin dependency. References to returned tag bytes are available values, not references to the key that produced that tag.

The slot's own `K_i` and own `t_i` do not occur in `m_i`. The key draw is independent of the compression oracle and all preceding state. Native code may perform the draw before assembling the transcript; that order is retained, including failures, provided the transcript's bytes and admission decisions have no dependency on this draw. Once first used, `m_i` is immutable for that original report. Future validations use that same recipe; copying or reopening the original report preserves its identity.

This is a causal grammar: raw-key dependency edges `j -> i` imply `j < i`. Equality of two independently drawn key *values* is not a dependency edge.

### 2.2 An online protected set

Before using `K_i`, compute the flag

\[
 P_i=\mathbf 1\left[
   \operatorname{deps}_X(m_i)\ne\varnothing
   \ \lor\ 
   \exists j<i:\ P_j=1\ \land\ K_j\in\operatorname{deps}_K(m_i)
 \right].
\]

Thus a transcript that needs a source atom in `X` is protected, and protection propagates forward whenever a later transcript uses a protected **raw key**. It need not propagate merely because the later transcript contains an already returned tag.

The flag uses origin references and recipe structure, not actual key equality, hidden KEM coins, or a primitive challenger's secret bit. It is recomputed by the same rule in each hybrid execution; it may depend on that execution's earlier public replies. This is a proof classification, not an alteration of eligibility or an SDK policy.

One can replace `X`-generated protection by any online rule satisfying the same forward-closure property. The displayed rule gives a concrete minimal closure for the declared recipes.

### 2.3 Operations

The following are the complete uses of protected keys in the finite interface.

1. **Create.** Allocate a fresh origin `i`, draw a uniform independent 256-bit `K_i`, and evaluate the immutable recipe if its ordinary admission checks succeed. The real report tag is `t_i = HMAC_h(K_i,m_i)`. A zero tag takes the existing nonzero-ID error branch without resampling. A subsequent failure may leave no durable original or may leave a committed original according to the explicit storage outcome; these states stay distinct.
2. **Replay and validate.** The request names an existing original report handle. It may request the tag again or compare a supplied identifier against that report's retained tag after available binding checks. Honest MAC recomputation uses exactly `m_i` and counts as a row call. Wrong identities, nonexistent originals, incompatible phases and binding errors preserve their specified responses. This operation does not accept a new arbitrary transcript under `K_i`.
3. **Acknowledge and erase.** Acknowledgement checks the original handle/tag and replaces the current logical state according to the protocol. An exact later acknowledgement may compare the retained terminal tag. Host deletion does not retract earlier disclosures or rewrite historical original handles.
4. **Private storage.** Keys and transcripts may be stored as immutable recipes in the explicit opaque-record tables. Exact copy, replay, crash/resume and historical retention copy the original references. Public object metadata, lengths, already idealized commitments and permitted known-object outputs are generated by the corresponding table algorithms. No storage operation receives a selected unknown key merely to materialize an otherwise private buffer. The source-to-storage cryptographic replacement has its own error term and is not folded into `epsilon_row`.
5. **Known public computation.** Metadata-only report bodies and other allowed responses are functions of available inputs. An application plaintext response keeps its actual authorized interface; it is not silently promoted to public metadata. Private bytes needed by such a response must be supplied by that interface or counted as a disclosure below.
6. **Fragment/key disclosure.** The full real experiment may return a report-key fragment or another explicitly described private projection. Its immutable recipe has a known origin-dependency set. Such a response is an actual disclosure; no selected-session Snapshot event is inferred solely from the fact that it contains a report key.

All other protocol computations may use the common functional interfaces and shared public oracles with their actual query accounting. Protected raw keys do not have an additional unlisted output, equality-test or computational-use interface. Intentional reuse of an existing report key for a different transcript is not a fresh `Create` operation of this grammar.

### 2.4 The observed exposure event

Let `Bad` be the first successful outward disclosure whose recipe depends on a raw key `K_i` with `P_i=1`. Its occurrence is determined from the operation's actual origin mapping **before** returning the dependent bytes. An unsuccessful read, a terminal tag alone or a fragment with no protected-key dependency does not trigger `Bad`.

Let `G` be the full real experiment with the original target eligibility and all its declared disclosure responses. Let `G^stop` be the experiment which is identical until `Bad`, then ends with score zero before returning that response. This is an analysis game. It is not claimed to equal `G` merely because a report key was requested.

For an application score `Z`, define the real, eligibility-sensitive exposure residual

\[
 \eta_{\rm rep}(Z)
   =\mathbb E_G\!\left[|Z|\,\mathbf1_{\mathsf{Bad}}\right].
\]

For the centered message score this is exactly

\[
 \eta_{\rm rep}=\Pr_G[\mathsf{Eligible}\land\mathsf{Bad}].
\]

This definition preserves permitted batch-only fragments in `G`. If an independently established provenance result shows that the observed disclosure permanently invalidates the original scored target, its contribution to `eta_rep` is zero. Otherwise it remains an explicit term, to be treated by the relevant disclosure analysis. There is no conditioning or division by an eligibility probability.

## 3. The explicit reverse-order hybrids

For `k` from `0` to `N`, define `H_k` as the stopped experiment with the same code and the following report rule:

* every unprotected row is real;
* a protected row with invocation index `i <= k` is real;
* a protected row with index `i > k` gets a fresh independent uniform tag on its first call and its cached original tag thereafter.

All flags, recipes, branches, selectors and disclosure decisions are evaluated in that hybrid's own history. In particular, a tag of zero, a changed report body caused by earlier tags, and a different number of subsequently reached slots are recomputed normally. There is no post hoc replacement in a fixed real transcript.

Then `H_N = G^stop`. The experiment `H_0` is the final ideal-report stopped machine, denoted `S^stop`.

The proof compares `H_i` to `H_(i-1)`: rows after `i` have already been idealized when they use a protected raw key from row `i`. This is the reason for the reverse order.

## 4. One-hop reduction algorithm

Fix slot `i`. The derived algorithm `B_i` receives the existing one-row real-or-random interface with an unknown uniform key `K*` and the shared public compression oracle `h`.

1. **Run the full prefix.** Execute the adversary and the protocol from setup, using the same public oracles and locally sampling every report key for slots before `i`. Their tags are real because their indices are smaller. Compute their immutable recipes normally from the real source atoms, locally known keys and available earlier tags. Keep all handles, history and storage outcomes.
2. **Locate the slot.** If slot `i` is never reached, the two hybrids are identical and `B_i` uses no row challenge. If `P_i=0`, sample `K_i` locally and complete the common real behavior; again no challenge is needed. The flag has already been computed without `K_i`.
3. **Install the opaque challenged key.** If `P_i=1`, represent the key by `KeyRef(i)` rather than bytes. Its transcript `m_i` is computable: it contains no own key, every referenced earlier key was locally sampled, and the source atoms are still available at this proof stage. Send that exact transcript to the one-row interface on the first required MAC evaluation. Preserve pre-MAC failures and all subsequent errors.
4. **Cache the selected original.** Retain the supplied `t_i`; execute the genuine zero-ID check. Exact retry and validation use the same selected row/transcript and original tag. Supplied-tag checks are ordinary comparisons. The reduction can forward repeated row calls to preserve their counted occurrence; no extra independent ideal output is drawn.
5. **Simulate all future rows.** Sample each other fresh key locally. If a future row is unprotected, forward closure implies that its recipe has no dependency on `KeyRef(i)`, so compute its real MAC using known inputs and public `h`. If it is protected, its index exceeds `i`: it is already ideal in both hybrids. Sample/cache its tag without evaluating its transcript bytes. Preserve the recipe's length, dependencies and known validation/admission outcomes. Later use of this row's locally sampled key by a still later protected recipe remains symbolic if necessary.
6. **Run storage and public code.** Store recipe references, not unavailable challenged bytes. Propagate returned tags into the current hybrid's later recipes and records. Keep public metadata, nonzero checks, exact copies, commit/absence outcomes and crash recovery. Other ordinary computations and oracle calls are performed from their available inputs.
7. **Process disclosure.** Before a projection depending on a protected key is returned, the common event ledger raises `Bad`; enter the common stopped state with application score zero. An allowed terminal-bit postprocessing of that state is evaluated from its available metadata and test coins. Unprotected-key fragments and other known projections keep their real bytes. A repeated/copy origin does not evade the event.
8. **Output the common terminal test.** It uses only the declared available view, event ledger and independent test coins. It never reads `K*`.

The algorithm has no call which fabricates the selected key, asks for its bytes, or asserts an unexplained private-renderer oracle. Each future operation involving the unavailable key is accounted for by a concrete table operation, an already ideal later row, or the common observed stopping event.

## 5. Reverse-order composition theorem

For each slot `i`, choose public uniform resource bounds `L_i`, `T_i` and `q_i` for the **entire actual derived algorithm** `B_i`, including the whole prefix, all future computation, other real report rows, shared-oracle preparation, the adversary and the final test. The length bound is for an immutable transcript at that slot whenever it occurs. Set

\[
 \epsilon_i=\epsilon_{\rm row}(T_i,q_i,L_i),\qquad
 \epsilon_\Sigma=\min\left\{1,\sum_{i=1}^N\epsilon_i\right\}.
\]

Unused/unprotected slots cause no difference; including their public worst-case bounds is merely conservative.

**Theorem 1 — stopped multi-report composition.** Under the typed interface above, for any allowed terminal bit `D`, with the stipulated common terminal value on stopping,

\[
 \left|\Pr[G^{\rm stop}:D=1]
       -\Pr[S^{\rm stop}:D=1]\right|
 \le \epsilon_\Sigma.
\]

For any declared score `Z` in `[-1,1]` which is zero on stopping,

\[
 \left|\mathbb E_{G^{\rm stop}}Z
       -\mathbb E_{S^{\rm stop}}Z\right|
 \le 2\epsilon_\Sigma.
\]

**Proof.** Consider the adjacent hybrids `H_i` and `H_(i-1)`. Their complete prefixes before slot `i` are generated by the same code and real earlier rows. Consequently they compute the same rule for whether that slot exists and whether it is protected. If it is absent or unprotected, they are identical.

Otherwise install the one-row key as `KeyRef(i)`. Before its first query, the transcript can be computed from the already generated prefix and independent earlier keys. Its source atoms are real and available at this stage. Its grammar excludes the selected key and its own output; the one-row input conditions hold. The preparation is actually run and counted, rather than replaced by oracle-dependent advice.

After the selected tag is returned, verify the simulation invariant: the reduction holds the same original-handle, key-origin, recipe, durable-state and event metadata as the corresponding hybrid; every externally available value agrees; all remaining real-row inputs are computable without `KeyRef(i)`; and the sole unavailable key occurs only inside retained recipes or later ideal rows. For an earlier row, its fixed transcript predates `i` and its actual key was sampled locally. For a future unprotected row, the forward-closure rule excludes a dependency on the selected protected key. A future protected row is ideal in both hybrids and is implemented by its original-tag cache; its transcript need not be evaluated. This proves the real-row computability invariant for every subsequent report, including later reports that contain earlier protected keys and tags.

All public decisions are functions of available inputs, so the reduction executes their real branches. A zero tag produces the specified failure, not a fresh sample. Exact original replay and acknowledgement keep their original tag and metadata. Ordinary errors or a failure after a durable write preserve the actual committed state. Copy/crash/reopen do not create new keys or transcripts. On the first outward protected-key disclosure, the reduction recognizes the same `Bad` event and returns the stipulated zero before unknown bytes are required.

The selected real row therefore gives exactly `H_i`; the selected ideal row gives exactly `H_(i-1)`. The adversary may retain quantum state and query the common compression oracle: the algorithm runs those queries with their actual inputs, introduces no measurement of a quantum query, and counts the complete ordinary-query work in `q_i`. Apply the existing one-row lemma to obtain an adjacent bit-probability difference at most `epsilon_i`. Sum over `i` by the triangle inequality and cap a bit-probability difference at one.

For a score in `[-1,1]`, form an allowed randomized test which returns one with probability `(1+Z)/2`; it uses its own independent coin. Its probability difference equals half the score-expectation difference. Applying the bit bound gives the factor two. There is no multiplication of a bit-guessing baseline of one half. ∎

### Corollary 2 — the original eligibility and real disclosures

For the full real experiment `G` with its original disclosures and target predicate,

\[
 \left|\mathbb E_G Z-\mathbb E_{S^{\rm stop}}Z\right|
 \le \min\{2,\eta_{\rm rep}(Z)+2\epsilon_\Sigma\}.
\]

Consequently,

\[
 |\mathbb E_G Z|
 \le\min\{1,\eta_{\rm rep}(Z)
                 +2\epsilon_\Sigma
                 +|\mathbb E_{S^{\rm stop}}Z|\}.
\]

For a winning event `W` which implies the original eligibility and is scored zero on stopping,

\[
 \Pr_G[W]
 \le\min\{1,\Pr_{S^{\rm stop}}[W]
                  +\Pr_G[W\land\mathsf{Bad}]
                  +\epsilon_\Sigma\}.
\]

**Proof.** Couple `G` and `G^stop` through the first `Bad` event. On runs with no such event they coincide. On runs with `Bad`, the stopped score is zero while the real experiment continues with its actual disclosure and later target selection. Therefore

\[
 \mathbb E_GZ-\mathbb E_{G^{\rm stop}}Z
   =\mathbb E_G[Z\mathbf1_{\mathsf{Bad}}],
\]

whose absolute value is at most `eta_rep(Z)`. Combine with Theorem 1. The event version follows from the exact decomposition of `W` into its `Bad` and no-`Bad` parts and the bit bound. ∎

This corollary neither declares a report-key fragment ineligible nor discards its possibility. It isolates the precise probability mass on which a later disclosure analysis is needed. If the existing event provenance establishes `Bad => not Eligible` for a particular surface, then that surface contributes zero by the original predicate, without changing the game.

## 6. Key aliases: exact retries, accidental equality and reuse

There are three distinct cases.

**The same original draw.** Exact copies and retries are references to one key origin and one immutable transcript. They share the original tag cache, even if physical locations or report handles differ. They spend no new fresh-key slot.

**Different independent draws with equal values.** The theorem does not condition on distinct keys or sample without replacement. In the hop for `i`, every other key `K_j` is an actual locally sampled byte string. A real row under `K_j` is evaluated using public `h` even if, unbeknownst to the reduction, `K_j = K*`. That execution is faithful: equality of byte values implies the same HMAC behavior automatically. Such ordinary evaluations and key guesses are part of `q_i`, and hence part of the one-row security bound. The selected key need not be compared to `K_j`. Later ideal rows have the same invocation-indexed caches in both adjacent hybrids. Thus no extra unsupported “all keys distinct” assumption or omitted collision event enters the reduction.

This does not say equal-key effects have zero probability or zero cryptographic cost. For example, in an ideal keyed-function model, two independently uniform `kappa`-bit keys used on the same message produce equal tags with probability

\[
 2^{-\kappa}+(1-2^{-\kappa})2^{-\tau},
\]

whereas independent `tau`-bit tags match with probability `2^-tau`. The gap is `2^-kappa(1-2^-tau)`. A correct single-row reduction already allows the other known key to be used in public primitive computations; that effect must lie within its error budget. It is not erased by naming two invocation indices.

**Intentional key reuse under a new transcript.** This is a different interface. A fresh independent per-invocation tag is not justified for two uses of a deliberately shared key merely by calling them different reports. If the same key and same transcript are reused, deterministic real tags agree with probability one; independently resampling them would differ with advantage `1-2^-256`. The correct representation is the original shared row/cache. If the same key is deliberately used on a different transcript, a multi-query keyed-function interface and its consistency table are required. The finite theorem here admits exact same-transcript retry and independent fresh draws, which are the native creation/replay forms identified below.

## 7. Why the ordering and disclosure boundary matter

### 7.1 Reverse-order simulation is constructive

Consider `m_1 = encode(X)` and `m_2 = encode(K_1,t_1,metadata)`. When replacing row 2 first, the reduction knows `K_1` and can submit `m_2`. When it later replaces row 1, row 2 is already ideal and requires only its cached tag; its raw `K_1` bytes are unnecessary. This is a complete two-row instance of the general invariant.

A forward-order reduction would encounter a different situation: while `K_1` is the unavailable challenge key, row 2 would still require an actual MAC on `encode(K_1,...)`. The existing one-row oracle does not provide those bytes or that related input. This observation identifies the missing simulation operation; it does not assert that every forward-order proof is impossible under richer assumptions.

### 7.2 Key fragments can distinguish an independently replaced tag

Take a known immutable transcript `m`, return its real tag `t`, and then permit a fragment containing `K` while leaving the application target eligible. The adversary computes `HMAC_h(K,m)` and compares it with `t`. The real comparison accepts with probability one. If `t` was independently replaced, it accepts with probability `2^-256`; the difference is `1-2^-256`.

The fragment need not include a selected-session reservation, and the transcript can be known from other authorized inputs. This is an exact distinguishing example for an overbroad report-hiding claim. It is not a claim that any particular native batch-only fragment also supplies the whole native member-state transcript. In a native branch where that transcript remains unknown, this recomputation example does not by itself establish an attack; the declared residual records that the current hidden-key row argument has reached a different disclosure interface.

A replacement such as “a protected report-key fragment counts as a target Snapshot” would change the acquisition predicate and is not part of this theorem.

### 7.3 Changed-transcript validation is a real additional oracle

The original immutable-row interface allows `Verify(i,t')` for the retained `m_i`. It does not authorize replacing `HMAC(K_i,m')` on attacker-supplied changed bytes by a comparison with the old `t_i`. For example, if changed `m'` is accepted by an arbitrary-byte importer and a later response exposes a computed tag or validation outcome under the same key, the exact computation is a new query under that key. A malformed-input simulator must preserve it through an appropriately extended MAC interface or reject it at an independently established earlier check. Honest immutable replay alone establishes neither choice.

## 8. Native correspondence checked at the fixed snapshot

The following observations were obtained from the local source at the stated commit. They identify the native instances of the grammar, without silently changing a public report's audience or broadening trusted-handle reopening to arbitrary imported bytes.

| Report family | Key and transcript | Replay, freeze and terminal behavior | Dependency relevant to the theorem |
|---|---|---|---|
| Independent closure | `closure.rs::begin_closure` draws a fresh 32-byte key. `report_mac` covers the message-domain label, journal, owner, record context, payload length, payload except its final 64 bytes, then 64 zero bytes. | `MessagesClosing` retains the original key and tag. `validate_record` recomputes the frozen MAC. Acknowledgement calls `Retired::closed` and persists a keyless terminal payload. | The zeroed tail excludes this report's own key/tag. The remaining `State::encode` prefix includes all retained traffic entries and control state, so an earlier resolution key/tag can occur in this later transcript. |
| Fanout abandonment | `fanout/abandonment.rs::begin_fanout_cleanup` draws a fresh 32-byte key. `report_mac` covers batch metadata and each member's record context, length and complete private payload. | The code sets member phases to `MessagesAbandoning`, retains `BatchState::Abandoning { report, key }`, persists, then returns the report. Retries reuse this state. Acknowledgement validates and replaces member payloads with terminal records. | `Batch::metadata` excludes the batch's report/key tail; `Batch::record` stores that key in a separate batch record. The member payloads can contain earlier resolution keys. A batch-only fragment is not a member payload. |
| Closed-epoch resolution | `resolution.rs::begin_closed_epoch_resolution` draws `resolution_key`; `resolution_mac` covers session/role/epoch, counters, retained message IDs, input/ciphertext/plaintext digests and skipped indices, excluding its own key and output. | `require_unresolved` fences old-epoch operations. Pending validation repeats the retained transcript. Acknowledgement clears retained maps, zeroes traffic/ACK keys, removes `resolution_key` and retains the terminal ID. | `traffic.rs::encode_into` serializes the pending resolution status and key before traffic keys/maps. Therefore a later full-session closure/fanout MAC can contain the earlier key/tag. The resolution report itself returns unconsumed plaintext to the authorized application. |

Additional source points:

* `messages.rs::State::encode` writes each epoch's traffic encoding and the control encoding before `closure::encode_pending`; the latter contributes the fixed 64-byte closure tail.
* `closure.rs::decode_pending`, `fanout/codec.rs` and resolution validation distinguish empty/acknowledged states by their tags, flags and canonical zero tails. A pending report key is **not** constrained to be nonzero. The proof therefore samples uniform 256-bit keys without rejecting zero. The **tag** retains its nonzero-ID check.
* The legitimate frozen-handle paths establish immutable replay. The source also contains raw-image decoding and full MAC revalidation. Any adversary interface allowing arbitrary changed private bytes must be mapped to that actual validation path; the finite grammar's trusted original-handle replay is not its substitute.
* Failed construction or persistence is not an automatic permanent closure. Report emission occurs after the relevant persistence/release checks; a committed original followed by an error and an attempt with definite absence have different retry origins.

These are source observations. This note does not claim a new native execution, a new Tamarin certificate, or coverage of every storage projection.

## 9. Composition order and shared-oracle accounting

A clean order for a native instantiation is the following:

1. In the full real native experiment, define the origin-mapped report disclosure event and charge its actual eligible-exposure residual. Pass to the explicitly stopped analysis game. This retains the original native eligibility in the claimed final score; it does not label a batch-only fragment as a selected-session capture.
2. While reservation coins and report keys are still ordinary locally sampled values, establish the private-record abstraction for **that stopped game**, preserving its exact output/stopping interfaces. The actual source-to-record proof must supply its separate error term. The frozen opaque renderer's original permanent-ineligibility premise is not, by itself, a proof of this enlarged stopping interface.
3. Run the reverse-order report hybrids above, retaining the same public compression oracle and including all ordinary work in each `q_i`. The source atoms in `X` are still available when a selected real report transcript is submitted.
4. In the final protected-row ideal machine, report **tag generation and immutable tag validation** depend only on their original row caches and available metadata. Every unprotected transcript is free of `X` and protected-key dependencies by the online rule. This report-tag layer can therefore retain opaque source handles for the later KEM adapter.

Direct source-atom or application-plaintext outputs remain in their own declared interfaces. The residual `eta_rep` accounts for protected report-key dependencies; it does not also discharge a raw `X`-source output. Such an output needs its own adapter or a stopping event justified by the original target predicate. In particular, independent authorized plaintext-report delivery is not made public merely by idealizing its tag.

An alternative order may first abstract storage and then apply Corollary 2 to the resulting real-report game. In that case its residual is the probability in that **actual intermediate game**, and transferring a residual asserted in a different game requires its own comparison bound.

The storage layer here is an explicit recipe/handle table, not an oracle that secretly possesses the challenged report key. Its remaining private encryptions/MAC buffers, if materialized in an intermediate description, can be omitted **pointwise for fixed public oracles** when their only uses are already idealized commitments, structural identity, or disclosures stopped before return: their output bytes never feed an observable branch. This is a deterministic noninterference observation about the stated operation grammar, not a new cryptographic assumption. Oracle queries inside such omitted private evaluations are reads of fixed functions; they do not change the public oracle. Earlier cryptographic hops must still count every query required by their own reductions.

This pointwise omission does not authorize dropping a public report MAC or an unknown-byte validation result: those are precisely the interfaces treated by the row theorem or its stated boundary. If a preceding record hop models SHA3 and SHA-256 as distinct oracles, it must retain their declared independence and joint query accounting. The report theorem does not silently change that model.

For the first order above, let `G_nat` be the native full real experiment, let `G_nat^stop` stop at the actual mapped report-key event, and let `V^stop` be its report-interface abstraction. If a separate source correspondence establishes

\[
 |\mathbb E_{G_{\rm nat}^{\rm stop}}Z
   -\mathbb E_{V^{\rm stop}}Z|
 \le\epsilon_{\rm store,score},
\]

then triangle inequality gives

\[
 |\mathbb E_{G_{\rm nat}}Z-\mathbb E_{S^{\rm stop}}Z|
 \le\eta_{\rm rep}^{G_{\rm nat}}(Z)
       +\epsilon_{\rm store,score}+2\epsilon_\Sigma.
\]

The exposure term here is in the original full native game because it was charged before the record hop. This is a precise composition rule conditional on the displayed stopped-game source correspondence, not an assertion that all native storage surfaces have already been mapped.

## 10. What is proved and what the next source step is

The immutable report-family theorem and its explicit reductions are proved for the stated finite interface. The later-report key dependency is handled by the reverse order; it is no longer an unexplained multi-report independence premise. Original retry and accidental same-value key aliases have distinct, accounted semantics. Real fragment disclosures remain in the original experiment with an exact, eligibility-sensitive residual.

The next native source step is to enumerate actual report-key projections and their original record/session contents. For an intact aggregate containing the selected post-cut state, the existing acquisition predicate may establish zero residual. For a batch-only key fragment, the original target predicate and any remaining hidden-transcript structure must be analyzed as they stand. The theorem makes that distinction a concrete mapping problem rather than a blanket ban on acquisition.
