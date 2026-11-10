# Candidate-local simulation from one native recovery experiment

Version 0.2 — complete statement and hand proof, incorporating root and independent review.
Source reviewed: `work/paper_round2/manuscript` (35-page research manuscript).

## Purpose and status

This is a technical connection lemma, not a new claim of a complete native confidentiality theorem. It connects the already proved fixed-candidate record/report simulators to adaptive origin-pair accounting without requiring their candidate-dependent intermediate games to be one common virtual experiment.

The original adaptive accounting proposition remains valid under its stated common-`V` hypotheses. The applicability issue is that choosing an opaque source family `X_j` can change the designated record rows, protected report closure and analysis stopping event. Those local constructions need not instantiate one shared real-component virtual game `V`. The following formulation begins with one full native game, localizes its score there, then permits a distinct continuation for each candidate.

The additional stopping certificate proves an all-continuations property from immutable source metadata. It works even when the final cut has not yet been selected and the candidate's other reservation has not occurred. A batch-only report-key fragment is not such a certificate.

## 1. One original game and candidate-local monitors

Let `G_nat` be one full native experiment with finite execution/query budgets and the original application challenge. Its terminal variables are:

* `E`: the original eligibility predicate, including the actual selected cut and session;
* `A`: the efficiently evaluable event that the selected accepted logical send has a unique usable original reservation pair;
* `I in J`: that pair on `A`, where `J` is a fixed finite index set, such as `[G] x [C]`;
* `S in [-1,1]`: an efficiently evaluable terminal application score. For message indistinguishability, `S = (-1)^(b xor b')`.

There is still only the original accepted logical challenge send. Selecting coordinates does not transfer its challenge bit to another send. All these variables are evaluated from this game's actual complete execution. Define

\[
 Z=\mathbf1_E S,
 \qquad
 Z_j=\mathbf1_{E\land A\land(I=j)}S.
\]

For each candidate `j`, instrument the native execution with two prefix monitors:

* `U_j`: a **free stop** with a proved permanent-zero property: for every complete continuation of any prefix that triggers it, `E AND A AND (I=j)` is false;
* `B_j`: a **charged stop**, such as a successful projection containing a protected report key for source family `X_j`.

Both monitors are efficient functions of the available semantic/origin ledger and declared classical operations. They neither inspect an unknown challenged tape nor change the native public responses before stopping. Their events are cumulative once triggered. All candidates' monitors can be evaluated on the same full native trace; no monitor changes that trace. They do not measure adversarial quantum-oracle queries.

Define `G_nat^[j]` to execute the same native experiment until the first `U_j` or `B_j`, then enter a distinguished stopped state with candidate score zero before the monitored response. On a run which does not stop, its terminal score is the same code for `Z_j`, evaluated in that run. A terminal bit postprocessing of the stopped state may still use its available metadata and independent test coins.

The monitors are local to the candidate reduction. An event for candidate `j` does not authorize stopping the original game or a different candidate's reduction.

## 2. An all-continuations acquisition certificate

The certificate uses these already declared source semantics:

1. An original reservation `o` has immutable session `session(o)` and reservation time `res(o)`.
2. An intact session-record version `v` has immutable subject `subject(v)` and first durable save time `save(v)`.
3. If `v` retains `o`, then `res(o) <= save(v)`.
4. A successful acquisition of an intact object carrying `v` inserts `v` into the cumulative acquisition ledger. Copying, resealing, acknowledgement and host deletion do not remove that acquisition or change `v`'s original subject/save time.
5. Whenever an eligible accepted target is attributed to pair `j`, each member origin of `j` belongs to that selected session, and the selected cut precedes both original reservations. This is part of *usable target attribution*: independently equal public keys do not transfer an origin into a different session.

These are subject/origin assertions, not statements that the adversary can decrypt the bytes. The source map must supply an actual intact-version path; a commitment or causal report dependency does not supply one.

**Lemma 1 — origin-anchored adaptive stop.** Fix `j` and let `o` be either of its original reservation slots. Suppose `o` has occurred. At a successful capture, the monitor obtains an intact-version witness `v` satisfying

\[
 \mathsf{subject}(v)=\mathsf{session}(o),\qquad
 \mathsf{res}(o)\le\mathsf{save}(v).
\]

Actual retention `Retains(v,o)` is one source-supported way to establish the time inequality. The inequality can also follow directly from the recorded event order for a later version of the same session; the record need not still retain the original token.

Then this prefix permanently falsifies `E AND A AND (I=j)`, for every later admissible choice of cut, message coordinates and pair attribution. It supplies a valid `U_j` event. The result holds if the other member of `j` does not yet exist, if the challenge send has not yet occurred, or if the cut is still to be chosen.

**Proof.** Assume for contradiction that some continuation ends with `E AND A AND (I=j)`. Attribution makes the selected session equal to `session(o)`. Eligibility requires the selected cut `c` to satisfy `c < res(o)`. The certified time inequality therefore gives

\[
 c<\mathsf{res}(o)\le\mathsf{save}(v),
 \qquad
 \mathsf{subject}(v)=s.
\]

The successful capture has already placed `v` in the cumulative final acquisition set. Thus the final execution contains an acquired version of selected session `s` saved after `c`, contradicting the original acquisition conjunct of `E`. No wrapping-key disclosure or successful decryption is needed for this contradiction: the predicate concerns acquisition.

If the other reservation or challenge send never occurs, the attributed eligible event is already false. If either occurs later, the same contradiction applies. A later choice of cut can only satisfy eligibility by remaining earlier than `res(o)`; it cannot move the captured version to the other side of that cut. Immutable metadata and cumulative acquisition preserve the contradiction after copies, later writes, deletion or recovery. ∎

An online implementation checks the certificate tuple `(j,o,v,session(o),res(o),save(v),capture-event)`. Its checks use origin handles and actual event order; they do not require the selected random tape, the final adversary guess, or the final cut. One occurred member is enough. It does not require the eventual origin pair to be fully formed at the stopping time.

**Exact temporal characterization.** For a final native trace and selected session `s`, let

\[
 L_s=\max\bigl(\{\mathsf{save}(v):v\in\mathcal C_T,
                  \mathsf{subject}(v)=s\}\cup\{-\infty\}\bigr).
\]

When both candidate reservations exist, put `r_j = min(res(g),res(a))`. The reservation-time and record-acquisition conjuncts of the original eligibility are exactly

\[
 L_s\le c<r_j.
\]

This is an equivalence only for those temporal conjuncts; authentication, entropy, accepted-send and attribution conditions retain their own tests. It follows directly because excluding `c < save(v)` for every acquired matching version is equivalent to `save(v) <= c` for all of them. Once one member `o` has occurred, the inequality `L_s(t) >= res(o)` already makes every eventual eligible cut impossible, regardless of when the other member is drawn. `L_s` is monotone and uses **original version save times**, not the capture time or the enclosing image's latest seal time. An acquired digest or batch-only fragment adds no matching intact version and therefore does not raise this statistic by itself.

The same reasoning applies to any free stop already known to contradict the scored candidate, including an actual exposure of a fixed target authentication key when every eligible target attributed to that candidate uses it. Such a rule needs its own matching identity statement; it is not inferred from a session label alone.

## 3. Exact common-native decomposition

On the full native run, let `B_I` mean the charged-stop event of its final attributed candidate; it is read only on `A`. Set

\[
 \eta_{\rm attr}^{\rm nat}
   =\Pr_{G_{\rm nat}}[E\land\neg A],
 \qquad
 \eta_{\rm proj}^{\rm nat}
   =\Pr_{G_{\rm nat}}[E\land A\land B_I].
\]

The first concerns failed attribution. The second concerns the **finally selected candidate's** actual charged projection. They are disjoint events in one game. In particular,

\[
 \eta_{\rm attr}^{\rm nat}+\eta_{\rm proj}^{\rm nat}
 =\Pr_{G_{\rm nat}}\!\left[
 E\land\bigl(\neg A\lor(A\land B_I)\bigr)\right]\le1.
\]

For report composition, `B_j` can be the first actual protected report-key projection under the online closure induced by `X_j`. This does not relabel the projection as a target-session acquisition. A matched intact acquisition satisfying Lemma 1 is a free `U_j`, rather than a charged report event.

**Lemma 2 — exact localization with local stops.** Let `z_j^stop` denote the candidate score produced by `G_nat^[j]`. Then

\[
 \mathbb E_{G_{\rm nat}^{[j]}}z_j^{\rm stop}
   =\mathbb E_{G_{\rm nat}}[Z_j\mathbf1_{\neg B_j}].
 \tag{1}
\]

Consequently the following identity holds:

\[
 \mathbb E_{G_{\rm nat}}Z
 =\mathbb E_{G_{\rm nat}}[Z\mathbf1_{\neg A}]
  +\mathbb E_{G_{\rm nat}}[Z\mathbf1_{A\land B_I}]
  +\sum_{j\in J}
      \mathbb E_{G_{\rm nat}^{[j]}}z_j^{\rm stop}.
 \tag{2}
\]

**Proof.** The candidate-stopped machine has exactly the native prefix distribution until its first monitored event. On a native run without either stop, both executions continue by the same code and have the same candidate score. On a run with `B_j`, the stopped score is zero. On a run with `U_j`, the permanent-zero property gives `Z_j=0` for every native continuation, whether or not `B_j` later occurs. Thus deleting the stopped continuations has precisely the effect of multiplying the native candidate score by `1_not B_j`, proving (1).

Now partition the native eligible score into its unattributed part and its disjoint attributed candidate parts. For each attributed part separate `B_j` and its complement. Since the final index is unique on `A`,

\[
 \sum_j Z_j\mathbf1_{B_j}
 =Z\mathbf1_{A\land B_I}
\]

pointwise on the native trace. Apply (1) to the complementary terms to obtain (2). The reductions do not need to know the future `I` when they stop; `I` is used only in the mathematical decomposition of the full native run. No independence of target selection and history is assumed. ∎

For a quantum adversary, this argument is a comparison of the identical classical-prefix instruments and their stopped continuations. The monitor reads only the declared classical ledger. It neither clones a quantum state to discover a counterfactual target nor measures a quantum oracle query. The full-run probabilities in (1) and (2) are mathematical expectations, not an extra operation required of the reduction.

## 4. Candidate-local computational continuations

For each `j`, let `V^[j]` be an explicitly specified candidate-local real-component continuation game after its record/report replacements. It need not equal `V^[k]` for another candidate. Denote its random-component continuation game by `Ideal_j`. This symbol is distinct from the free-stop monitor `U_j`.

Use the same candidate score code in each game, with that game's actual eligibility, attribution, selector and application/test coins. Write this score as `Psi_j`. It is zero at the declared stop state. All its event tests must be efficiently evaluable by the corresponding adapters from available semantic state; no native final event is transplanted into an altered transcript.

Suppose an established local source/record/report comparison gives the score bound

\[
 \left|\mathbb E_{G_{\rm nat}^{[j]}}z_j^{\rm stop}
       -\mathbb E_{V^{[j]}}\Psi_j\right|\le\rho_j.
 \tag{3}
\]

This is the actual stopped-game correspondence, with its actual interfaces. For example, bit-distinguishing bounds from the opaque renderer and report theorem give twice their sums for this score; any preceding native source correspondence is retained in `rho_j`. No application of the renderer's original permanent-failure rule to a batch-only fragment is presumed.

For the component step and Proposition 3, specialize to the message score `S in {-1,+1}`, so that each candidate score is in `{-1,0,+1}`. Lemma 2 above continues to hold for any bounded `S in [-1,1]`. Suppose the fixed-pair KEM adapter in that **same** local game yields, for `sigma in {+1,-1}`,

\[
 \left|\Pr_{V^{[j]}}[\Psi_j=\sigma]
       -\Pr_{\mathsf{Ideal}_j}[\Psi_j=\sigma]\right|
 \le a_j^{\sigma}+\delta_j,
 \tag{4}
\]

for the message score `Psi_j in {-1,0,+1}`. Here `a_j^sigma` is the advantage of the actual derived component distinguisher, including the local record/report machinery and complete shared-oracle computation. The term `delta_j` is the fixed challenge pair's correctness term. Set

\[
 b_j=\mathbb E_{\mathsf{Ideal}_j}\Psi_j,
 \qquad
 \kappa_j=a_j^++a_j^-+2\delta_j.
\]

**Proposition 3 — native accounting with candidate-local continuations.** Under (3) and (4),

\[
 \left|\mathbb E_{G_{\rm nat}}Z\right|
 \le\min\left\{1,
  \eta_{\rm attr}^{\rm nat}+\eta_{\rm proj}^{\rm nat}
   +\sum_{j\in J}\bigl(\rho_j+\kappa_j+|b_j|\bigr)
 \right\}.
 \tag{5}
\]

The usual message-guessing advantage, completing invalid runs by an independent fair guess, is at most one half the right-hand side.

**Proof.** In identity (2), the unattributed term has magnitude at most `eta_attr^nat`. The charged-stop term has magnitude at most `eta_proj^nat`. For each candidate, (3) bounds its actual stopped native expectation by its local real-component expectation with error `rho_j`. Because `Psi_j` is the difference of its positive and negative event indicators, applying (4) to those two events bounds its distance from `b_j` by `kappa_j`. Apply the triangle inequality to the remaining candidate sum. Finally `|Z|<=1` supplies the cap. The conversion to ordinary bit-guessing advantage is the unchanged centered-score convention. ∎

The compact gain is in the exact provenance of the terms, not in claiming a new primitive reduction: **all native residuals occur in one original game, while every cryptographic comparison is made within its specified local game**. The probabilities defining `b_j` remain in different ideal continuations and are not normalized as a partition. Their sum of absolute values stays explicit.

If a genuine common intermediate game and one global score bound are established, one can charge that bound once before applying the existing common-`V` proposition. Proposition 3 does not demand paying a candidate sum when such a stronger shared comparison is available. It covers the local interface proofs that the present manuscript actually constructs.

## 5. Quantitative and logical benefits

### 5.1 The selected projection is charged once

A loose substitution might assign the same scalar bound to `Pr[E AND B_j]` for every candidate, then pay `|J|` copies. The exact quantity is

\[
 \eta_{\rm proj}^{\rm nat}
 =\sum_j\Pr_{G_{\rm nat}}[E\land A\land(I=j)\land B_j].
\]

The summands are disjoint, even when many monitors flag the same physical capture. A disclosure affecting only a different candidate contributes nothing to the final candidate's residual. This is an accounting improvement in the original game; it does not move a probability between a native and an ideal world.

For a simple finite trace distribution with uniform `I in J`, suppose every `B_j` occurs on every trace and eligibility/attribution always hold. Then the exact residual is one. Summing the unlocalized probabilities gives `|J|`. This example illustrates duplicate accounting; it does not assert that this event distribution is a native attack.

### 5.2 A free candidate stop is not a global stop

Consider two admitted sessions with candidate pairs `j_1` and `j_2`. Capture an intact post-reservation record of the first session. Later make the single application challenge in the second session, whose record has not been acquired, and select that accepted logical send. The first capture supplies `U_(j_1)` but leaves `E AND A AND (I=j_2)` possible. A global halt would delete that branch. The candidate-local machines preserve it in `G_nat^[j_2]`.

This execution respects the one-challenge rule: the challenge bit is never moved from one send to another. It can be instantiated with an old captured image that contains only the first session, or with separately scoped retained objects. The example exposes an invalid simulation shortcut, not a cryptographic attack on the second session.

### 5.3 Causal report protection is not intact-session acquisition

Suppose a protected report authenticates a member transcript retaining `o`, but its fresh independent report key is held in a separate batch record. The report protection flag is true, yet acquiring that key-only record supplies no intact member-version witness `v` for Lemma 1. A public tag or image digest likewise supplies no such path. The event remains a charged `B_j` unless another actual mapped exposure independently yields a free certificate. This preserves the original acquisition predicate.

### 5.4 Separate ideal-world selectors still cannot be normalized

With two override games, an observable marker in `Ideal_1` may make the final selector choose one, while a different marker in `Ideal_2` makes it choose two. Each matching-index event can have probability one in its own world. Their sum is two, without contradicting the disjoint native partition. Therefore the common-native identity does not justify replacing `sum_j |b_j|` by one shared all-random-game quantity. A further relationship among those games would be needed for such a replacement.

## 6. Source support and evidence boundaries

The reviewed source model already provides the metadata used by Lemma 1:

* `security-model.tex`, Definition "Reservation origin": fixed owner/session/epoch/binding at the actual draw; exact replay keeps that origin.
* Its version and transition rules: an immutable session subject and original first `Saved` event; pending targets become saved before application; copies and sibling reseals retain the original version.
* Equation `origin-causality`: an origin actually retained in a version precedes or coincides with that version's save.
* Definition "Record acquisition and readability": acquisition is cumulative and immediate on an intact object's capture; decryption can occur later and is not required for the original eligibility exclusion.
* Definition "Fixed-target recovery experiment" and the adaptive extension: an attributed pair is the original pair for the actual accepted logical challenge send, with session/cut checks still evaluated on the final execution.
* `native-correspondence.tex`: persisted reservation token before computation; pending writes retain complete original targets; aggregate reseals preserve contained version origins.

These are the exact premises used. The 37-entry native map supports the stated constructor/transition shapes, while a source-subject match for each admitted capture surface still belongs to that surface's concrete mapping. The certificate does not elevate metadata-only observations, partial batch rows or arbitrary byte imports into intact session captures.

The existing finite exposure checks and symbolic certificates are unchanged. This proof does not claim another native experiment or a new mechanized protocol theorem.
