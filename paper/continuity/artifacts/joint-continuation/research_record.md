# Round 4 research record: joint continuation

Date: 2026-11-07. Mathematical source version: frozen v0.4 (the primitive appendix is retained byte-for-byte from v0.3).

## Completed result

The new theorem composes the actual HMAC/HKDF uses of one recovered epoch root into the first message of a designated fresh traffic allocation. It treats confirmation, traffic, ACK verification, successor roots and the selected chain's next seed in one shared compression-oracle experiment. The profile supports a compromised old root/wrapping key, disclosed later contributions, and actual successor-root/next-seed projections.

For at most \(M\) distinct traffic information strings and \(t_+\) successor contributions, the schedule's bit-gap bound is

\[
\begin{aligned}
\Delta_{\rm sched}=\min\{1,\;&
\varepsilon_{\rm Hjoint}(2,t_+,q_R,32)
+\varepsilon_{\rm Hrow}(3+4M,q_0,188)\\
&+\varepsilon_{\rm Hrow}(4M,q_1,188)
+\varepsilon_{\rm Hcol}(q_s)
+\varepsilon_{\rm Hrow}(2,q_M,89)\}.
\end{aligned}
\]

The primitive row is explicitly the multiple-adaptive-message experiment, distinct from the earlier report theorem's one-immutable-transcript row. For the specified one-message AEAD interface, the centered, eligibility-gated score is bounded by \(2\Delta_{\rm sched}+2\varepsilon_{\rm AEAD}\). The separate actual Extract/Expand initialization adds \(2\Delta_{\rm init}\) when its input is an independently uniform recovered contribution.

The score at that last entry is named \(b_j^{\rm cont}\), distinct from the native accounting term \(b_j=\mathbb E_{\widetilde{\mathsf V}^{[j]}}\Psi_j\) in the random-component game. Its proved bound is
\[
|b_j^{\rm cont}|
\le2\Delta_{{\rm init},j}+2\Delta_{{\rm sched},j}
+2\varepsilon_{{\rm AEAD},j}.
\]
If the actual complete comparison from the random-component game to the uniform-combined-contribution continuation has bit gap \(\varepsilon_{{\rm CB},j}\), with the same controller, query interfaces, counted shared-oracle work and recomputed score/event code, then
\[
|b_j|\le2\varepsilon_{{\rm CB},j}+|b_j^{\rm cont}|.
\]
This v0.4 notation correction makes the ContextBound step explicit; it does not assign zero error to a combiner that is still real.

The new proof is the composition. It uses earlier shared-root, root-initialization and exact HKDF-table lemmas as inputs. Its consequential step is to normalize the parent Expand row before hiding a traffic seed: otherwise that seed still appears in the parent's next internal HMAC input, so the next primitive's independent-input premise would be incomplete.

## Scope decisions resolved this round

- **Finite complete information strings:** source response locking does not by itself prove a whole-root single-wire theorem. The final result allows \(M\) distinct complete information strings. A target entry and direction are marked at first fresh allocation before block values are produced. An existing entry cannot be re-marked as fresh; every equal-info alias inherits the original protection.
- **Actual shared salts:** the proof caches column PRKs by \(\Gamma(salt)\). A zero session identifier or distinct salts with equal public pad states use one row. Independent PRK values may also coincide numerically; the reductions perform other known-key calls through the same oracle instead of assuming all keys distinct.
- **Future disclosure:** successor roots and the next chain seed are generated and disclosed in each current hybrid. No statement tests an intermediate real root against a random replacement while freezing its real future view.
- **Application API:** the network adversary gets Resume, status, ciphertext and real authentication/ACK outcomes. Its private application retains plaintext-bearing Send and delivery. A same-ID plaintext-guess Send would reveal the challenge through retained-result versus Conflict; that concrete enlarged-interface attack is included in the proof note.
- **Unknown payload storage:** challenge payload and its retained send-intent digest have opaque handles. The Send path's outer journal prefix contains no clear send-intent digest; the focused evidence is retained separately.
- **Score computation:** HMAC comparisons can fix or locally sample the application bit and then average. The AEAD reduction's gate \(A\) is computed without the challenger's hidden bit. This preserves the exact factor 2 without granting a key/nonce read to the terminal test.
- **Combiner boundary:** \(b_j\) retains its random-component-game definition. The new symbol \(b_j^{\rm cont}\) denotes the uniform-combined-contribution continuation. Their connection is an actual complete bit-gap comparison with score cost \(2\varepsilon_{{\rm CB},j}\), not an identification of the two games.

## Manuscript integration

Use \(\texttt{joint-continuation.tex}\) after native correspondence in the computational section. Put \(\texttt{joint-primitive-bounds.tex}\) after the existing primitive-input appendix. The latter includes the three shared-root hybrids, the multi-message row instance, single-column instance, and actual root-entry proof and bounds. These formal ingredients are therefore present in the PDF, not only in repository notes.

Stable labels:

- sec:joint-continuation
- lem:joint-expand-blocks
- thm:joint-message-leaf
- cor:joint-first-message
- app:joint-primitives
- lem:appendix-joint-hmac
- lem:appendix-hmac-instances
- app:joint-root-entry

There is no separately numbered entry corollary in the TeX; entry is an explicit paragraph and displayed bound.

### Suggested abstract sentence

> A conditional shared-oracle reduction carries a uniform recovered contribution through confirmation, traffic, ACK and successor derivations to confidentiality of the first message under a designated fresh traffic allocation.

### Suggested contribution sentence

> For the actual HMAC/HKDF call graph, we prove a joint continuation bound that retains confirmation-dependent traffic information, salt aliases, chosen-input ACK verification and later successor-root and next-seed disclosure. The proof derives the next Extract's independent-input condition from an exact private-row normalization.

### Suggested scope sentence

> This establishes the continuation term after the uniform-contribution boundary; the native record correspondence, component replacement and original source attribution retain their own named comparisons.

These formulations affirm the completed result without presenting it as an unconditional native multi-epoch computational theorem.

## Verification and frozen identities

The proof was supplied for independent mathematical/source review by the evidence agent. The existing native proof record has 24 source files bound to both the current checkout and the manuscript's original pin; those are source identities, not coverage statistics.

For v0.3, a standalone typesetting probe compiled the core and primitive appendix together in two pdflatex runs: 8 pages, no undefined-reference, overfull/underfull or LaTeX-warning entries on the second pass. Version v0.4 makes the score-name/ContextBound connection explicit and receives a focused independent review; the parent owns integrated typesetting. These are separate build and proof checks. No new native benchmarks or exhaustive protocol tests were run.

Frozen SHA-256 identities:

| Source | SHA-256 |
| --- | --- |
| joint_continuation.md | 8f69ae7dc88d378ea31c0a29c4578daf81047a47907dc2b3d4fa28761e2a7a15 |
| joint-continuation.tex | 865b128155662d8916ef648a7852a9973e9d24f22287d29c9ec59ca191fee989 |
| joint-primitive-bounds.tex | 8f7d3cdd7fb314f8c183318667d86e1a8c762ffc5ae513716b1da40769ecd19d |

Only this theory directory was edited. The parent agent owns manuscript integration, source-profile artifacts, repository changes and publication decisions.
