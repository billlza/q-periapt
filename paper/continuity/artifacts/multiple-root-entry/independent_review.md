# Independent review: finite multiple-root entry

**Verdict: PASS.** The final finite multiple-root entry theorem and its first-message corollary can be included under their stated available-controller interface and retained primitive bounds. The review found no unresolved mathematical correction within these results.

Review date: 7 November 2026. This reviewer is separate from the theory author. The record is an independent mathematical argument review, with adversarial interface examples and exact file hashes; it is not a machine-checked proof or a native runtime test report.

## Established result

One initially hidden uniform contribution can support finitely many available salts and complete root-information strings. The exact descriptor is `(Gamma(r),I)`. First compare all selected-contribution Extract columns, then compare the independent PRK rows in first-class-allocation order. The resulting whole-controller bit bound is

`Delta_mr = min(1, epsilon_Hjoint(C,0,q_S,32) + sum_i epsilon_Hrow(N_i,q_i,98))`.

With `N = sum_i N_i`, the explicit conservative ordinary-query budgets are

`q_S = B + 2D + 5N`, and `q_i = B + 2D + 5 sum_(k>i) N_k`.

The final private table has independent entries at complete descriptors. An online mark on one new descriptor therefore supplies a fresh root even if that class already supplied other roots. All class rows were already included in the hybrid sequence, so this selection introduces no additional class-guessing factor. Every target alias retrieves one retained schedule handle, whose full uses match the existing joint first-message interface. Its signed message-score bound is

`min(1, 2 Delta_mr + 2 Delta_sched + 2 epsilon_AEAD)`.

The ContextBound comparison adds `2 Phi_256` for a candidate whose stopped execution realizes this controller. Existing component, correctness, record and original native residual terms retain their established locations. The retained primitive results are inputs; the added result is the finite interface composition and its fresh-root connection.

## Independent reasoning

The review separately derived the column-to-rows chain before receiving the final fragment. It checked exact Gamma aliases, adaptive class names, independent PRK coincidences, the two different freshness times, whole-reduction query accounting, target alias ownership and available-data feedback. Six concrete counterexample patterns appear in `independent_derivation.md`; the final research note contains the corresponding interface explanations. Existing primitive and schedule proofs were used as retained dependencies rather than repeated in full.

The distinction between the two freshness times is essential: the hidden row key is installed at its class's first allocation, while the selected root is installed at a new descriptor's first evaluation. This supports selecting a new info in an old class. The full proof does not condition the original contribution on its later transcript.

## Statement-by-statement findings

### M01 — One uniform contribution and the retained oracle model

**PASS.** S is initially independent uniform on 32 bytes, with the same public compression oracle h and independent initial auxiliary state. Oracle-dependent preparation is executed and charged. The independent whole-hash H interface can remain present. The proof begins before the contribution is used, rather than assuming S is still uniform conditioned on earlier outputs.

Evidence: TeX introduction and budget paragraph; MD sections 1-2.

### M02 — Contribution and PRK interfaces supply the reduction inputs

**PASS.** The parent contribution is accessed through its Extract columns, and each resulting PRK through its class root-Expand row. The controller computes salts and complete infos from its defined available data. These positive interface definitions supply every byte string required by the column and row simulators.

Evidence: TeX introduction and descriptors/available-data paragraph; MD exact interface.

### M03 — Exact Gamma quotient and descriptor identity

**PASS.** For 32-byte salts, the retained compression identity shows Gamma(r)=Gamma(r') implies F(r,S)=F(r',S) for every S. Equal complete infos then give equal root values. Canonicalizing by exact (Gamma(r),I) is therefore an exact real-interface rewrite; it does not assume equal pad-state pairs imply equal salts.

Evidence: TeX descriptor paragraph; MD compression identity and lifetime tables.

### M04 — Separate salt, class and root tables

**PASS.** The salt cache uses the actual 32-byte salt, the class map uses the full Gamma pair and a lifetime allocation index, and the root table uses class plus complete information. Exact aliases across call sites and restarts preserve these identities. The cryptographic table does not merge or transfer source provenance.

Evidence: MD section 2 lifetime tables; TeX lifetime class indices.

### M05 — Uniform finite budget vector

**PASS.** D, C and N_i are chosen in advance and bound every comparison execution. N_i refers to the i-th class in that execution's first-allocation order. The same budget-exhaustion action is retained if one is part of the controller. Counts from one observed real trace are not used as proof of a bound in all hybrids.

Evidence: TeX finite-bounds paragraph; MD section 3.

### M06 — Column reduction endpoints

**PASS.** The simulator makes one hidden-S column call for the first representative of each new Gamma class and reuses that reply for equal classes. The real branch is the real root service; the ideal branch has independent private PRKs V(Gamma). All Expand rows and subsequent controller computation are simulated from numeric replies. The cost is the retained epsilon_Hjoint(C,0,q_S,32).

Evidence: Theorem multiple-root-entry proof opening; MD section 4.

### M07 — Adaptive class allocation and PRK challenge installation

**PASS.** The i-th row challenge key is presampled and withheld until the i-th new class is encountered. Before that event the complete prefix uses h, earlier replies and independent local values, with no access to this key. The class name may depend on that prefix; the proof does not treat the future name as a fixed independent value. The newly allocated V reply is nevertheless fresh uniform.

Evidence: TeX class-by-class proof; MD section 5 steps 1-4.

### M08 — Complete row hybrid endpoints

**PASS.** In hop i, earlier class rows are already private tables, class i uses the challenge row, and later classes use locally sampled independent keys with the same h. Every actual adaptive I||01 message is routed to the challenge row. The real branch is G_(i-1) and the ideal branch is G_i. Class scheduling is rerun on each actual game trace.

Evidence: TeX class-by-class proof; MD definition of G_i and simulator.

### M09 — Zero and never-allocated classes

**PASS.** If class i never occurs, no challenge-row call is needed and the adjacent executions agree. With zero allocated classes the entry service is empty in both experiments. The fixed sum remains a valid conservative bound and does not condition on a realized random class count.

Evidence: TeX proof sentence on unused class slots; MD section 5.

### M10 — Independent PRK coincidences across distinct Gamma classes

**PASS.** The proof preserves the full independent-key distribution. A locally sampled real-row key can numerically equal the hidden challenge key; evaluation through the same h then preserves real functional correlations. Those known-key queries are in q_i. Earlier ideal rows retain their prescribed independent tables. No hidden-key equality test, collision-free conditioning or extra birthday premise is introduced.

Evidence: TeX numerical-coincidence paragraph; MD section 5 numerical PRK coincidences.

### M11 — Adaptive complete infos and exact table rewrite

**PASS.** The map from the full 97-byte I to the 98-byte I||01 row message is injective. Once all rows are ideal, the interface is exactly an independent table W(Gamma(r),I), with consistent aliases. Later infos may depend on prior replies, public-oracle computation and available protocol outputs; the adaptive row primitive and lazy table semantics cover this choice.

Evidence: TeX final proof paragraph; MD section 6.

### M12 — Complete shared-oracle budgets in every reduction

**PASS.** q_S and q_i include executed preparation, class scheduling, all other real primitive work, complete continuations and terminal testing. Downstream schedule/AEAD reductions separately include the complete entry controller. Work is charged within each full derived distinguisher; a later hop does not reset a counter or treat its prefix as free advice.

Evidence: TeX query-accounting paragraph; MD section 3.

### M13 — External Gamma computation and internal column pad work

**PASS.** The controller caches Gamma by actual salt bytes, so at most D new salts require 2D external public compression calls. New salt bytes can share an existing class, so C alone does not bound this work. The column primitive's internal pad computations remain charged by its own bound. The possible duplicate computation is conservative, with no omitted pad queries.

Evidence: TeX explicit accounting; MD section 3.

### M14 — Five-compression Expand count and concrete query formulas

**PASS.** For a 98-byte HMAC message, the two key-pad calls, two inner continuation blocks and one outer continuation block total five compression calls; ell(98)=3. All root rows are real in the column comparison, giving q_S=B+2D+5 sum N_k. At row step i only later classes remain real, giving q_i=B+2D+5 sum_(k>i) N_k. Earlier ideal rows' subsequent work remains in B.

Evidence: Equation multiple-root-budgets; MD section 3.

### M15 — Distinct PRK and target-root freshness times

**PASS.** The PRK challenge is installed at the class's first allocation and receives all its adaptive row messages. The marked root is installed at a new descriptor's first evaluation. These are different times. A class that has already produced other roots can supply a new independent root entry without pretending its already used PRK is fresh.

Evidence: TeX row embedding and final proof paragraph; MD sections 5-6.

### M16 — Fresh marked descriptor and no extra target-class loss

**PASS.** The mark is chosen from the available prefix before the complete descriptor's first root evaluation. In the final table its unused value can be presampled independently of h and withheld until allocation. All class rows were already covered by the fixed hybrid sequence, so choosing the target adaptively in any class adds no class-guessing factor beyond that stated sum.

Evidence: Theorem multiple-root-entry conclusion and proof; MD section 6.

### M17 — One retained schedule handle for every target alias

**PASS.** Every later equal descriptor retrieves the same retained schedule handle. All target-handle uses collectively satisfy the retained schedule's fixed session salt, {0,s} columns, confirmation/successor uses, full traffic-info table, fresh direction mark and budgets. This prevents an uncounted second session or a raw-value return through another descriptor alias.

Evidence: TeX controller definition; MD marking and aliases.

### M18 — Available numeric values versus raw protected-handle feedback

**PASS.** Unmarked roots and declared schedule outputs may drive later salts and infos. A known value can numerically equal a protected root or PRK and still be computed locally with ordinary shared-h queries. Passing the protected handle's raw root into a new parent Extract would instead require an additional operation outside the declared schedule. The text identifies that interface distinction without conditioning on numerical inequality.

Evidence: TeX available-data definition; MD interface and section 9.

### M19 — First-message corollary and signed-score conversion

**PASS.** The corollary expressly uses the available controller and retained first-message qualification predicate. The entry comparison is applied for each fixed application bit and then averaged. The terminal test with probability (Z+1)/2 yields the factor 2; no-marked-challenge runs have score zero. The resulting bound is min(1,2 Delta_mr+2 Delta_sched+2 epsilon_AEAD).

Evidence: Corollary multiple-root-message and proof; MD section 7.

### M20 — AEAD endpoint and candidate accounting

**PASS.** The qualified predicate is computable from the available view and ledger. Guessing fairly on unqualified runs realizes half the absolute expected score in the actual AEAD game. If a candidate's stopped execution realizes this root controller, the ContextBound hop contributes 2 Phi and Delta_mr substitutes for Delta_init. Existing component, correctness, record and original native residual terms retain their definitions.

Evidence: Corollary multiple-root-message; MD section 7.

### M21 — Constructive example including Gamma aliases

**PASS.** The four distinct complete infos are I0, I1, I* and I2. Consequently the later Root(R0,I2) remains an unmarked fresh descriptor even if Gamma(R0)=Gamma(r0). Bounds D=2, C=2, N_1=4 and N_2=1 cover both one-class and two-class executions, including accidental R0=r0. The totals q_S=B+29, q_1=B+9 and q_2=B+4 are arithmetically correct.

Evidence: MD section 8.

### M22 — Counterexamples identify concrete interface failures

**PASS.** Per-origin roots for an equal descriptor give the stated gap 1-2^-256; retrospectively marking a disclosed root defeats fresh-key embedding; merging two different effective infos changes the ideal-row distribution; new salt aliases still consume public pad work. Raw handle feedback and an extra session are correctly described as additional interfaces, not asserted attacks against the admitted controller.

Evidence: MD section 9; independent_derivation.md section 5.

### M23 — Single-entry specialization and source scope

**PASS.** The single-entry controller is an interface special case. The text correctly retains the older tighter Delta_init budget rather than asserting numerical equality with the new default conservative Delta_mr. The multiple-root mathematical interface is proved here; a concrete source instance supplies its descriptor, available-data and shared-handle correspondence. The existing one-root source result remains intact.

Evidence: MD sections 3 and 7; corollary candidate condition.

### M24 — Contribution attribution and positive presentation

**PASS.** The additional result is a finite composition with adaptive class allocation, exact descriptor consistency, explicit budgets and a fresh-root coupling. The underlying HMAC column/row bounds and prior joint schedule remain cited dependencies. The manuscript states one positive controller definition before the theorem and corollary, with boundary facts concentrated there and in one numerical-coincidence explanation; it contains no version-promotion label.

Evidence: TeX structure; MD section 10.

### M25 — Final file structure and evidence type

**PASS.** The final fragment has one theorem, one corollary, two matching proof environments and three matching numbered equation environments. This is independent mathematical argument review, not a formal verification or native execution campaign. Full manuscript compilation and integration are handled by the parent task. Input hashes bind the exact final fragment, proof note and retained dependencies.

Evidence: Final TeX and this review record.

## Precision points resolved

- Separated first-class PRK challenge installation from first-descriptor selected-root installation.
- Made the target's complete alias family share one retained schedule handle, including the fixed session salt and all retained budgets.
- Explicitly accounted for distinct salt bytes D in external Gamma work, separately from C class calls and internal primitive pad work.
- Explicitly used fixed application challenge bits followed by averaging in the score comparison.
- Conditioned candidate-bound substitution on its stopped execution realizing the stated available controller.
- Made all four information strings in the constructive example distinct, preserving the fourth entry even under a Gamma alias.
- Distinguished the single-entry interface specialization from equality of the new conservative and older tighter query budgets.

## Scope and presentation

- The result is one finite contribution/root-entry controller with the stated S, PRK and selected-root interfaces.
- The marked descriptor may be adaptive and may lie in an existing Gamma class; its value is selected before its first evaluation, and all its aliases share the retained schedule handle.
- A concrete native multi-root instance supplies source correspondence for this controller; the module does not assert that every unrestricted owner/fork/multi-session API automatically satisfies it.
- Known numeric coincidences are admitted and covered by shared-oracle primitive comparisons; direct protected-handle feedback is a different interface.
- Retained primitive bounds and published parameter regimes remain unchanged. No concrete numerical security level is inferred from asymptotic formulas.

The main fragment gives the available-data and retained-handle contract before its theorem, then develops canonicalization, the class comparisons, exact table identity, fresh installation and the message consequence. This positive sequence is suitable for the manuscript. The more detailed counterexamples belong together in the research artifact. No further repeated caveats or version labels are needed.

There is no outstanding theorem correction. The parent task performs full manuscript compilation and integration. Subsequent editorial changes to dependency files should be accompanied by their semantic diff review; the hashes below identify exactly the inputs used here, including frozen prior modules.

## Exact input hashes

Absolute paths and byte counts are retained in `independent_review.json`.

| Input | SHA256 |
| --- | --- |
| `module/multiple-root-entry.tex` | `60f842d35f1a86c7e478bb7c60358ab7944aa78c5388b1c5d7305eb77d921e34` |
| `research/multiple_root_entry_proof.md` | `6fd92f5673f48e39658a8968d9ed1b4b9c7f45c6e6c6d66b3b5b88d415ab704e` |
| `review/independent_derivation.md` | `e39516ea24ea3fdf964e0294b8cd3772a5c7eba0b7d55f250841c9cb9056b29a` |
| `dependency/current/joint-primitive-bounds.tex` | `8f7d3cdd7fb314f8c183318667d86e1a8c762ffc5ae513716b1da40769ecd19d` |
| `dependency/current/joint-continuation.tex` | `865b128155662d8916ef648a7852a9973e9d24f22287d29c9ec59ca191fee989` |
| `dependency/current/primitive-inputs.tex` | `78c4c40bfa0a4d2d9f441ac59f40df436863583ab5bdf538beb6fd5fc59e43aa` |
| `dependency/current/candidate-local-accounting.tex` | `4a38c6bb00c70f2611c2395aec754c0af6b8231a8e3f94e027cf1a17b657865d` |
| `dependency/current/contextbound-connection.tex` | `97758cda00a7159839b80f6bcc66e78ca4a0d8702ec5d12a687fa64f67ade0a1` |
| `dependency/frozen/joint-primitive-bounds.tex` | `8f7d3cdd7fb314f8c183318667d86e1a8c762ffc5ae513716b1da40769ecd19d` |
| `dependency/frozen/joint-continuation.tex` | `865b128155662d8916ef648a7852a9973e9d24f22287d29c9ec59ca191fee989` |
| `dependency/frozen/candidate-local-accounting.tex` | `4a38c6bb00c70f2611c2395aec754c0af6b8231a8e3f94e027cf1a17b657865d` |
| `dependency/frozen/contextbound-connection.tex` | `97758cda00a7159839b80f6bcc66e78ca4a0d8702ec5d12a687fa64f67ade0a1` |
