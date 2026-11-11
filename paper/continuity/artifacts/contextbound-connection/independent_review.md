# Independent mathematical review: ContextBound connection

**Verdict: PASS.** The complete-tuple hidden-component lemma, next-rekey root-use correspondence and native next-rekey theorem can be included under the experiment and source profile stated in the final draft. There are no unresolved mathematical issues within those stated results.

Review date: 7 November 2026. The reviewer is separate from the mathematical author and the source-audit author. Native source pin: `228c944fc476e3e57d6c08063cacb19bca5b360e`; comparison revision: `1c68aa666db22d36ee136be1ec712545a9e74f03`; manuscript starting revision: `1cd40686209d68de509d63eab0b77465b8701b54`. Exact reviewed input hashes appear below and in the companion JSON.

## What is established

The first lemma instantiates the existing hidden-input theorem on the actual ten-field, length-prefixed ContextBound input, with one uniform 32-byte ML-KEM component and every other effective field retained. Its bit gap is `Phi_256(d,Q_H)`, for distinct protected tuples and the complete ordinary SHA3-query budget. The second lemma proves, from the pinned native plan transitions, that the marked tuple of the original matching encapsulation has only one old-root/complete-root-info use in the declared next-rekey profile. Together they provide the previously explicit entry to the retained root, joint schedule and first-message continuation.

The candidate continuation score satisfies

`|b_j| <= min(1, 2 Phi_256(d_j,Q_H,j) + 2 Delta_init,j + 2 Delta_sched,j + 2 epsilon_AEAD,j)`.

The native message bound keeps the original attribution/projection residuals and the existing candidate record, component and correctness terms. This is a completed protocol-specific connection; the cited DFH theorem and retained HMAC/HKDF primitives are prior inputs. The optional multiple-root extension in the research note is not part of this acceptance verdict.

## Method and primary source

The review read the exact final theory and source-audit text, the actual core combiner, and the native preparation, response and completion paths that establish the one-use invariant. Existing candidate-local and joint-continuation modules were treated as retained dependencies; their entire proofs were not repeated. The independent Python framing/router checker was rerun and passed all 36 checks. The source audit receipt binds fourteen native files and reports twelve static assertions; the semantic source induction remains a manual proof.

Primary source inspected directly: Don, Fehr and Huang, *Adaptive versus Static Multi-oracle Algorithms, and Quantum Security of a Split-key PRF*, arXiv:2206.08132v3, Section 4.2, equations (6)-(7), Theorem 2, and the hybrid setup in Section 4.3: <https://arxiv.org/pdf/2206.08132>. The fixed-input point-probability premise, all-secret freshness premise and adaptive-query bound match the manuscript's use.

## Statement-by-statement findings

### R01 — Independent oracles and complete preparation

**PASS.** The experiment retains one whole SHA3-256 oracle H and a separate independent SHA-256 compression oracle h. Oracle-dependent construction of the established starting state and every continuation are charged. The proof does not import a correlated starting history as free advice.

Evidence: TeX introduction; MD section 2.

### R02 — Exact native ContextBound encoding

**PASS.** The ten LP8 fields, their order, the nested policy context and the full signed-offer-derived application context match the pinned core/source. Total length is 2639 bytes and selected ML-KEM shared-secret data occupy zero-based offsets 76 through 107. Trust-root and original-slot metadata are kept outside this cryptographic input.

Evidence: TeX complete-effective-tuples paragraph; MD section 3; core combine_validated and encode_policy_bound_context.

### R03 — Point-probability premise of DFH Theorem 2

**PASS.** For any fixed remaining nine fields m and any complete string w, parsing permits at most one u with f(u,m)=w. A uniform 256-bit component therefore gives the required probability at most 2^-256. This is an instantiation of the cited primitive theorem.

Evidence: Lemma cb-hidden-component; DFH equations (6)-(7), Theorem 2.

### R04 — All-secret freshness and adaptive private inputs

**PASS.** Different effective m values encode different complete inputs for every u. Exact repetitions are cached before a private query, so distinct private queries meet the all-secret freshness premise. The cited theorem permits adaptive m. No uniformity conditioned on a later transcript or acceptance event is used.

Evidence: Lemma cb-hidden-component proof; DFH Theorem 2.

### R05 — Hash cache identity and provenance identity remain distinct

**PASS.** The cache contains every effective field, including the other shared secret. It merges exact protected tuples even across origin handles, while provenance remains in its own ledger. The counterexample is correct: equal real hash inputs always agree; independently sampled per-origin answers agree only with probability 2^-256.

Evidence: TeX paragraph following cb-hidden-component; MD cache counterexample; source section 5.

### R06 — Ordinary oracle queries that happen to match a protected point

**PASS.** Known independent-origin computations retain ordinary H answers and are counted in Q_H. The proof does not silently route these queries to the private table, test equality with unknown U, or assume independent numeric secrets cannot coincide.

Evidence: Lemma cb-hidden-component proof; source section 5.

### R07 — Actual protected component and actual companion computation

**PASS.** The protected uniform-key experiment is for ML-KEM-768. The X25519 leg is locally evaluated with its native rejection behavior. No claim is made that a raw X25519 DH output is uniform over all 256-bit strings.

Evidence: TeX introduction and component adapter; MD sections 1 and 4.

### R08 — Operational two-stage component security game

**PASS.** The public key and ordinary prechallenge decapsulation phase precede one adaptively requested challenge at the first private computation of original a. Afterwards the component oracle rejects that challenge ciphertext. The final text explicitly declines to assume equivalence with a challenge supplied up front. The advantage terms therefore refer to the actual stated operational game.

Evidence: TeX component adapter; MD section 4.

### R09 — CCA-safe ciphertext routing

**PASS.** Every postchallenge selected-owner decapsulation with the challenged PQ ciphertext returns the cached challenge key, regardless of the accompanying traditional ciphertext or context. Other PQ ciphertexts use the component oracle. The native traditional leg and errors still run, and preceding work remains charged.

Evidence: TeX component adapter; source section 4; checker routing cases.

### R10 — Preservation of prechallenge history

**PASS.** An earlier selected-key decapsulation that happens to equal the eventual challenge ciphertext retains its original answer. The final draft neither deletes this history nor retroactively replaces the answer with U. The finite routing checker explicitly exercises this case.

Evidence: TeX component game; MD section 4; independent fixture prechallenge-query-may-equal-eventual-ciphertext.

### R11 — Original slots, challenge timing and retries

**PASS.** The challenge is attached to the selected original encapsulation on the original retained offer, at the first actual private computation, and cached before persistence/release. Exact retries reuse it; a fresh entropy reservation receives a new slot. Equal external IDs, public keys or physical copies do not create or transfer origins.

Evidence: TeX component adapter; MD section 4; source sections 3-4.

### R12 — Component endpoint gaps and correctness accounting

**PASS.** D_j^sigma outputs the actual event indicator 1[Psi_j=sigma]. Its real branch matches V^[j] up to the selected-pair correctness cost delta_j; its uniform branch is exactly Vtilde^[j]. The two event inequalities yield a_j^+ + a_j^- + 2 delta_j. Record and permitted-projection costs are not erased.

Evidence: TeX definition of D_j^sigma and a_j^sigma; existing candidate-local proposition.

### R13 — Valid start of the hidden-input comparison

**PASS.** A new simulator for this adjacent experiment pair may materialize the native KEM tapes, execute the actual algorithms and substitute fresh independent U only at the designated protected returns. It need not inherit an earlier reduction's unknown challenge tape. Its ordinary KEM SHA3 work and opaque record interfaces remain part of the full experiment.

Evidence: TeX last component-adapter paragraph; source section 5.

### R14 — Declared next-rekey native profile

**PASS.** The profile starts with the two authoritative endpoints of one established session sharing old root, epoch and control parent, with no selected pending rekey. It allows failures, recovery, active packets, asynchronous completion and subsequent epochs. It fixes the starting state/call surface while retaining the original eligibility predicate. It excludes arbitrary export of selected owners and activation of read-only copies as competing histories.

Evidence: TeX concrete-profile paragraph; source section 6.

### R15 — Online source invariant rather than future-event conditioning

**PASS.** The hypothesis is an immutable admitted binding that identifies a as consuming the retained original offer from g. The conclusion holds throughout every supported continuation of that matching prefix, including branches with no later acceptance, no eligibility, or score zero. Contrary immutable bindings may stop only under the already established permanent-zero certificate.

Evidence: Lemma cb-native-root-use; final source section 6.

### R16 — One root-use descriptor from actual source transitions

**PASS.** The saved proposer generation plan preserves one complete offer; the responder token preserves that exact offer and rejects a different one. The fixed response prefix and both complete ciphertext fields determine one response core and one complete 97-byte I_R. Pending message operations do not replace the old r. Thus all protected target-tuple uses feed the same (r,I_R). These key source paths were independently read, not inferred from the Python model.

Evidence: Lemma cb-native-root-use proof; pinned C09-C11 source paths.

### R17 — Crash and completion preserve the one-use descriptor

**PASS.** The responder leaves the encapsulation-token stage for retained-root state before response release; the proposer leaves the generation-token stage before root installation. Final/receipt are the live rekey-root installation sites. A precommit crash returns to the same token and old root; committed recovery uses the retained result. Selected tokens are not recomputed under a newly installed root.

Evidence: Lemma cb-native-root-use proof; C09-C11; source section 6 induction.

### R18 — The marked target is the original a tuple

**PASS.** m* is fixed by the original a challenge ciphertext, local traditional leg, original offer context, policy and public fields. It is not an arbitrary first tuple from the protected family. Its first private computation at any alias, including a computation before failed persistence, allocates the target. A later durable acceptance cannot reset freshness or choose another tuple.

Evidence: TeX fresh-allocation paragraph; MD section 5.

### R19 — Fresh uniform contribution and retained root-entry interface

**PASS.** The first allocation T(m*) provides an unconditioned fresh uniform 32-byte S* that can be presampled and withheld. Exact aliases reuse it, and other private table entries are available controller values. The source invariant gives one original Extract/Expand plus exact repetitions, which is the existing single-entry initialization premise. Entire future continuations are regenerated rather than frozen.

Evidence: TeX fresh-allocation paragraph and theorem proof; joint-root-entry dependency.

### R20 — Existing first-message and qualification interface is preserved

**PASS.** The online fresh traffic-entry/direction mark, private honest application and existing continuation remain in force. Qualification is computed from the available classical view and provenance ledger rather than the hidden challenge bit. The fair-guess-on-disqualified-runs reduction realizes the full qualified score in the actual AEAD game. The stated counterexample with qualification 1[b=0] correctly has mean 1/2.

Evidence: TeX score semantics; MD sections 6-7; joint-first-message dependency.

### R21 — Bit-to-signed-score factors and candidate continuation bound

**PASS.** The terminal test with output probability (Psi+1)/2 converts a bit gap epsilon into a score gap at most 2 epsilon. Therefore B_j^cont = min(1, 2 Phi_256(d_j,Q_H,j) + 2 Delta_init,j + 2 Delta_sched,j + 2 epsilon_AEAD,j) is correct. The component event terms are already score terms and are not doubled again.

Evidence: Theorem cb-next-rekey and proof.

### R22 — Native residuals and candidate-local composition

**PASS.** The final native bound is min(1/2, (eta_attr^nat + eta_proj^nat + sum_j(rho_j+a_j^++a_j^-+2 delta_j+B_j^cont))/2). Both residuals remain in the original native game; candidate ideals are compared separately rather than identified as one global partition. Finite budgets are fixed in advance and include the full derived experiment.

Evidence: Theorem cb-next-rekey; candidate-local proposition.

### R23 — Attribution of new result and excluded generalization

**PASS.** The completed result is the protocol-specific accepted-operation/encoding/root-use connection and its composition with retained bounds. DFH and the existing HMAC/HKDF primitive results remain cited prior inputs. The suggested multiple-root construction is explicitly excluded from this manuscript theorem; its full generalization is not certified by this review.

Evidence: TeX final paragraph; MD sections 8-9.

### R24 — Evidence classification and final artifact consistency

**PASS.** The independently rerun Python checker passes 36 finite framing/routing/model checks. The source receipt reports 14 pinned files and 12 static assertions; the semantic invariant is a manual source proof. No native Rust execution, formal proof assistant, new Tamarin baseline or new benchmark is asserted. Final TeX has three matched numbered equation environments and the previously damaged line-spacing syntax is repaired. Full manuscript compilation is the parent task.

Evidence: Source receipt/map; independently rerun checker; TeX structural inspection.

## Draft issues resolved before this verdict

- Made the actual two-stage operational component game explicit; no implicit conversion to an up-front-challenge interface.
- Defined the actual D_j^sigma output-event gaps and real-versus-uniform endpoint correspondence, retaining delta_j.
- Preserved all prechallenge decapsulation history, including equality with the eventually sampled challenge ciphertext.
- Marked the original a tuple at its first actual private computation at any alias, including failed writes.
- Stated root-use correspondence for every continuation of a matching immutable prefix, without assuming future acceptance or eligibility.
- Kept the factor two for bit-to-score hops and the original native residual locations.
- Repaired numbered-equation and line-spacing syntax introduced during draft editing.

## Scope of this verdict

- Security conclusion uses the stated operational ML-KEM component advantage, correctness, DFH/QROM, retained root/schedule/AEAD inputs and original native residuals.
- Root-use closure is for the declared one-session next-rekey authoritative call surface; arbitrary owner export, active forks and retrospective multi-root targets are outside this theorem.
- No theorem converting the operational component game to an up-front-challenge game is asserted.
- The multiple-root suggestion in research MD section 8 is not promoted to a theorem or included in the acceptance verdict.
- Manual mathematical/source review and finite checks are not a machine-checked proof or native runtime test campaign.

There is no outstanding correction required for the three stated results. Full manuscript compilation and editorial integration are the parent task; this review does not claim those checks have already run.

## Exact input hashes

The logical paths below identify the reviewed files. Absolute source paths, byte counts and the same hashes are in `independent_review.json`.

| Input | SHA256 |
| --- | --- |
| `theory/contextbound-connection.tex` | `97758cda00a7159839b80f6bcc66e78ca4a0d8702ec5d12a687fa64f67ade0a1` |
| `theory/contextbound_connection.md` | `e9165579272d819c82ec197cf526e2556262c5d15242a3d81caa2cf2ee9227df` |
| `source/source_audit.md` | `7d318029e9921d1c4d8d2c08a5730656d6f5672c8495e17ec3c2d0f6a16af635` |
| `source/source_map.json` | `8d1eedcd7f9d711dfaf6f9fe32b5825107f6cdb332ae6762153c1778661dfe05` |
| `source/audit_source.py` | `2afbb47b4e5c251c47977aa5c2096df7458d95b1a555da6b5feb87916387f437` |
| `source/check_contextbound_adapter.py` | `0ff4fbd0babf570a3b70b92383c6d45515ac3d1034b8522708457d1c5cd34d1e` |
| `source/fixtures.json` | `1a3dc4f032ac31904ba5eaa3f690be8a11b34a6b0b4612d16618a808a9f2e462` |
| `source/check_receipt.json` | `76511a7b62e0d93f43b144f6eb6eb809d1fad68ae3e48b972966d14fc7dcf76a` |
| `review/independent_checker_receipt.json` | `76511a7b62e0d93f43b144f6eb6eb809d1fad68ae3e48b972966d14fc7dcf76a` |
| `dependency/candidate-local-accounting.tex` | `4a38c6bb00c70f2611c2395aec754c0af6b8231a8e3f94e027cf1a17b657865d` |
| `dependency/joint-continuation.tex` | `865b128155662d8916ef648a7852a9973e9d24f22287d29c9ec59ca191fee989` |
| `dependency/primitive-inputs.tex` | `78c4c40bfa0a4d2d9f441ac59f40df436863583ab5bdf538beb6fd5fc59e43aa` |
| `dependency/joint-primitive-bounds.tex` | `8f7d3cdd7fb314f8c183318667d86e1a8c762ffc5ae513716b1da40769ecd19d` |
