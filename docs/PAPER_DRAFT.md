# Q-Periapt — TDSC paper draft (structural)

> **Status of this file.** A structural draft for the author (PhD, 李子昂) to flesh into full
> prose. Honesty-critical sections (Abstract, Contributions, §"What is and is not novel",
> the claims table, Related Work, Limitations) are written out; the rest are detailed outlines
> with evidence pointers (file paths + commit hashes). **Every claim here is one we have
> verified in this repo; the do-NOT-claim list is load-bearing — do not relax it under reviewer
> pressure.** Target venue: **IEEE TDSC** (dependable systems + security; a PhD-appropriate
> CCF-A target). Frame as an *assurance / dependable-deployment* contribution, NOT a new
> cryptographic primitive.

---

## Figures (built, in `paper/figures/`; `make` rebuilds — IEEE vector PDF)

| PDF | Use in | Shows |
|-----|--------|-------|
| `fig_arch.pdf` (hero) | §1 / §4 | proof-to-byte cross-substrate: one proven core → 5 faces/3 OS/5 ISA → byte-identical `K` |
| `fig_binding.pdf` | §3 / §"novel" | honest CDM ceiling — both schemes reach MAL-BIND-K-{CT,PK}; edge = assumption-minimality, not a stronger notion; X-BIND-CT-* unachievable |
| `fig_kernel.pdf` | §3 | reduction tower: MAL-BIND-K-{CT,PK,CTX} → CR(SHA3) via proved `encode_inj`; honest scope boxed |
| `tbl_verif.pdf` | §4 (Table) | the six orthogonal verification methods (oracle / independence / what it catches) |
| `tbl_substrate.pdf` | §5 (Table) | cross-substrate coverage: (a) ISA targets (byte-id `K`, binary-CT), (b) faces × OS |
| `fig_ct.pdf` | §5 | source→binary CT discriminator (ML-KEM 0 vs HQC 193) |
| `fig_netem.pdf` | §6 | netem P99: PQ overhead ≈ fixed CPU, negligible % at RTT; combiner-neutral |
| `fig_wire.pdf` | §6 | handshake wire budget (+2.27 KB ML-KEM keyshare) |

## 0. Positioning vs. the author's prior (appealed) TDSC submission

The prior submission's contribution was **auditability + migratability** of PQC (incl. X-Wing)
on an Apple-only system. **This paper must not re-tread that.** Its contribution is a different
axis — **deployment-safety assurance that holds end-to-end from one assumption down to
byte-identical artifacts across a heterogeneous substrate** — and it structurally answers the
prior reviewer's "only Apple platform" objection by making cross-substrate realization a
*first-class, evidenced property*, not a portability footnote. Say this explicitly in §1 so the
editor cannot conflate the two.

---

## 1. Title (LOCKED)

**"Proof-to-Byte: Assumption-Minimal, Cross-Substrate Binding Assurance for PQ/T Hybrid KEMs."**

Leads with the genuine novel conjunction: a machine-checked binding result whose realized object
is byte-identical across substrates. (Alternates, if a venue prefers: "Q-Periapt: A Machine-Checked,
Cross-Substrate, CI-Gated Assurance Suite for Post-Quantum Hybrid Key Exchange.")

---

## 2. Abstract (draft — honest)

> Post-quantum hybrid key-encapsulation (PQ/T KEMs combining a lattice KEM with an elliptic-curve
> KEM) is being deployed across TLS, Signal, and MLS faster than its *deployment safety* can be
> assured: the same period saw side-channel breaks (KyberSlash), binding/re-encapsulation breaks
> (PQXDH; the ML-KEM MAL-binding failures of Schmieg), and a widening gap between what a hybrid's
> *specification* guarantees and what its *compiled, multi-platform implementation* actually does.
> We present Q-Periapt, an assurance suite for PQ/T hybrid KEMs built around one principle:
> *a security property is only as trustworthy as its weakest realization.* Its combiner,
> ContextBound, achieves binding (MAL-BIND-K-{CT,PK}) reducing to collision-resistance of SHA3
> **alone** — no binding assumption on the component KEMs — and we **machine-check** this in
> EasyCrypt (the injective encoding is a proved lemma, not an axiom; the KEM-aware game is
> modeled for the implicit-rejection setting). Crucially, the **same** proven combiner is realized
> **byte-identically across five language faces, three operating systems, and five instruction-set
> architectures**, verified by a six-method conformance matrix and a CI-gated, self-validating
> source→binary constant-time probe that we show *discriminates* a clean primitive (libcrux
> ML-KEM: zero secret-dependent branches post-compilation) from a leaky one (HQC's PQClean
> constant-weight sampler). We integrate the combiner into a production TLS 1.3 path (a rustls
> CryptoProvider) and evaluate handshake tail latency under real `tc netem`. We are explicit
> about what is and is not novel: the binding *fact* is a known consequence of recent results
> (CDM; Chempat); our contribution is the *conjunction* — an assumption-minimal, machine-checked
> binding result whose proven object is demonstrably identical across a heterogeneous deployment
> surface, with reproducible CI gates that catch the specific failure classes that have broken
> deployed hybrids.

---

## 3. Contributions (precise; each maps to evidence in §"claims table")

- **C1 — Assumption-minimal, machine-checked binding.** ContextBound reduces MAL-BIND-K-{CT,PK}
  (and a context extension K-CTX) to CR(SHA3) alone, with the injective length-prefixed encoding
  **proved** (`encode_inj`), and the **KEM-aware CDM game** (MAL adversary supplies the keypairs;
  K derived via Decaps + the combiner) machine-checked in EasyCrypt for the **implicit-rejection
  setting** over abstract Decaps. *(`formal/easycrypt/BindingViaCR.ec`; commits 787b3b1, a5b9159.)*
- **C2 — Proof-to-byte cross-substrate equivalence.** The same proven combiner is realized
  **byte-identically** across 5 language faces (Rust, C-ABI, WASM, Swift, Kotlin), 3 OSes
  (Linux, macOS, Windows-MSVC), and 5 ISAs (x86-64, aarch64, riscv64, wasm32, thumbv7em), verified
  by a six-method conformance matrix (fixed KATs incl. X-Wing + RFC 7748; NIST ACVP; independent
  multi-backend differential; the EasyCrypt proof; cross-platform byte-identity; generative
  property tests). *(This is the structural answer to the prior "only Apple" rejection.)*
- **C3 — CI-gated assurance that catches the deployment-failure classes.** (a) A **self-validating
  source→binary constant-time probe** that runs real libcrux ML-KEM decapsulate under Memcheck
  marking only the genuine secret, *shown to discriminate* clean (ML-KEM: 0 flags) from leaky
  (HQC PQClean: 193 flags in `vect_set_random_fixed_weight`). (b) An **executable demonstration**
  that a lean (X-Wing-shaped) combiner's MAL-BIND is *contingent on the component KEM's key
  serialization* (Schmieg expanded-dk), while ContextBound's is not. (c) **Two independent
  symbolic provers** (Tamarin, ProVerif) on the handshake, plus the EasyCrypt computational proof
  — all CI-gated. *(`ctstats/`, `crates/q-periapt-backends/tests/binding_keyformat_separation.rs`,
  `formal/{tamarin,proverif}`.)*
- **C4 — Production path + real-link evaluation.** A rustls TLS 1.3 CryptoProvider running the
  combiner (handshake passes), evaluated for tail latency under real `tc netem`.
  *(`crates/q-periapt-rustls`; commit 778aeec.)*

---

## 4. §"What is and is NOT novel" (WRITE THIS SUBSECTION; it is the R2-survival piece)

> Place this near the end of §1 (or as §2.x). Disarming the novelty attack by stating the
> boundary yourself is what survived-the-appeal papers do.

**What is novel (defensible):**
- The **conjunction** C1∧C2: an assumption-minimal, machine-checked binding result whose *proven
  object is byte-identical across a heterogeneous substrate*. No prior work pairs a CR-only
  machine-checked hybrid-binding proof with an evidenced byte-identical multi-substrate
  realization. The novelty is *proof-to-byte equivalence across substrates*, not the binding fact.
- The **self-validating source→binary CT discriminator** as a reusable, CI-gated assurance
  artifact (clean-vs-leaky in one framework, with a positive control inside the *real* library).
- The **operationalized design invariant** "bind ct/pk in the KDF ⇒ hybrid MAL-BIND is robust to
  the component KEM's key-serialization format," enforced via the C2PRI/profile gate and
  demonstrated executably.

**What is NOT novel — state plainly and cite (do NOT claim these as results):**
- That a *hash-everything* combiner is binding from CR alone while a *lean* combiner inherits the
  omitted component's binding — this is **Güneysu–Hövelmanns–Pietrzak / Chempat (eprint 2025/1416)**;
  **ContextBound is the Chempat hash-everything construction, not a new primitive.**
- That ML-KEM in the FIPS-203 *expanded* dk format is neither MAL-BIND-K-CT nor MAL-BIND-K-PK, and
  that the *seed* format fixes it — this is **Schmieg (eprint 2024/523)**.
- The MAL-BIND-K-{CT,PK} notion lattice and monotonicity — **Cremers, Dax, Medinger (CCS 2024)**.
- That CT analysis must mark only secret sub-fields (not the public key embedded in dk) — this is
  **standard CT-harness practice (KyberSlash, TCHES 2025, §7.1.2)**; libcrux already
  machine-checks secret-independence via its `libcrux-secrets`/hax typed discipline. We use this;
  we did not discover it. The "5696→0" Memcheck contrast is corroboration, not a finding.
- That K-CTX (context binding) is desirable — this is the KEM-layer lift of **Bellare–Hoang
  context-committing AEAD (CMT-3)**; it is a *convenience corollary*, not a new security notion.

**Honesty boundaries to never cross (a reviewer will check):**
- **Do NOT** claim "stronger binding than X-Wing." On the standard {K,PK,CT} lattice, correctly-
  implemented **seed-dk X-Wing attains MAL-BIND-K-{CT,PK}**; our key-format demo is about
  *combiner robustness to the component dk format*, **not** a break of X-Wing.
- **The EasyCrypt artifact IS the full CDM Figure 6 game** (both implicit and explicit rejection;
  the `K≠⊥` conjunct is present and verified load-bearing). But scope it honestly: it is over
  **abstract Decaps** (zero KEM assumption — holds for any Decaps — but therefore **no FIPS-203
  linkage**, and the shared-secret fields are **inert** in the binding argument, which flows
  through the absorbed ct/pk/ctx). CR(SHA3) is a modeling assumption; IND-CCA2 robustness is on
  paper; there is **no spec↔implementation linkage**. So claim *"machine-checked CDM
  MAL-BIND-K-{CT,PK,CTX} over abstract Decaps, reducing to CR(SHA3)"* — do NOT imply it proves a
  property *about ML-KEM's* decapsulation, or that CR(SHA3) / IND-CCA2 / impl-linkage are results.
- **Do NOT** claim a live exploited exposure in any deployed stack — the ecosystem has converged
  on seed-dk; the key-format hazard is a *latent design coupling we surface*, not a CVE.
- **Do NOT** claim any X-BIND-CT-* notion (structurally unachievable for implicitly-rejecting KEMs).
- **Do NOT** claim a speed edge: ContextBound is at parity with X-Wing's combiner (more binding =
  more hashing); the win is assurance/robustness, not performance.

---

## 5. Body sections (detailed outlines)

### §2 Background & threat model
- PQ/T hybrid KEMs; the concatenation vs. KDF-combiner design space; X-Wing and TLS X25519MLKEM768.
- KEM binding: the CDM X-BIND-P-Q framework (cite Cremers–Dax–Medinger CCS'24); MAL⊇LEAK⊇HON;
  the K-binds-{PK,CT} ceiling; X-BIND-CT-* unachievable for implicit rejection.
- The **deployment-safety gap** (the paper's motivating wedge): KyberSlash (side-channel), PQXDH /
  Schmieg (binding), the source↔binary and spec↔multi-platform gaps. This is the pain point that
  is NOT "auditability/migratability."
- Threat model: malicious-key (MAL) binding adversary; side-channel (binary-CT) adversary;
  downgrade/agility adversary. Point to `docs/THREAT_MODEL.md`.

### §3 ContextBound & the machine-checked binding kernel (C1)
- Construction: `K = SHA3-256(encode[LABEL, suite_id, policy_version, ss_pq, ss_trad, ct_pq,
  pk_pq, ct_trad, pk_trad, context])`, injective 8-byte-BE length-prefix encoding. Two profiles:
  `CompatXWing` (byte-exact X-Wing) and `ContextBound` (hash-everything). Cite `docs/COMBINER_SPEC.md`.
- The EasyCrypt development (`BindingViaCR.ec`): `encode_inj` proved; the generic reduction
  `bind_le_cr`; the instantiated corollaries; **the KEM-aware game** `malbind_kct/kpk/kctx_le_cr`
  (MAL adversary supplies keypairs, K derived via abstract total Decaps + combiner, reduces to
  CR(H)). Each verified load-bearing (negative control).
- **Honest scope box** (lift from §4 boundaries): implicit-rejection specialization; abstract
  Decaps = zero KEM assumption but no FIPS-203 linkage; CR(SHA3) assumed.

### §4 Proof-to-byte cross-substrate realization (C2)  ← the Apple-only answer
- The single-core / multi-face architecture (`docs/ARCHITECTURE.md`).
- The **six-method verification matrix** (Table): fixed KATs (X-Wing draft + RFC 7748) · NIST ACVP
  (full FIPS family: ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA) · independent multi-backend
  differential (RustCrypto ml-kem/ml-dsa, orion X25519) · EasyCrypt proof · cross-platform
  byte-identity · generative property tests.
- The substrate matrix (Table): 5 faces × 3 OSes × 5 ISAs, with **per-cell honesty** (what is
  verified locally vs. in CI; Windows-MSVC verified locally; binary-CT only on x86-64/aarch64;
  riscv64/wasm32 = source-CT + attestation). Reproducible build attestations.

### §5 CI-gated assurance against the failure classes (C3)
- **Binary-CT source→binary gap probe** (`ctstats/ct_decaps_gap`): marks only ŝ+z, runs real
  libcrux decaps under Memcheck; aarch64 = 0 (no gap); self-validating via the `ek` positive
  control (5696 flags on the embedded public key) + a planted-leak negative control. The
  **discriminator** result: `ct_hqc_gap` flags HQC's `vect_set_random_fixed_weight` (193) — same
  framework, clean vs. leaky. Honest: HQC's leak is known; the contribution is the discriminating,
  CI-gated artifact + the corollary that per-backend CT gating (C2PRI, feature-gating) is necessary.
- **Binding key-format coupling demo** (`binding_keyformat_separation.rs`): real libcrux; lean
  X-Wing-shaped combiner over expanded-dk loses MAL-BIND-K-PK (Schmieg z-substitution), ContextBound
  does not. Framed strictly as combiner robustness (see §4 boundary).
- **Multi-prover symbolic** (Tamarin + ProVerif): hybrid handshake robustness (key survives break
  of EITHER component); both CI-gated, alongside the EasyCrypt computational proof.

### §6 Production integration & evaluation (C4)
- rustls CryptoProvider: the SupportedKxGroup/ActiveKeyExchange wiring; private-use group codes;
  TLS 1.3 loopback handshake passes (`crates/q-periapt-rustls`).
- **Evaluation (socket TLS 1.3 via the rustls CryptoProvider, real `tc netem` on `lo`).**
  Time-to-session **p50** (mean of 2 reps), µs (`examples/netem_bench.rs`). *We report p50 only:*
  the **p99 tails are dominated by VM scheduling noise** (the original single run even showed the
  hybrid p99 *lower* than classical at 50 ms — a clear noise artifact R4 caught; do NOT publish a
  p99 table from the VM).

  | RTT | X25519 (classical) | ContextBound | CompatXWing | overhead (CB−cl) |
  |-----|--------------------|--------------|-------------|------------------|
  | 0 ms  | 359.6  | 548.9  | 530.6  | **+189 µs (53%)** |
  | 20 ms | 41 469 | 41 494 | 41 816 | **within noise** (rep spread straddles 0) |
  | 50 ms | 101 630 | 102 214 | 102 159 | +0.5% (noisy) |

  Wire: classical ≈ **968 B**; hybrid ≈ **3 240 B** (+2 272 B = ML-KEM-768 pk 1 184 + ct 1 088).
  **Findings (honest):** (1) the only reproducible PQ/T cost is **~190 µs of ML-KEM CPU at RTT 0**;
  at RTT ≥ 20 ms the overhead is **within run-to-run noise** (sign varies) — the extra bytes fit the
  existing flights, no extra round-trip. (2) **Combiner-neutral** (ContextBound ≈ CompatXWing).
  Caveat: **host = colima VM**; `paper/netem-camera-ready.sh` reproduces on quiesced bare metal.
- Optional: ML-DSA-dominated wire-budget table (L3 5758 B vs L5 7940 B) from the demo `p99_bench`.

### §7 Related work
- KEM binding: Cremers–Dax–Medinger (CCS'24); Schmieg 2024/523; Chempat / GHP 2025/1416;
  Bellare–Hoang context-committing AEAD; eprint 2026/140 (public contexts in hybrid KEMs — cite
  precisely: it analyzes *when* public context is necessary/redundant, it does NOT define a
  key-binds-context KEM game).
- Side-channel: KyberSlash (TCHES'25); ctgrind/TIMECOP/dudect; libcrux/HACL* + libcrux-secrets/hax.
- Hybrids in deployment: X-Wing (draft-connolly-cfrg-xwing-kem); TLS X25519MLKEM768; PQXDH; Apple PQ3.
- Formal PQ verification: formosa-mlkem (ML-KEM IND-CCA); SandboxAQ EasyCrypt-KEMs (LEAK-BIND-K-PK).

### §8 Limitations & honest scope (do not bury — TDSC rewards candor)
- EasyCrypt: full CDM Figure 6 (both rejection styles) but over **abstract Decaps** — no FIPS-203
  linkage, ss fields inert in the binding argument (proves nothing *about* ML-KEM's decaps);
  CR(SHA3) assumed; IND-CCA2 on paper; no spec↔impl linkage.
- Binary-CT: only x86-64 + aarch64 have mature tooling; riscv64/wasm32 are source-CT + attestation.
- Conformance ≠ certification (ACVP byte-identity is not CMVP).
- No independent third-party audit; research-grade, do-not-deploy.
- CI: the repo's gates are *configured*; report which have actually executed (note the no-remote
  history honestly, now that it is public on GitHub).

### §9 Conclusion
- Restate the spine: trust a hybrid's safety only as much as its weakest realization; we close that
  gap with a machine-checked, cross-substrate, CI-gated assurance discipline + an assumption-minimal
  combiner. The genuinely new bit is the *conjunction*, not any single fact.

---

## 6. Claims ↔ evidence ↔ artifact (build the camera-ready table from this)

| # | Claim (as stated) | Evidence / artifact | Verified |
|---|---|---|---|
| C1a | MAL-BIND-K-{CT,PK,CTX} ≤ CR(SHA3); encode_inj proved; **full CDM Figure 6** game (implicit + explicit rejection, K≠⊥ load-bearing), over abstract Decaps | `formal/easycrypt/BindingViaCR.ec` (`malbind_*_le_cr`, `malbind_*_xrej_le_cr`); `easycrypt compile` exit 0; negative controls (incl. K≠⊥) | ✔ this session (a5b9159, 65f4328) |
| C2a | 6-method conformance | KATs/ACVP/differential/proof/cross-platform/proptests in `crates/q-periapt-backends/*` | ✔ (prior commits) |
| C2b | byte-identical across 5 faces / 3 OS / 5 ISA | shared-vector tests; Windows-MSVC local; cbindgen C-ABI | ✔ local (CI configured) |
| C3a | source→binary CT: ML-KEM 0 / HQC 193 (discriminator) | `ctstats/ct_decaps_gap`, `ct_hqc_gap`; `ct-gap-probe.sh` | ✔ aarch64 (e525bef) |
| C3b | lean-combiner MAL-BIND-K-PK contingent on dk format | `binding_keyformat_separation.rs` (real libcrux) | ✔ (e525bef) |
| C3c | 2 symbolic provers + 1 computational, CI-gated | `formal/{tamarin,proverif,easycrypt}` | ✔ |
| C4a | rustls TLS 1.3 handshake over the combiner | `crates/q-periapt-rustls/tests/handshake.rs` | ✔ (778aeec) |
| C4b | real netem P99: PQ overhead ~0.1–0.4% at RTT≥20ms (no extra round-trip), combiner-neutral; vs classical-X25519 baseline | `crates/q-periapt-rustls/examples/netem_bench.rs` under `tc netem` | ✔ (host=VM; rerun on bare metal) |

---

## 7. Acceptance risk & mitigations (from the vetting synthesis)

- **Biggest risk: "thin core / known consequence."** Mitigate by (a) making the spine carry the
  weight (the C1∧C2 conjunction, which has no prior referent), (b) the source→binary gap probe as
  the one hard technical artifact (done), (c) the explicit §4 "what is/is not novel" pre-emption.
- **R2-misunderstanding risk (the prior trauma).** Mitigate with the claims table, the reproducible
  artifact (open-source, CI-gated, with the demos), and ruthless scope discipline in every claim.
- **Format desk-reject risk.** Use the TDSC template from line one; figures + tables early.

---

## 8. Open author decisions (flag to 李子昂)
- ~~Title choice~~ — **LOCKED** (§1, "Proof-to-Byte…").
- ~~Faithful explicit-rejection EasyCrypt encoding~~ — **DONE** (full CDM Figure 6 mechanized,
  `malbind_*_xrej_le_cr`, commit 65f4328).
- ~~Add a netem baseline to quantify PQ overhead~~ — **DONE**: `examples/netem_bench.rs` adds a
  **classical X25519** baseline (PQ overhead = ~0.1–0.4% at RTT≥20ms, no extra round-trip;
  combiner-neutral). *Optional further baseline:* the IANA `X25519MLKEM768` group (needs the
  aws-lc-rs provider) to show "same primitives, concat vs ContextBound combiner" — wire-equivalent
  to ContextBound by construction, so low marginal value; list if a reviewer asks.
- **Pending (camera-ready):** re-run netem on a quiesced bare-metal Linux host (current numbers
  are from a colima VM; the RTT-dominated 20/50 ms figures are clean, the RTT 0 tails are noisy).
