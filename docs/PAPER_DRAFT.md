# Q-Periapt — TDSC paper draft (structural)

> **Status of this file.** Authoring notes, not the current evidence authority. The paper source is
> [`../paper/q-periapt.tex`](../paper/q-periapt.tex), and machine-readable current claim status is
> [`../artifact/claim-ledger.json`](../artifact/claim-ledger.json). Historical numbers and checked
> boxes below remain useful provenance but must not be promoted to current clean-device,
> cross-platform Cartesian-product, refinement, or performance-parity claims. The do-NOT-claim list
> is load-bearing — do not relax it under reviewer pressure. Target venue: **IEEE TDSC** (dependable systems + security; a PhD-appropriate
> CCF-A target). Frame as an *assurance / dependable-deployment* contribution, NOT a new
> cryptographic primitive.
> ABI 2 / `0.1.5` is the stable-version Rust crate source line, succeeding the
> published `0.1.4` release. Its GitHub distributions are public and immutable,
> and all ten `0.1.5` crates are published and independently verified. The complete
> three-domain record is preserved at `v0.1.5-verified-cohort`. Its pre-publication package-ready contract alone does not prove
> crates.io upload-API acceptance, crate-name ownership, publishing credentials or
> authorization, server-side policy acceptance, or a registry receipt. The two immutable
> GitHub stable targets are the Apple XCFramework `v0.1.5` (Rust 1.96.1;
> the predecessor `v0.1.3` is published and immutable but superseded, the earlier `v0.1.0-alpha.2`
> on 1.96.0 is superseded, and the `v0.1.0`, `v0.1.1`, and
> `v0.1.2` tags were never published) and the
> `abi2-platforms-v0.1.5` platform distribution (Android AAR + API 35 / 16 KiB-page
> emulator runtime evidence and Linux x86_64+aarch64 SDKs); both went live on 2026-09-05
> and have separate asset-verification receipts. The older `0.1.4` GitHub releases
> and all ten `0.1.4` crates remain immutable published history. The unsigned Windows
> package remains an unsupported CI diagnostic outside the formal stable asset set.
> Tag-scoped receipts live in `artifact/results.json`; only a verified receipt may
> promote either target to public/current with `prerelease=false`. The `0.1.4` verified cohort is
> recorded at the annotated tag `v0.1.4-verified-cohort`, not on main: reopening the source line
> returned `artifact/results.json` to its 190-key initial baseline, so main's trusted results
> record no `0.1.4` publication and still name `apple_v0_1_3` as the active Apple selector. That
> states where the evidence lives, not whether `0.1.4` shipped; the published GitHub and
> crates.io records are immutable and unaffected. Stable publication is not a production-readiness claim,
> and they do not promote historical measurements below.
>
> **Backend-migration history and current boundary.** The 2026-07-13 migration moved
> the artifact from its former provider to portable `mlkem-native` v1.2.0 through
> `q-periapt-mlkem-native-sys`, `fips204` 0.4.6, and `sha3` 0.10.9. The current
> source now selects upstream AArch64 native arithmetic plus a fixed per-target
> FIPS 202 assembly profile (Armv8.4-A SHA3 on the two Apple Silicon slices,
> Armv8-A scalar elsewhere) on exactly five little-endian Apple/Linux/Android
> targets and retains portable C everywhere else, including Wasm. There is no
> runtime dispatch, and ABI 2/key/wire contracts are unchanged. Both migrations
> changed the canonical source digest. Every portable-derived package/device/
> performance/binary-CT result below is historical evidence, not current ABI2
> production-promotion evidence. Fresh per-target source-bound capture and independent
> cryptographic/ABI review remain pending.

---

## Figures (built, in `paper/figures/`; `make` rebuilds — IEEE vector PDF)

| PDF | Use in | Shows |
|-----|--------|-------|
| `fig_arch.pdf` (hero) | §1 / §4 | proof-to-byte conformance: one modeled combiner → one Rust core → deterministic conformance cells plus fail-closed native-product workflow cells |
| `fig_binding.pdf` | §3 / §"novel" | honest CDM ceiling — both schemes reach MAL-BIND-K-{CT,PK}; edge = assumption-minimality, not a stronger notion; X-BIND-CT-* unachievable |
| `fig_kernel.pdf` | §3 | reduction tower: standard MAL-BIND-K-{CT,PK} plus the separately labeled syntactic K-CTX extension → CR(SHA3) via proved `encode_inj`; honest scope boxed |
| `tbl_verif.pdf` | §4 (Table) | the six orthogonal verification methods (oracle / independence / what it catches) |
| `tbl_substrate.pdf` | §5 (Table) | cross-substrate coverage: (a) ISA targets (byte-id `K`, binary-CT), (b) faces × OS |
| `fig_ct.pdf` | §5 | historical older-source `libcrux` ML-KEM 0 vs PQClean-HQC 193 contrast; the intervening `fips203` gate failed on both ISAs, while pre-selection portable-`mlkem-native` results are historical and fresh x86_64-portable/aarch64-native release-source captures remain pending |
| `fig_netem.pdf` | §6 | historical netem result; fixed local cost becomes small relative to RTT, but it is not current production/device parity |
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

Leads with the artifact-specific conjunction: a machine-checked binding result whose realized object
is byte-identical across substrates. This is positioning of the demonstrated evidence, not an
exhaustive priority claim. (Alternates, if a venue prefers: "Q-Periapt: A Machine-Checked,
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
> modeled for the implicit- and explicit-rejection games). The modeled combiner has one Rust
> implementation with deterministic conformance harnesses and native ABI 2 product adapters that
> exercise signed-policy/context semantics, round trip, rollback, and failure atomicity without
> exposing caller-controlled seeds or raw combine operations. Predecessor source recorded four ISA
> executions plus one cross-build; the backend-migrated source requires fresh execution before
> those cells can be claimed. The artifact uses a
> six-method conformance matrix and a CI-gated, self-validating
> source→binary constant-time probe whose migrated hard gate requires zero for every real
> target-selected `mlkem-native` ML-KEM-512/768/1024 secret path and a positive result for each synthetic planted secret-indexed
> leak. The former `libcrux` zero result, older-source PQClean-HQC positive counts,
> and pre-selection portable `mlkem-native` captures are historical; fresh
> x86_64-portable and aarch64-native captures for the current source are pending. A private-use
> research TLS 1.3 integration against the production rustls library (a `CryptoProvider`) exists;
> its recorded `tc netem` evaluation is
> historical predecessor-source evidence. We are explicit
> about what is and is not novel: the binding *fact* is a known consequence of recent results
> (CDM; Chempat); our contribution is the *conjunction* — an assumption-minimal, machine-checked
> binding result tied by conformance — not mechanized refinement — to a heterogeneous implementation
> surface, with reproducible gates that catch specific failure classes. A signed policy is resolved
> to one closed suite/profile/key-format/version decision and its exact digest is committed by the
> decision-controlled ContextBound path. A matched-backend, single-host performance gate accepts
> only controlled runs bound to the live canonical source digest. The recorded clean Apple matrix
> covered one physical iPad and one distinct physical iPhone on predecessor source and is now stale;
> a fresh same-source device/performance capture, formal spec-to-Rust refinement,
> and cross-device/end-to-end performance parity remain pending.

The concrete SHA3 staging owner uses explicit public/secret absorption without changing any
combiner byte: it volatile-wipes the component-secret and conservatively sensitive caller-context
ranges from every live inline/heap copy and fails closed to whole-buffer erasure for unclassified
input or invalid metadata. This is a candidate implementation optimization with a local
secret-hygiene property and a controlled-host matched-backend non-regression diagnostic.
`artifact/results.json` selects the time-varying proof and the live domain verifier checks its
source, artifacts, budget, host contract, and freshness. A selected raw-schema-v5 /
proof-schema-v8 / budget-schema-v10 proof authorizes only its separately measured,
O3/codegen-matched native-over-portable ContextBound `hybrid_core` implementation
improvement over one generated `expanded_fips203_2400` keypair supplied to both
implementations; it excludes FFI and OS RNG and is not a
ContextBound-over-X-Wing speed, energy, cross-platform, or optimized-production
parity claim. This is not a new reduction or a full-runtime zeroization guarantee.

A local dirty native/portable diagnostic indicated material ML-KEM-768 primitive and
hybrid-core improvement. It has no checked-in canonical-source/toolchain-bound raw
and analysis bundle, so it is not formal release evidence, a device result, or a
cross-platform performance claim. Exact quantitative results require a fresh
raw-schema-v5/proof-schema-v8 run under budget schema v10.

The PQClean-HQC dependency/runtime path has since been removed; numeric suite code `3`
is a permanent tombstone. `research/hqc-fips207-candidate` is a standalone
`publish = false` RustCrypto `hqc-kem 0.1.0-rc.0` HQC-v5/FIPS-207-draft shadow with no ABI or
product-suite identity. Upstream says it tracks an IPD, but as of 2026-07-12 NIST
still says FIPS 207 is coming soon and no official IPD is retrievable; freezing the
eventual official text is a promotion gate. The earlier provider migration to
portable `mlkem-native` v1.2.0 through `q-periapt-mlkem-native-sys`, pinned
`fips204` 0.4.6, and `sha3` 0.10.9 removed both the intervening `fips203` path
that failed the binary-CT gate and the earlier `libcrux`/hax/unsuppressed
`proc-macro-error2` advisory path; `cargo audit --deny warnings`
now passes without an ignore. The subsequent fixed target-selection migration makes
all portable-derived package, Apple, Android, matched-performance, and binary-CT
proofs historical for the current source.
The vendored ML-KEM trust anchors are upstream commit
`0ba906cb14b1c241476134d7403a811b382ca498` and immutable GitHub commit archive SHA-256
`f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677`.
Exactly the little-endian targets `aarch64-apple-darwin`, `aarch64-apple-ios`,
`aarch64-apple-ios-sim`, `aarch64-unknown-linux-gnu`, and
`aarch64-linux-android` build upstream native arithmetic with a fixed per-target
FIPS 202 assembly profile (Armv8.4-A SHA3 x1/x2 on the two Apple Silicon slices,
Armv8-A scalar x1/x4 elsewhere), while every other target remains portable. Upstream HOL-Light
evidence is limited to selected upstream assembly source/object routines, not
downstream reassembly, this Rust/C wrapper, or the full ABI. RustSec covers the
resolved Rust graph, not vendored C, and neither the upstream provider nor this
integration has a completed independent audit.
Currentness is authoritative only through `artifact/results.json` plus live verification.
ABI 2 is the stable-version source/Rust-crate line; package readiness is not registry
publication. The published stable binary
targets are the Apple `v0.1.5` XCFramework and the
`abi2-platforms-v0.1.5` Android/Linux packages, published immutable on 2026-09-05;
their asset-verification and ten-crate registry receipts are complete in
`v0.1.5-verified-cohort`. The older `0.1.4` cohort is recorded
at the annotated tag `v0.1.4-verified-cohort` and not in main's results. Fresh same-source
device/performance evidence, independent cryptographic/C-FFI/ABI review,
signed or transparency-backed source provenance and registry publication remain
requirements for production promotion. Windows remains excluded until a signed
producer/verifier and certificate/timestamp-authority gate exist.

---

## 3. Contributions (precise; each maps to evidence in §"claims table")

- **C1 — Assumption-minimal, machine-checked binding.** ContextBound reduces the standard
  MAL-BIND-K-{CT,PK} games to CR(SHA3) alone. Separately, a self-defined
  context-parameterized K-CTX wrapper collision game has the same syntactic bound; it is not a
  CDM node. The injective length-prefixed encoding is **proved** (`encode_inj`), and the
  KEM-aware games (MAL adversary supplies the keypairs; K derived via Decaps + the combiner) are
  machine-checked for the **implicit-rejection setting** over abstract Decaps.
  *(`formal/easycrypt/BindingViaCR.ec`; commits 787b3b1, a5b9159.)*
- **C2 — Proof-to-byte cross-substrate conformance.** One implementation of the modeled combiner
  has harnesses for pinned, byte-identical outputs in deterministic Rust/WASM/ISA conformance
  cells. Predecessor results are historical after the backend/source migration and must be
  rerun before reporting current cells. The native ABI 2 C/Swift/Kotlin/Android product faces reuse that implementation but are
  intentionally tested by semantic product invariants rather than replaying caller-selected
  randomness. The predecessor evidence executed four ISA targets and only cross-compiled
  thumbv7em; it was not a face × OS × ISA Cartesian-product claim. The harness set comprises
  a six-method conformance matrix (fixed KATs incl. the current CFRG
  concrete-hybrid-kems-04 Appendix B.2 MLKEM768-X25519 vector (stored as the
  repository vector-0 fixture), three retained
  X-Wing draft-10 vectors, and RFC 7748; NIST ACVP; independent
  multi-backend differential; the EasyCrypt proof; cross-platform byte-identity; generative
  property tests). *(This is the structural answer to the prior "only Apple" rejection.)*
- **C3 — CI-gated assurance that catches the deployment-failure classes.** (a) A **self-validating
  source→binary constant-time probe** that runs real target-selected `mlkem-native`
  ML-KEM-512/768/1024 decapsulation under Memcheck, marking only each genuine secret
  and hard-gating zero against a positive synthetic planted-leak control. No fresh
  target-selected capture is claimed yet; the intervening `fips203` provider failed
  on both ISAs, while the former `libcrux` zero result and
  retired PQClean-HQC lane's 193/22,849 counts are historical corroboration, not a current-source
  gate. (b) An **executable demonstration**
  that a lean (X-Wing-shaped) combiner's MAL-BIND is *contingent on the component KEM's key
  serialization* (Schmieg expanded-dk), while ContextBound's is not. (c) **Two independent
  symbolic provers** (Tamarin, ProVerif) on the handshake, plus the EasyCrypt computational proof
  — configured as fail-closed CI gates; current local execution and a fresh remote run must be
  reported separately. *(`ctstats/`, `crates/q-periapt-backends/tests/binding_keyformat_separation.rs`,
  `formal/{tamarin,proverif}`.)*
- **C4 — Production-library research integration + real-link evaluation.** A rustls TLS 1.3
  `CryptoProvider` runs the combiner under private-use `0xFE01`/`0xFE02` groups (the
  handshake passes). Its Compat client expands the stable 32-byte seed exactly once
  per in-flight handshake, retains the 2,400-byte expanded key in a non-Clone
  zeroizing prepared owner, and reuses that owner for completion; there is no global
  secret-key cache or C-ABI prepared-key surface. Historical predecessor-source
  `tc netem` data remains supporting evidence only. This is
  not the RFC 10024 `0x11EC` group or independent standards-interoperability evidence.
  *(`crates/q-periapt-rustls`.)*
- **C5 — Policy-to-byte fail closure.** A domain-separated signed policy with persisted
  `(version,digest)` state resolves to one private-field `ResolvedSuite`; fixed L3 faces reject L5
  documents, and decision-controlled ContextBound APIs commit the policy digest plus application
  context. The native ABI 2 product surface exposes no raw hybrid, deterministic key-generation,
  X-Wing, or combine operation; its 40-byte decision descriptor and WASM's raw/conformance APIs
  remain forgeable trusted-caller values, not authorization capabilities, and are outside this
  claim. Its first dynamically allocated Rust-owned policy-bound-context copy has one
  RAII owner that reserves before writing and wipes on normal return, error, or unwind;
  caller/marshalling copies, registers, paging, and abort remain outside that local
  guarantee. A hostile
  local caller requires an external service/process that owns the pinned verification key and
  monotonic state.

---

## 4. §"What the artifact contributes and does NOT claim" (WRITE THIS SUBSECTION; it is the R2-survival piece)

> Place this near the end of §1 (or as §2.x). Disarming the novelty attack by stating the
> boundary yourself is what survived-the-appeal papers do.

**Artifact-specific contributions (non-exhaustive positioning):**
- The **conjunction** C1∧C2: an assumption-minimal, machine-checked binding model tied by
  conformance — not formal refinement — to pinned outputs across the deterministic substrate cells
  and to fail-closed semantics across the native product cells. The
  paper positions this evidence conjunction against the cited prior work; it does not claim a
  verified compiler or exhaustive proof-to-binary equivalence.
- The **self-validating source→binary CT discriminator** as a reusable, CI-gated assurance
  artifact (real ML-KEM zero versus a synthetic planted leak in one framework, with an
  additional embedded-public-key control inside the *real* library).
- The **operationalized design invariant** "bind ct/pk in the KDF ⇒ hybrid MAL-BIND is robust to
  the component KEM's key-serialization format," enforced by the default-false
  `COMPAT_XWING_SAFE` backend/key-format capability (strictly stronger than recording primitive
  C2PRI) and demonstrated executably.

**What is NOT novel — state plainly and cite (do NOT claim these as results):**
- That a *hash-everything* combiner is binding from CR alone while a *lean* combiner inherits the
  omitted component's binding — this is **Güneysu–Hövelmanns–Pietrzak / Chempat (eprint 2025/1416)**;
  **ContextBound is the Chempat hash-everything construction, not a new primitive.**
- That ML-KEM in the FIPS-203 *expanded* dk format is neither MAL-BIND-K-CT nor MAL-BIND-K-PK, and
  that the *seed* format fixes it — this is **Schmieg (eprint 2024/523)**.
- The MAL-BIND-K-{CT,PK} notion lattice and monotonicity — **Cremers, Dax, Medinger (CCS 2024)**.
- That CT analysis must mark only secret sub-fields (not the public key embedded in dk) — this is
  **standard CT-harness practice (KyberSlash, TCHES 2025, §7.1.2)**. The predecessor
  `libcrux` implementation separately used `libcrux-secrets`/hax typed
  secret-independence; that assurance does not transfer to `mlkem-native`. The historical
  "5696→0" Memcheck contrast is provenance, not a current-backend finding.
- That context commitment is desirable is related to **Bellare–Hoang context-committing AEAD
  (CMT-3)**. Our K-CTX game is nevertheless a self-defined syntactic extension for a
  context-parameterized KEM: CTX is an input, not a CDM transcript output, so it is outside the
  published CDM lattice and does not inherit CDM monotonicity. The novelty claim is its
  mechanization/integration, not the desirability of binding context bytes.

**Honesty boundaries to never cross (a reviewer will check):**
- **Do NOT** claim "stronger binding than X-Wing." On the standard {K,PK,CT} lattice, correctly-
  implemented **seed-dk X-Wing attains MAL-BIND-K-{CT,PK}**; our key-format demo is about
  *combiner robustness to the component dk format*, **not** a break of X-Wing.
- **The EasyCrypt artifact implements the full CDM Figure 6 game for the standard CT/PK axes**
  (both implicit and explicit rejection; the `K≠⊥` conjunct is present and verified load-bearing).
  The K-CTX theorem reuses that rejection skeleton after an explicit syntactic change to a
  context-parameterized KEM; it is not a literal CDM lattice instantiation. Scope both honestly:
  they are over
  **abstract Decaps** (zero KEM assumption — holds for any Decaps — but therefore **no FIPS-203
  linkage**, and the shared-secret fields are **inert** in the binding argument, which flows
  through the absorbed ct/pk/ctx). CR(SHA3) is a modeling assumption; IND-CCA2 robustness is on
  paper; there is **no spec↔implementation linkage**. So claim *"machine-checked standard CDM
  MAL-BIND-K-{CT,PK}, plus a self-defined K-CTX syntactic extension, over abstract Decaps,
  reducing to CR(SHA3)"* — do NOT imply it proves a
  property *about ML-KEM's* decapsulation, or that CR(SHA3) / IND-CCA2 / impl-linkage are results.
- **Do NOT** claim a live exploited exposure in any deployed stack — the ecosystem has converged
  on seed-dk; the key-format hazard is a *latent design coupling we surface*, not a CVE.
- **Do NOT** claim any X-BIND-CT-* notion (structurally unachievable for implicitly-rejecting KEMs).
- **Do NOT** claim a ContextBound-over-X-Wing speed edge or overall parity:
  ContextBound hashes more bytes than X-Wing. The matched Mac core gate accepts only
  a controlled current-source raw-schema-v5/proof-schema-v8 proof under budget
  schema v10. Its profile estimand is non-regression with strict ContextBound fixed
  inputs and CompatXWing canonical `[]`/`0`/`[]`, while its distinct same-process
  ABBA/BAAB implementation estimand uses one generated `expanded_fips203_2400`
  keypair as the common input to O3/codegen-matched native/portable ContextBound
  `hybrid_core` encapsulation and decapsulation, requiring byte-equivalent per-case
  outputs with p50/p95 upper ratios at most
  0.95 and p99 at most 1.0. It excludes FFI and OS RNG. The proof binds the final binary, evidence-only portable
  archive/source, rustup toolchain and target, and macOS SDK identity, plus Cargo,
  Rustc, Xcode Clang, and Xcode `ar` executable paths and hashes. The producer uses
  a configuration-rejecting fresh-target build, but still trusts the mutable Cargo
  registry/Rust sysroot/OS and collector. Each estimand/operation is warmed
  independently immediately before its collection under the raw/budget contract.
  iPad/iPhone energy, clean baseline history, rustls end-to-end, and optimized production
  comparison remain pending.

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
  `bind_le_cr`; standard KEM-aware CDM games `malbind_kct/kpk_le_cr`; and a separate
  KEM-aware local-wrapper game `malbind_kctx_le_cr` (MAL adversary supplies keypairs, K derived
  via abstract total Decaps + combiner, each reduces to CR(H)). Seven hint-deletion checks are
  **proof-dependency regression controls**, not logical
  necessity proofs. Only explicit checked countermodels support semantic necessity; in particular,
  `kctx_without_nonbottom_broken` gives the probability-one witness for omitting `K != bottom`.
- **Honest scope box** (lift from §4 boundaries): implicit-rejection specialization; abstract
  Decaps means zero additional component-KEM binding/injectivity assumptions inside the reduction,
  not zero cryptographic assumptions and not FIPS-203 linkage; CR(SHA3) is assumed.

### §4 Proof-to-byte cross-substrate realization (C2)  ← the Apple-only answer
- The single-core / multi-face architecture (`docs/ARCHITECTURE.md`).
- The **six-method verification matrix** (Table): fixed KATs (current CFRG
  concrete-hybrid-kems-04 Appendix B.2 MLKEM768-X25519 vector (stored as the
  repository vector-0 fixture), three historical X-Wing
  draft-10 vectors, and RFC 7748) · NIST ACVP
  (full FIPS family: ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA) · independent multi-backend
  differential (RustCrypto ml-kem/ml-dsa, orion X25519) · EasyCrypt proof · cross-platform
  byte-identity · generative property tests.
- The substrate matrix (Table): deterministic conformance and native product-workflow cells across
  the reported OS/ISA targets, with **per-cell honesty** (what is
  verified locally vs. in CI; Windows-MSVC evidence is historical; binary-CT tooling targets
  x86-64/aarch64, but the target-selected backend needs fresh x86_64-portable and
  aarch64-native release-source captures;
  riscv64/wasm32 have no current binary-CT or inherited source-CT claim). Reproducible build
  attestations remain pending. The artifact now also
  has a separate Apple physical-device proof lane capable of source/artifact-bound iPad+iPhone
  evidence. A clean schema-3 matrix passed on distinct physical devices for predecessor source,
  but the backend migration made it historical; both lanes must be rerun and validated from the
  results manifest. The Android ART runtime harness is also separate from package proof and requires
  a current clean rerun before a release claim.

### §5 CI-gated assurance against the failure classes (C3)
- **Binary-CT source→binary gap probe** (`ctstats/ct_decaps_gap`): marks only each
  parameter set's ŝ+z and runs real target-selected `mlkem-native` decapsulation under
  Memcheck, with a planted-leak positive control;
  embedded-public-key and whole-dk observations are diagnostic because an expanded dk embeds
  public `ek` and `H(ek)`. The former `libcrux` aarch64 zero/`ek`-5696 capture is historical
  and does not transfer. `fips203` 0.4.3 then failed with 34,306 errors / 100 contexts
  on x86-64 and 30,464 / 70 on aarch64 in
  [CI run 29230650107](https://github.com/billlza/q-periapt/actions/runs/29230650107);
  those are historical failure counts, not current-provider evidence. Pre-selection
  portable `mlkem-native` captures are historical too. Fresh x86_64-portable and
  aarch64-native release-source passes are pending. The old
  `ct_hqc_gap` result (193 on
  aarch64; 22,849 on x86-64) is retained only as historical evidence from the removed
  PQClean-HQC graph, not as a current CI/release result.
- **Binding key-format coupling demo** (`binding_keyformat_separation.rs`): target-selected release-graph `mlkem-native`; lean
  X-Wing-shaped combiner over expanded-dk loses MAL-BIND-K-PK (Schmieg z-substitution), ContextBound
  does not. Framed strictly as combiner robustness (see §4 boundary).
- **Multi-prover symbolic** (Tamarin: 5 lemmas; ProVerif: 6 exact queries): authenticated context
  agreement plus hybrid handshake robustness (key survives break of EITHER component); lemma/query
  presence and full prover execution are hard-gated in CI, alongside
  the EasyCrypt computational proof — a **containerized pinned-source hard gate**: the
  base-image digest and EasyCrypt source revision are pinned, and `formal/Dockerfile`
  re-checks `BindingViaCR.ec` + proof-dependency controls on every run. The apt/opam
  solver and transitive graph remain floating, so this is not a bit-reproducible or
  hermetic toolchain. Explicit countermodels, not tactic failures, carry necessity claims.

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
  **Historical interpretation only:** on this VM capture the fixed local cost was visible at RTT 0
  and the 20/50 ms cells were dominated by link/runtime noise; the extra bytes fit existing flights
  without another round-trip. The ContextBound/CompatXWing ordering was not stable enough here for a
  parity claim. The later bare-metal capture is also predecessor-source supporting data, not
  current release evidence. The matched Mac core gate records live canonical-source-input
  freshness in the machine-readable manifest. The separate local dirty native/portable
  diagnostic indicated material improvement but lacks a checked-in raw and analysis
  bundle bound to the source and toolchain and is not formal release evidence. A fresh
  target-selected capture, iPad/iPhone energy, and optimized/end-to-end
  baselines remain pending.
- Optional: ML-DSA-dominated wire-budget table (L3 5758 B vs L5 7940 B) from the demo `p99_bench`.

### §7 Related work
- KEM binding: Cremers–Dax–Medinger (CCS'24); Schmieg 2024/523; Chempat / GHP 2025/1416;
  Bellare–Hoang context-committing AEAD; eprint 2026/140 (public contexts in hybrid KEMs — cite
  precisely: it analyzes *when* public context is necessary/redundant, it does NOT define a
  key-binds-context KEM game).
- Side-channel: KyberSlash (TCHES'25); ctgrind/TIMECOP/dudect; the predecessor
  `libcrux`/HACL* + `libcrux-secrets`/hax assurance as historical related work,
  not an inherited property of `mlkem-native`.
- Hybrids in deployment: the MLKEM768-X25519 construction in CFRG
  `draft-irtf-cfrg-concrete-hybrid-kems-04` (identical to X-Wing and still not an
  RFC), with draft-10 retained only as historical KAT provenance; TLS
  X25519MLKEM768; Signal PQXDH **plus its 2025 SPQR/ML-KEM-Braid Triple Ratchet**;
  Sesame multi-device session management; Apple PQ3. Do not repeat the obsolete
  comparison that Signal has only initial PQ protection.
- IRTF hybrid-kems draft-12 already defines all-field `UniversalCombiner` input and
  is in CFRG RG Last Call. Its §6.4.2 calls the LEAK-BIND arguments informal sketches,
  defers rigorous proofs, and does not prove the potential common-seed MAL strengthening.
  Position Q-Periapt on machine-checked, field-resolved standard MAL-BIND-K-CT/K-PK
  reductions plus a separately scoped local K-CTX wrapper reduction, countermodels, and
  realization evidence—never on inventing the field list.
- Stateful implementation assurance: Signal reports ProVerif state-machine modeling
  plus hax/F* checks of core Rust pre/postconditions and panic freedom in CI. This is
  directly relevant prior art for the paper's honest “no spec↔impl linkage” boundary;
  proof-to-byte is provenance/conformance evidence, not a stronger refinement result.
- Evidence-verifier hardening: describe strict bounded JSON/auxiliary snapshots, same-byte
  hash/semantic verification, hostile-Git-environment/index-flag/actual-byte controls,
  ignore-independent untracked-input inventory, isolated source-only Python startup with
  repository bytecode rejection, recomputed device commitments, fixed iPad+iPhone matrix policy, and the canonical
  performance budget and path/hash/schema/source/pass summary. Preserve the boundary that the
  required domain verifier must still load the actual proof and artifacts, and that this closes
  verifier consistency attacks but does not make a dirty manifest immutable, prove model-to-code
  refinement, or attest a hostile builder.
- Formal PQ verification: formosa-mlkem (ML-KEM IND-CCA); SandboxAQ EasyCrypt-KEMs (LEAK-BIND-K-PK).

### §8 Limitations & honest scope (do not bury — TDSC rewards candor)
- EasyCrypt: full CDM Figure 6 for standard CT/PK (both rejection styles), plus the separately
  labeled K-CTX syntactic extension using the same rejection skeleton, but over **abstract
  Decaps** — no FIPS-203 linkage, ss fields inert in the binding argument (proves nothing *about*
  ML-KEM's decaps); CR(SHA3) assumed; IND-CCA2 on paper; no spec↔impl linkage.
- Binary-CT: only x86-64 + aarch64 have configured tooling, and the target-selected
  `mlkem-native` paths still need fresh x86_64-portable and aarch64-native
  release-source captures;
  the superseded `fips203` run is historical failure evidence; riscv64/wasm32 have no
  current binary-CT or inherited source-CT claim.
- Conformance ≠ certification (ACVP byte-identity is not CMVP).
- No independent third-party audit; research-grade, do-not-deploy.
- Upstream HOL-Light evidence is scoped to the selected upstream AArch64 assembly
  source/object routines. It is not a proof of downstream reassembly, the Rust/C
  integration, the full ABI, or the final package.
- The rustls `SupportedKxGroup` path has a fixed protocol-domain label, not per-session K-CTX. Its
  `provider_with_policy` API consumes an already parsed, unauthenticated `Policy`, supports both
  resolved profiles, and is excluded from the signed-policy authenticity/digest claim.
- The native ABI 2 decision descriptor and WASM decision/raw-conformance inputs are forgeable
  trusted-caller values; the native ABI exports no raw crypto bypass, but decision APIs still only
  reduce accidental mixing and do not authorize hostile same-process code. An opaque
  in-process handle is also insufficient; a trusted service/process must own the key and state.
- A clean-tree schema-3 matrix passed on one physical iPad and one distinct physical
  iPhone for predecessor source; the target-selection migration made it stale. The manifest-bound
  verifier, not this prose, determines currentness. The matched-backend Mac gate accepts
  only controlled canonical-source-input proofs, but a fresh target-selected proof,
  device energy, rustls end-to-end, clean baseline history, and optimized-production
  parity remain unproved.
- CI: the repo's gates are *configured*; report which have actually executed (note the no-remote
  history honestly, now that it is public on GitHub).
- Distribution: three stable lines have published as immutable GitHub releases with
  `prerelease=false` — `v0.1.3`/`abi2-platforms-v0.1.3` (2026-08-25) and
  `v0.1.4`/`abi2-platforms-v0.1.4` (2026-08-30), and
  `v0.1.5`/`abi2-platforms-v0.1.5` (2026-09-05) — alongside the earlier immutable
  GitHub *research prereleases* (Apple XCFramework r1; Android/Linux/Windows platform
  packages r2, Windows unsigned experimental). The ten `0.1.3` crates and the ten
  `0.1.4` crates are published on crates.io. All ten `0.1.5` crates are published
  and independently verified; `v0.1.5-verified-cohort` records their complete cohort. No Maven/deb/rpm/MSIX registry publication, Authenticode,
  physical-Android coverage, or store distribution is claimed for any line; do not let
  the artifact paragraph imply otherwise, and do not let the published 0.1.3/0.1.4
  crate sets stand in as evidence for `0.1.5`.
- The artifact is not an asynchronous messaging protocol: no identity directory,
  prekeys, ongoing ratchet, multi-device state, recovery, or key transparency. Apple
  PQ3 and Signal's public PQXDH/SPQR/Triple-Ratchet components plus Sesame manager remain ahead on
  lifecycle and deployment. Separately, a `publish = false` Continuity research model
  now explores canonical typed lifecycle-context admission, a strict model-only
  two-leg prekey-selection record, exact version-and-digest repository advances, and
  no-op-anchor rejection, but deliberately has no context-advance API or credential/
  manifest/prekey service, production wire, ratchet, provider-
  policy authorization, real adapter, or implementation refinement. It is future
  research evidence and not a claim of this KEM paper.

### §9 Conclusion
- Restate the spine: trust a hybrid's safety only as much as its weakest realization; we narrow and
  make that gap auditable with a machine-checked, cross-substrate, CI-gated assurance discipline + an assumption-minimal
  combiner. The evaluated artifact-specific contribution is the *conjunction*, not an exhaustive
  priority claim about any single fact.
- Name Q-Periapt Continuity only as a separate future research line: first reproduce
  the current public session components and specify their manager integration, then
  test authenticated policy/context, prekey-accountability, crash/rollback,
  schedule-relative healing debt, native Apple PQ providers, metadata privacy, and
  proof-to-state-to-byte hypotheses under physical-device wire/latency/energy budgets.

---

## 6. Claims ↔ evidence ↔ artifact (build the camera-ready table from this)

| # | Claim (as stated) | Evidence / artifact | Verified |
|---|---|---|---|
| C1a | Standard MAL-BIND-K-{CT,PK} ≤ CR(SHA3); encode_inj proved; **full CDM Figure 6** game (implicit + explicit rejection), over abstract Decaps | `formal/easycrypt/BindingViaCR.ec` (`malbind_kct_*`, `malbind_kpk_*`); explicit `K != bottom` countermodel; proof-dependency controls | Machine-checked; no spec↔Rust refinement |
| C1b | Self-defined context-parameterized K-CTX syntactic extension ≤ CR(SHA3); not a CDM lattice node or monotonicity corollary | `formal/easycrypt/BindingViaCR.ec` (`malbind_kctx_*`, `omit_ctx_kctx_broken`); Tamarin/ProVerif authenticated-context models | Machine-checked at hash/game level; protocol meaning depends on authenticated context and trusted host |
| C2a | 6-method conformance | KATs/ACVP/differential/proof/cross-platform/proptests in `crates/q-periapt-backends/*` | Harnesses present; report current-source live results separately, because predecessor runs are historical |
| C2b | byte-identical in reported deterministic conformance cells plus semantic invariants in native product cells; four ISA executions + one cross-build | shared-vector Rust/WASM tests; exact-nine dynamic `q_periapt_*` C ABI contract (static archives constrain that public namespace but retain unsupported hidden bridge symbols); `artifact/embedding-readiness.sh`; separate device harnesses; release receipts in `artifact/results.json` | ABI2 surface implemented; static embedding is a trusted same-process boundary. Existing prerelease receipts cover their exact historical portable-derived Apple/Android/Linux/Windows artifacts, not the current target-selected source. Fresh target-specific package/device/performance/CT evidence and a verified publication transaction remain pending. |
| C3a | source→binary CT: target-selected `mlkem-native` ML-KEM-512/768/1024 zero / synthetic-positive discriminator | `ctstats/ct_decaps_gap`; `ct-gap-probe.sh`; historical `camera-ready-results.txt` | Gate migrated; `fips203`, former `libcrux`, PQClean-HQC, and pre-selection portable rows are historical, and fresh x86_64-portable/aarch64-native capture is pending |
| C3b | lean-combiner MAL-BIND-K-PK contingent on dk format | `binding_keyformat_separation.rs` (target-selected release-graph `mlkem-native`) | Adapter migrated; report the live current-source result separately; predecessor commit result is historical |
| C3c | Tamarin 5 lemmas + ProVerif 6 exact queries + EasyCrypt computational proof | `formal/{tamarin,proverif,easycrypt}` | Proof artifacts present; report fresh local and remote execution separately |
| C4a | rustls TLS 1.3 handshake over the combiner; Compat prepares one process-local key owner per in-flight handshake | `crates/q-periapt-rustls/tests/handshake.rs` plus exact-once preparation and concurrent-owner tests | Implemented; stable private bytes remain the 32-byte seed, each active Compat owner holds 2,400 secret bytes, and no global secret-key cache or C-ABI prepared-key surface is claimed |
| C4b | historical netem measurements and repaired benchmark harness | `crates/q-periapt-rustls/examples/netem_bench.rs`, `paper/camera-ready-results.txt` | Supporting host data only; optimized-baseline/device parity pending |
| C5 | signed policy → closed decision → policy/application-context bytes | `q-periapt-policy`, decision-controlled native/WASM tests | Native ABI2 raw crypto bypass removed; decision descriptor and WASM raw surface remain trusted-caller inputs |

---

## 7. Acceptance risk & mitigations (from the vetting synthesis)

- **Biggest risk: "thin core / known consequence."** Mitigate by (a) making the spine carry the
  weight (the C1∧C2 conjunction demonstrated by this artifact, without asserting exhaustive
  priority), (b) the source→binary gap probe as
  the one hard technical artifact (done), (c) the explicit §4 "what is/is not novel" pre-emption.
- **R2-misunderstanding risk (the prior trauma).** Mitigate with the claims table, the reproducible
  artifact (open-source, CI-gated, with the demos), and ruthless scope discipline in every claim.
- **Format desk-reject risk.** Use the TDSC template from line one; figures + tables early.

---

## 8. Open author decisions
- ~~Title choice~~ — **LOCKED** (§1, "Proof-to-Byte…").
- ~~Faithful explicit-rejection EasyCrypt encoding~~ — **DONE** (full CDM Figure 6 for CT/PK and
  the separately labeled K-CTX rejection skeleton mechanized in `malbind_*_xrej_le_cr`, commit
  65f4328).
- ~~Add local netem baselines~~ — **historical supporting data present** for classical X25519,
  IANA `X25519MLKEM768`, CompatXWing, and ContextBound.
- ~~Add matched backend/input Mac p50/p95/p99 budget~~ — **DONE as a gate; the
  quantitative claim is published only while `artifact/results.json` selects a
  fresh controlled proof.** Raw schema v5 carries two separately named
  estimands in one same-process ABBA/BAAB slot: profile non-regression and
  output-equivalent native/portable ContextBound implementation improvement.
  Its nested `profile_inputs` fixes the distinct canonical metadata inputs for both
  profiles. The implementation estimand feeds one generated
  `expanded_fips203_2400` keypair, coins, and corpus to O3/codegen-matched native and
  portable `hybrid_core` encap/decap paths, excluding FFI and OS RNG. Proof schema v8
  and budget schema v10 retain 1,024-pair primary estimate
  blocks,
  at least 10 nearest-rank p99 tail observations per block, the former 256-pair
  profile regression guard, and separately parameterized 5% CV stability windows.
  They additionally bind the SDK/toolchain, final harness binary, portable archive,
  and source identity. The
  remaining decision is iPad+iPhone energy coverage plus rustls/optimized-production end-to-end
  comparison.
