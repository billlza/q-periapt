# Q-Periapt — PQ/T Hybrid Cryptographic Suite

[![CI](https://github.com/billlza/q-periapt/actions/workflows/ci.yml/badge.svg)](https://github.com/billlza/q-periapt/actions/workflows/ci.yml)

> [!WARNING]
> **Status: pre-1.0 research / doctoral-thesis project (v0.1.0-alpha.1, unpublished ABI 2 candidate). NOT audited,
> NOT FIPS-validated — do not use in production yet.** Production-relevant reviewed
> upstream implementations are wired for ML-KEM / ML-DSA / SHA3 via libcrux,
> X25519 via x25519-dalek, and optional SLH-DSA via fips205. The former
> `pqcrypto-hqc`/PQClean adapter has been removed from the publishable dependency and
> runtime-suite graph. A separate `publish = false`
> [`research/hqc-fips207-candidate`](research/hqc-fips207-candidate/) shadow lane evaluates
> RustCrypto `hqc-kem 0.1.0-rc.0` against the HQC v5 / prospective FIPS-207 draft
> candidate. The crate describes itself as tracking an IPD, but as of 2026-07-12 the
> official FIPS 207 IPD is not publicly retrievable and NIST still says it is coming soon;
> it is not ABI 2, not a production backend, and has no suite code. The X-Wing
> construction-conformance KAT passes byte-for-byte against the official draft
> vectors, and the combiner
> binding theorem is machine-checked in EasyCrypt — but the suite has had no
> third-party audit. See [Status & disclaimer](#status--disclaimer).

**Q-Periapt** — *Q for Quantum; a periapt is an amulet worn to ward off danger* —
is a portable, `no_std` post-quantum / traditional (PQ/T) hybrid cryptographic
suite, **built side-channel-aware from the start** (with the caveats below: the
failure-path indistinguishability check is a hard CI gate; empirical timing is a
local diagnostic and is not run or gated on noisy shared CI). The name is the design: a periapt
shields its bearer from a fatal blow (in the spirit of the Chinese 玉佩, a jade
pendant said to shatter to protect its wearer). The hybrid design targets secrecy
when at least one component assumption holds; the symbolic protocol models verify
that property under their stated abstractions. Separately, EasyCrypt machine-checks
the standard K-CT/K-PK combiner claims and a self-defined context-parameterized
K-CTX syntactic extension under its collision-resistance model. K-CTX is not a node
in the published CDM lattice, and hashing context bytes does not authenticate their
protocol meaning. Binding and hybrid IND-CCA/robustness are distinct claims; neither is used as
a shortcut proof of the other. The suite is built around one dependency-free Rust core
(crate namespace `q-periapt-*`) that third-party primitive backends are injected into
through traits, and that is reused unchanged across C, WASM, Swift and Kotlin. The
honest pitch is narrow and deliberate: this project does **not** try to beat
ML-KEM/ML-DSA on speed, and it does **not** beat X-Wing's combiner on cycles —
adding more transcript binding than X-Wing means strictly *more* hashing, i.e. a
*slower* combiner, never a faster one. What it aims to do better than the
mainstream is the part that is actually hard in the field: safe *composition*, a
side-channel CI pipeline that re-checks the property the compiler can break,
policy-driven crypto-agility with assumption diversity (a structural capability
X-Wing's single fixed construction does not have), audit transparency, and P99
*transport* measurement done on the constraint that actually binds (bytes and
packets, not encap/decap cycles).

## Honest positioning

ML-KEM-768 is the **same standardized primitive family** used by X-Wing and the
TLS `X25519MLKEM768` group. Apple PQ3 is a protocol-level baseline, not the same
construction: it uses Kyber-1024 for initial establishment and Kyber-768 for its
ongoing PQ ratchet. Signal's current public baseline is likewise no longer PQXDH
alone: its 2025 Double Ratchet revision adds SPQR/ML-KEM Braid and a Triple Ratchet
for ongoing hybrid FS/PCS. Sesame is the separate generic multi-device manager model;
composition with the newer components is an integration claim, not one published stack spec.
Q-Periapt currently implements none of those stateful lifecycle layers. You get no
security or raw-speed edge on the primitive itself.

The current IRTF hybrid-KEM draft-12 already specifies a `UniversalCombiner` over
both secrets, ciphertexts, public keys, and a label, so that field list is not our
novelty. Its Section 6.4.2 explicitly presents informal LEAK-BIND sketches, defers
rigorous proofs, and does not prove the potential common-seed MAL strengthening. The
narrow defensible research delta is Q-Periapt's machine-checked, field-resolved standard
MAL-BIND-K-CT/K-PK reductions, a separately scoped local K-CTX wrapper reduction,
executable countermodels, and realization evidence—not “hash everything.”
Because of that, the suite ships **two combiner profiles**
selected by policy, and is explicit about the trade between them:

| Profile | What it binds | Cost | When |
|---|---|---|---|
| **`CompatXWing`** | `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label` (X-Wing draft-10 layout) | the same one-block combiner shape; byte equality is KAT-checked | X-Wing-compatible construction/control profile; only admitted for a backend whose exposed key format is X-Wing-safe (today: the ML-KEM-768 seed-dk backend). External endpoint/HPKE interoperability is not yet an artifact claim. |
| **`ContextBound`** | domain tag + length-prefixed *every* shared secret, ciphertext, public key, **and** an external context (transcript / suite / policy version) | strictly **slower** (more SHA3 input → more Keccak blocks); a deliberate robustness trade, **not** a speed win | default profile; expanded/imported keys, backends without a mapped C2PRI/API proof, or when maximal binding / downgrade resistance is required |

The library core keeps both profiles for comparison and KAT research. The unpublished
ABI 2 product boundary deliberately exposes only `ContextBound`: its nine-symbol C
surface requires a signed-policy decision, obtains key-generation and encapsulation
randomness from the operating system, and does not export raw hybrid, deterministic
seed/coins, X-Wing, or combiner entry points.

The `CompatXWing` profile can omit the ML-KEM ciphertext **only** because
ML-KEM-768 is C2PRI (ciphertext-second-preimage-resistant via the FO transform and
implicit rejection) **and** because X-Wing's seed-derived key format preserves that
self-binding precondition. Primitive C2PRI is necessary but not sufficient: an
expanded/imported-key backend can be C2PRI while still unsafe for the lean
X-Wing-shaped API, so `CompatXWing` requires both `Kem::C2PRI` and
`Kem::COMPAT_XWING_SAFE`. Raw expanded ML-KEM must use `ContextBound`; X25519 is
valid in X-Wing's absorbed traditional slot but is rejected
if placed in the omitted first slot. `ContextBound` hashes all fields directly. The
hashing delta between the two profiles is real and directional but is a *small*
fraction of total encap/decap — encap/decap is dominated by the component-KEM work,
not the combiner hash. This is **measured**, not asserted. The historical
Criterion harness remains useful for primitive scale, while
[`paired_profile_perf.rs`](crates/q-periapt-backends/examples/paired_profile_perf.rs)
now gives both profiles the same ML-KEM-768 seed-dk backend, X25519 backend, keys,
coins, ciphertext corpus, suite/version/context inputs, and ABBA/BAAB order. The
fail-closed [`performance_gate.py`](artifact/performance_gate.py) requires 20,480
paired samples per operation/profile, fixed 256/1/2-call timing batches, balanced
time blocks, a stable host, and the published
[`performance-budgets.json`](artifact/performance-budgets.json). Controlled
Apple-Silicon runs are judged against one-sided 95% upper budgets: p50/p95/p99 ratios
of 1.10/1.15/1.20 and a 15 µs p95 absolute delta for encapsulation/decapsulation,
plus a 10 µs combiner p95 delta. A run counts as current only when its bound canonical
source digest equals the verifier's live digest; source drift and uncontrolled power
or thermal state fail closed. Release verification always loads the exact repository
`artifact/performance-budgets.json`; a proof cannot select an alternate policy path.
Budget schema v4 uses 1,024-pair primary percentile-estimate blocks, so nearest-rank
p99 is supported by 11 tail observations per block instead of only three. It also
recomputes the former 256-pair estimator as a regression guard and applies every
published numeric limit to both block scales; changing the primary estimator therefore
cannot turn a former-scale failure green. Separately parameterized 64/256/256-pair
stability windows retain the same 5% CV limit.
The same policy pins the Cargo/Rustc executable hashes, versions, and target. Collection
selects one same-directory matching pair, rejects repository/ancestor/user Cargo configuration,
clears caller compiler/wrapper/loader controls, fixes system-tool lookup, and builds offline in a
fresh private target before rechecking the two executables. The user-writable Cargo registry cache,
Rust sysroot/driver, OS tools/libraries, and same-UID replace-and-restore races remain trusted; this
is a strengthened local diagnostic, not a hermetic or hostile-builder attestation.
Within `combine`, the SHA3 staging backend marks the two component shared-secret bodies and the
conservatively sensitive caller-context body for volatile erasure, while preserving the exact
X-Wing/ContextBound byte stream. It erases both inline and heap copies, safely wipes
secret-bearing old allocations before replacement, and falls back to a whole-buffer wipe for
legacy/unclassified input or invalid range metadata. Allocation/invariant failure wipes live
staging before termination. This removes the large public ciphertext/key transcript from the
erase path without weakening the previous conservative contract; it is not a new cryptographic
or full-memory-erasure claim. TLS key confirmation independently labels its own secret inputs.
Exact run values and the current freshness state live
in the proof and
[`artifact/results.json`](artifact/results.json), rather than being copied into this
source file. A passing result is a matched-backend single-host
non-regression result, not cross-device, energy, rustls end-to-end, or optimized
production-X-Wing parity. We never claim a combiner speed win.

### Where this can plausibly win

- **Crypto-agility + assumption diversity** — the single most defensible claim.
  A strictly parsed signed policy is authenticated, checked against persisted
  `(version, digest)` state, and resolved into one closed `ResolvedSuite`
  (suite + profile + key format + non-zero policy version). The **library**
  instantiates ML-KEM-768/1024 + X25519. Wire/suite code `3`, formerly assigned to
  the retired PQClean-HQC experiment, is a permanent fail-closed tombstone and is
  not reassigned. The HQC-v5/FIPS-207-draft shadow lane has no runtime suite or ABI identity.
  Runtime faces remain deliberately narrower: **rustls** accepts only its exact
  ML-KEM-768 + X25519/version-1 group, while the fixed **C ABI 2** product path
  accepts only a compatible ContextBound decision and rejects an L5 policy rather
  than binding false agility metadata. Raw/deterministic conformance remains private
  Rust test code and is absent from the product export allowlist. The 40-byte decision
  is still a trusted-local descriptor, not an unforgeable capability: the host must
  pin the policy verification key and isolate untrusted native code.
- **One auditable codebase across platforms** — a single Rust core means one
  CT-verified, one fuzzed, one differential-tested implementation under C / WASM /
  Swift / Kotlin, reducing audit and implementation-bug surface. (Note: ML-KEM and
  X25519 are deterministic standardized primitives, so *any* conformant
  implementation interops across platforms — the win here is reduced audit
  surface, **not** a unique cross-platform interop capability.)
- **Side-channel CI as an assurance feature** — the failure-path indistinguishability
  / implicit-rejection check **is a hard merge gate today**
  ([`ctstats/`](ctstats/README.md): an invalid ML-KEM-768 ciphertext decapsulates
  to a deterministic, success-shaped secret, with no error-code oracle). The
  empirical dudect-style Welch t-test is a **local diagnostic**, not a shared-CI
  step (shared runners are too noisy for a stable threshold), and
  binary-level constant-time re-verification (Valgrind/Memcheck-TIMECOP) — needed
  because source-level CT does not survive the compiler (clangover, KyberSlash) — is
  now a **hard CI gate** (`constant-time` job) over the suite's own CT composition
  code (`ct_eq`/`ct_select32`/the combiner). The same x86_64+aarch64 job also runs a
  self-validating libcrux ML-KEM decapsulation gap probe with the corrected
  ŝ `[0..1152]` + z `[2368..2400]` marking and requires zero reports. Other
  primitive paths and riscv64/wasm32 binary-CT remain **TODO**. See
  [`ctstats/README.md`](ctstats/README.md) for the honest per-cell scope.
- **Audit transparency** — a machine-checked combiner binding model is **done**
  ([`formal/easycrypt/BindingViaCR.ec`](formal/easycrypt/BindingViaCR.ec),
  CI-gated against admits). CBOM (CycloneDX crypto-bill-of-materials) + SBOM +
  migration-inventory tooling are scaffolded (see status).
- **P99 transport measured on the right constraint** — the differentiator is the
  *methodology* (P99 handshake completion on emulated lossy / high-RTT links,
  where pure encap/decap microbenchmarks mis-rank designs), not the transport
  techniques themselves (IW10 budgeting, cert compression, resumption are standard
  TLS/QUIC engineering that mainstream stacks already do).

### Where it explicitly cannot win

- **Combiner CPU speed** — more binding is strictly more hashing. `CompatXWing`
  targets byte compatibility; historical combiner-only measurements are not a
  current production parity claim. `ContextBound` is intentionally slower.
- **Primitive performance** — it wires libcrux (ML-KEM / ML-DSA / SHA3),
  x25519-dalek, and fips205 (SLH-DSA). The isolated RustCrypto HQC candidate is a
  shadow comparison, not a product-graph primitive. There is
  no evidence of superiority over optimized AVX2 ML-KEM or FIPS-validated AWS-LC;
  those remain required baselines. This is a composition / safety layer, not a
  demonstrated faster primitive.
- **FIPS 140-3 validation out of the box** — the pure-Rust `no_std` core is **not**
  FIPS-validated. The trait-injected backend design leaves room for a FIPS path
  (e.g. an aws-lc-rs / AWS-LC backend) later, but no such backend is wired today
  and the project makes no validation claim of its own.
- **Wire-format / standards novelty** — it implements X-Wing (an Independent
  Submission draft, `draft-connolly-cfrg-xwing-kem`, *not* a CFRG WG item),
  while the local rustls groups remain private-use `0xFE01`/`0xFE02`. The IANA
  `X25519MLKEM768` group from `draft-ietf-tls-ecdhe-mlkem` (`0x11EC`, RFC number
  unassigned) is only an optional aws-lc benchmark baseline, not the local wire group.
  The separate HQC shadow tracks HQC v5 and a prospective, not-yet-public FIPS 207 draft.
  The project tracks standards; it does not set them, and an `-rc.0` implementation is
  not promoted into ABI 2.
- **A completed independent audit** — this suite has none, and source-level backend
  verification does not by itself establish compiled-binary side-channel safety.
  This project provides audit *enablers* (CBOM, CT-CI, formal model), not a finished
  external audit.

### Stateful protocol research is a separate lane

The future **Q-Periapt Continuity** work is intentionally separate from the current
KEM artifact and paper. Its reference lane will first model component-conformant PQXDH
bootstrap and Triple Ratchet/SPQR, wrapped by a separately specified Sesame-compatible
multi-device manager; the integrated composition and external interoperability need
their own traces. It will not insert `ContextBound` into published KDFs and still call
the result compatible. A distinct research lane will
then test authenticated policy/context continuity, verifiable prekey behavior,
active-PQ identity options, crash/rollback-safe state, measurable PQ-healing debt,
native CryptoKit/Secure Enclave PQ provider experiments, and proof-to-state-to-byte
evidence against that matched reference.

The candidate contribution is the **conjunction** of those properties under explicit
wire/latency/energy/healing budgets, not invention of prekeys, Merkle manifests,
chunking, receipts, or a triple ratchet. G1 has only partially started: exact public
reference revisions/reproducible content hashes and a `publish = false`, non-normative
effect/journal lifecycle model plus candidate canonical `LifecycleContextV1` and
strict `PrekeySelectionV1` bytes now exist. The model binds trusted role-ordered
account/device generations, suite/policy, independent classical/PQ prekey quality and
IDs, directory/roster, transcript and root epochs to exact model bytes;
repository CAS uses exact version+digest revisions and no-op per-transition anchors
fail before mutation. Lifecycle B21-B23 are derived from one selection record; callers
cannot supply an opaque digest alongside an unrelated mode/manifest tuple. Rust and
independent Python encoders/decoders agree on frozen full-byte vectors. Separate
non-normative EasyCrypt diagnostics prove injectivity for their modeled LP8 projections
and exhibit policy/direction plus named prekey-field omission collisions; this is not a protocol
proof, projection-completeness result, or Rust refinement.
It deliberately has no context-advance API. Mutable publisher pages are not archived.
This is not credential, manifest, prekey or directory authentication: trusted genesis,
legal stage evidence, unique leasing/consumption/tombstones, ratchet security and
session rejection semantics remain open.
Provider profile/epoch equality prevents only an in-flight swap; provider-policy
authorization, downgrade resistance, and epoch attestation also remain open. There
is still no real protocol, identity/prekey system, wire
bytes, ratchet, or session security claim. See
[`docs/CONTINUITY_RESEARCH.md`](docs/CONTINUITY_RESEARCH.md) and
[`docs/continuity/README.md`](docs/continuity/README.md).

## Feature matrix vs the target dimensions

Legend: ✅ implemented & exercised · 🟡 partial / scaffolded · ⛔ planned, not started.

| Dimension | Target | Today (v0.1.0-alpha.1 ABI 2 candidate) |
|---|---|---|
| Auditable `no_std` core | dependency-free combiner + traits, builds bare-metal | ✅ `q-periapt-core` (zero crypto deps; `#![deny(unsafe_code)]` with ONE documented shared secure-wipe block; builds `thumbv7em-none-eabihf`) |
| Hybrid KEM | ML-KEM-768 + X25519, with independently bounded algorithm-diversity research | ✅ ML-KEM-768 (libcrux) + X25519 (x25519-dalek) are wired; real hybrid encap/decap round-trips under `ContextBound` with expanded ML-KEM keys and under `CompatXWing` with the X-Wing seed-dk backend. The **enhanced** suite **ML-KEM-1024 + X25519** is instantiated end-to-end (real `HybridKem<MlKem1024,X25519>`, ACVP + differential + a pinned, independently cross-checked KAT) and is `ContextBound`-only. **ML-KEM-512** (L1) also has a verified backend, so the FIPS-203 family (512/768/1024) is ACVP + differential covered for agility. The old timing-leaky/unmaintained PQClean-HQC adapter and `hqc` feature are gone from the publishable graph; suite code `3` is tombstoned. RustCrypto `hqc-kem 0.1.0-rc.0` lives only in the `publish = false` HQC-v5/FIPS-207-draft shadow crate, with deterministic round-trip/size research tests but no product-suite, ABI, official-IPD-conformance, or final-standard claim. |
| Combiner profiles | `CompatXWing` (byte-compatible control) + `ContextBound` (binding) | ✅ both profiles implemented over a trait XOF and wired to a **real SHA3-256** (libcrux) backend; the matched-backend Mac gate enforces canonical-source-input and controlled-host freshness, while cross-device/end-to-end parity remains pending |
| Combiner safety guards | C2PRI + X-Wing-safe backend guards, 32-byte length checks, implicit rejection | ✅ `CompatXWing` hard-checks all four absorbed fields are exactly 32 bytes; `HybridKem::new` rejects the omitted first-slot backend unless both `Kem::C2PRI` and `Kem::COMPAT_XWING_SAFE` are true, with contradictory third-party declarations failing closed as `Error::PolicyDenied`; `ct_eq`/`ct_select32` provide the branch-free implicit-rejection primitive |
| Signatures | ML-DSA-44/65/87, SLH-DSA | ✅ the full FIPS-204 family **ML-DSA-44/65/87** (libcrux) wired & tested (NIST ACVP — incl. hedged / context / SHAKE-128 pre-hash modes — + RustCrypto differential each); ML-DSA-65 is the default, ML-DSA-87 the enhanced-mode (L5) signature; **SLH-DSA-SHA2-128s/192s/256s** (fips205) — with **NIST ACVP conformance** (`acvp_slhdsa.rs`) — behind the off-by-default `slh-dsa` feature |
| Crypto-agility / policy | signed policy, downgrade/equivocation state, atomic suite decision | ✅ `q-periapt-policy`: strict TOML loading (`Policy::from_toml`) + domain-separated signed-policy verification (`Policy::load_signed` / `load_signed_monotonic`); `(version, SHA3-256(exact bytes))` rollback/equivocation state; closed, private-field `ResolvedSuite` selected against concrete locally supported suites. Authentication, parsing, or resolution failure is returned as an error; there is no fallback-success API. |
| KATs / differential tests | X-Wing draft + FIPS 203 ACVP vectors, multi-backend differential | 🟡 byte-exact **X-Wing draft KAT PASSES** (3 official `draft-connolly-cfrg-xwing-kem` vectors); **multi-backend differential PASSES** over the whole KEM chain (`src/differential.rs`) — **ML-KEM-512/768/1024** vs RustCrypto `ml-kem`, X25519 vs `orion` + RFC 7748, and the full `HybridKem` reconstructed from independent ML-KEM + X25519 + SHA3; and **ML-DSA-44/65/87 vs RustCrypto `ml-dsa`** (byte-identical keygen + signatures, cross-verification both directions, tamper rejection) — all byte-identical on random inputs; **NIST ACVP** ground-truth conformance PASSES (`src/acvp.rs`) — the **full FIPS family**: ML-KEM-512/768/1024 (60 cases each, incl. implicit-rejection) + **ML-DSA-44/65/87** keygen/sig **across signature modes** — external/pure (deterministic + **hedged**, with **non-empty contexts**), **HashML-DSA SHAKE-128 pre-hash**, and the **internal interface** (FIPS 204 Alg. 7/8, `externalMu=false`, via the libcrux `acvp` feature) (`acvp_ml_dsa_*_signature_modes`); only `externalMu=true` (no μ-injection entry in libcrux) and non-SHAKE128 pre-hash (libcrux wires only SHAKE-128) remain out of scope; **SLH-DSA-SHA2-{128,192,256}s** (FIPS 205) also have NIST ACVP conformance under the `slh-dsa` feature (`acvp_slhdsa.rs` — deterministic keyGen via a seed-replay RNG, plus sigGen/sigVer); **property-based tests** (proptest, `src/proptests.rs`) hold the combiner + hybrid invariants — binding injectivity, determinism, domain separation, the guards, and KEM round-trip — over random inputs |
| Side-channel CI | indistinguishability gate + binary-CT matrix; dudect local diagnostic | 🟡 failure-path indistinguishability / implicit rejection is a **hard gate** (`ctstats/`); **dataflow constant-time** is a **hard gate** (`constant-time` job: `ct_verify` plus the self-validating libcrux ML-KEM decapsulation gap probe under Valgrind/Memcheck-TIMECOP). The corrected ŝ+z probe is required to report zero on x86_64 + aarch64; positive/negative controls make zero non-vacuous. Dudect timing is not run on shared CI and has no current gate; other primitive paths are not covered, and riscv64/wasm32 remain source-CT (see `docs/THREAT_MODEL.md` §5.2). |
| Cross-platform build | ISAs: x86_64 / aarch64 / riscv64gc / wasm32 / embedded · OSes: Linux / macOS / Windows | 🟡 CI `cross` builds the core/KEM across the declared ISA targets and `no_std` builds `thumbv7em-none-eabihf`. Linux and macOS lanes are current. A 2026-06 Windows run covered the then-current core/workspace and historical `slh-dsa,hqc` vectors, but that retired-HQC result is not current release-graph evidence and predates ABI2 packaging; current `q_periapt_ffi_abi2.dll`, import-library, and PE-export evidence remain pending. |
| FFI / bindings | C ABI + Swift + Kotlin/JVM + Android AAR/JNI + WASM | 🟡 the unpublished **ABI 2** native product surface is reduced to nine exact C exports: metadata (5), signed-policy decision, OS-CSPRNG atomic key generation, OS-CSPRNG encapsulation, and decapsulation. The macOS C archive, five-slice Apple XCFramework, four-ABI Android AAR, and schema-2 diagnostic release index pass isolated-consumer and semantic validation on their recorded sources. Android JNI consumes rather than duplicates the contract. The selected clean-tree Apple schema-3 matrix covers one physical iPad and one distinct physical iPhone, and the selected matched-backend Mac proof passes the fixed non-regression budget; currentness is authoritative only through `artifact/results.json` plus the live domain verifiers. Neither result proves distribution signing, device energy, cross-platform performance, or parity with optimized production systems. Deterministic/X-Wing/combine checks remain internal Rust/WASM conformance evidence rather than a native product bypass. Kotlin requires JDK 22+; Android ART, Linux SONAME execution, and Windows PE packaging remain separate gates. Release remains blocked by the unsuppressed upstream `proc-macro-error2` maintenance advisory inherited through libcrux/hax, incomplete cross-platform runtime evidence, third-party audit, and public signing/attestation. |
| Transport / P99 | rustls X25519MLKEM768, HPKE, netem P99 harness | 🟡 `q-periapt-tls-demo` workspace member: loopback server-authenticated hybrid handshake in **two suites** — default (ML-KEM-768 + X25519, ML-DSA-65) and enhanced **L5** (ML-KEM-1024 + X25519, ML-DSA-87) over one generic handshake core — + a report-only P99 bench in CI |
| Asynchronous identity/prekeys/ratchet/multi-device | component-conformant PQXDH + Triple Ratchet/SPQR reference plus a separately specified Sesame-compatible manager, followed by Continuity research deltas | 🟡 G1 partial: selected source revisions, a non-normative exact version+digest lifecycle model, candidate role-ordered Bootstrap/RootTransition bytes, and a strict four-quadrant `PrekeySelectionV1` with independent Python full-byte correspondence/frozen SHA3 vectors are present; there is no manifest verifier, lease/consumption/tombstone state, context-advance API, credential/prekey/directory protocol, production session crate, outer wire decoder, persistent ratchet, recovery adapter, key transparency, FS/PCS, interoperability, or deployment claim |
| Auditability tooling | CBOM / SBOM / migration scanner | 🟡 `q-periapt-cli` workspace member emitting CycloneDX CBOM/SBOM in CI |
| Formal models | EasyCrypt combiner binding + Tamarin & ProVerif handshake models | ✅ EasyCrypt: `bind_le_cr` **machine-checked** as a generic transcript-projection collision bound; CT/PK instantiate standard X-BIND games and CTX is a separately labeled local wrapper projection. `encode_inj` is a **proved lemma**; **0 admits**. The hermetic gate re-runs `BindingViaCR.ec`, seven **proof-dependency regression controls**, and the non-normative Lifecycle/Prekey LP8 projection/omission diagnostics; none is a Rust refinement or protocol proof. Tactic failure is not called logical necessity. Semantic necessity is claimed only for checked countermodels, including the probability-one `K = bottom` context countermodel when the explicit-rejection wrapper game omits `K != bottom`. The symbolic handshake is checked by **Tamarin (5 lemmas)** and **ProVerif (6 exact queries)**, including authenticated context agreement as well as authentication and hybrid robustness. |

> The mechanized formal scope is deliberately bounded and stated honestly. The
> machine-checked theorem establishes that the `ContextBound` combiner's standard
> `MAL-BIND-K-CT`/`K-PK` claims, plus the separately identified non-standard K-CTX
> syntactic extension, reduce **only** to collision-resistance of the
> hash, with no binding assumption on the component KEMs — the canonical encoding is
> modeled concretely and its injectivity is proved. Honest residuals (see
> [`docs/BINDING_SECURITY.md`](docs/BINDING_SECURITY.md)): `H`'s collision-resistance
> is a modeling assumption; IND-CCA2 robustness is argued on paper, not mechanized;
> there is no spec↔implementation linkage proof; `X-BIND-CT-*` is structurally
> impossible for an implicitly-rejecting ML-KEM and is **not** claimed; and
> `ContextBound` is **not** "stronger binding than X-Wing" (same malicious ceiling)
> — its edge is assumption-minimality and proof coverage, not a stronger guarantee.

## Quickstart

Requires a stable Rust toolchain (`rustup` recommended).

```sh
git clone <repo-url> q-periapt
cd q-periapt

cargo build --workspace          # build the implemented crates
cargo test  --workspace          # unit tests + real-backend round-trips + X-Wing KAT
cargo clippy --workspace --all-targets

# Prove the security-critical core is dependency-free and builds bare-metal no_std:
rustup target add thumbv7em-none-eabihf
cargo build -p q-periapt-core --target thumbv7em-none-eabihf

# Cross-platform behavioural consistency (same code, every ISA):
rustup target add aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu wasm32-unknown-unknown
cargo build -p q-periapt-core -p q-periapt-kem --target wasm32-unknown-unknown
```

For downstream embedding readiness across the current Rust/C/Swift/Android/Kotlin/WASM faces, run
`sh artifact/embedding-readiness.sh`. It is stricter than the quickstart: it checks locked
dependencies, warning-denied clippy, generated C-header freshness, C link smoke, Swift XCTest count,
Swift XCFramework/binaryTarget pre-publication packaging through an isolated consumer, host C archive
extraction through dynamic/static pkg-config and CMake consumers, archive license texts plus
CycloneDX CBOM/SBOM, Android AAR/JNI packaging through four ABI slices and an isolated Java
consumer compile, Kotlin/Panama, WASM Node, and the proof-to-byte manifest. Rust crates also have a
separate pre-publication contract in `artifact/rust-publish-dry-run.sh` for the explicit publish
allow/deny list, package contents, patched `cargo publish --dry-run`, and an isolated inspection of
Cargo's normalized backend manifest/file set for retired HQC/PQCrypto material. `artifact/local-release-index.sh`
can then aggregate the existing C archive, Swift XCFramework zip, Android AAR, and optional
sanitized runtime proof summaries into one local hash-bound index; release mode requires a clean
tree, while dirty trees must use diagnostic mode and are not public provenance. See
[`docs/EMBEDDING_READINESS.md`](docs/EMBEDDING_READINESS.md) for the current package boundary:
Swift has a local XCFramework/binaryTarget gate but not a public release URL/provenance yet, and
Android has only a historical pre-ABI2 emulator runtime proof; the current ABI2 AAR
package is verified, but ART must be rerun and still needs clean-tree provenance plus
an explicit emulator/physical-device policy before a product-ready runtime claim.

### Crate tree

```
q-periapt/
├── crates/
│   ├── q-periapt-core      # ✅ dependency-free no_std core: combiner + transcript binding + primitive traits
│   ├── q-periapt-kem       # ✅ generic hybrid-KEM composition; CompatXWing-safe backend guard
│   ├── q-periapt-sig       # ✅ signature trait surface: ML-DSA-65/87, SLH-DSA (roots/firmware/long-term)
│   ├── q-periapt-backends  # ✅ publishable third-party backends (libcrux, x25519-dalek, optional fips205)
│   ├── q-periapt-policy    # ✅ crypto-agility policy engine: TOML + signed-policy verification, no hardcoded algorithms
│   ├── q-periapt-ffi       # 🟡 versioned pre-release C ABI (ABI 2 candidate; not published)
│   ├── q-periapt-wasm      # 🟡 wasm-bindgen surface (pure-Rust backends only)
│   ├── q-periapt-tls-demo  # 🟡 loopback PQ/T hybrid handshake + P99 harness
│   └── q-periapt-cli       # 🟡 migration inventory + CBOM/SBOM generator
├── research/
│   └── hqc-fips207-candidate # 🧪 publish=false RustCrypto RC shadow; no ABI/suite code
├── ctstats/          # ✅ indistinguishability hard gate + binary-CT probes; dudect local diagnostic
├── docs/             # BINDING_SECURITY.md, COMBINER_SPEC.md, ARCHITECTURE.md, ...; policy/default.policy.toml
├── formal/           # ✅ EasyCrypt binding proof (hermetic re-check + proof-dependency controls and explicit countermodels) + Tamarin & ProVerif symbolic proofs
├── tests/            # kat/ + differential/ (X-Wing KAT currently lives in q-periapt-backends)
├── bench/  fuzz/  sbom/   # harness scaffolds (combiner bench lives in q-periapt-backends/benches/)
└── bindings/         # c/ + swift/ + kotlin/ (exercised in CI against a shared test vector)
```

All crates above plus `ctstats` are Cargo workspace `members` (see `Cargo.toml`).

### Architecture in one line

`q-periapt-core` is **dependency-free and `no_std`** (zero crypto crates) and contains
only the security-critical *composition* logic — the combiner and its binding.
Primitives (for example ML-KEM, X25519, and SHA3/SHAKE) are injected through the `Kem`,
`Xof256` (and forthcoming `Dh` / `Hash` / `Sig`) traits, so the security review surface
stays tiny and reviewable in isolation. Because primitives live in swappable
backends, the constant-time guarantee is **per-(backend, arch)**: backend
selection changes the CT posture, and each backend must carry its own independent
CT attestation. The differential testing (the whole KEM chain — ML-KEM-768, X25519,
and the full hybrid — vs independent implementations) proves *output equality*, never
CT equality.

## Status & disclaimer

This is a **research artifact for a doctoral thesis**, not a product.

- **Not audited. Not FIPS-validated. Not production-ready.**
- **What is real now** (each grounded in committed code — read it before relying on
  any of it):
  - Real third-party backends are wired in `q-periapt-backends`: ML-KEM-768 / ML-DSA-65 /
    SHA3-256 via libcrux and X25519 via x25519-dalek, with SLH-DSA (fips205) behind an
    off-by-default feature. The former `pqcrypto-hqc` feature was retired rather than
    suppressing three maintenance advisories or carrying a known timing-leaky C path. The hybrid KEM round-trips under
    `ContextBound` with expanded ML-KEM keys and under `CompatXWing` with the
    X-Wing seed-dk ML-KEM-768 backend.
  - The byte-exact X-Wing draft KAT **passes** against the 3 official
    `draft-connolly-cfrg-xwing-kem` vectors (`q-periapt-backends/src/xwing_kat.rs`).
    Beyond that, the **full NIST ACVP conformance set passes** (`src/acvp.rs`):
    ML-KEM-512/768/1024 + ML-DSA-44/65/87 (incl. the broader signature modes) and
    SLH-DSA-SHA2-{128,192,256}s. That is conformance to the published vectors — **not**
    CMVP/CAVP certification (no formal FIPS validation is claimed).
  - Combiner safety guards are implemented: `CompatXWing` hard-checks all four
    absorbed fields are exactly 32 bytes (`q-periapt-core` `combine`);
    `HybridKem::new` forbids any backend that is not explicitly
    both `Kem::C2PRI` and `Kem::COMPAT_XWING_SAFE` under `CompatXWing`
    (`Error::PolicyDenied`), confining expanded/imported ML-KEM keys to
    `ContextBound` and preventing X25519 from occupying the omitted
    first slot; and
    `ct_eq`/`ct_select32` give the branch-free implicit-rejection primitive with a
    side-channel-safe, secret-free `Error`.
  - `q-periapt-policy` does strict TOML loading **and** domain-separated
    signed-policy verification. `Policy::load_signed_monotonic` authenticates the
    exact policy bytes via an injected verifier, rejects rollback and same-version
    equivocation using persisted `(version, digest)` state, and resolves a closed
    suite/profile/key-format/version decision against the runtime's concrete suites.
    Verification or resolution failure remains an error; it is never converted into
    a default-success posture.
  - The EasyCrypt binding theorem is **machine-checked** with 0 admits, and
    `encode_inj` is now a proved lemma rather than an axiom
    (`formal/easycrypt/BindingViaCR.ec`); CI hard-gates against any reintroduced
    `admit`/`sorry`.
- **`Secret`** securely zeroizes its own storage on drop (volatile write + compiler
  fence — the `zeroize` technique, inlined to keep the core dependency-free) and is
  **not** `Clone`/`Copy`, preventing implicit owner duplication. A caller can still
  copy bytes obtained through `as_bytes`; those copies are caller-managed. The core
  is `#![deny(unsafe_code)]` with that single, documented shared wipe block as the only `unsafe`.
- **Still scaffolded / pending** (do not assume these are finished): extending
  binary-level constant-time over the libcrux *primitive* paths + non-x86 (the dataflow
  CT gate over our **composition** code is done); a production rustls `CryptoProvider`
  over the FFI; and the libcrux-gated `externalMu=true` / non-SHAKE128 pre-hash ACVP
  modes. **Done since earlier drafts** (no longer pending): the full NIST ACVP set
  (ML-KEM-512/768/1024 + ML-DSA-44/65/87 incl. the hedged/context, SHAKE-128 pre-hash and
  internal-interface signature modes + SLH-DSA), the multi-backend differentials, the
  `ContextBound` reference vectors, the cargo-fuzz targets, and **both** the Tamarin and
  ProVerif machine-checked handshake proofs (`formal/`).
- **The former PQClean-HQC path is historical evidence, not a current gate or hedge**:
  its decoder had documented data-dependent timing and its dependency chain was
  unmaintained, so it was removed from the publishable graph. The recorded 193/22,849
  Memcheck counts remain provenance for older-source experiments only. The current
  constant-time gate validates itself with a synthetic planted secret-indexed leak.
  The separate HQC-v5/FIPS-207-draft RustCrypto shadow has its own research boundary and makes
  no binary-CT, production-readiness, ABI, or final-standard claim.
- The wired backends are pre-release / unaudited to varying degrees (libcrux is
  `0.0.9` / contact-maintainers-before-production; the others are likewise
  unaudited). Versions are pinned and kept swappable for differential testing and
  CVE mitigation.

Use it to read, learn from, and critique the *composition and CI methodology*. Do
not deploy it.

## Docs

Authoritative documents (refined as the code lands):

- [`docs/BINDING_SECURITY.md`](docs/BINDING_SECURITY.md) — **binding/committing security** (authoritative): target notion (`MAL-BIND-K-CT`/`K-PK`), construction, the machine-checked EasyCrypt reduction, honest claim vs X-Wing ✅
- [`docs/COMBINER_SPEC.md`](docs/COMBINER_SPEC.md) — combiner definition + test-vector plan ✅
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — core/backend split, trait surface ✅
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, adversary, mitigations ✅
- [`docs/COMPETITIVE_ANALYSIS.md`](docs/COMPETITIVE_ANALYSIS.md) — honest win / cannot-win table vs X-Wing / PQ3 / current Signal stack ✅
- [`docs/CONTINUITY_RESEARCH.md`](docs/CONTINUITY_RESEARCH.md) — **future-only** component-reference and Sesame-manager integration lane, research hypotheses, performance/privacy budgets, and evidence gates ✅
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — milestones M0–M5 and exit criteria ✅
- [`formal/easycrypt/README.md`](formal/easycrypt/README.md) — the mechanized binding proof: `BindingViaCR.ec`, scope, and how to reproduce `make check` ✅
- [`docs/policy/default.policy.toml`](docs/policy/default.policy.toml) — example agility policy ✅

## License

Apache-2.0 OR MIT, at your option. See [`LICENSE`](LICENSE), [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt), and [`LICENSES/MIT.txt`](LICENSES/MIT.txt).
