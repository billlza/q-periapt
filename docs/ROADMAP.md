# Q-Periapt — Roadmap

Authoritative status and forward plan for **Q-Periapt**, a portable, `no_std`,
side-channel-first PQ/T (post-quantum / traditional) hybrid cryptographic suite.
One dependency-free Rust core (`q-periapt-core`) is reused across C ABI / WASM /
Swift / Kotlin / Android. Deterministic conformance cells are byte-identical;
native ABI 2 product cells use OS randomness and are checked by semantic invariants.
ABI 2 / `0.1.0-alpha.2` is a release-ready research-alpha source line intended
for coordinated Rust-crate publication (not yet on crates.io), with two published
immutable GitHub research prereleases: the Apple XCFramework revision
`v0.1.0-alpha.2-r1` and the `abi2-platforms-v0.1.0-alpha.2-r2` platform
distribution (Android AAR, GNU/Linux x86_64+aarch64 SDKs, unsigned experimental
Windows x64 MSVC SDK). These are attested research prereleases, not a production
release; registry publication, Authenticode, physical-device coverage, and
independent audit remain open (see
[`../artifact/abi2-platform-release-notes.md`](../artifact/abi2-platform-release-notes.md)).

This file is the single source of truth for *what is done* vs *what is pending*.
Where a claim is subtle, it cross-references the authoritative spec
([`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md),
[`docs/COMBINER_SPEC.md`](COMBINER_SPEC.md),
[`docs/CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md),
[`ctstats/README.md`](../ctstats/README.md),
[`tests/kat/README.md`](../tests/kat/README.md),
[`formal/easycrypt/README.md`](../formal/easycrypt/README.md)).

---

## Honest positioning — read this first

Q-Periapt composes existing standardized or ecosystem-defined primitives — ML-KEM,
X25519, ML-DSA, and SLH-DSA — through third-party backends. The old timing-leaky,
unmaintained PQClean-HQC path has been removed from the publishable/runtime graph.
HQC is evaluated only in an independent `publish = false` HQC-v5/FIPS-207-draft shadow, not as
a standardized shipping advantage. Q-Periapt does **not** invent or accelerate a primitive.

**What we explicitly do NOT claim:**

- **Not faster than X-Wing / the component primitives.** `Profile::CompatXWing` is
  byte-exact against the X-Wing draft vectors. The combiner micro-benchmark
  ([`crates/q-periapt-backends/benches/combiner.rs`](../crates/q-periapt-backends/benches/combiner.rs))
  has historical single-host data against a streaming X-Wing reference; it does not
  establish current production or device parity. `Profile::ContextBound` deliberately
  does more combiner hashing in exchange for binding coverage. **We never claim a
  speed edge or current parity with X-Wing.**
- **No own FIPS validation.** The artifact reproduces NIST ACVP vectors for the
  implemented FIPS 203/204/205 parameter sets, but local vector conformance is not
  CAVP/CMVP validation or a FIPS 140-3 certificate.
- **We track standards; we do not set them.** X-Wing is an IETF draft, not a
  ratified standard.
- **No completed third-party audit.** This is **research-grade, not
  production**: the portable-only `q-periapt-mlkem-native-sys` integration over
  `mlkem-native` v1.2.0, pinned `fips204` 0.4.6, `sha3` 0.10.9,
  x25519-dalek, and optional fips205 integrations have not been independently
  audited as this suite or ABI. **Do not deploy.**

**Where the genuine, defensible value is** — none of it is speed:

1. **Provable binding with minimal assumptions.** The `ContextBound` combiner's
   binding reduces *only* to collision-resistance of the hash, and that
   reduction is **machine-checked in EasyCrypt** (see DONE §7). Correct seed-`dk`
   X-Wing reaches the same MAL K-CT/K-PK ceiling; the claimed delta is explicit
   all-field/context coverage and proof packaging, not a stronger shared-axis notion.
2. **Crypto-agility.** Suite id + policy version are bound first-class; the
   suite is a thin composition over swappable, attested backends.
3. **Side-channel CI.** Failure-path indistinguishability (implicit rejection)
   is a hard merge gate.
4. **Cross-platform consistency without a product bypass.** One core, deterministic
   byte-identity where replay inputs are appropriate, and signed-policy/round-trip/
   failure-atomicity parity in native ABI 2 product faces — a reduced audit surface,
   not unique interop.
5. **Auditability.** CBOM/SBOM, a documented threat model, and a published,
   per-cell honest scope for every assurance claim.

The 2026 protocol baseline is Apple PQ3 plus Signal's published PQXDH and
SPQR/Triple Ratchet + ML-KEM Braid components and a separately specified
Sesame-compatible manager integration. Q-Periapt currently has no
asynchronous prekey, persistent ratchet, multi-device, recovery, or key-transparency
implementation. The separate Continuity plan may pursue end-to-end performance and
security improvements, but none may be projected back onto the implemented KEM.
PQ3/Signal therefore retain material leads in deployed identity/directory handling,
offline prekeys, multi-device lifecycle, ongoing PQ ratcheting, FS/PCS, real scale,
and (for Signal SPQR) reported model-to-implementation checks. `CompatXWing` remains
the byte-exact fast comparison profile, not an inferior design to relabel.

---

## DONE

Every item below is grounded in code/commits in this repository.

### 1. Real third-party backends wired with explicit assurance boundaries
[`crates/q-periapt-backends`](../crates/q-periapt-backends) wires the core
traits (`Kem`, `Xof256`, `Signer`/`Verifier`) to real implementations — no toy primitives in
the shipped path:

- **ML-KEM-512/768/1024** through `q-periapt-mlkem-native-sys` over portable
  `mlkem-native` v1.2.0 and **ML-DSA-44/65/87** via `fips204` 0.4.6. Explicit
  seed/randomness inputs preserve deterministic conformance testing. Expanded-DK import
  validates the embedded public key's canonical encoding and stored hash before
  decapsulation; malformed keys fail without publishing temporary output. No
  source-CT/hax assurance from a replaced backend is inherited.
- **X25519** via `x25519-dalek` 2 (`default-features = false`, `static_secrets`).
- **SHA3-256 / SHAKE-256** via RustCrypto `sha3` 0.10.9.
- **SLH-DSA** (FIPS 205) via `fips205 0.4.1`, **off by default** behind the
  `slh-dsa` feature. The former `pqcrypto-hqc`/PQClean dependencies and `hqc` feature
  are removed rather than advisory-suppressed. `research/hqc-fips207-candidate`
  separately exercises RustCrypto `hqc-kem 0.1.0-rc.0` against the HQC v5 /
  prospective FIPS-207 draft candidate. The crate says it tracks an IPD, but as of
  2026-07-12 the official FIPS 207 IPD is unavailable and NIST says it is coming soon.
  That crate is `publish = false`, has no public suite
  code or ABI, and is not a vetted production fallback.

### 2. X-Wing byte-exact KAT
[`crates/q-periapt-backends/src/xwing_kat.rs`](../crates/q-periapt-backends/src/xwing_kat.rs)
reproduces all **3 official `draft-connolly-cfrg-xwing-kem` vectors**
byte-for-byte — public key, ciphertext, **and** shared secret, for encaps **and**
decaps. This **reproduces FIPS 203 reference output on those three happy-path
vectors** (the broader ACVP set is covered separately; this is not CMVP/FIPS
module validation) and confirms
the admitted `HybridKem<MlKem768XWingSeed, X25519>` construction reproduces those
vectors. `CompatXWing` is its byte-exact combiner profile; independent endpoint/HPKE
interoperability is not proved. See [`tests/kat/README.md`](../tests/kat/README.md).

### 3. Both combiner profiles + backend-safety guard
[`crates/q-periapt-core/src/lib.rs`](../crates/q-periapt-core/src/lib.rs),
`fn combine`:

- **`Profile::CompatXWing`** — byte-exact X-Wing: SHA3-256 over
  `ss_pq || ss_trad || ct_trad || pk_trad || XWING_LABEL`, all four 32-byte
  fields **hard-length-checked** (else `Error::InvalidLength`), a single 134-byte
  block, allocation-free.
- **`Profile::ContextBound`** — GHP / "hash everything": injective, fixed-width
  **8-byte big-endian length-prefixed** encoding (`fn absorb_lp`), domain-
  separated by `DOMAIN = b"Q-PERIAPT-HYBRID-KEM/v1"`, binding `suite_id` +
  `policy_version` + every ct/pk + a **mandatory non-empty `context`** (empty
  context ⇒ `Error::InvalidLength`).
- **`CompatXWing` backend guard** — `Kem::C2PRI` records the primitive property,
  while `Kem::COMPAT_XWING_SAFE` records the additional opt-in for X-Wing-compatible
  exposed key formats. `HybridKem::new`
  ([`crates/q-periapt-kem/src/lib.rs`](../crates/q-periapt-kem/src/lib.rs)):
  requires both flags for the omitted first slot. It rejects expanded ML-KEM, and
  rejects X25519 only if it is incorrectly placed in that
  slot; `Error::PolicyDenied` fails closed instead of silently changing profiles.

### 4. `no_std` bare-metal core
`q-periapt-core` is `#![no_std]` with `#![deny(unsafe_code)]` and exactly **one**
documented `unsafe` block (the `Secret::drop` wipe; see §6). CI `no_std` job
builds it for `thumbv7em-none-eabihf` (Cortex-M) and must not pull `std`.

### 5. Cross-platform faces, split product/conformance evidence
The same core is exposed through multiple faces, but ABI2 now separates product
misuse resistance from deterministic conformance:

- **C ABI / FFI** — `q-periapt-ffi`: exact-nine dynamic `q_periapt_*`
  policy-controlled product ABI; the static archive constrains only that public
  namespace and retains unsupported hidden bridge link symbols, so it assumes a
  trusted same-process consumer. Raw deterministic KAT helpers remain private Rust tests.
- **WASM** — `q-periapt-wasm`, run on a real Node runtime via `wasm-pack test`
  (CI `bindings-wasm`).
- **Swift** — `bindings/swift` over ABI2; host product test passes.
- **Kotlin** — `bindings/kotlin` via Panama FFM, JDK 22+; current-source rerun required.
- **Android** — `bindings/android` via JNI over the same C ABI. `artifact/android-aar.sh`
  builds and audits a deterministic ABI2 four-ABI AAR and compiles an isolated
  Java consumer (CI `bindings-android-aar`). The published r2 AAR ships with an
  API 35 / 16 KiB-page emulator runtime-evidence bundle; whether a clean-tree ART
  rerun matches the live source digest is selected by `artifact/results.json` and
  goes stale after each source-changing commit
  (`ANDROID-RUNTIME-DIAGNOSTIC-CURRENTNESS`).

`bindings/shared-test-vectors.json`, combiner vectors and X-Wing vectors remain
conformance/KAT inputs. Native product faces instead resolve the same signed policy,
use OS randomness, and prove context binding, legacy-state/rollback/tamper rejection,
output atomicity and secret wipe. WASM remains separately scoped.

### 6. Hardened `Secret` zeroization
`q_periapt_core::Secret` is securely zeroized on drop — volatile byte writes the
optimizer may not elide, then a `compiler_fence(SeqCst)` (the `zeroize` crate's
technique, inlined to keep the core dependency-free). `Secret` is intentionally
**not** `Clone`/`Copy`, preventing implicit owner duplication. Drop wipes only the
owned storage; explicit copies made from a borrow remain caller-managed.
The concrete SHA3 staging backend now uses absorption explicitly labeled by sensitivity:
component-secret and caller-context ranges are volatile-wiped in every live inline/heap copy,
public framing/ciphertext/key bytes are left alone,
and legacy/unclassified input or range-metadata failure falls back to a full wipe. KATs prove the
classification does not alter digest bytes; this remains local storage hygiene, not full-stack
zeroization.

### 7. Machine-checked binding proof + CI formal-proof gate
[`formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec):

- **`bind_le_cr`** is machine-checked for a generic observable projection. The CT/PK
  projections instantiate the standard `MAL-BIND-K-CT` / `MAL-BIND-K-PK` games;
  the CTX projection is a separately self-defined context-wrapper collision game.
  Each reduces **only** to collision-resistance of the hash — no binding assumption
  on ML-KEM / X25519 — but K-CTX is not a CDM node or monotonicity result.
- **`encode_inj` is now a proved `lemma`** (commit `ef98df1`), no longer an axiom:
  the canonical encoding is modeled concretely and its injectivity proved,
  reducing only to two elementary `be8` facts (8-byte fixed width + injectivity)
  plus collision-resistance of SHA3. **0 admits / 0 sorry.**
- **CI formal jobs** — a complete-token `! grep -rnEw 'admit|sorry'` **hard gate** (catches
  a proof being stubbed out), `formal-easycrypt` for the pinned-source EasyCrypt re-check plus
  seven proof-dependency regression controls, and full Tamarin/ProVerif `make prove`
  gates. The hint-deletion controls document dependencies of the current proof
  scripts; they are not semantic necessity proofs. `kctx_without_nonbottom_broken`
  is the checked probability-one countermodel for omitting `K != bottom`.

**Honest scope (unchanged):** H's collision-resistance is a modeling assumption;
IND-CCA2 robustness is argued on paper, not mechanized; there is no
spec↔implementation linkage proof; `X-BIND-CT-*` is structurally impossible for
implicitly-rejecting ML-KEM and is **not** claimed; `ContextBound` is **not**
"stronger binding than X-Wing" (same malicious-adversary ceiling) — the edge is
**assumption-minimality and proof coverage**. See
[`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md) and
[`formal/easycrypt/README.md`](../formal/easycrypt/README.md).

### 8. Signed-policy verification + atomic suite resolution
[`crates/q-periapt-policy`](../crates/q-periapt-policy):

- `Policy::try_new` / `Policy::from_toml` — strict validation: non-zero version,
  recognized NIST floor/algorithms, no duplicate or unknown fields, and at least one
  complete suite plus signature.
- `Policy::load_signed` — verifies the domain-separated message
  `Q-PERIAPT-SIGNED-POLICY/v1 || u64_be(len) || exact_toml_bytes` through an injected
  verifier before trusting the document. Authentication or parsing failure remains an
  error; no fallback-success API exists.
- `Policy::load_signed_monotonic` — compares `(version, SHA3-256(exact TOML))` with
  persisted trusted state, rejecting rollback and same-version equivocation.
- `AuthenticatedPolicy::resolve_suite` — resolves against concrete local
  `HybridSuite` values and returns one private-field `AuthenticatedResolvedSuite`
  carrying suite/profile/key-format/version plus the exact policy state. Fixed L3
  runtime faces reject L5 policies instead of binding false algorithm metadata.
- The decision-controlled native/WASM paths commit the policy digest and application
  context. Native ABI 2 exports no raw hybrid, deterministic key-generation, X-Wing,
  or combine operation. Its decision descriptor and WASM's raw/conformance inputs
  remain trusted-caller values, not remote authorization capabilities.

### 9. CBOM / SBOM (CycloneDX)
[`crates/q-periapt-cli`](../crates/q-periapt-cli) (`qperiapt` binary) emits a
CycloneDX 1.6 **Crypto** BOM (`cbom`) of the suite's cryptographic assets and a
CycloneDX 1.6 **SBOM** (`sbom`) from `Cargo.lock`, plus a legacy/quantum-
vulnerable **migration scanner** (`scan`). CI `audit` job runs all and uploads
the BOMs as artifacts.

### 10. Matched-backend performance gate
[`paired_profile_perf.rs`](../crates/q-periapt-backends/examples/paired_profile_perf.rs)
gives ContextBound and CompatXWing the same seed-dk ML-KEM/X25519 backend, keys,
coins, ciphertext corpus, suite/version/context inputs, and paired ABBA/BAAB ordering.
[`performance_gate.py`](../artifact/performance_gate.py) enforces schema, sample inventory,
host stability, source/binary/budget hashes, and the published p50/p95/p99 plus absolute
delta budgets. A performance proof counts as current only when its canonical source
digest equals the live verifier digest and the host satisfies the controlled-power and
thermal contract. The time-varying proof state is recorded in `artifact/results.json`,
not copied into this source document. The older Criterion combiner harness remains a
reference/primitive-scale tool; neither host result closes device energy, rustls
end-to-end, stable clean-baseline history, or optimized-production parity.
Budget schema v4 keeps the thresholds and 20,480-sample corpus fixed while using
1,024-pair primary percentile-estimate blocks, yielding 11 nearest-rank p99 tail
observations per block. It also retains the former 256-pair estimator as a regression
guard and applies the same limits at both scales; separately parameterized temporal-
stability windows retain the same 5% CV limit.
The schema-v4 producer also fixes Cargo/Rustc executable hashes, versions, and target;
rejects repository/ancestor/user Cargo configuration and caller compiler/wrapper/loader
controls; and builds offline in a fresh private target. It still trusts the user-writable
Cargo registry, Rust sysroot/driver, OS tools/libraries, same-UID host, and collector
source-to-binary honesty, so hermetic producer attestation remains pending.

### 11. Multi-backend differential tests
[`crates/q-periapt-backends/src/differential.rs`](../crates/q-periapt-backends/src/differential.rs)
cross-validates the primitives **and the full hybrid** against independent
implementations on random `SHAKE-256(counter)` inputs (no RNG) — an assurance method
orthogonal to KATs and the proof, catching integration/encoding bugs that 3 fixed
vectors would miss:
- **ML-KEM-512/768/1024** — release-graph portable `mlkem-native` vs independent RustCrypto `ml-kem`
  (byte-identical keygen, encapsulation, decapsulation over 64 inputs each).
- **X25519** — our `x25519-dalek` backend vs the independent `orion` implementation,
  plus the authoritative **RFC 7748 §6.1** ground-truth Diffie–Hellman vector.
- **Hybrid CompatXWing** — our seed-dk `HybridKem` output reconstructed from
  independent RustCrypto ML-KEM + orion X25519 while using the same RustCrypto SHA3
  implementation as production, byte-identical for encaps and decaps. Official X-Wing
  and separately encoded `ContextBound` KATs protect the combiner independently.
  Expanded ML-KEM backends are also negatively tested as
  rejected under `CompatXWing`.
- **ML-DSA-44/65/87** — production `fips204` vs RustCrypto `ml-dsa`:
  byte-identical keygen + deterministic signatures (FIPS 204 external mode, rnd = 0), plus
  cross-verification (each implementation verifies the other's signature) and tamper
  rejection, for all three parameter sets (`differential.rs`).

Extending the differential to SLH-DSA is pending (its keygen is randomized, so the
check would be signature interoperability rather than byte-identity).

### 12. NIST ACVP ground-truth conformance
[`crates/q-periapt-backends/src/acvp.rs`](../crates/q-periapt-backends/src/acvp.rs)
validates the `mlkem-native`/`fips204` adapters against the **authoritative** NIST ACVP vectors
(vendored under `crates/q-periapt-backends/vectors/`, from `usnistgov/ACVP-Server`):
- **ML-KEM-512/768/1024 (FIPS 203)** — the full set each: keyGen `(d,z)→(dk,ek)`,
  encaps `(ek,m)→(c,k)`, and decaps `(dk,c)→k` including modified-ciphertext cases that
  exercise FO implicit rejection. All byte-identical to NIST.
- **ML-DSA-44/65/87 (FIPS 204)** — keyGen `ξ→(sk,pk)`, plus sigGen/sigVer across the
  signature modes our backend exposes: external/pure (deterministic **and** hedged, with
  non-empty contexts) and HashML-DSA **SHAKE-128 pre-hash**. The vendored internal
  Alg. 7/8 vectors remain explicit, unwired reference data and are not counted as a pass.
- **SLH-DSA-SHA2-{128,192,256}s (FIPS 205)** — keyGen/sigGen/sigVer under the `slh-dsa`
  feature (`acvp_slhdsa.rs`), deterministic keyGen via a seed-replay RNG.

This is *direct* NIST ground truth, orthogonal to the differential (which compares
against another implementation). The internal interface, `externalMu=true`, and
non-SHAKE128 pre-hash modes remain out of scope.

### 13. Generative property-based tests
[`crates/q-periapt-backends/src/proptests.rs`](../crates/q-periapt-backends/src/proptests.rs)
(proptest) generates random inputs — and shrinks any failure to a minimal case —
to hold the load-bearing combiner / hybrid invariants over the real backends:
determinism; the CompatXWing 32-byte length guard; the ContextBound non-empty-context
guard; **encoding injectivity under a field-boundary shift** (the binding property,
where naive concatenation would collide); profile domain separation; context binding
(K-CTX bit-sensitivity); and hybrid CompatXWing KEM round-trip. A sixth assurance
method orthogonal to fixed KATs, ACVP, the differential, the proof, and cross-platform.

---

## PENDING

Stated honestly. None of these are blockers for the research claims above; they
are the gap between research-grade and audited/production.

1. **Broader ACVP coverage + `ContextBound` cross-platform reference vectors.**
   The NIST ACVP ML-KEM-768 **and ML-KEM-1024** sets (keyGen/encaps/decaps incl.
   implicit-rejection) and ML-DSA-65 (keyGen + the deterministic/external/empty-context
   sigGen/sigVer cases) are now wired and passing (see §12). ML-KEM-1024 — the
   enhanced-mode KEM the policy references — now has a real backend (`MlKem1024`),
   covered by both NIST ACVP and the RustCrypto differential, **and the enhanced suite
   ML-KEM-1024 + X25519 is instantiated end-to-end** as a real `HybridKem<MlKem1024,
   X25519, Sha3_256Xof>` with a pinned, independently-cross-checked KAT
   (`enhanced_kat.rs`) — no longer just a policy allow-list string. Remaining:
   ML-DSA internal-interface, `externalMu=true`, and non-SHAKE128 pre-hash ACVP modes.
   The vendored internal vectors are deliberately unwired reference data, not a pass.
   ML-KEM-512/768/1024, ML-DSA-44/65/87 contexts/hedged/SHAKE-128 pre-hash modes,
   and SLH-DSA are done (§12). Fixed `(suite_id, policy_version,
   components, context) → K` reference vectors for `ContextBound` now exist as an
   in-repo KAT (`crates/q-periapt-backends/src/contextbound_kat.rs`, independently
   cross-checked by a second SHA3 + a from-scratch encoder, and including a
   load-bearing length-prefix collision pair). The former public cross-language raw
   combine surface was intentionally removed before ABI2 freeze so a conformance
   helper cannot become a stable policy bypass. Rust/WASM retain deterministic
   reference checks; native product faces use the signed-policy workflow.
   See [`tests/kat/README.md`](../tests/kat/README.md).

2. **Binary-level constant-time + making timing a hard gate.** Today,
   failure-path indistinguishability / implicit rejection **is** a hard CI gate
   ([`ctstats/README.md`](../ctstats/README.md), CI `sidechannel` job). The
   **dudect timing test is a local diagnostic**, intentionally absent from shared
   CI because those runners are too noisy for a stable threshold. Its exit status
   is not converted into default success.
   Binary-level **dataflow** constant-time is now a **hard gate** (the
   `constant-time` CI job runs `ct_verify` under Valgrind/Memcheck-TIMECOP) over the
   suite's own CT composition code — `ct_eq`, `ct_select32`, and the combiner. The
   same x86_64+aarch64 job is configured to hard-gate corrected ŝ+z
   ML-KEM-512/768/1024 shipped-provider decapsulation probes with planted controls.
   The superseded `fips203` provider failed this gate on both ISAs in
   [CI run 29230650107](https://github.com/billlza/q-periapt/actions/runs/29230650107),
   and those historical counts do not describe portable `mlkem-native`. The backend/source
   migration also invalidated previous `libcrux` captures, so a fresh two-ISA pass
   for the release digest is required. No source-CT/hax result transfers. Still TODO: other component
   primitive paths, riscv64/wasm32 binary-CT, and promoting a quiesced-hardware
   **timing** check to a gate (the
   statistical dudect test is still local-only, so *timing* is not yet gated).

3. **Broader `cargo-fuzz` corpora.** Two targets exist and have been run locally
   (`combine`, `mlkem_decapsulate`; CI `fuzz` job *compiles* all targets); see
   [`fuzz/README.md`](../fuzz/README.md). Larger seed corpora, longer time-boxed
   CI runs, and additional targets (signature paths, policy/TOML parsing) are
   pending.

4. **Independent third-party audit.** None has been performed.

5. **Embedding and package distribution.** `artifact/embedding-readiness.sh` now gives
   downstream consumers one fail-closed gate over the current Rust/C/Swift/Android/Kotlin/WASM faces:
   locked dependencies, warning-denied Rust checks, generated-header freshness, C link smoke,
   Swift XCTest, Swift XCFramework/binaryTarget consumer proof, Android AAR/JNI package proof,
   Kotlin/Panama, WASM Node, and `proof-to-byte`. Authoritative proof JSON and Apple auxiliary
   artifacts now use strict single-byte snapshots and one pinned results-manifest digest per run;
   clean provenance compares HEAD/index/actual tracked bytes under a fixed Git environment,
   inventories ignored and visible inputs under fixed output policy, and dispatches Python through
   an isolated source-only launcher rather than trusting Git excludes, repository pyc, user-site,
   or caller `PYTHON*`. The Apple device matrix is also real proof when explicitly required
   (`QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX=1`). The HQC graph/tombstone change invalidated the
   earlier Apple evidence. The later clean-tree schema-3 matrix also predates the
   backend/source-digest migration and is now historical, as are the recorded package,
   performance, and CT proofs. Time-varying status lives only in the results manifest plus the live
   domain verifier; a source document cannot promote an older device digest. A current clean,
   same-commit schema-3 matrix remains required for production promotion or a
   platform-binary claim. The published prerelease surface now covers Apple (signed
   XCFramework, `v0.1.0-alpha.2-r1`), Android (four-ABI AAR + emulator runtime evidence),
   GNU/Linux (x86_64+aarch64 SDK tars), and Windows (unsigned experimental x64 MSVC SDK)
   through the immutable `abi2-platforms-v0.1.0-alpha.2-r2` release, but it is still not a
   liboqs-style production distribution surface:
   Swift has both a credential-free XCFramework gate and a separately scoped detached-source
   Developer ID-signed static-SDK prerelease lane; `artifact/results.json` alone decides whether its public
   URL/checksum/provenance is current. The SDK ZIP is not a complete Git-URL Swift package and does
   not contain a notarizable executable/bundle; final consuming products retain their platform
   signing, provisioning, and macOS notarization duties. Android's published r2 AAR is
   source-bound with emulator runtime evidence; live-tree ART-rerun currentness is
   selected by `artifact/results.json` (stale after each source-changing commit), and
   an explicit CI-emulator or
   physical-device release policy remains open; Rust now has a crates.io pre-publication contract
   (`artifact/rust-publish-dry-run.sh`) over the explicit ten-crate publish allow/deny list,
   every downstream local patch, package file lists, patched `cargo publish --dry-run`, an
   independent sys `.crate` fixed 124-entry upstream inventory/exact 118-code-file packaged-subset
   hash/license/forbidden-path check (six upstream README files excluded), and a normalized
   backends audit with the sys crate patched in. The planned coordinated dependency-order
   registry release defines the intended research-alpha Rust surface; independent signed
   or transparency-backed provenance remains required before production promotion.
   C now has published multi-target SDK archives — Linux x86_64+aarch64 tars and the
   unsigned experimental Windows x64 MSVC ZIP in `abi2-platforms-v0.1.0-alpha.2-r2` —
   each with ABI-major headers, exact-version pkg-config/CMake configs, the frozen ABI
   contract, SBOM/CBOM, and license material, validated by attested candidate-CI native
   consumers; deb/rpm/MSIX registry packaging and Windows Authenticode remain open. See
   [`docs/EMBEDDING_READINESS.md`](EMBEDDING_READINESS.md).

   The coordinated Rust registry order is `q-periapt-mlkem-native-sys`, core,
   KEM/signature traits, backends, policy, then the FFI/WASM/rustls leaves. The
   dependency-free CLI may upload independently but remains in the same ten-crate version set.

   Package `0.1.0-alpha.2` is the release-ready research-alpha source/crate line and has a
   frozen machine-readable C **ABI 2** contract: nine exact dynamic public exports
   (and the same exact reserved public namespace in static archives), OS-random key/encapsulation,
   ABI-major library/header/package identities, 40/36-byte layouts, and forbidden
   raw/deterministic symbols. ABI1 is an explicit hard cut—its version-only state is
   rejected and requires authorized re-enrollment/reset, not a synthetic migration.
   The source publication by itself implies no prebuilt binary; the prebuilt platform
   binaries that do exist are the independently evidence-selected Apple `v0.1.0-alpha.2-r1`
   XCFramework and `abi2-platforms-v0.1.0-alpha.2-r2` Android/Linux/Windows packages,
   each bound to its own release receipt. Production promotion remains blocked on
   warning-clean dependency audit currency, clean signed or
   transparency-backed source provenance, independent cryptographic/C-FFI/ABI review,
   and live verification of same-source Apple matrix and controlled-host performance evidence.
   Continuity's abstract snapshot schema 3 is unrelated and must not enter ABI 2.
   The backend/source migration invalidated all prior package, Apple/performance, and
   binary-CT proofs, including proofs collected after the HQC tombstone change.
   `artifact/results.json` and the live verifiers are authoritative for currentness.
   These production-promotion gates do not turn the release-ready research
   alpha into a production or full-binary release.

6. **Production hardening.** Backends are pre-1.0 / unaudited for this integration.
   The current graph uses portable `mlkem-native` v1.2.0, `fips204`, and `sha3`; it
   removes both the `fips203` path that failed the project CT gate and the earlier
   `libcrux`/hax/`proc-macro-error2` advisory edge. The ML-KEM trust anchors are commit
   `0ba906cb14b1c241476134d7403a811b382ca498` and immutable GitHub commit archive SHA-256
   `f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677`.
   Current `cargo audit --deny warnings` passes with `.cargo/audit.toml` still carrying
   `ignore = []`, but RustSec does not inspect vendored C. This closes the Rust dependency-
   advisory gate only; independent cryptographic/C-FFI/code/ABI review, fresh per-source
   CT and platform evidence, and signed distribution provenance remain mandatory.

7. **Q-Periapt Continuity session research.** This is a separate, gated workstream,
   not an extension of the current theorem or `q-periapt-core`:

   - G0: keep the comparison baseline current — Signal includes SPQR/Triple Ratchet,
     ML-KEM Braid, Sesame, ProVerif, and reported hax/F* implementation checks.
   - G1: freeze identity semantics, canonical wire grammar, prekey lifecycle,
     ratchet/effect state machine, recovery/anchor behavior, complete metadata surface,
     numeric resource/convergence bounds, and physical-device latency/energy/thermal
     budgets.
   - G2: implement component-conformant PQXDH bootstrap and Triple Ratchet/SPQR, plus
     a separately specified Sesame-compatible manager integration. Component
     conformance, integrated behavior, and external interoperability are separate;
     modifying a published KDF or transition creates a new protocol.
   - G3: test the Continuity research hypotheses against that matched reference:
     authenticated policy/context continuity, verifiable prekey behavior, accountable
     versus deniable PQ identity, measurable healing debt, crash/rollback-safe state,
     proof-to-state-to-byte, native CryptoKit/Secure Enclave PQ provider experiments,
     metadata privacy, and workload-matched sparse-ratchet selection.
     Performance candidates must preserve bytes/security floors: public-only SHA3
     prefix-state cloning with byte-equality KATs, bounded independent prekey batches,
     and fixed-budget authenticated chunking/erasure-code experiments measured against
     an unchanged healing-debt bound. Omitting fields or silently lowering PQ cadence
     is not an optimization.
   - G4: establish model-to-Rust refinement or translation validation and panic
     freedom; provenance hashes alone do not meet Signal's reported baseline.
   - G5: close same-source physical iPad, iPhone, macOS, and physical Android
     latency/wire/energy/thermal/storage/healing budgets.
   - G6: obtain independent review and pilot fault/scale telemetry before deployment.

   The complete gates, candidate performance budgets, and forbidden claims are in
   [`docs/CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md). G0 documentation baseline
   correction is complete. G1 is **partially started**: selected public revisions,
   reproducible content hashes, and a non-normative, `publish = false`
   effect/journal lifecycle model are present. The model now has candidate
   role-ordered `LifecycleContextV1` and strict `PrekeySelectionV1` projections,
   independent Python encoders/decoders, frozen SHA3 vectors, 31 lifecycle integration
   tests, 12 canonical-context tests, eight strict prekey-selection tests, and one
   private receipt-atomicity regression. It fixes trusted durable pairwise
   session/current-context authority, exact version+digest state advances, and rejects
   draft grafts and no-op anchors before mutation. It intentionally does not advance
   context until role/profile semantics are frozen. Mutable publisher pages are not
   archived. Trusted genesis/credentials, legal stage transitions, signed manifest/
   leaf verification, unique lease/consumption/tombstone state, outer/production
   strict decoding, production wire/identity/prekey/ratchet/storage
   adapters, metadata, numeric budgets and all G2–G6 outcomes remain open.

8. **(Future) SkyBridge integration.** Folding Q-Periapt into the SkyBridge
   quantum-comm project still needs a downstream harness per target repo. The Q-Periapt embedding
   gate proves this repo's language faces; it does not prove SkyBridge product integration.

---

## Status snapshot

| Area | Status |
| --- | --- |
| Third-party release backends wired (ML-KEM/ML-DSA/SHA3/X25519; opt-in SLH-DSA) | **Done; retired PQClean-HQC removed, HQC-v5/FIPS-207-draft RC isolated in a publish=false shadow** |
| X-Wing byte-exact KAT (3 draft vectors) | **Done** |
| Both combiner profiles + backend-safety guard | **Done** |
| `no_std` bare-metal core (one documented `unsafe`) | **Done** |
| Native ABI2 C/Swift/Kotlin/Android product surface; deterministic Rust/WASM conformance split | **Implemented; Swift includes a separate Developer ID-signed static-only XCFramework prerelease lane whose currentness is evidence-selected and whose notarization applicability is explicitly false. The published r2 platform prerelease covers the Android AAR and Linux/Windows C SDK archives; Kotlin JDK22 and current-source runtime lanes remain independent and pending or historical as recorded in results.json.** |
| Hardened `Secret` zeroization | **Done** |
| Signed-policy verification + `(version,digest)` state + closed `ResolvedSuite` | **Done; native raw bypass exports removed, byte decision still trusted-local and requires pinned verification key** |
| CBOM / SBOM (CycloneDX) + migration scanner | **Done** |
| Machine-checked `bind_le_cr` + `encode_inj` lemma + CI no-admits gate | **Done** |
| Tamarin symbolic handshake model (auth, authenticated context agreement, hybrid robustness; 5 lemmas) | **Done** |
| ProVerif handshake model — independent second symbolic prover (6 exact queries) | **Done** |
| CI gate for the Tamarin proof (hard lemma-presence gate + hard `make prove`) | **Done** |
| Matched-backend paired performance budget | **Canonical-source, controlled-host diagnostic implemented; verifier policy fixes the repository budget, manifest currentness requires a path/hash/schema/source/pass summary, and the required domain verifier checks the actual proof/freshness/artifacts; hermetic producer provenance, clean baseline history, device energy, and optimized-production parity pending** |
| NIST ACVP conformance (ML-KEM-768 + ML-KEM-1024 + ML-DSA-65 + ML-DSA-87) | **Done** |
| `ContextBound` reference vectors (in-repo KAT, independently cross-checked) | **Done** |
| Deterministic `ContextBound`/`CompatXWing` conformance vectors | **Done in Rust/WASM; intentionally not exported by native ABI2** |
| ML-KEM-1024 backend (enhanced-mode KEM) + NIST ACVP + differential | **Done** |
| ML-DSA-87 backend (enhanced-mode L5 signature) + NIST ACVP + differential | **Done** |
| Enhanced suite `HybridKem<MlKem1024,X25519>` end-to-end + pinned KAT | **Done** |
| Enhanced L5 handshake (ML-KEM-1024 + X25519 + ML-DSA-87) in `tls-demo`, generic core | **Done** |
| ACVP ML-DSA signature modes: hedged + non-empty context + SHAKE-128 pre-hash (65 & 87) | **Done** |
| Full FIPS family backends + ACVP + differential (ML-KEM-512/768/1024, ML-DSA-44/65/87) | **Done** |
| SLH-DSA-SHA2-{128,192,256}s NIST ACVP conformance (FIPS 205, `slh-dsa` feature) | **Done** |
| ACVP ML-DSA internal interface (FIPS 204 Alg. 7/8) | **Pending; vendored vectors are retained as unwired reference data and are not a backend pass** |
| Remaining ACVP modes: `externalMu=true` / non-SHAKE128 pre-hash | Pending |
| Dataflow CT gate (Memcheck/TIMECOP, our composition code) | **Done** |
| Embedding readiness gate across Rust/C/Swift/Android/Kotlin/WASM package/runtime-tested faces | **Implemented; time-varying pass state is selected by `artifact/results.json` and checked by live verifiers** |
| Physical Apple matrix proof (iPad + iPhone, stable-Xcode lane) | **Harness/schema implemented; recorded clean-tree matrix is historical after the backend/source-digest migration and both physical lanes must be rerun** |
| Strict evidence snapshots + selected-proof atomic manifest binding | **Implemented: duplicate/non-finite JSON and top-level hash/semantics A/B mixing fail closed; clean signed manifest provenance remains pending** |
| Git/Python verifier-input provenance | **Implemented and negative-tested: local excludes, hidden index flags, ignored pyc, user-site/`.pth`, and caller `PYTHON*` fail closed; external interpreter/host attestation remains pending** |
| Android AAR/JNI package proof | **Done for the published r2 AAR: the four-ABI package was rebuilt from the corrected source-bound path, audited (16 KiB alignment, exact nine-symbol exports, RELRO/NOW/NX, no text relocations or RPATH/RUNPATH), and published with its manifest in `abi2-platforms-v0.1.0-alpha.2-r2`** |
| Android ART runtime smoke | **The r2 release binds an API 35 / 16 KiB-page emulator runtime-evidence bundle executed on the exact public AAR; live-tree rerun currentness is selected by `artifact/results.json` and goes stale after each source-changing commit, while clean release provenance for reruns and the physical-vs-CI-emulator policy remain pending (`ANDROID-RUNTIME-DIAGNOSTIC-CURRENTNESS`)** |
| Local hash-bound release index (C archive + Swift XCFramework + Android AAR) | **Schema2 semantic diagnostic index and checks are implemented; the recorded component artifacts predate the backend/source migration and a new same-source index is required; clean release channel remains pending** |
| C ABI 2 research-alpha release readiness | **The 0.1.0-alpha.2 source/crate contract is release-ready and intended for coordinated source-crate publication. The Apple `v0.1.0-alpha.2-r1` XCFramework and the r2 Android/Linux/Windows packages are published, attested prereleases. Same-source device/performance evidence, signed or transparency-backed source provenance, independent cryptographic/C-FFI/ABI audit, and Windows Authenticode remain required for production promotion; ART-rerun currentness is tracked live in `artifact/results.json`.** |
| Published immutable GitHub prereleases (Apple r1 + platform r2) | **Done as research prereleases; machine-checked receipts in `results.json` (`release_publications`, `swift_xcframework.distribution`) under `platform_release_contract.py`. Not a production, registry, or store release.** |
| liboqs-style package distribution surface (crates/C archive/XCFramework/AAR) | Partial; Apple XCFramework + Android AAR + Linux/Windows C SDK GitHub prereleases are published, while a complete remote Swift package and crates.io/Maven/deb/rpm/MSIX registry publication remain pending |
| Fresh ML-KEM CT capture plus binary-CT beyond the configured decap probe + riscv64/wasm32 + timing as a hard gate | Pending |
| Broader `cargo-fuzz` corpora | Pending |
| Independent third-party audit | Pending |
| Production hardening | Pending |
| PQXDH + Triple-Ratchet component reference and separately specified Sesame-compatible manager | Future; no session crate, integration trace, or interoperability claim |
| Q-Periapt Continuity research lane | G1 partial: selected revisions/reproducible content hashes + test-only lifecycle model with candidate canonical context and strict four-quadrant prekey-selection bytes, independent encoders/decoders/vectors, structural EasyCrypt diagnostics, exact state CAS and trusted session/context admission; no manifest/lease/consumption state, context advancement, or identity/protocol/security claim |
| Stateful protocol model-to-Rust refinement | Future; current claim remains pending |
| SkyBridge integration | Future |
