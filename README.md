# Q-Periapt — PQ/T Hybrid Cryptographic Suite

> [!WARNING]
> **Status: pre-1.0 research / undergraduate-thesis project (v0.0.1). NOT audited,
> NOT FIPS-validated — do not use in production yet.** Real vetted backends are
> wired (ML-KEM-768 / ML-DSA-65 / SHA3 via libcrux, X25519 via x25519-dalek;
> SLH-DSA via fips205 and HQC via pqcrypto-hqc behind features), the X-Wing interop
> KAT passes byte-for-byte against the official draft vectors, and the combiner
> binding theorem is machine-checked in EasyCrypt — but the suite has had no
> third-party audit. See [Status & disclaimer](#status--disclaimer).

**Q-Periapt** — *Q for Quantum; a periapt is an amulet worn to ward off danger* —
is a portable, `no_std` post-quantum / traditional (PQ/T) hybrid cryptographic
suite, **built side-channel-aware from the start** (with the caveats below: the
failure-path indistinguishability check is a hard CI gate; empirical timing is
report-only today, not yet a merge gate). The name is the design: a periapt
shields its bearer from a fatal blow (in the spirit of the Chinese 玉佩, a jade
pendant said to shatter to protect its wearer) — likewise this suite stays secure
even if **one** of its two independent assumptions (a lattice KEM, and a
traditional or — in enhanced mode — code-based one) is broken, because a combiner
**provably binds** the two into a single shared key (the binding theorem is
machine-checked in EasyCrypt). It is built around one dependency-free Rust core
(crate namespace `q-periapt-*`) that vetted primitive backends are injected into
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

The KEM primitive (ML-KEM-768) is the **same NIST standard** that X-Wing, Apple
PQ3, Chrome and rustls already ship. You get no security or raw-speed edge on the
primitive itself. Because of that, the suite ships **two combiner profiles**
selected by policy, and is explicit about the trade between them:

| Profile | What it binds | Cost | When |
|---|---|---|---|
| **`CompatXWing`** | `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label` (X-Wing draft-10 layout) | parity with X-Wing — one Keccak block | wire interop with X-Wing / HPKE; only sound with a C2PRI KEM (ML-KEM) |
| **`ContextBound`** | domain tag + length-prefixed *every* shared secret, ciphertext, public key, **and** an external context (transcript / suite / policy version) | strictly **slower** (more SHA3 input → more Keccak blocks); a deliberate robustness trade, **not** a speed win | non-C2PRI components (HQC, generic KEMs), or when maximal binding / downgrade resistance is required |

The `CompatXWing` profile can omit the ML-KEM ciphertext **only** because
ML-KEM-768 is C2PRI (ciphertext-second-preimage-resistant via the FO transform +
explicit rejection). That property is load-bearing; a non-C2PRI component (HQC, or
X25519-as-KEM) **must** use `ContextBound`, which hashes all ciphertexts. The
hashing delta between the two profiles is real and directional but is a *small*
fraction of total encap/decap — encap/decap is dominated by ML-KEM arithmetic and
SHAKE, not the combiner hash. This is **measured**, not asserted:
[`crates/q-periapt-backends/benches/combiner.rs`](crates/q-periapt-backends/benches/combiner.rs)
benchmarks our `CompatXWing` combiner (allocation-free, single 134-byte Keccak
block via libcrux) against a streaming X-Wing reference, asserting byte-identical
output first so the comparison is fair. The result is parity — our generic
abstraction costs on the order of tens of nanoseconds versus a hand-rolled
streaming X-Wing combiner, negligible against a full handshake — and `ContextBound`
is deliberately ~19× more combiner hashing. We never claim a combiner speed win.

### Where this can plausibly win

- **Crypto-agility + assumption diversity** — the single most defensible claim.
  A signed policy file negotiates fast (X-Wing-parity) vs strong (context-bound)
  combiner, swaps the PQ KEM, raises to L5, or adds a code-based HQC hedge against
  a lattice break, all without a recompile. X-Wing is a *single fixed
  construction*; deployments cannot do any of this without forking it.
- **One auditable codebase across platforms** — a single Rust core means one
  CT-verified, one fuzzed, one differential-tested implementation under C / WASM /
  Swift / Kotlin, reducing audit and implementation-bug surface. (Note: ML-KEM and
  X25519 are deterministic standardized primitives, so *any* conformant
  implementation interops across platforms — the win here is reduced audit
  surface, **not** a unique cross-platform interop capability.)
- **Side-channel CI as a product feature** — the failure-path indistinguishability
  / implicit-rejection check **is a hard merge gate today**
  ([`ctstats/`](ctstats/README.md): an invalid ML-KEM-768 ciphertext decapsulates
  to a deterministic, success-shaped secret, with no error-code oracle). The
  empirical dudect-style Welch t-test runs in CI but is **report-only** (it never
  fails the build — shared runners are too noisy for a stable threshold), and
  binary-level constant-time re-verification (Valgrind/Memcheck-TIMECOP) — needed
  because source-level CT does not survive the compiler (clangover, KyberSlash) — is
  now a **hard CI gate** (`constant-time` job) over the suite's own CT composition
  code (`ct_eq`/`ct_select32`/the combiner); extending it over the primitive paths
  and to non-x86 targets is still **TODO**. See
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
  targets *parity* with X-Wing; `ContextBound` is intentionally slower.
- **Primitive performance** — it wires libcrux (ML-KEM / ML-DSA / SHA3),
  x25519-dalek, fips205 (SLH-DSA) and pqcrypto-hqc; it will not out-perform AVX2
  ML-KEM or FIPS-validated AWS-LC. This is a composition / safety layer, not a
  faster primitive.
- **FIPS 140-3 validation out of the box** — the pure-Rust `no_std` core is **not**
  FIPS-validated. The trait-injected backend design leaves room for a FIPS path
  (e.g. an aws-lc-rs / AWS-LC backend) later, but no such backend is wired today
  and the project makes no validation claim of its own.
- **Wire-format / standards novelty** — it implements X-Wing (an Independent
  Submission draft, `draft-connolly-cfrg-xwing-kem`, *not* a CFRG WG item),
  `draft-ietf-tls-ecdhe-mlkem` (X25519MLKEM768, codepoint `0x11EC`, RFC number
  unassigned), and HQC (FIPS 207 not final). It tracks standards; it does not set
  them.
- **A completed independent audit** — as of 2026-06-23 no pure-Rust PQC crate has
  a completed third-party audit, and `libcrux`'s verification explicitly excludes
  compiled-binary side channels. This project provides audit *enablers*
  (CBOM, CT-CI, formal model), not a finished external audit.

## Feature matrix vs the target dimensions

Legend: ✅ implemented & exercised · 🟡 partial / scaffolded · ⛔ planned, not started.

| Dimension | Target | Today (v0.0.1) |
|---|---|---|
| Auditable `no_std` core | dependency-free combiner + traits, builds bare-metal | ✅ `q-periapt-core` (zero crypto deps; `#![deny(unsafe_code)]` with ONE documented `Secret` wipe block; builds `thumbv7em-none-eabihf`) |
| Hybrid KEM | ML-KEM-768 + X25519, HQC backup | ✅ ML-KEM-768 (libcrux) + X25519 (x25519-dalek) wired; real hybrid encap/decap round-trips under both profiles; the **enhanced** suite **ML-KEM-1024 + X25519** is instantiated end-to-end (real `HybridKem<MlKem1024,X25519>`, ACVP + differential + a pinned, independently-cross-checked end-to-end KAT), not just a policy string; **ML-KEM-512** (L1) also has a verified backend, so the whole FIPS-203 family (512/768/1024) is ACVP + differential covered for agility; HQC-128/256 (pqcrypto-hqc) behind the off-by-default `hqc` feature |
| Combiner profiles | `CompatXWing` (parity) + `ContextBound` (binding) | ✅ both profiles implemented over a trait XOF and wired to a **real SHA3-256** (libcrux) backend |
| Combiner safety guards | C2PRI guard, 32-byte length checks, implicit rejection | ✅ `CompatXWing` hard-checks all four fields are exactly 32 bytes; `HybridKem::new` rejects a non-C2PRI KEM under `CompatXWing` with `Error::PolicyDenied`; `ct_eq`/`ct_select32` provide the branch-free implicit-rejection primitive |
| Signatures | ML-DSA-44/65/87, SLH-DSA | ✅ the full FIPS-204 family **ML-DSA-44/65/87** (libcrux) wired & tested (NIST ACVP — incl. hedged / context / SHAKE-128 pre-hash modes — + RustCrypto differential each); ML-DSA-65 is the default, ML-DSA-87 the enhanced-mode (L5) signature; **SLH-DSA-SHA2-128s/192s/256s** (fips205) — with **NIST ACVP conformance** (`acvp_slhdsa.rs`) — behind the off-by-default `slh-dsa` feature |
| Crypto-agility / policy | signed policy, downgrade floor, profile select | ✅ `q-periapt-policy`: real TOML loading (`Policy::from_toml`) + **signed-policy verification** (`Policy::load_signed`, fail-closed, plus `load_signed_or_failsafe`); downgrade floor + `negotiate_kem` + `select_profile` enforced |
| KATs / differential tests | X-Wing draft + FIPS 203 ACVP vectors, multi-backend differential | 🟡 byte-exact **X-Wing draft KAT PASSES** (3 official `draft-connolly-cfrg-xwing-kem` vectors); **multi-backend differential PASSES** over the whole KEM chain (`src/differential.rs`) — **ML-KEM-512/768/1024** vs RustCrypto `ml-kem`, X25519 vs `orion` + RFC 7748, and the full `HybridKem` reconstructed from independent ML-KEM + X25519 + SHA3; and **ML-DSA-44/65/87 vs RustCrypto `ml-dsa`** (byte-identical keygen + signatures, cross-verification both directions, tamper rejection) — all byte-identical on random inputs; **NIST ACVP** ground-truth conformance PASSES (`src/acvp.rs`) — the **full FIPS family**: ML-KEM-512/768/1024 (60 cases each, incl. implicit-rejection) + **ML-DSA-44/65/87** keygen/sig **across signature modes** — external/pure (deterministic + **hedged**, with **non-empty contexts**), **HashML-DSA SHAKE-128 pre-hash**, and the **internal interface** (FIPS 204 Alg. 7/8, `externalMu=false`, via the libcrux `acvp` feature) (`acvp_ml_dsa_*_signature_modes`); only `externalMu=true` (no μ-injection entry in libcrux) and non-SHAKE128 pre-hash (libcrux wires only SHAKE-128) remain out of scope; **SLH-DSA-SHA2-{128,192,256}s** (FIPS 205) also have NIST ACVP conformance under the `slh-dsa` feature (`acvp_slhdsa.rs` — deterministic keyGen via a seed-replay RNG, plus sigGen/sigVer); **property-based tests** (proptest, `src/proptests.rs`) hold the combiner + hybrid invariants — binding injectivity, determinism, domain separation, the guards, and KEM round-trip — over random inputs |
| Side-channel CI | indistinguishability gate + dudect + binary-CT matrix | 🟡 failure-path indistinguishability / implicit rejection is a **hard gate** (`ctstats/`); **dataflow constant-time** is a **hard gate** (`constant-time` job: `ct_verify` under Valgrind/Memcheck-TIMECOP over `ct_eq`/`ct_select32`/the combiner); dudect timing stays **report-only** (`\|\| true`); extending binary-CT to the primitive paths + non-x86 targets pending |
| Cross-platform build | x86_64 / aarch64 / riscv64gc / wasm32 / embedded | ✅ CI `cross` job builds `q-periapt-core`+`q-periapt-kem` on x86_64/aarch64/riscv64gc/wasm32; the `no_std` job builds `q-periapt-core` alone on embedded `thumbv7em-none-eabihf` |
| FFI / bindings | C ABI + Swift + Kotlin + WASM, byte-identical results | ✅ all five faces (Rust core, C ABI, WASM/wasm32, Swift, Kotlin/Panama-FFM) reproduce both the hybrid shared vector **and** the combiner reference vectors (`q_periapt_combine` + `bindings/contextbound-vectors.txt`) byte-for-byte |
| Transport / P99 | rustls X25519MLKEM768, HPKE, netem P99 harness | 🟡 `q-periapt-tls-demo` workspace member: loopback server-authenticated hybrid handshake in **two suites** — default (ML-KEM-768 + X25519, ML-DSA-65) and enhanced **L5** (ML-KEM-1024 + X25519, ML-DSA-87) over one generic handshake core — + a report-only P99 bench in CI |
| Auditability tooling | CBOM / SBOM / migration scanner | 🟡 `q-periapt-cli` workspace member emitting CycloneDX CBOM/SBOM in CI |
| Formal models | EasyCrypt combiner binding + Tamarin & ProVerif handshake models | ✅ EasyCrypt: `bind_le_cr` **machine-checked** (`Adv^{X-BIND-K-*} ≤ Adv^{CR}(H)`), `encode_inj` a **proved lemma**, **0 admits**, CI-gated (`formal/easycrypt/BindingViaCR.ec`); the symbolic handshake is **machine-checked by *two independent* provers** — **Tamarin** (`formal/tamarin/handshake.spthy`, 4 lemmas, **CI-gated**) and **ProVerif** (`formal/proverif/handshake.pv`, 5 queries) — both proving server authentication + **hybrid robustness** (the session key survives a break of *either* the PQ *or* the classical KEM; only breaking **both** loses it) |

> The mechanized formal scope is deliberately bounded and stated honestly. The
> machine-checked theorem establishes that the `ContextBound` combiner's binding
> (`MAL-BIND-K-CT`/`K-PK`/`K-CTX`) reduces **only** to collision-resistance of the
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

### Crate tree

```
q-periapt/
├── crates/
│   ├── q-periapt-core      # ✅ dependency-free no_std core: combiner + transcript binding + primitive traits
│   ├── q-periapt-kem       # ✅ hybrid KEM (ML-KEM-768 + X25519) + pluggable HQC, generic over backends; C2PRI guard
│   ├── q-periapt-sig       # ✅ signature trait surface: ML-DSA-65/87, SLH-DSA (roots/firmware/long-term)
│   ├── q-periapt-backends  # ✅ vetted backends: libcrux ML-KEM/ML-DSA/SHA3, x25519-dalek, fips205, pqcrypto-hqc
│   ├── q-periapt-policy    # ✅ crypto-agility policy engine: TOML + signed-policy verification, no hardcoded algorithms
│   ├── q-periapt-ffi       # 🟡 stable C ABI (cdylib + staticlib + cbindgen header)
│   ├── q-periapt-wasm      # 🟡 wasm-bindgen surface (pure-Rust backends only)
│   ├── q-periapt-tls-demo  # 🟡 loopback PQ/T hybrid handshake + P99 harness
│   └── q-periapt-cli       # 🟡 migration inventory + CBOM/SBOM generator
├── ctstats/          # ✅ side-channel CI: indistinguishability hard gate + dudect report
├── docs/             # BINDING_SECURITY.md, COMBINER_SPEC.md, ARCHITECTURE.md, ...; policy/default.policy.toml
├── formal/easycrypt/ # ✅ machine-checked binding proof (BindingViaCR.ec); tamarin/ planned
├── tests/            # kat/ + differential/ (X-Wing KAT currently lives in q-periapt-backends)
├── bench/  fuzz/  sbom/   # harness scaffolds (combiner bench lives in q-periapt-backends/benches/)
└── bindings/         # swift/ + kotlin/ (exercised in CI against a shared test vector)
```

All crates above plus `ctstats` are Cargo workspace `members` (see `Cargo.toml`).

### Architecture in one line

`q-periapt-core` is **dependency-free and `no_std`** (zero crypto crates) and contains
only the security-critical *composition* logic — the combiner and its binding.
Primitives (ML-KEM, X25519, HQC, SHA3/SHAKE) are injected through the `Kem`,
`Xof256` (and forthcoming `Dh` / `Hash` / `Sig`) traits, so the audited surface
stays tiny and reviewable in isolation. Because primitives live in swappable
backends, the constant-time guarantee is **per-(backend, arch)**: backend
selection changes the CT posture, and each backend must carry its own independent
CT attestation. The differential testing (the whole KEM chain — ML-KEM-768, X25519,
and the full hybrid — vs independent implementations) proves *output equality*, never
CT equality.

## Status & disclaimer

This is a **research artifact for an undergraduate thesis**, not a product.

- **Not audited. Not FIPS-validated. Not production-ready.**
- **What is real now** (each grounded in committed code — read it before relying on
  any of it):
  - Real vetted backends are wired in `q-periapt-backends`: ML-KEM-768 / ML-DSA-65 /
    SHA3-256 via libcrux, X25519 via x25519-dalek, with SLH-DSA (fips205) and HQC
    (pqcrypto-hqc) behind off-by-default features. The hybrid KEM round-trips under
    both combiner profiles with these real backends.
  - The byte-exact X-Wing draft KAT **passes** against the 3 official
    `draft-connolly-cfrg-xwing-kem` vectors (`q-periapt-backends/src/xwing_kat.rs`).
    Beyond that, the **full NIST ACVP conformance set passes** (`src/acvp.rs`):
    ML-KEM-512/768/1024 + ML-DSA-44/65/87 (incl. the broader signature modes) and
    SLH-DSA-SHA2-{128,192,256}s. That is conformance to the published vectors — **not**
    CMVP/CAVP certification (no formal FIPS validation is claimed).
  - Combiner safety guards are implemented: `CompatXWing` hard-checks all four
    fields are exactly 32 bytes (`q-periapt-core` `combine`); `HybridKem::new`
    forbids a non-C2PRI KEM under `CompatXWing` (`Error::PolicyDenied`), confining
    X25519/HQC to `ContextBound`; and `ct_eq`/`ct_select32` give the branch-free
    implicit-rejection primitive with a side-channel-safe, secret-free `Error`.
  - `q-periapt-policy` does real TOML loading **and** signed-policy verification
    (`Policy::load_signed` authenticates the exact policy bytes via an injected
    SLH-DSA-intended `Verifier` before trusting them, fail-closed;
    `load_signed_or_failsafe` falls back to the L5/`ContextBound` posture), with the
    downgrade floor and negotiation enforced.
  - The EasyCrypt binding theorem is **machine-checked** with 0 admits, and
    `encode_inj` is now a proved lemma rather than an axiom
    (`formal/easycrypt/BindingViaCR.ec`); CI hard-gates against any reintroduced
    `admit`/`sorry`.
- **`Secret`** is securely zeroized on drop (volatile write + compiler fence — the
  `zeroize` technique, inlined to keep the core dependency-free) and is **not**
  `Clone`/`Copy`, so no copy can outlive the wipe. The core is `#![deny(unsafe_code)]`
  with that single, documented wipe block as the only `unsafe`.
- **Still scaffolded / pending** (do not assume these are finished): extending
  binary-level constant-time over the libcrux *primitive* paths + non-x86 (the dataflow
  CT gate over our **composition** code is done); a production rustls `CryptoProvider`
  over the FFI; and the libcrux-gated `externalMu=true` / non-SHAKE128 pre-hash ACVP
  modes. **Done since earlier drafts** (no longer pending): the full NIST ACVP set
  (ML-KEM-512/768/1024 + ML-DSA-44/65/87 incl. the hedged/context, SHAKE-128 pre-hash and
  internal-interface signature modes + SLH-DSA), the multi-backend differentials, the
  `ContextBound` reference vectors, the cargo-fuzz targets, and **both** the Tamarin and
  ProVerif machine-checked handshake proofs (`formal/`).
- **HQC is excluded from the side-channel claim**: its decoder has documented
  data-dependent timing and `pqcrypto-hqc` wraps C (breaks `no_std`). It is a
  strictly feature-gated, experimental *hedge*, never a default.
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
- [`docs/COMPETITIVE_ANALYSIS.md`](docs/COMPETITIVE_ANALYSIS.md) — honest win / cannot-win table vs X-Wing / PQ3 ✅
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — milestones M0–M5 and exit criteria ✅
- [`formal/easycrypt/README.md`](formal/easycrypt/README.md) — the mechanized binding proof: `BindingViaCR.ec`, scope, and how to reproduce `make check` ✅
- [`docs/policy/default.policy.toml`](docs/policy/default.policy.toml) — example agility policy ✅

## License

Apache-2.0 OR MIT, at your option.
