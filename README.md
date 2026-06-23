# PQ/T Hybrid Cryptographic Suite

> [!WARNING]
> **Status: pre-alpha scaffold (v0.0.1). Research / undergraduate-thesis project.
> NOT audited. NOT FIPS-validated. Do not use in production, and do not use it to
> protect anything you care about.** No cryptographic backend is wired yet — the
> combiner is currently exercised only with a non-cryptographic toy hash. See
> [Status & disclaimer](#status--disclaimer) for exactly what does and does not
> exist today.

A portable, `no_std`, **side-channel-resistant-first** post-quantum / traditional
(PQ/T) hybrid cryptographic suite, built around a single dependency-free Rust core
(`pqt-core`) that vetted primitive backends are injected into through traits, and
that is intended to be reused unchanged across C, WASM, Swift and Kotlin. The
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
SHAKE, not the combiner hash. Concrete cycle counts will be **measured** in the M4
benchmark harness per backend/arch and are not asserted here.

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
- **Side-channel CI as a product feature** — empirical timing tests (dudect-style
  Welch t-test) plus static / binary-level constant-time re-verification, because
  source-level CT does not survive the compiler (clangover, KyberSlash). This is
  *planned and partially scoped*, not yet built (see status below).
- **Audit transparency** — CBOM (CycloneDX crypto-bill-of-materials) + SBOM +
  migration-inventory tooling + a machine-checked combiner model (all planned).
- **P99 transport measured on the right constraint** — the differentiator is the
  *methodology* (P99 handshake completion on emulated lossy / high-RTT links,
  where pure encap/decap microbenchmarks mis-rank designs), not the transport
  techniques themselves (IW10 budgeting, cert compression, resumption are standard
  TLS/QUIC engineering that mainstream stacks already do).

### Where it explicitly cannot win

- **Combiner CPU speed** — more binding is strictly more hashing. `CompatXWing`
  targets *parity* with X-Wing; `ContextBound` is intentionally slower.
- **Primitive performance** — it wires libcrux / RustCrypto / aws-lc-rs; it will
  not out-perform AVX2 ML-KEM or FIPS-validated AWS-LC. This is a composition /
  safety layer, not a faster primitive.
- **FIPS 140-3 validation out of the box** — the pure-Rust `no_std` core is **not**
  FIPS-validated. aws-lc-rs (AWS-LC FIPS) is offered as a backend for that
  requirement; the project makes no validation claim of its own.
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
| Auditable `no_std` core | dependency-free combiner + traits, builds bare-metal | ✅ `pqt-core` (266 LOC, zero crypto deps, `#![forbid(unsafe_code)]`, builds `thumbv7em-none-eabihf`) |
| Hybrid KEM | ML-KEM-768 + X25519, HQC backup | 🟡 `pqt-kem` trait wiring only — **no primitive backend wired** |
| Combiner profiles | `CompatXWing` (parity) + `ContextBound` (binding) | 🟡 both profiles implemented over a trait XOF; currently tested with a **toy non-crypto hash** only |
| Combiner safety guards | C2PRI guard, 32-byte length checks, implicit rejection | ⛔ **not implemented** (known critical gap — see status) |
| Signatures | ML-DSA-65/87, SLH-DSA + 2²⁴ key cap | 🟡 `pqt-sig` traits only — no backend, no key-usage guard |
| Crypto-agility / policy | signed CBOR/TOML policy, downgrade floor, profile select | 🟡 `pqt-policy` in-memory struct; **no signing, no enforcement, no TOML parsing** |
| KATs / differential tests | X-Wing draft-10 + FIPS 203 ACVP vectors, 3-backend triple | ⛔ `tests/kat/`, `tests/differential/` empty — **byte-exact parity unverified** |
| Side-channel CI | dudect + ctgrind/TIMECOP + binary-CT matrix + clangover cells | ⛔ comment-only placeholders in CI; harnesses not written |
| Cross-platform build | x86_64 / aarch64 / riscv64gc / wasm32 / embedded | ✅ CI builds `pqt-core`(+`pqt-kem`) green across all five targets |
| FFI / bindings | C ABI + Swift + Kotlin + WASM, byte-identical results | ⛔ `pqt-ffi`/`pqt-wasm`/`bindings/*` scaffolded (no `src/`, not workspace members) |
| Transport / P99 | rustls X25519MLKEM768, HPKE, netem P99 harness | ⛔ `pqt-tls-demo` scaffolded only |
| Auditability tooling | CBOM / SBOM / migration scanner | ⛔ `pqt-cli` scaffolded only |
| Formal models | EasyCrypt combiner PQ-case + Tamarin handshake | ⛔ `formal/{easycrypt,tamarin,proverif}` empty |

> The MVP formal scope, when it lands, is intentionally partial: a standard-model
> PQ IND-CCA reduction for the context-bound combiner (`H`-as-PRF, PQ-KEM
> black-box, C2PRI as a declared axiom) plus a Tamarin symbolic handshake model.
> The classical ROM+SDH case and a full computational handshake proof are **out of
> MVP scope**. Until proofs exist, "machine-checked proof" is a roadmap item, not
> a current property.

## Quickstart

Requires a stable Rust toolchain (`rustup` recommended). Only the four core crates
are workspace members today; the rest are scaffolded.

```sh
git clone <repo-url> pqt_hybrid_suite
cd pqt_hybrid_suite

cargo build --workspace          # build the implemented crates
cargo test  --workspace          # unit tests (toy-hash combiner wiring, no KATs yet)
cargo clippy --workspace --all-targets

# Prove the security-critical core is dependency-free and builds bare-metal no_std:
rustup target add thumbv7em-none-eabihf
cargo build -p pqt-core --target thumbv7em-none-eabihf

# Cross-platform behavioural consistency (same code, every ISA):
rustup target add aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu wasm32-unknown-unknown
cargo build -p pqt-core -p pqt-kem --target wasm32-unknown-unknown
```

### Crate tree

```
pqt_hybrid_suite/
├── crates/
│   ├── pqt-core      # ✅ dependency-free no_std core: combiner + transcript binding + primitive traits
│   ├── pqt-kem       # 🟡 hybrid KEM (ML-KEM-768 + X25519) + pluggable HQC, generic over backends
│   ├── pqt-sig       # 🟡 signature surface: ML-DSA-65/87, SLH-DSA (roots/firmware/long-term)
│   ├── pqt-policy    # 🟡 crypto-agility policy engine (no hardcoded algorithms)
│   ├── pqt-ffi       # ⛔ stable C ABI (cdylib + staticlib + cbindgen header)        [scaffold]
│   ├── pqt-wasm      # ⛔ wasm-bindgen surface (pure-Rust backends only)             [scaffold]
│   ├── pqt-tls-demo  # ⛔ rustls TLS 1.3 / QUIC / HPKE integration + P99 harness     [scaffold]
│   └── pqt-cli       # ⛔ migration inventory + CBOM/SBOM generator                  [scaffold]
├── docs/             # policy/default.policy.toml (further docs are roadmap items)
├── formal/           # easycrypt / tamarin / proverif (empty placeholders)
├── tests/            # kat/ + differential/ (empty placeholders)
├── bench/  ctstats/  fuzz/  sbom/   # harness placeholders
└── bindings/         # swift/ + kotlin/ (placeholders)
```

Only `pqt-core`, `pqt-kem`, `pqt-sig`, and `pqt-policy` are in the Cargo workspace
`members`; the four scaffolded crates are added as they are implemented.

### Architecture in one line

`pqt-core` is **dependency-free and `no_std`** (zero crypto crates) and contains
only the security-critical *composition* logic — the combiner and its binding.
Primitives (ML-KEM, X25519, HQC, SHA3/SHAKE) are injected through the `Kem`,
`Xof256` (and forthcoming `Dh` / `Hash` / `Sig`) traits, so the audited surface
stays tiny and reviewable in isolation. Because primitives live in swappable
backends, the constant-time guarantee is **per-(backend, arch)**: backend
selection changes the CT posture, and each backend must carry its own independent
CT attestation. The (planned) differential triple proves *output equality*, never
CT equality.

## Status & disclaimer

This is a **research artifact for an undergraduate thesis**, not a product.

- **Not audited. Not FIPS-validated. Not production-ready.**
- **No cryptographic backend is wired.** The combiner is currently exercised with
  a non-cryptographic FNV-style toy hash to verify wiring/determinism only. The
  byte-exact X-Wing parity claim is therefore **unverified**: there are no
  committed KAT vectors yet.
- **Known critical gaps tracked for the next milestones** (do not rely on the
  current code for any security property):
  - No `Kem::C2PRI` guard — nothing yet prevents misusing `CompatXWing` with a
    non-C2PRI KEM, which would break the IND-CCA argument.
  - No `CompatXWing` field-length validation (each X-Wing field must be exactly
    32 bytes; missing checks allow a length-ambiguity / canonicalization break).
  - No implicit-rejection / constant-time `cmov` decapsulation path yet.
  - `pqt-policy` does no signing, no downgrade-floor enforcement, and no TOML
    parsing; the policy file is not yet consumed by code.
  - Side-channel CI cells, fuzz targets, CBOM/SBOM, FFI, transport, and formal
    proofs are placeholders.
- **`Secret`** uses a best-effort `black_box` wipe (not the audited `zeroize`
  crate) and still derives `Clone`; treat zeroization as incomplete.
- **HQC is excluded from the side-channel-resistant claim**: its decoder has
  documented data-dependent timing and `pqcrypto-hqc` wraps C (breaks `no_std`).
  It is a strictly feature-gated, experimental *hedge*, never a default.
- Backends to be wired are pre-release / unaudited to varying degrees (libcrux is
  `<0.1` / contact-maintainers-before-production; RustCrypto is unaudited;
  aws-lc-rs is the FIPS path). Versions will be pinned and kept swappable for
  differential testing and CVE mitigation.

Use it to read, learn from, and critique the *composition and CI methodology*. Do
not deploy it.

## Docs

Authoritative documents (first drafts present; refined as the code lands):

- [`docs/BINDING_SECURITY.md`](docs/BINDING_SECURITY.md) — **binding/committing security**: target notion (`MAL-BIND-K-CT`/`K-PK`), construction, EasyCrypt proof plan, honest claim vs X-Wing ✅
- [`docs/COMBINER_SPEC.md`](docs/COMBINER_SPEC.md) — combiner definition + test-vector plan ✅
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — core/backend split, trait surface ✅
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, adversary, mitigations ✅
- [`docs/COMPETITIVE_ANALYSIS.md`](docs/COMPETITIVE_ANALYSIS.md) — honest win / cannot-win table vs X-Wing / PQ3 ✅
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — milestones M0–M5 and exit criteria ✅
- [`formal/easycrypt/README.md`](formal/easycrypt/README.md) — mechanized-proof plan (the formal half) ✅
- [`docs/policy/default.policy.toml`](docs/policy/default.policy.toml) — example agility policy ✅

## License

Apache-2.0 OR MIT, at your option.
