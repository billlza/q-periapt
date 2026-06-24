# Q-Periapt — Architecture

Authoritative architecture document for **Q-Periapt**, a portable, `no_std`,
side-channel-first PQ/T (post-quantum / traditional) hybrid cryptographic suite.

> **Status: research-grade, not production.** Q-Periapt ships the *same* NIST
> primitives everyone else does (ML-KEM-768, X25519, ML-DSA-65/87, SLH-DSA, HQC)
> through vetted third-party backends. It has **no third-party audit**, and it
> depends on pre-1.0 / unaudited backends (e.g. `libcrux-ml-kem` 0.0.9, whose own
> notice asks you to contact the maintainers before production use). **Do not
> deploy.** The value proposition is *not* primitive or speed superiority — it is
> auditable composition, crypto-agility, side-channel CI, machine-checked binding
> proofs, and byte-identical cross-platform behavior.

For the security argument behind the combiner, read
[`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md) (authoritative) and the
EasyCrypt development under [`formal/easycrypt/`](../formal/easycrypt/). For the
exact wire format, read [`docs/COMBINER_SPEC.md`](COMBINER_SPEC.md).

---

## 1. The one idea

There is **one** dependency-free, `no_std` Rust core — `q-periapt-core` — that
contains *only* the security-critical composition logic: the hybrid-KEM
**combiner**, its **binding/encoding**, the **primitive trait surface**, and the
**constant-time helpers**. It implements **no cryptographic primitive**. Every
primitive (ML-KEM, X25519, HQC, SHA3/SHAKE, ML-DSA, SLH-DSA) is *injected*
through a trait.

That same core is reused, unchanged, across **four non-Rust faces**: a C
ABI, a WASM surface, and Swift / Kotlin language bindings (the latter two built on
the C ABI). All faces are validated **byte-identical** against a single shared
reference vector.

```
                         injected primitives
                    (Kem / Xof256 / Signer / Verifier)
                                  │
                                  ▼
   ┌───────────────────────────────────────────────────────────┐
   │  q-periapt-core   (no_std, dependency-free, deny unsafe)    │
   │  • combine()  — CompatXWing | ContextBound                  │
   │  • CombineInput / absorb_lp (injective LP encoding)         │
   │  • traits: Kem (+ C2PRI), Xof256                            │
   │  • Secret (zeroize-on-drop, not Clone)                      │
   │  • ct_eq / ct_select32 / ct_is_zero                         │
   └───────────────────────────────────────────────────────────┘
                                  ▲
        ┌─────────────────────────┼──────────────────────────┐
        │                         │                          │
  q-periapt-kem            q-periapt-sig              (Signer/Verifier
  HybridKem<P,T,X>         SigAlg / Signer /           trait surface)
  (C2PRI guard)            Verifier traits
        │                         │
        └────────────┬────────────┘
                     ▼
            q-periapt-backends            q-periapt-policy
   real vetted primitives wired           crypto-agility engine
   into the traits:                       (depends on -core + -sig):
   • MlKem768  (libcrux, C2PRI)           • Policy / from_toml / load_signed
   • X25519    (x25519-dalek)             • downgrade floor / negotiate_kem
   • Sha3_256Xof (libcrux-sha3)           • select_profile
   • MlDsa65   (libcrux-ml-dsa)
   • [feature slh-dsa] SlhDsa*  (fips205)
   • [feature hqc]     Hqc*     (pqcrypto-hqc)
                     │
   ┌─────────────────┼───────────────────┬───────────────────┐
   ▼                 ▼                   ▼                   ▼
 q-periapt-ffi   q-periapt-wasm    q-periapt-cli      bindings/{swift,kotlin}
 (C ABI:         (wasm-bindgen)    (CBOM / SBOM /     (Swift over staticlib;
 cdylib +                          migration scan)    Kotlin over Panama FFM —
 staticlib +                                          both consume the C ABI)
 cbindgen .h)
```

The workspace members are listed in [`Cargo.toml`](../Cargo.toml):
`q-periapt-core`, `-kem`, `-sig`, `-policy`, `-backends`, `-ffi`, `-wasm`,
`-tls-demo`, `-cli`, and `ctstats`.

---

## 2. Why this shape

**Auditable composition reviewable in isolation.** Hybrid KEMs fail at the
*seams*, not in the primitives: a combiner that omits a ciphertext from its KDF,
or concatenates fields ambiguously, breaks binding regardless of how good ML-KEM
is. Q-Periapt therefore quarantines exactly that risky logic into `q-periapt-core`
— a crate with **zero dependencies**, `#![no_std]`, and `#![deny(unsafe_code)]`
with a *single* documented `unsafe` block (the `Secret` wipe). A reviewer can read
the whole security-relevant surface — combiner, encoding, traits, CT helpers — in
one file (`crates/q-periapt-core/src/lib.rs`, a few hundred lines) without auditing
any primitive implementation. The primitives are someone else's verified code; the
*glue* is ours and is kept small enough to verify by eye and by proof.

**One core, reused across four non-Rust faces.** Because primitives are injected through
traits, the same combiner runs against any backend and on any platform. The C ABI,
WASM, Swift, and Kotlin faces are thin marshaling layers over the identical Rust
logic — there is no re-implementation per platform, so there is one thing to audit,
not six. This is also what makes the byte-identical cross-platform guarantee
*possible* and *cheap* to test (§6).

**Crypto-agility lives in policy, not in code.** Algorithm choices are data
(`q-periapt-policy`), not hardcoded constants, so migration (L3 → L5, enabling an
HQC backup, deprecating an algorithm) is a config change and a minimum-NIST-level
floor gives downgrade protection.

---

## 3. The dependency-free core (`q-periapt-core`)

`crates/q-periapt-core/src/lib.rs`. `#![cfg_attr(not(test), no_std)]`,
`#![deny(unsafe_code)]`. **No primitive implementations.**

### 3.1 Injected primitive traits

| Trait | Method surface | Contract |
|---|---|---|
| `Kem` | `algorithm()`, `encapsulate()`, `decapsulate()`, `const C2PRI: bool` | Constant-time w.r.t. secrets; `decapsulate` **must** use implicit rejection and must NOT return `Error` to signal an invalid ciphertext (only public conditions). `C2PRI` defaults to `false` (the safe choice). |
| `Xof256` | `new()`, `absorb()`, `squeeze32()` | Incremental hash/XOF producing 32 bytes; constant-time w.r.t. absorbed data. |
| `Signer` / `Verifier` | in `q-periapt-sig` (see §5) | — |

The core never names ML-KEM, X25519, SHA3, etc. — it only sees `impl Kem` /
`impl Xof256`. Concrete types live in `q-periapt-backends` (§4).

### 3.2 The combiner: two profiles

`combine::<X: Xof256>(profile, &CombineInput) -> Result<Secret, Error>` is the
heart of the suite. `CombineInput` carries slices (`suite_id`, `policy_version`,
`ss_pq`, `ss_trad`, `ct_pq`, `pk_pq`, `ct_trad`, `pk_trad`, `context`), so it works
for any parameter set.

**`Profile::CompatXWing` — byte-exact X-Wing.**
Computes `SHA3-256(ss_pq || ss_trad || ct_trad || pk_trad || XWING_LABEL)` where
`XWING_LABEL` is the 6-byte `\.//^\` from `draft-connolly-cfrg-xwing-kem`. The four
32-byte fields are concatenated with **no** length prefixes for byte-exactness, but
each is **hard-checked** to be exactly `SHARED_SECRET_LEN` (32) first — otherwise
arbitrary-length slices could collide across field boundaries (33+31 vs 32+32) and
collapse domain separation; a wrong length returns `Error::InvalidLength`. The
absorbed input is a single 134-byte block (≤ Keccak rate 136) and the path is
allocation-free. This profile deliberately does **not** bind the PQ ciphertext/
pubkey, nor `suite_id` / `policy_version` / `context` — it relies on the PQ KEM
being `C2PRI` (§3.4). It **is** X-Wing byte-for-byte (verified, §6).

**`Profile::ContextBound` — GHP/"hash everything".**
The conservative profile. Domain-separated by
`DOMAIN = b"Q-PERIAPT-HYBRID-KEM/v1"`, and every field is absorbed via `absorb_lp`,
which prepends a **fixed-width 8-byte big-endian length prefix** before the data.
That fixed width makes the encoding **injective**: distinct field tuples — including
ones differing only in where a field boundary falls — can never map to the same byte
string. Injectivity is the load-bearing step that reduces binding to XOF
collision-resistance (`docs/BINDING_SECURITY.md` §3.2). The canonical field order is:

```
0 DOMAIN, 1 suite_id, 2 policy_version, 3 ss_pq, 4 ss_trad,
5 ct_pq, 6 pk_pq, 7 ct_trad, 8 pk_trad, 9 context
```

`ContextBound` binds the **agility block** (`suite_id`, `policy_version`)
first-class for downgrade/substitution resistance, binds **every** component
ciphertext and public key, and requires a **mandatory non-empty `context`** (an
empty context returns `Error::InvalidLength`; callers with no application context
pass a fixed protocol/role/version label). Because it hashes the full ~2.5 KB of
ML-KEM-768 + X25519 material with length prefixes, it costs roughly **19× more
combiner hashing** than `CompatXWing`. That cost is deliberate and is a tiny
fraction of a full handshake.

### 3.3 Performance positioning (measured, honest)

Benchmarked in [`crates/q-periapt-backends/benches/combiner.rs`](../crates/q-periapt-backends/benches/combiner.rs)
against a faithful streaming X-Wing reference built on RustCrypto `sha3`:

- `CompatXWing` **is** X-Wing byte-for-byte; our generic combiner runs at **~parity**
  — in fact tens of ns *slower* than a hand-rolled streaming X-Wing through our trait
  abstraction. That is negligible: the combiner is **< 1%** of a handshake.
- `ContextBound` is intentionally ~19× more combiner hashing than `CompatXWing`.

**We never claim "faster than X-Wing."** There is no primitive or speed edge — the
primitives are the standard ones via standard backends. The wins are provable
binding, crypto-agility, side-channel CI, byte-identical cross-platform behavior,
and auditability.

### 3.4 The C2PRI safety guard

`CompatXWing` omits the PQ ciphertext from the KDF. That is sound **only** when the
PQ KEM is *ciphertext second-preimage resistant* (C2PRI) — true for ML-KEM-768 (FO
transform), false for X25519-as-KEM and HQC-as-wired. The guard is enforced in two
layers:

1. `Kem::C2PRI` is an associated `const` (default `false`); only proven-C2PRI
   backends override it to `true` (`MlKem768::C2PRI = true`).
2. `HybridKem::new` (in `q-periapt-kem`) rejects `CompatXWing` paired with a
   non-C2PRI PQ KEM, returning `Error::PolicyDenied`. This confines X25519/HQC to
   `ContextBound`, which binds all ciphertexts.

### 3.5 `Secret` and constant-time helpers

`Secret` wraps the 32-byte combined key. On `Drop` it is securely wiped with
**volatile zero writes** (which the optimizer may not elide) followed by a
**compiler fence** — the `zeroize` crate's technique, inlined to keep the core
dependency-free. This wipe is the **only** `unsafe` block in the crate (hence
`deny`, not `forbid`). `Secret` is intentionally **not** `Clone`/`Copy`: a combined
key has a single owner so no copy survives past the wipe.

The CT helpers — `ct_eq` (branch-free byte-slice equality → `0xFF`/`0x00`),
`ct_select32` (branch-free 32-byte select, the primitive for implicit rejection),
and `ct_is_zero` — are best-effort in portable Rust. See §7 for the honest scope of
the side-channel assurance.

### 3.6 The `Error` type

`Error` is deliberately coarse — `InvalidLength`, `Backend`, `PolicyDenied` — and
`#[non_exhaustive]`. Every variant corresponds to a **publicly observable** condition
(buffer length, policy). It **must never** encode secret-dependent information such
as *why* a decapsulation failed; failure paths are designed to be indistinguishable.

---

## 4. Backends (`q-periapt-backends`)

`crates/q-periapt-backends/src/lib.rs`. The **only** crates that touch real
cryptographic primitives. Each is a zero-sized type implementing a core trait:

| Backend | Primitive | Crate | Notes |
|---|---|---|---|
| `MlKem768` | ML-KEM-768 (FIPS 203) | `libcrux-ml-kem` 0.0.9 (HACL*-derived, constant-time) | `Kem`, `C2PRI = true`. Takes randomness as explicit bytes — deterministic / KAT-able / `no_std`. |
| `X25519` | X25519 ECDH-as-KEM | `x25519-dalek` 2 | `Kem`, non-C2PRI; deterministic from a 32-byte scalar. |
| `Sha3_256Xof` | SHA3-256 | `libcrux-sha3` 0.0.9 | `Xof256`; the combiner XOF. |
| `MlDsa65` | ML-DSA-65 (FIPS 204) | `libcrux-ml-dsa` 0.0.9 | `Signer` + `Verifier`. |
| `SlhDsaSha2_128s/256s` | SLH-DSA (FIPS 205) | `fips205` 0.4.1 | **feature `slh-dsa`** (off by default). |
| `Hqc128/256` | HQC | `pqcrypto-hqc` 0.2.2 (PQClean C) | **feature `hqc`** (off by default); std/native only, unaudited, non-deterministic encaps. |

These backends are reused by `q-periapt-ffi`, `q-periapt-wasm`, the binding
test-vector generator (`examples/refvec.rs`), and the X-Wing KAT.

### 4.1 Feature gating

From [`crates/q-periapt-backends/Cargo.toml`](../crates/q-periapt-backends/Cargo.toml):

```toml
[features]
default = []
std     = ["q-periapt-core/std"]
slh-dsa = ["dep:fips205"]
hqc     = ["dep:pqcrypto-hqc", "dep:pqcrypto-traits"]
```

`slh-dsa` and `hqc` are **optional and off by default**. `dep:` gating keeps them
out of the default, `wasm32`, and `no_std` builds entirely — so the
verified-green build matrix stays green. HQC in particular pulls PQClean C through
`cc` (std/native only) and is fenced off `wasm32`/`no_std` with a `compile_error!`.
The default suite — and the C ABI / WASM faces — is exactly **ML-KEM-768 + X25519**
with SHA3-256. The **enhanced** posture (NIST level 5) suite **ML-KEM-1024 + X25519**
is also instantiated at the Rust-core layer as a real `HybridKem<MlKem1024, X25519,
Sha3_256Xof>` under `ContextBound`, pinned by an end-to-end, independently-cross-checked
KAT (`q-periapt-backends/src/enhanced_kat.rs`, `suite_id = "ML-KEM-1024+X25519"`). It is
**not** exposed through the deliberately fixed-suite C ABI / WASM faces — those remain
ML-KEM-768 + X25519 only.

---

## 5. Signature layer (`q-periapt-sig`)

`crates/q-periapt-sig/src/lib.rs`. `no_std`, `forbid(unsafe_code)`. Defines the
algorithm-agnostic surface that policy and FFI build on:

- `SigAlg`: `MlDsa65`, `MlDsa87` (FIPS 204), `SlhDsaSha2_{128s,192s,256s}`
  (FIPS 205), each with a stable `id()` string and `nist_level()`.
- `Signer` / `Verifier` traits. `Signer::sign` takes caller-supplied `randomness`
  (the signing nonce) so signing is deterministic and KAT-able with no internal RNG;
  pass all-zero for deterministic signing.

ML-DSA-65/87 are the general-purpose signatures; SLH-DSA (hash-based, minimal
assumptions, large/slow) is reserved for the most conservative trust anchors —
roots, firmware, and the signed-policy root key (§8).

---

## 6. The faces and the byte-identical guarantee

The headline interop property is **byte-identical results across platforms**, made
executable by validating every face against **one shared oracle**.

### 6.1 The shared reference vector

[`bindings/shared-test-vectors.json`](../bindings/shared-test-vectors.json) is
generated *from the Rust core*:

```sh
cargo run -p q-periapt-backends --example refvec > bindings/shared-test-vectors.json
```

It is a full `ContextBound` vector (`profile_code: 2`,
`suite_id = "ML-KEM-768+X25519"`, `policy_version: 1`, a fixed non-empty `context`,
both secret/public keys, encapsulation randomness, both ciphertexts, and the
resulting 32-byte `secret`). Every binding's test suite `decapsulate`s the
vector's inputs and asserts the result equals `secret` (the ML-KEM/X25519 backends
are deterministic, so re-encapsulation reproduction of `ct_pq`/`ct_trad` is a planned
addition). **If any platform disagrees by a single byte, that suite fails** — that is
the cross-platform guarantee, made executable.

### 6.2 The faces

| Face | Crate / dir | Surface | Consistency check |
|---|---|---|---|
| **Rust core** | `q-periapt-core` / `-kem` | source of truth | `cargo test` (combiner KATs, X-Wing KAT) |
| **C ABI** | `q-periapt-ffi` | `cdylib` + `staticlib`; cbindgen header `include/q_periapt.h`; `int32` status codes; every entry `catch_unwind`-wrapped | `cargo test -p q-periapt-ffi` (`ffi_matches_shared_vector`) |
| **WASM** | `q-periapt-wasm` | `wasm-bindgen`; JS supplies randomness as `Uint8Array` | `cargo test -p q-periapt-wasm`; CI builds `wasm32` |
| **Swift** | `bindings/swift/` | links the C `staticlib` | `swift test` (CI: `bindings-swift`, macOS) |
| **Kotlin** | `bindings/kotlin/` | Panama **FFM** over the C ABI, JDK ≥ 22 | `gradle test` (CI: `bindings-kotlin`) |

All four non-Rust faces decapsulate `shared-test-vectors.json` to the same 32-byte
secret, byte-for-byte, gated in CI.

### 6.3 The C ABI in detail (`q-periapt-ffi`)

`crates/q-periapt-ffi/src/lib.rs`. Fixed to the default suite ML-KEM-768 + X25519 +
SHA3-256. ABI conventions:

- Every function returns an `int32` status: `Q_PERIAPT_OK` (0) or a negative error
  (`_ERR_NULL`, `_ERR_LENGTH`, `_ERR_POLICY`, `_ERR_PANIC`, `_ERR_INTERNAL`). Errors
  encode **only public conditions** — never secret-dependent information.
- Buffers are `(ptr, len)` pairs with validated lengths; length constants are
  emitted as numeric `#define`s and pinned to the backend by `const _: () = { assert! }`
  so they cannot silently drift.
- `decapsulate` returns `Q_PERIAPT_OK` for any syntactically valid (correct-length)
  ciphertext even if cryptographically invalid — implicit rejection yields a
  pseudorandom secret, so there is **no decapsulation oracle**.
- Every entry point is wrapped in `catch_unwind`; a panic becomes `Q_PERIAPT_ERR_PANIC`
  rather than unwinding across the ABI (which would be UB).

The C header (`crates/q-periapt-ffi/include/q_periapt.h`) is generated by cbindgen
and is what Swift and Kotlin consume.

### 6.4 X-Wing conformance KAT

`crates/q-periapt-backends/src/xwing_kat.rs` drives `HybridKem<_,_,Sha3_256Xof>`
under `CompatXWing` with X-Wing's key expansion (`SHAKE-256(seed, 96)`) and
encapsulation-coin split, and asserts the ML-KEM-768 public key, ciphertext, and
shared secret against **3 official `draft-connolly-cfrg-xwing-kem` vectors**. This
proves the combiner **reproduces the FIPS 203 reference output on those 3 happy-path
vectors** byte-for-byte. (Beyond these, the full NIST ACVP set for ML-KEM-512/768/1024
+ ML-DSA-44/65/87 also passes in `acvp.rs` — broad conformance to the published
vectors, though not CMVP/CAVP certification.)

---

## 7. Side-channel posture (honest scope)

- **Failure-path indistinguishability / implicit rejection is a HARD CI gate**
  (the `ctstats` crate). An invalid ciphertext must produce a pseudorandom secret,
  not an error, so the failure path is indistinguishable from success. This is
  gated.
- **The `dudect` timing test is REPORT-ONLY.** It runs (with `|| true`) and reports,
  but is **not** a merge gate.
- **Binary-level (dataflow) constant-time** over our own composition code (`ct_eq`,
  `ct_select32`, the combiner) is a **HARD CI gate** (`constant-time` job: `ct_verify`
  under Valgrind/Memcheck-TIMECOP, x86_64 + aarch64). Extending it over the libcrux
  *primitive* paths and to riscv64/wasm32 is **TODO** (see `docs/THREAT_MODEL.md` §5.2).

So: do **not** read "side-channel-first" as "timing is gated." Structural failure-path
indistinguishability **and** binary-level dataflow CT over our composition code are gated;
the statistical `dudect` *timing* test and binary-CT over the primitive paths are
report-only / pending. Real constant-time assurance is per-backend and tracked in
`docs/ROADMAP.md`.

---

## 8. Crypto-agility & policy (`q-periapt-policy`)

`crates/q-periapt-policy/src/lib.rs`. `forbid(unsafe_code)`. Depends on
`q-periapt-core` and `q-periapt-sig`. Applications ask the policy "is this
allowed?", "does it meet the floor?", "which profile?" instead of naming concrete
algorithms inline.

- **`Policy`** carries `min_nist_level` (downgrade floor), `default_profile`,
  `allowed_kems`, `allowed_sigs`, `deprecated`. `Default` is the L3 / `CompatXWing`
  posture; `enhanced()` is L5 / `ContextBound` with an HQC backup for assumption
  diversity.
- **Downgrade floor.** `meets_floor` requires a leveled PQ algorithm to meet
  `min_nist_level`, allows a recognized traditional partner, and **fail-closes** on
  unknown ids. `kem_allowed` / `sig_allowed` require listed **and** not-deprecated
  **and** meets-floor.
- **`negotiate_kem`** returns the strongest peer-offered KEM that passes policy, or
  `Error::PolicyDenied` if nothing acceptable is offered — a downgrade attempt aborts
  rather than silently selecting a weak suite.
- **`select_profile`** forces `ContextBound` whenever any allowed KEM is non-C2PRI
  (e.g. HQC), overriding `default_profile`.
- **Signed policy.** `Policy::from_toml` parses+validates plain TOML (no
  authentication). `Policy::load_signed` authenticates the **exact policy bytes** via
  an injected `q_periapt_sig::Verifier` (intended SLH-DSA root) **before** trusting
  them — so a tampered policy cannot silently weaken the suite. It is **fail-closed**:
  any signature/parse failure is an `Err`. `load_signed_or_failsafe` falls back to the
  conservative compiled-in `enhanced()` (L5 / `ContextBound`) on failure, returning
  the offending `PolicyError` so the deployment can log it as a security event.

---

## 9. Tooling: `q-periapt-cli`

`crates/q-periapt-cli`. Auditability & migration tooling, emitting plain
`serde_json`:

- **`cbom`** — a CycloneDX 1.6 *Crypto* Bill of Materials of the suite's
  cryptographic assets (algorithms, parameter sets, quantum-security levels, OIDs).
- **`sbom`** — a CycloneDX 1.6 SBOM derived from `Cargo.lock`.
- **`scan`** — a migration scanner flagging legacy/quantum-vulnerable primitives
  (RSA, ECDSA, ECDH, DSA, NIST curves, MD5/SHA-1, 3DES, RC4) and recommending a PQ/T
  replacement + policy.

---

## 10. Formal binding proof

[`formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec)
(see [`formal/easycrypt/README.md`](../formal/easycrypt/README.md)).
Machine-checked, **0 admits**:

- `bind_le_cr`: `Adv^X-BIND-K-* ≤ Adv^CR(H)` — binding reduces to collision-resistance
  of the hash.
- `encode_inj` is now a **proved lemma** (formerly an axiom): the canonical encoding
  is modeled concretely and its injectivity proved, reducing only to two elementary
  `be8` facts (8-byte fixed width + injectivity) plus CR of SHA3.

**Honest scope.** H's collision-resistance is a modeling assumption; IND-CCA2
robustness is argued on paper; there is **no spec↔impl linkage proof**. `X-BIND-CT-*`
is structurally impossible for implicitly-rejecting ML-KEM and is **not** claimed.
`ContextBound` is **not** "stronger binding than X-Wing" — both share the same MAL
ceiling; the edge is **assumption-minimality / proof-coverage**, not a stronger bound.
CI has a formal-proof job: a no-admits hard gate plus best-effort `make check`.

---

## 11. Build & supply-chain hygiene

From [`Cargo.toml`](../Cargo.toml): workspace `resolver = "2"`, edition 2021,
`rust-version` 1.81. Release profile keeps `overflow-checks = true` even in release
(cheap insurance for crypto code), with `lto = "thin"` and `codegen-units = 1` for
reproducible/auditable builds; `Cargo.lock` is committed for supply-chain audit.
Workspace lints warn on `missing_docs`, `unreachable_pub`, and the security-relevant
clippy lints `indexing_slicing` / `panic` / `unwrap_used`.

---

## 12. Dependency direction (summary)

```
q-periapt-core  (no deps; no_std; deny unsafe)
   ▲   ▲   ▲
   │   │   └────────── q-periapt-sig   (core)
   │   └────────────── q-periapt-kem   (core)
   └──────── q-periapt-policy (core + sig)

q-periapt-backends  → core + sig + libcrux* / x25519-dalek / [fips205] / [pqcrypto-hqc]
q-periapt-ffi       → backends + kem + core            (C ABI)
q-periapt-wasm      → backends + kem + core            (wasm-bindgen)
q-periapt-cli       → serde_json (+ suite metadata)    (CBOM/SBOM/scan)
bindings/swift      → q-periapt-ffi staticlib (C ABI)
bindings/kotlin     → q-periapt-ffi C ABI via Panama FFM
```

Arrows point from dependent to dependency. The direction is strictly one-way:
nothing the core depends on, and nothing depends *into* the core except through its
trait surface. That is the whole point — the audited center never grows a dependency
edge, and every face above reuses it unchanged.
