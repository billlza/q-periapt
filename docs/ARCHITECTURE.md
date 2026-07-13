# Q-Periapt — Architecture

Authoritative architecture document for **Q-Periapt**, a portable, `no_std`,
side-channel-first PQ/T (post-quantum / traditional) hybrid cryptographic suite.

> **Status: research-grade, not production.** Q-Periapt composes existing
> standardized/ecosystem primitives (ML-KEM, X25519, ML-DSA, SLH-DSA) through
> third-party backends. The known-leaky, unmaintained PQClean-HQC adapter has been
> removed from the publishable graph; a RustCrypto HQC-v5/FIPS-207-draft candidate is isolated
> in a `publish = false` shadow crate with no suite code or ABI. It has **no third-party audit**, and
> the release graph depends on pinned pre-1.0 third-party backends (`fips203` 0.4.3,
> `fips204` 0.4.6, and `sha3` 0.10.9) that have not been independently audited for
> this integration. **Do not
> deploy.** The value proposition is *not* primitive or speed superiority — it is
> auditable composition, crypto-agility, side-channel CI, machine-checked binding
> proofs, deterministic byte identity in the explicitly tested conformance cells,
> and fail-closed semantic parity in the native product cells.

For the security argument behind the combiner, read
[`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md) (authoritative) and the
EasyCrypt development under [`formal/easycrypt/`](../formal/easycrypt/). For the
exact wire format, read [`docs/COMBINER_SPEC.md`](COMBINER_SPEC.md).
The future stateful protocol architecture is deliberately separate and specified in
[`docs/CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md); it is not implemented.

---

## 1. The one idea

There is **one** dependency-free, `no_std` Rust core — `q-periapt-core` — that
contains *only* the security-critical composition logic: the hybrid-KEM
**combiner**, its **binding/encoding**, the **primitive trait surface**, and the
**constant-time helpers**. It implements **no cryptographic primitive**. Every
primitive (ML-KEM, X25519, SHA3/SHAKE, ML-DSA, SLH-DSA, or a separately
evaluated candidate) is *injected*
through a trait.

That same core is reused, unchanged, across the C ABI, WASM, Swift, Kotlin, and
Android/JNI faces. Deterministic conformance surfaces are validated
**byte-identical** against shared reference vectors. Native ABI 2 product faces
deliberately obtain randomness from the OS and do not expose raw replay inputs;
they are instead validated against the same signed-policy/context semantics,
round-trip invariants, rollback rejection, and failure-output atomicity.

```
                         injected primitives
                    (Kem / Xof256 / Signer / Verifier)
                                  │
                                  ▼
   ┌───────────────────────────────────────────────────────────┐
   │  q-periapt-core   (no_std, dependency-free, deny unsafe)    │
   │  • combine()  — CompatXWing | ContextBound                  │
   │  • CombineInput / absorb_lp (injective LP encoding)         │
   │  • traits: Kem (+ C2PRI, COMPAT_XWING_SAFE), Xof256          │
   │  • Secret (zeroize-on-drop, not Clone)                      │
   │  • ct_eq / ct_select32 / ct_is_zero                         │
   └───────────────────────────────────────────────────────────┘
                                  ▲
        ┌─────────────────────────┼──────────────────────────┐
        │                         │                          │
  q-periapt-kem            q-periapt-sig              (Signer/Verifier
  HybridKem<P,T,X>         SigAlg / Signer /           trait surface)
  (profile/backend guard)  Verifier traits
        │                         │
        └────────────┬────────────┘
                     ▼
            q-periapt-backends            q-periapt-policy
   third-party primitives wired            crypto-agility engine
   into the traits:                       (depends on -core + -sig):
   • MlKem768  (fips203, C2PRI)           • Policy / AuthenticatedPolicy
   • X25519    (x25519-dalek)             • TrustedPolicyState (version + digest)
   • Sha3_256Xof (RustCrypto sha3)        • closed, atomic ResolvedSuite
   • MlDsa65   (fips204)
   • [feature slh-dsa] SlhDsa*  (fips205)
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
`-tls-demo`, `-rustls`, `-cli`, `ctstats`, and the Continuity model. The independent
[`research/hqc-fips207-candidate`](../research/hqc-fips207-candidate/) crate is
explicitly excluded from the root workspace, has its own lockfile, is `publish = false`,
and is not depended on by any product/publishable crate.

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
any primitive implementation. The primitives are third-party code with distinct
conformance, audit, and per-ISA constant-time boundaries; the
*glue* is ours and is kept small enough to verify by eye and by proof.

**One core, reused across native and conformance faces.** Because primitives are injected
through traits, the same combiner runs against any backend and on any platform. The
C ABI, WASM, Swift, Kotlin, and Android/JNI faces are marshaling layers over the
identical Rust logic — there is no per-platform cryptographic reimplementation.
Deterministic faces make byte identity directly testable; native ABI 2 product faces
make the stronger operational choice not to accept caller randomness and therefore
test semantic parity rather than manufacturing deterministic product outputs (§6).

**Crypto-agility is policy-controlled over a closed compiled set.** An authenticated policy
can select only a suite explicitly compiled, enumerated, and resolved by the code. Moving among
already supported L3/L5 suites or deprecating one is a policy change. Numeric suite code `3`,
formerly used by the PQClean-HQC experiment, is a permanent tombstone:
`HybridSuite::from_u8(3) == None`. It is not reassigned to the RustCrypto candidate.
Adding any future HQC runtime suite would require a new code plus an explicit final-standard,
suite/C2PRI/API decision, public-surface work, security review, and release evidence. It is never an automatic fallback. A minimum-NIST-level floor gives downgrade
protection. The safe default policy selects `ContextBound`;
`CompatXWing` is an explicit construction-compatibility/control profile, not the
ambient default. Official-vector equality does not establish an independent endpoint
or HPKE interoperability claim.

---

## 3. The dependency-free core (`q-periapt-core`)

`crates/q-periapt-core/src/lib.rs`. `#![cfg_attr(not(test), no_std)]`,
`#![deny(unsafe_code)]`. **No primitive implementations.**

### 3.1 Injected primitive traits

| Trait | Method surface | Contract |
|---|---|---|
| `Kem` | `algorithm()`, `encapsulate()`, `decapsulate()`, `const C2PRI: bool`, `const COMPAT_XWING_SAFE: bool` | Constant-time w.r.t. secrets; `decapsulate` **must** use implicit rejection and must NOT return `Error` to signal an invalid ciphertext (only public conditions). `C2PRI` records the primitive property. `COMPAT_XWING_SAFE` records the additional API/key-format precondition. Both default to `false` and both are checked for the first slot omitted by `CompatXWing`. |
| `Xof256` | `new()`, `reserve()`, `absorb()`, `absorb_public()`, `absorb_secret()`, `squeeze32()` | Incremental hash/XOF producing 32 bytes; constant-time w.r.t. absorbed data. Legacy `absorb` is conservatively unclassified/sensitive; explicit methods let a staging backend erase only secret ranges without changing hash bytes. |
| `Signer` / `Verifier` | in `q-periapt-sig` (see §5) | — |

The core never names ML-KEM, X25519, SHA3, etc. — it only sees `impl Kem` /
`impl Xof256`. Concrete types live in `q-periapt-backends` (§4).

### 3.2 The combiner: two profiles

`combine::<X: Xof256>(profile, &CombineInput) -> Result<Secret, Error>` is the
heart of the suite. `CombineInput` carries slices (`suite_id`, `policy_version`,
`ss_pq`, `ss_trad`, `ct_pq`, `pk_pq`, `ct_trad`, `pk_trad`, `context`), so it works
for any parameter set.

**`Profile::CompatXWing` — the byte-exact X-Wing combiner profile.**
Computes `SHA3-256(ss_pq || ss_trad || ct_trad || pk_trad || XWING_LABEL)` where
`XWING_LABEL` is the 6-byte `\.//^\` from `draft-connolly-cfrg-xwing-kem`. The four
32-byte fields are concatenated with **no** length prefixes for byte-exactness, but
each is **hard-checked** to be exactly `SHARED_SECRET_LEN` (32) first — otherwise
arbitrary-length slices could collide across field boundaries (33+31 vs 32+32) and
collapse domain separation; a wrong length returns `Error::InvalidLength`. The
absorbed input is a single 134-byte block (<= Keccak rate 136) and the path is
allocation-free. This profile deliberately does **not** bind the PQ ciphertext/
pubkey, nor `suite_id` / `policy_version` / `context` — it relies on the PQ KEM
being exposed through an X-Wing-safe seed-dk backend (§3.4). The admitted
`HybridKem<MlKem768XWingSeed, X25519>` construction reproduces all three official draft-10
vectors; the profile alone is only its combiner encoding. Independent endpoint/HPKE
interoperability is not established (§6).

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
pass a fixed protocol/role/version label). Because it hashes the full ML-KEM-768 +
X25519 transcript material with length prefixes, it necessarily does more combiner
work than `CompatXWing`. The matched-backend host gate bounds that local delta only
when its proof digest exactly matches the live canonical source tree and the host
satisfies the controlled-environment contract. Cross-device, energy, rustls
end-to-end, and optimized-production parity remain pending.

### 3.3 Performance positioning (measured, honest)

The historical combiner-only harness in
[`crates/q-periapt-backends/benches/combiner.rs`](../crates/q-periapt-backends/benches/combiner.rs)
compares against a faithful streaming X-Wing reference built on RustCrypto `sha3`.
The current gate in
[`paired_profile_perf.rs`](../crates/q-periapt-backends/examples/paired_profile_perf.rs)
instead gives both profiles identical ML-KEM-768 seed-dk + X25519 backends, keys,
coins, ciphertext corpus, suite/version/context inputs, and ABBA/BAAB ordering:

- `CompatXWing` is byte-exact against the X-Wing draft vectors. Historical
  single-host measurements put the generic wrapper within tens of ns of a hand-rolled
  streaming reference; that is supporting combiner evidence, not production parity.
- `ContextBound` intentionally hashes more fields than `CompatXWing` and is slower at
  the combiner layer. Controlled Apple-Silicon runs are checked against published
  one-sided p50/p95/p99 ratio and absolute-delta budgets. Only a proof whose source
  digest matches the live canonical tree counts as current; the machine-readable
  manifest, not this source document, carries that freshness state. A passing host
  diagnostic is not a device or production parity claim.

**We never claim "faster than X-Wing."** There is no primitive or speed edge — the
primitives are the standard ones via standard backends. The wins are provable
binding, crypto-agility, side-channel CI, deterministic cross-platform conformance,
and auditability.

### 3.4 The `CompatXWing` backend safety guard

`CompatXWing` omits the PQ ciphertext and public key from the KDF. That is sound
**only** when both conditions hold: the primitive is *ciphertext second-preimage
resistant* (C2PRI), and the backend API/key format preserves the X-Wing seed-dk
self-binding precondition. Primitive C2PRI alone is not enough for an API that
accepts arbitrary expanded/imported ML-KEM decapsulation keys. The guard is
enforced in two layers:

1. `Kem::C2PRI` is an associated `const` (default `false`) that records the
   primitive-level property (`MlKem768::C2PRI = true`).
2. `Kem::COMPAT_XWING_SAFE` is a stricter associated `const` (default `false`) for
   the exposed backend/key format. The raw expanded ML-KEM backends keep this
   `false`; `MlKem768XWingSeed` sets it to `true`.
3. `HybridKem::new` (in `q-periapt-kem`) rejects `CompatXWing` unless both
   `P::C2PRI` and `P::COMPAT_XWING_SAFE` are true, returning `Error::PolicyDenied`.
   This confines expanded/imported ML-KEM keys to `ContextBound`; X25519 remains
   valid in the absorbed traditional slot but cannot
   be placed in `P`, the omitted first slot. `ContextBound` binds all fields directly.

### 3.5 `Secret` and constant-time helpers

`Secret` wraps the 32-byte combined key. On `Drop` it is securely wiped with
**volatile zero writes** (which the optimizer may not elide) followed by a
**compiler fence** — the `zeroize` crate's technique, inlined to keep the core
dependency-free. The shared wipe primitive used by `Secret` and `ZeroizingBytes` is the
**only** `unsafe` block in the crate (hence
`deny`, not `forbid`). `Secret` is intentionally **not** `Clone`/`Copy`, preventing
implicit duplication of its owner. Its borrowed bytes can still be explicitly copied;
those caller-owned copies are outside the Drop guarantee.

`Sha3_256Xof` separately tracks the two component-secret ranges plus the conservatively
sensitive caller-context range in its one-shot staging transcript. Public framing,
ciphertexts, keys, and labels are not volatile-wiped; the marked bodies are wiped from both
inline and heap copies. Inline-to-heap migration
retains the inline extent so duplicate secret bytes are erased, and range exhaustion or invalid
metadata fails closed to a whole-buffer wipe. The legacy `absorb` also selects whole-buffer
erasure. Reallocation copies are migrated before the old live allocation's secret ranges are
wiped. This is an implementation hygiene/performance optimization, not a cryptographic claim:
`fips203`/`fips204`/`sha3` internals, registers, crash dumps, OS copies, and
caller-owned buffers remain outside it.
The `Xof256` contract therefore covers only secret-bearing storage the implementation owns and
can still reach at Drop; primitive/callee temporaries are a separate backend-assurance boundary.

The CT helpers — `ct_eq` (branch-free byte-slice equality → `0xFF`/`0x00`),
`ct_select32` (branch-free 32-byte select, the primitive for implicit rejection),
and `ct_is_zero` — are best-effort in portable Rust. See §7 for the honest scope of
the side-channel assurance.

### 3.6 The `Error` type

`Error` is deliberately coarse — `InvalidLength`, `Backend`, `InvalidKeyShare`,
`PolicyDenied` — and `#[non_exhaustive]`. Every variant corresponds to a **publicly
observable** condition (buffer length, public malformed DH/key-share input, policy).
It **must never** encode secret-dependent information such as *why* an FO-KEM
decapsulation failed; failure paths are designed to be indistinguishable.

---

## 4. Backends (`q-periapt-backends`)

`crates/q-periapt-backends/src/lib.rs` is the **only publishable Q-Periapt crate**
that touches real cryptographic primitives. Each release-graph backend is a zero-sized
type implementing a core trait:

| Backend | Primitive | Crate | Notes |
|---|---|---|---|
| `MlKem768` | ML-KEM-768 (FIPS 203) | `fips203` 0.4.3 | `Kem`, `C2PRI = true`, `COMPAT_XWING_SAFE = false` because it exposes expanded/imported decapsulation keys. The adapter imports fixed-size keys through the backend's checked decoder and passes randomness explicitly for deterministic conformance testing. No predecessor source-CT claim is inherited. |
| `MlKem768XWingSeed` | ML-KEM-768 seed-dk API | `fips203` 0.4.3 + `sha3` 0.10.9 | `Kem`, `C2PRI = true`, `COMPAT_XWING_SAFE = true`; derives X-Wing's `(d||z)` key material from the 32-byte seed and is the only backend admitted to `CompatXWing`. |
| `X25519` | X25519 ECDH-as-KEM | `x25519-dalek` 2 | `Kem`, default-false first-slot capabilities; deterministic from a 32-byte scalar. Canonical X-Wing uses it in the absorbed traditional slot. |
| `Sha3_256Xof` | SHA3-256 | RustCrypto `sha3` 0.10.9 | `Xof256`; byte-identical public/secret absorption with fail-closed selective staging erasure. |
| `MlDsa65` | ML-DSA-65 (FIPS 204) | `fips204` 0.4.6 | `Signer` + `Verifier`; external/pure, context, hedged, and SHAKE-128 pre-hash modes are wired. The deprecated internal API is deliberately not exposed. Signing uses FIPS 204 rejection sampling and therefore has a documented variable-iteration boundary; verification is the ABI2 product path. |
| `SlhDsaSha2_128s/192s/256s` | SLH-DSA (FIPS 205) | `fips205` 0.4.1 | **feature `slh-dsa`** (off by default). |

These backends are reused by `q-periapt-ffi`, `q-periapt-wasm`, the binding
test-vector generator (`examples/refvec.rs`), and the X-Wing KAT.

HQC is deliberately outside that graph. The old `Hqc128/192/256` and `HqcAsKem`
PQClean adapter was removed, along with the `hqc` feature. It had a known timing leak,
three unmaintained dependency advisories, pre-FIPS207 sizes/semantics, and no mapped
C2PRI/API proof. The independent `research/hqc-fips207-candidate` crate evaluates
RustCrypto `hqc-kem 0.1.0-rc.0` for the HQC v5 / prospective FIPS-207 draft candidate.
The upstream crate describes itself as tracking an IPD, but as of 2026-07-12 the official
FIPS 207 IPD is not publicly retrievable and NIST still labels it coming soon. The crate is
`publish = false`, owns no public `HybridSuite` variant or numeric code, does not enter
ABI 2, and does not establish final-standard, audit, binary-CT, or production readiness.

### 4.1 Feature gating

From [`crates/q-periapt-backends/Cargo.toml`](../crates/q-periapt-backends/Cargo.toml):

```toml
[features]
default = []
slh-dsa = ["dep:fips205"]
```

`slh-dsa` is **optional and off by default**. `dep:` gating keeps it out of the
default build. No `hqc` product feature remains: the candidate's standalone manifest
is the architectural fence, rather than a release-crate feature that `--all-features`
could accidentally promote.
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

## 6. Deterministic conformance and native-product parity

The interop evidence has two non-interchangeable layers. Deterministic conformance
cells compare exact bytes against shared oracles. Native ABI 2 product cells use OS
randomness and therefore compare authenticated decisions, round trips, context
separation, state transitions, and failure atomicity. A green product cell is not
misreported as deterministic byte-replay evidence.

### 6.1 The shared reference vector

[`bindings/shared-test-vectors.json`](../bindings/shared-test-vectors.json) is
generated *from the Rust core*:

```sh
cargo run -p q-periapt-backends --example refvec > bindings/shared-test-vectors.json
```

It is a full `ContextBound` vector (`profile_code: 2`,
`suite_id = "ML-KEM-768+X25519"`, `policy_version: 1`, a fixed non-empty `context`,
both secret/public keys, encapsulation randomness, both ciphertexts, and the
resulting 32-byte `secret`). It remains a deterministic Rust/conformance oracle.
The native ABI 2 product faces deliberately do not expose seeds, coins, raw hybrid,
X-Wing, or combine calls; their cross-language tests instead exercise the same
signed-policy-controlled OS-random workflow and its fail-closed controls.

### 6.2 The faces

| Face | Crate / dir | Surface | Consistency check |
|---|---|---|---|
| **Rust core** | `q-periapt-core` / `-kem` | source of truth | `cargo test` (combiner KATs, X-Wing KAT) |
| **C ABI** | `q-periapt-ffi` | ABI-major `cdylib` + `staticlib`; exact nine-symbol product contract; OS CSPRNG; `int32` status codes; every entry `catch_unwind`-wrapped | internal Rust KAT + semantic product C smoke + `c_abi_contract.py` |
| **WASM** | `q-periapt-wasm` | `wasm-bindgen`; JS supplies randomness as `Uint8Array` | `cargo test -p q-periapt-wasm`; CI builds `wasm32` |
| **Swift** | `bindings/swift/` | links the ABI2 C `staticlib`; policy-controlled only | `swift test` + five-slice XCFramework consumer pass; physical-device proof remains source-bound |
| **Kotlin** | `bindings/kotlin/` | Panama **FFM** over ABI2, JDK ≥ 22; policy-controlled only | `gradle test` on JDK 22+ |
| **Android** | `bindings/android/` | JNI over ABI2; policy-controlled only | AAR build + physical ART device proof |

WASM is a separate deterministic conformance-oriented binding and is not part of the
native ABI2 package contract.

### 6.3 The C ABI in detail (`q-periapt-ffi`)

`crates/q-periapt-ffi/src/lib.rs`. Fixed to the default suite ML-KEM-768 + X25519 +
SHA3-256. ABI conventions:

- Every function returns an `int32` status: `Q_PERIAPT_OK` (0) or a negative error
  (`_ERR_NULL`, `_ERR_LENGTH`, `_ERR_POLICY`, `_ERR_PANIC`, `_ERR_INTERNAL`,
  `_ERR_INVALID_KEYSHARE`, `_ERR_ALIASING`, `_ERR_ENTROPY`). Errors
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

The current working-tree contract reports `Q_PERIAPT_ABI_VERSION = 2` and package
version `0.1.0-alpha.1`. It exposes exactly nine product symbols: five metadata/status
functions, signed-policy resolution, atomic OS-CSPRNG key generation, OS-CSPRNG
encapsulation, and decapsulation. Raw hybrid/combine, caller-provided deterministic
seeds/coins, X-Wing, and the old `*_with_decision` names are forbidden exports.
All valid product outputs are cleared before validation/crypto and are committed from
local temporaries only after success. The contract also freezes the 40-byte policy
decision and 36-byte trusted policy state.
This is an **unpublished ABI 2 candidate**, not a stable binary release. Continuity's
abstract snapshot schema 3 is unrelated and is not part of this ABI. Before ABI 2
can be published, all platform package identities, release-index cross-face semantics,
dependency audit, clean provenance, same-source Apple matrix verification, and controlled-host
performance verification must pass. ABI 1 compatibility is a hard cut: its four-byte state is rejected and cannot be
upgraded from a version alone; hosts require explicit authorized re-enrollment/reset.
The backend/source migration changed the canonical source digest and invalidated all
previous package, Apple-device, matched-performance, and binary-CT proofs, including
the later clean-tree schema-3 matrix. Each release lane must be rebuilt or re-collected
for the new source snapshot. Time-varying currentness is authoritative only through
`artifact/results.json` and live verification; neither is a distribution-signing or
device-energy claim.

### 6.4 X-Wing conformance KAT

`crates/q-periapt-backends/src/xwing_kat.rs` drives `HybridKem<_,_,Sha3_256Xof>`
under `CompatXWing` with X-Wing's key expansion (`SHAKE-256(seed, 96)`) and
encapsulation-coin split, and asserts the ML-KEM-768 public key, ciphertext, and
shared secret against **3 official `draft-connolly-cfrg-xwing-kem` vectors**. This
proves the combiner **reproduces the FIPS 203 reference output on those 3 happy-path
vectors** byte-for-byte. (Beyond these, the full NIST ACVP set for ML-KEM-512/768/1024
+ ML-DSA-44/65/87 external/pure, context, hedged, and SHAKE-128 pre-hash modes
also passes in `acvp.rs` — broad conformance to the published vectors, though not
CMVP/CAVP certification. Vendored internal-interface vectors are retained as
unwired reference data and are not a backend pass.)

---

## 7. Side-channel posture (honest scope)

- **Failure-path indistinguishability / implicit rejection is a HARD CI gate**
  (the `ctstats` crate). An invalid ciphertext must produce a pseudorandom secret,
  not an error, so the failure path is indistinguishable from success. This is
  gated.
- **The `dudect` timing test is a local diagnostic.** It is intentionally absent
  from noisy shared CI and is **not** a merge gate; local runs retain its exit status.
- **Binary-level (dataflow) constant-time** over our own composition code (`ct_eq`,
  `ct_select32`, the combiner) is a **HARD CI gate** (`constant-time` job: `ct_verify`
  under Valgrind/Memcheck-TIMECOP, x86_64 + aarch64). That job is configured to
  hard-gate the corrected ŝ+z `fips203` ML-KEM decapsulation gap probe: the
  genuine-secret path must report zero and a synthetic planted secret-indexed load
  must report positive. The backend/source migration invalidated earlier `libcrux`
  captures, so a fresh two-ISA run for the release digest is required. The
  retired PQClean-HQC 193/22,849 counts are historical older-source evidence, not a
  live gate.
  Other component-primitive paths and riscv64/wasm32 binary-CT remain **TODO** (see
  `docs/THREAT_MODEL.md` §5.2).

So: do **not** read "side-channel-first" as "timing is gated." Structural failure-path
indistinguishability **and** binary-level dataflow CT over our composition code are gated;
the statistical `dudect` *timing* test and binary-CT over primitives other than the
ML-KEM decapsulation probe are local-only / pending. No source-CT or hax property
from the replaced backend transfers to `fips203`; real assurance is per backend,
version, source digest, compiler, and ISA and is tracked in
`docs/ROADMAP.md`.

---

## 8. Crypto-agility & policy (`q-periapt-policy`)

`crates/q-periapt-policy/src/lib.rs`. `forbid(unsafe_code)`. Depends on
`q-periapt-core` and `q-periapt-sig`. The policy layer owns validation and selection;
callers receive one decision rather than assembling suite/profile/version metadata
independently.

- **Validated `Policy`.** `Policy::try_new` and `Policy::from_toml` reject zero
  versions, unknown or duplicate identifiers, invalid NIST floors, unknown TOML
  fields, and policies that cannot authorize a complete hybrid suite plus signature.
  Its fields are private. `Default` is ML-KEM-768 + X25519 / L3 / `ContextBound`;
  `enhanced()` is an L5 policy over ML-KEM-1024 + X25519. Retired HQC identifiers
  are not accepted as a hidden fallback, and suite code `3` decodes to `None`.
- **Domain-separated authentication.** `Policy::load_signed` verifies
  `Q-PERIAPT-SIGNED-POLICY/v1 || u64_be(len) || exact_toml_bytes` through an injected
  verifier before parsing or trusting the document. Failure remains a descriptive
  `PolicyError`; there is no fallback-success API.
- **Rollback and equivocation state.** `Policy::load_signed_monotonic` compares the
  authenticated document with a caller-persisted `TrustedPolicyState` containing the
  non-zero policy version and SHA3-256 digest of the exact TOML bytes. Lower versions
  and different documents reusing the same version are rejected. Persisting the
  returned state atomically is a caller responsibility.
- **Closed atomic resolution.** `AuthenticatedPolicy::resolve_suite` intersects the
  policy with a concrete list of locally implemented `HybridSuite` variants and
  returns an `AuthenticatedResolvedSuite`. Its private-field `ResolvedSuite` binds the
  chosen suite, profile, key format, and policy version as one value. A fixed L3 face
  therefore rejects an L5 policy instead of claiming ML-KEM-1024 while executing
  ML-KEM-768. Non-C2PRI/unsupported X-Wing pairings are upgraded to `ContextBound` or
  rejected at the concrete runtime boundary.
- **Runtime boundary.** The native ABI2 C/Swift/Kotlin/Android execution APIs accept
  the canonical decision and bind the exact policy digest with application context;
  no raw/deterministic alternative is exported. The decision bytes themselves remain
  trusted-local descriptors rather than authorization capabilities: same-process
  native code can forge them, and a caller-controlled verification key permits a
  self-signed policy. The host must pin that key and protect monotonic state. WASM is
  a separately scoped conformance surface with caller randomness. An opaque handle
  in the same hostile address space is insufficient. Authenticity against an untrusted
  local caller requires a service/process boundary that owns the pinned verification
  key and monotonic `(version,digest)` state and exposes only policy-bound operations.

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

- `bind_le_cr`: generic transcript-projection collision bound. CT/PK instantiate
  standard X-BIND games; CTX is a separate self-defined wrapper projection. Each
  reduces to collision-resistance of the hash.
- `encode_inj` is now a **proved lemma** (formerly an axiom): the canonical encoding
  is modeled concretely and its injectivity proved, reducing only to two elementary
  `be8` facts (8-byte fixed width + injectivity) plus CR of SHA3.

**Honest scope.** H's collision-resistance is a modeling assumption; IND-CCA2
robustness is argued on paper; there is **no spec↔impl linkage proof**. `X-BIND-CT-*`
is structurally impossible for implicitly-rejecting ML-KEM and is **not** claimed.
`ContextBound` is **not** "stronger binding than X-Wing" — both share the same MAL
ceiling; the edge is **assumption-minimality / proof-coverage**, not a stronger bound.
CI has formal hard gates: no-admits scanning, a pinned-source EasyCrypt container re-check plus
seven **proof-dependency regression controls**, and full Tamarin/ProVerif
`make prove`. An edited tactic failing is not a necessity proof. Semantic necessity
is attached only to explicit checked countermodels, including
`kctx_without_nonbottom_broken` for removing `K != bottom`; the J-injectivity deletion
control establishes only that the current reduction script depends on that fact. The base image
and EasyCrypt commit are immutable; apt/opam transitive inputs remain outside a hermetic,
bit-reproducible closure.

---

## 11. Build & supply-chain hygiene

From [`Cargo.toml`](../Cargo.toml): workspace `resolver = "2"`, edition 2021,
`rust-version` 1.85 (the true floor: the committed lock pulls clap 4.6 + hashbrown 0.17,
which require 1.85; enforced by the `msrv` CI job). Release profile keeps
`overflow-checks = true` even in release
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

q-periapt-backends  → core + sig + fips203 / fips204 / sha3 / x25519-dalek / [fips205]
q-periapt-ffi       → backends + kem + core            (C ABI)
q-periapt-wasm      → backends + kem + core            (wasm-bindgen)
q-periapt-cli       → serde_json (+ suite metadata)    (CBOM/SBOM/scan)
bindings/swift      → q-periapt-ffi staticlib (C ABI)
bindings/kotlin     → q-periapt-ffi C ABI via Panama FFM
research/hqc-fips207-candidate → hqc-kem RC only (publish=false; no product edge)
```

Arrows point from dependent to dependency. The direction is strictly one-way:
nothing the core depends on, and nothing depends *into* the core except through its
trait surface. That is the whole point — the reviewable center never grows a dependency
edge, and every face above reuses it unchanged.

---

## 13. Future-only session architecture (`Q-Periapt Continuity`)

There is currently no production session crate, prekey directory, persistent
ratchet, multi-device store, or recovery implementation. A `publish = false`,
non-normative lifecycle model exists under `models/`; it contains no real protocol
or secret bytes and no product crate depends on it. The model now retains one trusted
pairwise `SessionIdentity` and current `AuthenticatedContext` across abstract
snapshot schema 3 reconstruction. `AuthenticatedContext` can only be constructed
from candidate role-ordered `LifecycleContextV1` bytes, one signed-policy digest, and
an explicit fallible digest adapter. Bootstrap B21-B23 can only be reduced from one
strict `PrekeySelectionV1`; its suite, responder scope, directory checkpoint,
manifest and independent classical/PQ legs are not caller-assembled lifecycle fields.
Drafts that replace the protocol, policy,
session, either device, or the exact current context fail before reservation. These
bytes bind trusted claims but do not authenticate them. The model deliberately exposes
no context-advance API: role/profile-specific confirmation evidence, privilege rules,
and local outbox/delivery states are not yet frozen. `ZeroRttSent` is specifically not
a peer-agreed authentication stage. It
also retains exact pending repository intents, reconciles them before an
append-only suspension tombstone, and replays exact release/quarantine effects until
their modeled durable boundary. Typed persist subjects bind result-pin, anchor,
final-commit, release-ack, and closure records; `Volatile` provider results are scrubbed
at every durable cut. Exact state advances use version+digest CAS, so a same-version/
different-digest receipt cannot masquerade as idempotence; a no-op per-transition
anchor is rejected before mutation. The first suspension cause and its typed
fence/repository evidence
survive reconciliation. These are desired adapter contracts, not evidence for fsync,
WAL, provider, or hardware behavior. The host must durability-confirm the exact
journal intent before executing an emitted effect; this ordering is not enforced by
the model. The test-only codec dependency direction is acyclic:

```text
codec + commitments -> prekey -> context -> effect/state types -> model
```

Shared identifiers/commitments no longer live in `context.rs`, and the prekey module
cannot depend back on the lifecycle layer. Trusted initialization, credential/role/
device-epoch authentication, legal context advancement, signed manifest/leaf
verification, prekey leasing/consumption/tombstones, outer production decoding,
ratchet state, and session-level benign rejection remain unimplemented. If the
protocol research gates are
approved, the new layer must sit **above** the existing crates without sharing a
session implementation between the oracle and research protocol:

```text
dependency arrow: caller --> dependency

reference-manager/test-harness --> reference-session-model --> crypto contracts
continuity-session-service      --> q-periapt-continuity-core --> crypto contracts

existing/provider adapters --> crypto contracts
directory/repository/network/platform adapters --> service-owned ports
Swift/Kotlin/C/WASM application faces --> continuity-session-service
```

`q-periapt-continuity-core` would own its canonical wire parsing, typed
identity/prekey records, bootstrap, ratchet transitions, bounded state, and
domain-separated `SessionKdf`. Its deterministic effect protocol must enforce
`prepare -> persist PendingDraft + fence -> DurablePending::command -> provider ->
resume(DurablePending, CryptoCompletion)`. A draft cannot expose the command before
its reservation is known durable. It does not own sockets, HTTP, database drivers,
clocks, provider calls, platform keychains, Secure Enclave operations, or retry
loops. Every operation structurally binds protocol/version, session and devices,
prior/reserved state, transition ID, command ordinal, purpose, provider profile and
instance epoch, closed policy, writer fence, typed context and complete command
commitment. A short operation ID is only a correlation handle; `resume` checks the
full durable binding. The diagnostic `ProviderBinding` is still caller-selected: its
echo check blocks an in-flight swap but does not prove policy authorization, provider
identity, current epoch, or downgrade resistance.

The diagnostic model additionally admits that binding only against its trusted
durable session and exact current context. It does not infer or install a successor
context, and a provider success cannot upgrade the trusted context. These restrictions
test a candidate authority-admission invariant only; they do not authenticate the
trusted genesis, define roles or direction, or select accountable-versus-deniable
identity semantics.

A command is retryable under the same operation ID only when a sealed, one-use
entropy reservation makes the exact bytes deterministic. The diagnostic model uses a
closed operation variant that also fixes the expected result shape; the production
variant set remains a G1 decision. A stable-handle operation is queried against the
same provider epoch/profile/handle rather than recreated. The pending record CAS-
accepts the first complete valid result; completed, cancelled, or superseded
operations require durable tombstones and reject late results. The current model does
not yet fix a numeric retention bound or durable orphan-key/handle cleanup contract.
An uncertain non-repeatable timeout suspends. Production callers never inject raw
entropy.

The service applies each plan through one aggregate
`SessionRepository::transact`, atomically covering session state, local prekey
acceptance/tombstones, deduplication, inbox, and immutable outbox. The network
dispatcher sends only after commit. Receive commits use state-version/CAS; a losing
candidate destroys plaintext/keys and recomputes. Concurrent processes also need a
single-writer lease/fencing token.
Every aggregate write has an exact transition ID and linearizable outcome query. A
timeout after a possible commit becomes `CommitOutcomeUnknown`: it cannot be treated
as ordinary failure, and no crypto rerun, release, dispatch, or new transition occurs
until exact committed/absent/conflict reconciliation.

External non-rollback anchors are a different transaction domain. Profiles that use
one require a persisted `PendingAnchor` journal: persist the complete sealed staged
next state/effects, state digest, immutable outbox, and any operation-bound encrypted
inbox delivery record (never unencrypted plaintext),
advance an idempotent authenticated anchor over the operation and next-state digest,
install one exact idempotent release/delivery record, and only then
dispatch/unseal/release. The same ID is replayed until a distinct acknowledgement
record commits. Recovery uses an
authenticated compare-and-advance over exact prior/next values, transition ID and
fence: exact applied finalizes, exact prior retries the same intent, unknown is
queried, and ahead/conflict/equivocation/unauthenticated responses suspend.
Hardware/keychain deletion is not claimed atomic; if a profile anchors only
the device epoch, same-epoch full-snapshot rollback remains explicitly out of scope.

The service separates one pairwise per-device engine from an account-level
`SessionManager`. The manager freezes an authenticated roster snapshot and bounded
eligibility decision, prepares every required per-device ciphertext, and in one
all-or-none account transaction CAS-commits the roster/eligibility digest, each
required session's expected version and complete next ratchet/bootstrap state, all
prekey/dedup/new-session effects, and the immutable fanout outbox. Any CAS/fencing
failure commits none of them. It never silently succeeds after skipping a required
device.

When external anchors apply, an account-level `PendingFanout` seals all candidate
states/effects. Prefer one account-level anchor over its digest; otherwise no session
or outbox becomes dispatchable until every required anchor confirms and one final
transaction commits the fanout. Partial external-anchor progress is reconciled or the
whole fanout is suspended/rekeyed, never partially delivered. Post-commit delivery is
independently retryable; account serialization or account-then-sorted-session locking
defines the concurrency order.

Two lanes must remain separate:

- a dev/test-only, component-conformant reference for PQXDH bootstrap and Triple
  Ratchet/SPQR with ML-KEM Braid, wrapped by a separately specified
  Sesame-compatible manager integration; and
- a distinct Continuity research protocol for Q-Periapt-specific context-policy,
  identity, prekey-accountability, recovery, and evidence hypotheses.

They share only primitive providers—not codecs, KDFs, state types, transitions,
protocol/session identifiers, persistence keyspaces, or migration logic. The
reference `ReferenceProfile` freezes specification revisions, algorithms, encodings,
limits, and integration choices and is not shipped in the default product. An
upgrade starts a new session; it never converts ratchet state in place. Component
conformance, integrated composition, and external interoperability are independent
claims.

Modifying a Signal KDF, header, state transition, or limit creates a different
protocol. It must use a new identifier and must not be described as Signal-compatible
without an external interoperability suite. `CompatXWing` also cannot be used as a
session context-binding profile: its byte-compatible definition intentionally ignores
external context.

The current signed-policy abstraction may inspire a future closed
`ResolvedSessionPolicy`, but it cannot simply be reused as-is. A stateful decision
must atomically fix identity semantics, prekey mode, ratchet construction, wire
version, resource limits, PQ cadence floor, and exact policy digest. Database/session
rollback protection is likewise a new state invariant; current policy rollback
protection does not provide it. The reference lane uses its frozen profile rather
than runtime policy. The research lane receives a validated indivisible decision,
not direct dependencies on TOML parsing, `q-periapt-policy`, or concrete backends.

`ContextBound` is available only at a real Q-Periapt two-leg KEM combination. It is
not a transcript authenticator, identity verifier, policy engine, or ratchet KDF.
Ordinary DH, symmetric, and sparse-PQ root transitions use distinct protocol-domain
`SessionKdf` functions over a fixed-length canonical context digest whose
preauthenticated and confirmation-authenticated fields are distinguished by type.

The evidence plane is also layered rather than embedded in domain verifiers.
`artifact/evidence_io.py` is a leaf module that creates bounded, no-symlink regular-file
snapshots and strict-parses JSON; `artifact/proof_manifest.py` maps trusted
`results.json` path/hash fields to one selected snapshot. Apple and performance
verifiers consume that object for both digest comparison and semantics; Apple auxiliary
logs, plists, linkage output and binaries are likewise snapshotted once per verification.
`artifact/git_provenance.py` is the separate repository-truth leaf: it fixes Git and its
environment, rejects hidden index flags, compares HEAD, index and actual tracked
bytes/modes without stat-cache shortcuts, and inventories ignored as well as visible
untracked inputs using a verifier-owned fixed ephemeral-output policy. Local/global Git
excludes cannot hide an input; any untracked `.gitignore` outside fixed ephemeral outputs and any
repository Python bytecode cache fail closed. `artifact/python-env.sh` and the source-only
`artifact/python_bootstrap.py` form a sibling runtime-provenance leaf. Every covered shell
entrypoint runs an absolute CPython 3.11+ under `-I -S -B`, a fresh private cache prefix,
cleared `PYTHON*` state, standard-library-first import roots, and repository-confined script
dispatch. This prevents ignored timestamp/hash-pyc replacement and user-site/`.pth` startup
code, but does not attest the external interpreter or host. Release policy
fixes matrix membership and the performance budget outside proof-authored data. The
performance budget also fixes the Cargo/Rustc executable hashes, versions, and target; collection
rejects repository/ancestor/user Cargo configuration and caller compiler/wrapper/loader controls,
uses system-only tool lookup plus a fresh private target, and rechecks the two executables. It still
trusts the user-writable Cargo registry, Rust sysroot/driver, OS tools/libraries, same-UID host, and
collector source-to-binary honesty, so it is not a hermetic producer attestation. Likewise, fixed
generated-output prefixes are outside the canonical source-input inventory and can still be read by
a build; release-grade closure requires an isolated checkout, unique lane outputs, and hashes for
every generated artifact later consumed. The
shell remains an orchestrator and pins one results-manifest digest across subprocesses;
it does not re-open a verified proof for a later hash decision.

The exact deterministic command/result semantics must live in a future narrow
`q-periapt-session-crypto-contracts` layer, not in `q-periapt-core`. The reference
profile preserves the published DH/KEM/KDF/AEAD ordering and cannot route PQXDH
through `HybridKem` or X25519-as-KEM. Bootstrap's candidate peer-agreed stages are
`PrekeyAuthenticated`, `PeerConfirmed`, and `MutuallyConfirmed`; `ZeroRttSent` is a
separate local delivery state. This keeps a pre-signed offline bundle from being
mislabeled as fresh bilateral proof and avoids assuming final transcript
authentication as an input to itself. The current test-only model admits one exact
trusted canonical context but does not advance between stages. Role-specific
transition rules, credential verification, release semantics, and canonical
transcript construction remain future
service/core responsibilities. The malicious
directory/prekey/transparency/witness service must also receive an independent future
model/harness; client adapter traits alone do not establish R2.

See [`CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md) for the full parity baseline,
research hypotheses, performance budgets, formal-refinement gate, and forbidden
claims.
