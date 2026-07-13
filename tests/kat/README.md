# Known-Answer Tests (KATs)

Status of M0 KAT coverage.

These are primitive/combiner KATs. They do not cover the future Continuity wire,
prekey, ratchet, persistence, or multi-device state machine; those require a distinct
transition-vector corpus described in
[`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md).

## Present (passing)

- **X-Wing draft byte-exact KAT** ✅ — `q-periapt-backends/src/xwing_kat.rs` reproduces all
  3 official `draft-connolly-cfrg-xwing-kem` vectors (`spec/test-vectors.json`)
  **byte-for-byte**: public key, ciphertext, and shared secret, for encaps **and**
  decaps. This proves `CompatXWing` ≡ X-Wing, and — since `pk`/`ct`/`ss` are
  asserted against published reference values — **reproduces the FIPS 203
  reference output on these 3 happy-path vectors** (keygen/encaps/decaps). It is
  **not** itself a full ACVP / FIPS 203 validation — that breadth is provided by the
  NIST ACVP test below.
- **NIST ACVP ground-truth conformance** ✅ — `q-periapt-backends/src/acvp.rs` validates
  the portable `mlkem-native` v1.2.0 (through
  `q-periapt-mlkem-native-sys`) / `fips204` 0.4.6 adapters against the authoritative NIST
  vectors (vendored under
  `crates/q-periapt-backends/vectors/`, from `usnistgov/ACVP-Server`): the **full FIPS
  parameter family** — **ML-KEM-512/768/1024** (25 keyGen, 25 encaps, 10 decaps incl.
  implicit-rejection, each) and **ML-DSA-44/65/87** (25 keyGen each + the
  deterministic/external/empty-context sigGen/sigVer cases, plus the **broader signature
  modes** the backend can reproduce — external/pure **hedged** + **non-empty context**
  and **HashML-DSA SHAKE-128 pre-hash**) — byte-identical to NIST. Vendored
  internal-interface vectors remain explicit, unwired reference data and are not
  counted as passing backend cases. Direct ground truth, orthogonal to the differential.
- **Multi-backend differential (full KEM chain)** ✅ — `q-periapt-backends/src/differential.rs`
  cross-checks every component against an **independent** implementation on random
  inputs: **ML-KEM-512/768/1024** vs RustCrypto `ml-kem`, X25519 vs `orion`
  (+ the RFC 7748 §6.1 ground-truth vector), the full `HybridKem` reconstructed from
  independent ML-KEM + X25519 while sharing production's RustCrypto SHA3 implementation
  (for **both** the default ML-KEM-768 and the
  enhanced ML-KEM-1024 suites), and **ML-DSA-44/65/87** vs RustCrypto
  `ml-dsa` (byte-identical keygen + signatures + cross-verification + tamper rejection)
  — all byte-identical. The official X-Wing and separately encoded `ContextBound`
  KATs provide the independent combiner check; the differential does not claim an
  independent SHA3 implementation.
- **Generative property tests** ✅ — `q-periapt-backends/src/proptests.rs` (proptest)
  holds the combiner/hybrid invariants over random inputs: determinism, the
  CompatXWing length guard + ContextBound non-empty-context guard, encoding
  injectivity under a field-boundary shift (the binding property), profile domain
  separation, context bit-sensitivity, and hybrid KEM round-trip.
- **ContextBound reference vectors** ✅ — `q-periapt-backends/src/contextbound_kat.rs`
  pins fixed `(suite_id, policy_version, components, context) → K` vectors for the
  `ContextBound` combiner, each verified against `combine()` **and** an independent
  recompute (RustCrypto SHA3-256 over a from-scratch canonical encoder), plus a
  length-prefix **collision pair** (identical naive concatenation, distinct keys) that
  makes the injectivity property load-bearing. The positive companion to the X-Wing KAT.
- **SHA3-256 KAT** ✅ — `SHA3-256("")` matches the FIPS 202 digest.
- **ML-KEM-768 deterministic encaps** ✅ — same randomness ⇒ identical ct + ss.
- **ML-KEM-768 / X25519 round-trips** ✅.
- **Hybrid round-trip, both profiles** ✅ — real ML-KEM-768 + X25519 + SHA3-256
  through `q-periapt-kem::HybridKem`; `ContextBound` covers the expanded ML-KEM
  backend and `CompatXWing` covers the X-Wing seed-dk backend.
- **Enhanced suite (ML-KEM-1024 + X25519) end-to-end KAT** ✅ —
  `q-periapt-backends/src/enhanced_kat.rs` drives a real `HybridKem<MlKem1024, X25519>`
  `ContextBound` round-trip and pins the 32-byte secret three independent ways
  (round-trip, an independent length-prefixed SHA3-256 recompute over the real
  components, and a golden hex). The expanded ML-KEM-1024 backend is deliberately
  rejected under `CompatXWing`; `differential.rs` pins that fail-closed boundary.
  This makes the enhanced suite real end-to-end, not merely a policy string.
- **Negative injectivity KAT** ✅ — `q-periapt-core`: boundary-shift tuples that would
  collide under naive concatenation stay distinct under fixed-width length
  prefixing (`docs/BINDING_SECURITY.md` §3.2).

## Pending (hardening / later milestones)

- [ ] **Spec-to-implementation linkage proof** — the EasyCrypt model and the Rust
      implementation are linked by human review plus mirrored KATs today, not by a
      mechanized refinement proof.
- [ ] **More negative malformed-input vectors** — especially binding-language ABI
      surfaces and profile/policy rejection cases beyond the current unit tests.
