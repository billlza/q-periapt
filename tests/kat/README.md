# Known-Answer Tests (KATs)

Status of M0 KAT coverage.

## Present (passing)

- **X-Wing draft byte-exact KAT** ✅ — `q-periapt-backends/src/xwing_kat.rs` reproduces all
  3 official `draft-connolly-cfrg-xwing-kem` vectors (`spec/test-vectors.json`)
  **byte-for-byte**: public key, ciphertext, and shared secret, for encaps **and**
  decaps. This proves `CompatXWing` ≡ X-Wing, and — since `pk`/`ct`/`ss` are
  asserted against published reference values — **reproduces the FIPS 203
  reference output on these 3 happy-path vectors** (keygen/encaps/decaps). It is
  **not** itself a full ACVP / FIPS 203 validation — that breadth is provided by the
  NIST ACVP test above.
- **NIST ACVP ground-truth conformance** ✅ — `q-periapt-backends/src/acvp.rs` validates
  the libcrux backends against the authoritative NIST vectors (vendored under
  `crates/q-periapt-backends/vectors/`, from `usnistgov/ACVP-Server`): the full
  **ML-KEM-768** and **ML-KEM-1024** sets (25 keyGen, 25 encaps, 10 decaps incl.
  implicit-rejection, each) and **ML-DSA-65** and **ML-DSA-87** (25 keyGen each + the
  deterministic/external/empty-context sigGen/sigVer cases) — byte-identical to NIST.
  Direct ground truth, orthogonal to the differential.
- **Multi-backend differential (full KEM chain)** ✅ — `q-periapt-backends/src/differential.rs`
  cross-checks every component against an **independent** implementation on random
  inputs: ML-KEM-768 **and ML-KEM-1024** vs RustCrypto `ml-kem`, X25519 vs `orion`
  (+ the RFC 7748 §6.1 ground-truth vector), the full `HybridKem` reconstructed from
  independent ML-KEM + X25519 + SHA3 (for **both** the default ML-KEM-768 and the
  enhanced ML-KEM-1024 suites), and **ML-DSA-65** and **ML-DSA-87** vs RustCrypto
  `ml-dsa` (byte-identical keygen + signatures + cross-verification + tamper rejection)
  — all byte-identical. Orthogonal to fixed KATs.
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
  through `q-periapt-kem::HybridKem`.
- **Enhanced suite (ML-KEM-1024 + X25519) end-to-end KAT** ✅ —
  `q-periapt-backends/src/enhanced_kat.rs` drives a real `HybridKem<MlKem1024, X25519>`
  `ContextBound` round-trip and pins the 32-byte secret three independent ways
  (round-trip, an independent length-prefixed SHA3-256 recompute over the real
  components, and a golden hex). The `CompatXWing` enhanced hybrid is additionally
  cross-checked against a 3-way independent reconstruction (RustCrypto ML-KEM-1024 +
  orion X25519 + RustCrypto SHA3) in `differential.rs`. Makes the enhanced suite real
  end-to-end, not merely a policy string.
- **Negative injectivity KAT** ✅ — `q-periapt-core`: boundary-shift tuples that would
  collide under naive concatenation stay distinct under fixed-width length
  prefixing (`docs/BINDING_SECURITY.md` §3.2).

## Pending (hardening / later milestones)

- [ ] **Full FIPS 203 ACVP suite** — the complete NIST ACVP ML-KEM-768 case set
      (edge cases, many vectors). Core correctness is already covered by the X-Wing
      KAT above; this is breadth/hardening.
- [ ] **ContextBound reference vectors** — fixed `(suite_id, policy_version,
      components, context) → K` vectors so the construction is reproducible across
      the C / WASM / Swift / Kotlin bindings (cross-platform consistency, M3).
