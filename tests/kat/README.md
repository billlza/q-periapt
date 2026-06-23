# Known-Answer Tests (KATs)

Status of M0 KAT coverage.

## Present (passing)

- **X-Wing draft byte-exact KAT** ✅ — `q-periapt-backends/src/xwing_kat.rs` reproduces all
  3 official `draft-connolly-cfrg-xwing-kem` vectors (`spec/test-vectors.json`)
  **byte-for-byte**: public key, ciphertext, and shared secret, for encaps **and**
  decaps. This proves `CompatXWing` ≡ X-Wing, and — since `pk`/`ct`/`ss` are
  asserted against published reference values — **transitively validates the
  libcrux ML-KEM-768 backend (keygen/encaps/decaps) against FIPS 203**.
- **SHA3-256 KAT** ✅ — `SHA3-256("")` matches the FIPS 202 digest.
- **ML-KEM-768 deterministic encaps** ✅ — same randomness ⇒ identical ct + ss.
- **ML-KEM-768 / X25519 round-trips** ✅.
- **Hybrid round-trip, both profiles** ✅ — real ML-KEM-768 + X25519 + SHA3-256
  through `q-periapt-kem::HybridKem`.
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
