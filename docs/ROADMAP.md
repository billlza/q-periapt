# Q-Periapt — Roadmap

Authoritative status and forward plan for **Q-Periapt**, a portable, `no_std`,
side-channel-first PQ/T (post-quantum / traditional) hybrid cryptographic suite.
One dependency-free Rust core (`q-periapt-core`) is reused, byte-identically,
across C ABI / WASM / Swift / Kotlin.

This file is the single source of truth for *what is done* vs *what is pending*.
Where a claim is subtle, it cross-references the authoritative spec
([`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md),
[`docs/COMBINER_SPEC.md`](COMBINER_SPEC.md),
[`ctstats/README.md`](../ctstats/README.md),
[`tests/kat/README.md`](../tests/kat/README.md),
[`formal/easycrypt/README.md`](../formal/easycrypt/README.md)).

---

## Honest positioning — read this first

Q-Periapt ships the **same NIST primitives everyone else ships** — ML-KEM-768,
X25519, ML-DSA-65/87, SLH-DSA, HQC — through vetted backends. It does **not**
invent or accelerate any primitive.

**What we explicitly do NOT claim:**

- **Not faster than X-Wing / the NIST primitives.** `Profile::CompatXWing` *is*
  X-Wing byte-for-byte. The combiner micro-benchmark
  ([`crates/q-periapt-backends/benches/combiner.rs`](../crates/q-periapt-backends/benches/combiner.rs))
  measures our allocation-free combiner at roughly *parity* with a streaming
  X-Wing reference (in fact a few tens of nanoseconds slower through the generic
  trait abstraction) — negligible, because the combiner is well under 1% of a
  handshake dominated by ML-KEM. `Profile::ContextBound` deliberately does
  *more* combiner hashing (~19×) in exchange for binding coverage. **We never
  claim a speed edge over X-Wing.**
- **No own FIPS validation.** We *reproduce* FIPS 203 reference output on three
  happy-path X-Wing draft vectors; that is not an ACVP validation.
- **We track standards; we do not set them.** X-Wing is an IETF draft, not a
  ratified standard.
- **No completed third-party audit.** This is **research-grade, not
  production**: backends are pre-1.0 / unaudited (e.g. `libcrux 0.0.9` asks you
  to contact the maintainers before production use). **Do not deploy.**

**Where the genuine, defensible value is** — none of it is speed:

1. **Provable binding with minimal assumptions.** The `ContextBound` combiner's
   binding reduces *only* to collision-resistance of the hash, and that
   reduction is **machine-checked in EasyCrypt** (see DONE §7). X-Wing cannot
   match this without forking its construction.
2. **Crypto-agility.** Suite id + policy version are bound first-class; the
   suite is a thin composition over swappable, attested backends.
3. **Side-channel CI.** Failure-path indistinguishability (implicit rejection)
   is a hard merge gate.
4. **Cross-platform byte-identical consistency.** One core, four faces, one
   shared reference vector — a reduced audit surface, not unique interop.
5. **Auditability.** CBOM/SBOM, a documented threat model, and a published,
   per-cell honest scope for every assurance claim.

---

## DONE

Every item below is grounded in code/commits in this repository.

### 1. Real vetted backends wired
[`crates/q-periapt-backends`](../crates/q-periapt-backends) wires the core
traits (`Kem`, `Xof256`, `Signer`/`Verifier`) to vetted implementations — no toy primitives in
the shipped path:

- **ML-KEM-768** and **ML-DSA-65/87** via `libcrux-ml-kem` / `libcrux-ml-dsa`
  `0.0.9` (HACL\*-derived, constant-time; encapsulation coins passed explicitly
  for determinism and `no_std`).
- **X25519** via `x25519-dalek` 2 (`default-features = false`, `static_secrets`).
- **SHA3-256 / SHAKE-256** via `libcrux-sha3` (same verified family as the KEM).
- **SLH-DSA** (FIPS 205) via `fips205 0.4.1` and **HQC** via `pqcrypto-hqc 0.2.2`
  (PQClean C) — both **off by default**, behind the `slh-dsa` / `hqc` features.
  The default / wasm / `no_std` builds prove these stay un-pulled; the `hqc` C
  backend is fenced off `wasm32` by a `compile_error!` guard (CI `feature-fence`
  job).

### 2. X-Wing byte-exact KAT
[`crates/q-periapt-backends/src/xwing_kat.rs`](../crates/q-periapt-backends/src/xwing_kat.rs)
reproduces all **3 official `draft-connolly-cfrg-xwing-kem` vectors**
byte-for-byte — public key, ciphertext, **and** shared secret, for encaps **and**
decaps. This **reproduces FIPS 203 reference output on those three happy-path
vectors** (it is not a full FIPS 203 validation; see PENDING §1) and confirms
`Profile::CompatXWing` ≡ X-Wing. See [`tests/kat/README.md`](../tests/kat/README.md).

### 3. Both combiner profiles + C2PRI guard
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
- **C2PRI guard** — `Kem::C2PRI` (const, default `false`) + `HybridKem::new`
  ([`crates/q-periapt-kem/src/lib.rs`](../crates/q-periapt-kem/src/lib.rs)):
  pairing a non-C2PRI KEM (X25519 / HQC) with `CompatXWing` is rejected with
  `Error::PolicyDenied`, confining such KEMs to `ContextBound` (which binds all
  ciphertexts).

### 4. `no_std` bare-metal core
`q-periapt-core` is `#![no_std]` with `#![deny(unsafe_code)]` and exactly **one**
documented `unsafe` block (the `Secret::drop` wipe; see §6). CI `no_std` job
builds it for `thumbv7em-none-eabihf` (Cortex-M) and must not pull `std`.

### 5. Cross-platform faces, byte-identical vs a shared vector
The same core is exposed through four faces, each verified to reproduce the
**shared reference vector** byte-for-byte:

- **C ABI / FFI** — `q-periapt-ffi` (`ffi_matches_shared_vector`, checked in the
  `check` job).
- **WASM** — `q-periapt-wasm`, run on a real Node runtime via `wasm-pack test`
  (CI `bindings-wasm`).
- **Swift** — `bindings/swift` over the C ABI (CI `bindings-swift`, macOS).
- **Kotlin** — `bindings/kotlin` via the Panama FFM API, JDK 22+ (CI
  `bindings-kotlin`).

The single source of truth is `bindings/shared-test-vectors.json`; every face
decapsulates it and must reproduce the secret byte-for-byte.

### 6. Hardened `Secret` zeroization
`q_periapt_core::Secret` is securely zeroized on drop — volatile byte writes the
optimizer may not elide, then a `compiler_fence(SeqCst)` (the `zeroize` crate's
technique, inlined to keep the core dependency-free). `Secret` is intentionally
**not** `Clone`/`Copy`, so no copy survives past the wipe.

### 7. Machine-checked binding proof + CI formal-proof gate
[`formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec):

- **`bind_le_cr`** is machine-checked: `Adv^{X-BIND-K-*}(A) ≤ Adv^{CR}(H)` for the
  `ContextBound` combiner, generic over the observable projection (instantiates to
  `MAL-BIND-K-CT`, `K-PK`, `K-CTX`), reducing **only** to collision-resistance of
  the hash — no binding assumption on ML-KEM / X25519.
- **`encode_inj` is now a proved `lemma`** (commit `ef98df1`), no longer an axiom:
  the canonical encoding is modeled concretely and its injectivity proved,
  reducing only to two elementary `be8` facts (8-byte fixed width + injectivity)
  plus collision-resistance of SHA3. **0 admits / 0 sorry.**
- **CI `formal-proof` job** — a `! grep -rnE 'admit|sorry'` **hard gate** (catches
  a proof being stubbed out) plus a best-effort `make check` when an EasyCrypt
  toolchain installs.

**Honest scope (unchanged):** H's collision-resistance is a modeling assumption;
IND-CCA2 robustness is argued on paper, not mechanized; there is no
spec↔implementation linkage proof; `X-BIND-CT-*` is structurally impossible for
implicitly-rejecting ML-KEM and is **not** claimed; `ContextBound` is **not**
"stronger binding than X-Wing" (same malicious-adversary ceiling) — the edge is
**assumption-minimality and proof coverage**. See
[`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md) and
[`formal/easycrypt/README.md`](../formal/easycrypt/README.md).

### 8. Signed-policy verification + TOML loading
[`crates/q-periapt-policy`](../crates/q-periapt-policy):

- `Policy::from_toml` — real TOML parsing.
- `Policy::load_signed` — authenticates the exact policy bytes via an injected
  `q_periapt_sig::Verifier` (SLH-DSA-intended) **before** trusting them;
  fail-closed.
- `Policy::load_signed_or_failsafe` — falls back to an L5 / `ContextBound`
  fail-safe policy on any verification failure.
- Downgrade floor + `negotiate_kem` (aborts on a downgrade attempt) +
  `select_profile` are enforced.

### 9. CBOM / SBOM (CycloneDX)
[`crates/q-periapt-cli`](../crates/q-periapt-cli) (`qperiapt` binary) emits a
CycloneDX 1.6 **Crypto** BOM (`cbom`) of the suite's cryptographic assets and a
CycloneDX 1.6 **SBOM** (`sbom`) from `Cargo.lock`, plus a legacy/quantum-
vulnerable **migration scanner** (`scan`). CI `audit` job runs all and uploads
the BOMs as artifacts.

### 10. Combiner micro-benchmark
[`crates/q-periapt-backends/benches/combiner.rs`](../crates/q-periapt-backends/benches/combiner.rs)
isolates the only thing an X-Wing-compatible suite controls — the combiner
*implementation* — by hashing the identical 134-byte single-block input four
ways (our allocation-free libcrux one-shot, a streaming RustCrypto X-Wing
reference, a single-block RustCrypto one-shot, and the heap-`Vec` path we replaced),
asserting byte-identical output
at startup. This is the measurement behind the "parity, not faster" positioning.

### 11. Multi-backend differential tests
[`crates/q-periapt-backends/src/differential.rs`](../crates/q-periapt-backends/src/differential.rs)
cross-validates the primitives **and the full hybrid** against independent
implementations on random `SHAKE-256(counter)` inputs (no RNG) — an assurance method
orthogonal to KATs and the proof, catching integration/encoding bugs that 3 fixed
vectors would miss:
- **ML-KEM-768** — our libcrux backend vs RustCrypto `ml-kem` (byte-identical keygen,
  encapsulation, decapsulation over 64 inputs).
- **X25519** — our `x25519-dalek` backend vs the independent `orion` implementation,
  plus the authoritative **RFC 7748 §6.1** ground-truth Diffie–Hellman vector.
- **Hybrid CompatXWing** — our `HybridKem` output reconstructed from RustCrypto ML-KEM
  + orion X25519 + a RustCrypto SHA3 X-Wing combiner, byte-identical for encaps and
  decaps. Validates the orchestration + combiner end-to-end against three independent
  components.
- **ML-DSA-65** — our libcrux signature backend vs RustCrypto `ml-dsa`: byte-identical
  keygen + deterministic signatures (FIPS 204 external mode, rnd = 0), plus cross-
  verification (each implementation verifies the other's signature) and tamper rejection.

Extending the differential to SLH-DSA is pending (its keygen is randomized, so the
check would be signature interoperability rather than byte-identity).

### 12. NIST ACVP ground-truth conformance
[`crates/q-periapt-backends/src/acvp.rs`](../crates/q-periapt-backends/src/acvp.rs)
validates the libcrux backends against the **authoritative** NIST ACVP vectors
(vendored under `crates/q-periapt-backends/vectors/`, from `usnistgov/ACVP-Server`):
- **ML-KEM-768 (FIPS 203)** — the full set: 25 keyGen `(d,z)→(dk,ek)`, 25 encaps
  `(ek,m)→(c,k)`, 10 decaps `(dk,c)→k` including modified-ciphertext cases that
  exercise FO implicit rejection. All byte-identical to NIST.
- **ML-DSA-65 (FIPS 204)** — 25 keyGen `ξ→(sk,pk)`, plus the sigGen/sigVer cases
  matching our backend's mode (external interface, pure, deterministic, empty
  context). Broader sign/verify conformance is covered by the §11 differential.

This is *direct* NIST ground truth, orthogonal to the differential (which compares
against another implementation). Other parameter sets + broader signature modes
are pending (§PENDING).

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
   (`enhanced_kat.rs`) — no longer just a policy allow-list string. Remaining: the lower
   parameter sets (ML-KEM-512, ML-DSA-44/87) and the broader ACVP signature modes
   (contexts, pre-hash, internal interface, hedged). Fixed `(suite_id, policy_version,
   components, context) → K` reference vectors for `ContextBound` now exist as an
   in-repo KAT (`crates/q-periapt-backends/src/contextbound_kat.rs`, independently
   cross-checked by a second SHA3 + a from-scratch encoder, and including a
   load-bearing length-prefix collision pair). These are now also **reproduced across
   all five faces**: a raw-`combine` C ABI export (`q_periapt_combine`) is wired
   through C / WASM / Swift / Kotlin, and `bindings/contextbound-vectors.txt` is
   reproduced byte-for-byte on each (Rust core, C ABI, WASM on wasm32, Swift, Kotlin).
   See [`tests/kat/README.md`](../tests/kat/README.md).

2. **Binary-level constant-time + making timing a hard gate.** Today,
   failure-path indistinguishability / implicit rejection **is** a hard CI gate
   ([`ctstats/README.md`](../ctstats/README.md), CI `sidechannel` job). The
   **dudect timing test is report-only** (runs with `|| true`, never a merge
   gate) because shared CI runners are too noisy for a stable threshold.
   Binary-level **dataflow** constant-time is now a **hard gate** (the
   `constant-time` CI job runs `ct_verify` under Valgrind/Memcheck-TIMECOP) over the
   suite's own CT composition code — `ct_eq`, `ct_select32`, and the combiner. Still
   TODO: extending Memcheck over the component-primitive paths and to non-x86
   targets, and promoting a quiesced-hardware **timing** check to a gate (the
   statistical dudect test is still report-only, so *timing* is not yet gated).

3. **Broader `cargo-fuzz` corpora.** Two targets exist and have been run locally
   (`combine`, `mlkem_decapsulate`; CI `fuzz` job *compiles* all targets); see
   [`fuzz/README.md`](../fuzz/README.md). Larger seed corpora, longer time-boxed
   CI runs, and additional targets (signature paths, policy/TOML parsing) are
   pending.

4. **Independent third-party audit.** None has been performed.

5. **Production hardening.** Backends are pre-1.0 / unaudited (`libcrux 0.0.9`
   asks for maintainer contact before production); RUSTSEC-2026-0163
   (`pqcrypto-internals` unmaintained) is *surfaced*, not hidden, in
   `.cargo/audit.toml`. Q-Periapt is **not for deployment**.

6. **(Future) SkyBridge integration.** Folding Q-Periapt into the SkyBridge
   quantum-comm project is a longer-term direction, not current work.

---

## Status snapshot

| Area | Status |
| --- | --- |
| Vetted backends wired (ML-KEM/ML-DSA/SHA3/X25519; opt-in SLH-DSA/HQC) | **Done** |
| X-Wing byte-exact KAT (3 draft vectors) | **Done** |
| Both combiner profiles + C2PRI guard | **Done** |
| `no_std` bare-metal core (one documented `unsafe`) | **Done** |
| C ABI / WASM / Swift / Kotlin, byte-identical vs shared vector | **Done** |
| Hardened `Secret` zeroization | **Done** |
| Signed-policy verification + TOML loading | **Done** |
| CBOM / SBOM (CycloneDX) + migration scanner | **Done** |
| Machine-checked `bind_le_cr` + `encode_inj` lemma + CI no-admits gate | **Done** |
| Tamarin symbolic handshake model (server auth + hybrid robustness, 4 lemmas) | **Done** |
| Combiner micro-benchmark | **Done** |
| NIST ACVP conformance (ML-KEM-768 + ML-KEM-1024 + ML-DSA-65 + ML-DSA-87) | **Done** |
| `ContextBound` reference vectors (in-repo KAT, independently cross-checked) | **Done** |
| Cross-platform `ContextBound`/`CompatXWing` combiner vectors (all 5 faces) | **Done** |
| ML-KEM-1024 backend (enhanced-mode KEM) + NIST ACVP + differential | **Done** |
| ML-DSA-87 backend (enhanced-mode L5 signature) + NIST ACVP + differential | **Done** |
| Enhanced suite `HybridKem<MlKem1024,X25519>` end-to-end + pinned KAT | **Done** |
| Enhanced L5 handshake (ML-KEM-1024 + X25519 + ML-DSA-87) in `tls-demo`, generic core | **Done** |
| ACVP ML-DSA signature modes: hedged + non-empty context + SHAKE-128 pre-hash (65 & 87) | **Done** |
| Full FIPS family backends + ACVP + differential (ML-KEM-512/768/1024, ML-DSA-44/65/87) | **Done** |
| Remaining ACVP modes: internal interface / externalMu / non-SHAKE128 pre-hash (libcrux-gated) | Pending |
| Dataflow CT gate (Memcheck/TIMECOP, our composition code) | **Done** |
| Binary-CT over primitive paths + non-x86 + timing as a hard gate | Pending |
| Broader `cargo-fuzz` corpora | Pending |
| Independent third-party audit | Pending |
| Production hardening | Pending |
| SkyBridge integration | Future |
