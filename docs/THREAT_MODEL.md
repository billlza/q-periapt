# Threat Model — Q-Periapt PQ/T Hybrid Suite

> **Status: research-grade, pre-1.0, NOT for production deployment.**
> No third-party audit. Backends are unaudited / pre-1.0 (libcrux 0.0.9 explicitly
> asks you to contact the maintainers before production use). This document is the
> authoritative statement of *what the design defends against and — equally
> important — what it does not.* Every guarantee below is tagged as **ENFORCED**
> (a CI gate or a compile-time/type-level invariant fails the build on regression),
> **PROVED** (machine-checked in EasyCrypt at the abstract-spec level), or
> **REPORT-ONLY / TODO** (measured or aspirational, not gated). Read the
> [§5 Out-of-scope](#5-out-of-scope--honest-caveats) section before relying on
> anything here.

Cross-references:
[`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md) (the authoritative binding proof and
its honest scope),
[`formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec) +
[`formal/easycrypt/README.md`](../formal/easycrypt/README.md) (the mechanized proof),
[`ctstats/README.md`](../ctstats/README.md) (side-channel CI scope),
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (which checks gate vs report).

---

## 1. Assets

What an adversary wants and what the suite is built to protect:

| Asset | Description | Where it lives |
|-------|-------------|----------------|
| **A1 — Combined hybrid shared secret `K`** | The 32-byte output of the combiner ([`q_periapt_core::Secret`](../crates/q-periapt-core/src/lib.rs)). Compromise breaks the session that uses it as keying material. | Derived in [`q_periapt_core::combine`](../crates/q-periapt-core/src/lib.rs); transient. |
| **A2 — Long-term secret keys** | ML-KEM-768 decapsulation key, X25519 static secret, HQC secret key, and the signing keys (ML-DSA / SLH-DSA). | Backend types in `q-periapt-backends`; held by the application. |
| **A3 — Component shared secrets `ss_pq`, `ss_trad`** | The per-component KEM outputs that feed the combiner. Transient, but leakage of either degrades the hybrid toward its surviving half. | Caller-provided buffers passed to [`HybridKem::encapsulate`/`decapsulate`](../crates/q-periapt-kem/src/lib.rs). |
| **A4 — Policy authenticity / integrity** | The active algorithm policy (`min_nist_level`, allowed KEMs/sigs, combiner profile). A forged or tampered policy can silently weaken the whole suite. | [`q_periapt_policy::Policy`](../crates/q-periapt-policy/src/lib.rs), loaded from `*.policy.toml`. |
| **A5 — Binding integrity of the transcript** | The guarantee that one derived `K` is reachable from exactly one tuple of `(suite_id, policy_version, every ct/pk, context)`. Compromise enables key-reuse / re-encapsulation / cross-context confusion attacks. | Established by the combiner encoding; see [§4.1](#41-provable-binding-to-collision-resistance-of-sha3). |

The combiner core deliberately contains **no primitive implementations** and **no
secret-dependent error information** — its entire job is to compose A3 into A1 with
binding A5, in a way small enough to audit in isolation.

---

## 2. Adversary capabilities

We model four adversaries. They may be combined; each row states the assumed power.

| ID | Adversary | Assumed capability |
|----|-----------|--------------------|
| **ADV-MAL** | Malicious-key / binding adversary | Supplies adversarially chosen public keys **and** decapsulation keys (the **MAL** class of Cremers–Dürmuth–Medinger–Naderpour). Tries to produce two encapsulation transcripts that collide on `K` while disagreeing on some `ct`, `pk`, or `context` (re-encapsulation / UKS / cross-context confusion). This is the load-bearing adversary — its venues (PQ-KEM-in-HPKE, Signal/MLS-style handshakes, PQXDH) accept attacker-supplied key material. |
| **ADV-CCA** | Chosen-ciphertext adversary | Submits arbitrary (including malformed or maliciously mutated) ciphertexts to `decapsulate` and observes any distinguishable reaction — a return code, a derived-secret relationship, or an error string. Seeks a Bleichenbacher/Manger-class **decapsulation oracle**. |
| **ADV-TIME** | Passive timing / microarchitectural side-channel | Measures wall-clock latency (and, on a quiet host, finer signals) of `decapsulate` over many calls to distinguish valid from invalid ciphertexts or to recover secret-dependent control flow. Cannot read memory directly. |
| **ADV-POLICY** | Policy-tampering / downgrade adversary | Modifies the policy file in transit or at rest, or stands in as a downgrading peer during negotiation, to push the suite below its intended NIST floor or onto a weaker combiner profile. |

**Adversary boundary (assumed honest / out of model):** the host running the code,
its RNG, the compiler/toolchain, the OS, and physical access (fault injection,
power/EM, cold-boot). See [§5](#5-out-of-scope--honest-caveats).

---

## 3. Trust base

Every in-scope guarantee rests on these assumptions; if one fails, the
corresponding guarantee fails:

- **Collision-resistance (and, for the KDF, PRF/ROM behaviour) of SHA3-256 /
  SHAKE-256.** This is the single primitive assumption under the binding proof.
- **The selected backends correctly and constant-time-ly implement their
  primitives** (libcrux ML-KEM-768 / ML-DSA, x25519-dalek, fips205 SLH-DSA,
  pqcrypto-hqc). These are vetted but **unaudited-for-this-use and pre-1.0**.
- **The host RNG is sound**, and encapsulation randomness fed to
  [`Kem::encapsulate`](../crates/q-periapt-core/src/lib.rs) is unpredictable to the
  adversary. (The core is `no_std` with no internal RNG by design — randomness is
  caller-supplied so operations are deterministic for KATs; this moves RNG trust to
  the caller.)
- **The policy verification key is a genuine trust anchor** (out-of-band
  provisioned), and the intended SLH-DSA root signer is honest.

---

## 4. In-scope guarantees

### 4.1 Provable binding to collision-resistance of SHA3 — **PROVED (abstract spec)**

Defends against: **ADV-MAL**.

The `ContextBound` combiner profile
([`Profile::ContextBound`](../crates/q-periapt-core/src/lib.rs)) hashes the **full**
component tuple under an injective, fixed-width-length-prefixed, domain-separated
encoding:

```
K = SHA3-256( Encode( DOMAIN, suite_id, policy_version,
                      ss_pq, ss_trad, ct_pq, pk_pq, ct_trad, pk_trad, context ) )
```

where `DOMAIN = b"Q-PERIAPT-HYBRID-KEM/v1"` and every field is emitted as an
8-byte big-endian length prefix followed by the field bytes
([`absorb_lp`](../crates/q-periapt-core/src/lib.rs)). Because **every** ciphertext
and public key is absorbed, binding reduces to collision-resistance of SHA3 **with
no binding assumption on ML-KEM or X25519**.

- **Machine-checked.** `bind_le_cr` in
  [`BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec) proves
  `Adv^{X-BIND-K-*} ≤ Adv^{CR}(H)`, instantiating to `MAL-BIND-K-CT`,
  `MAL-BIND-K-PK`, and `MAL-BIND-K-CTX`, with **0 admits**. `encode_inj` (the
  injectivity of the encoding) is now a **proved lemma**, reducing only to two
  elementary `be8` facts (8-byte fixed width + injectivity) plus CR of SHA3 — it is
  no longer an axiom.
- **CI enforcement.** A `formal-proof` job
  ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) hard-gates on
  `! grep -rnE 'admit|sorry' formal/easycrypt/` (catches a proof being stubbed out)
  and runs `make check` best-effort (a hermetic EasyCrypt install is heavy, so the
  full re-check is not a merge gate, but the no-admits guard is).
- **Implementation mirror.** The injective encoding is exercised by a negative KAT
  in [`q-periapt-core`](../crates/q-periapt-core/src/lib.rs)
  (`injective_encoding_prevents_boundary_collision`): two tuples that would collide
  under naive concatenation are kept distinct by length prefixing. A mandatory
  non-empty `context` is enforced (`Error::InvalidLength` otherwise), without which
  the `K-CTX` guarantee degenerates.

**Honest ceiling (do not overstate):** `ContextBound` is **not** "stronger binding
than X-Wing." A correctly-implemented seed-format X-Wing attains the same
`MAL-BIND-K-CT` / `MAL-BIND-K-PK` ceiling; the X-BIND lattice has no point above
that pair on the CT/PK axes. The real edge is **assumption-minimality and proof
coverage** (binding from CR alone, in one self-contained machine-checked proof,
instead of relying on ML-KEM's FO self-binding), plus the orthogonal context-binding
axis. `X-BIND-CT-*` notions (a *ciphertext* binding the key) are **structurally
impossible** for an implicitly-rejecting ML-KEM-based hybrid and are **not claimed**.
See [`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md) §5–§6 for the full, careful
claim. The proof is **abstract-spec level only**: H's collision-resistance is a
modeling assumption, IND-CCA2 robustness is argued on paper (not mechanized), and
there is **no spec↔implementation linkage proof**.

### 4.2 No decapsulation oracle — implicit rejection — **ENFORCED (hard CI gate)**

Defends against: **ADV-CCA**, and the return-code half of **ADV-TIME**.

The [`Kem`](../crates/q-periapt-core/src/lib.rs) trait contract requires
`decapsulate` to use **implicit rejection**: an invalid ciphertext yields a
deterministic pseudorandom secret rather than an error. The failure path is
designed to be indistinguishable from success.

- **No error oracle.** `decapsulate` does **not** return `Error` to signal an
  invalid ciphertext. The only `Error` values the suite produces correspond to
  **publicly observable** conditions — buffer-length mismatches and policy denials.
  `q_periapt_core::Error` has exactly three variants
  (`InvalidLength`, `Backend`, `PolicyDenied`), each a public fact; by construction
  none encodes *why* a decapsulation "failed."
- **Errors encode only PUBLIC conditions.** This is a deliberate design property of
  the coarse `Error` type ([`q-periapt-core`](../crates/q-periapt-core/src/lib.rs)
  "Security notes"). The `?` operators in
  [`HybridKem::decapsulate`](../crates/q-periapt-kem/src/lib.rs) propagate only
  these public conditions.
- **CI hard gate.** `cargo test -p q-periapt-ctstats` is a **merge-blocking** gate.
  `mlkem_implicit_rejection_no_error_oracle` asserts that decapsulating a corrupted
  ML-KEM-768 ciphertext (a) returns `Ok` (no oracle), (b) yields a secret different
  from the valid one, and (c) is deterministic across repeats.
  `hybrid_decaps_no_error_on_invalid_ct` asserts the same for the full hybrid
  decapsulation. See [`ctstats/src/lib.rs`](../ctstats/src/lib.rs) and the
  `sidechannel` job in CI.
- **Constant-time selection primitive.**
  [`ct_select32`](../crates/q-periapt-core/src/lib.rs) is the branch-free
  primitive intended for implicit rejection: always compute both the real and the
  rejection derivation, then select with a mask so the failure path is
  instruction-indistinguishable. [`ct_eq`](../crates/q-periapt-core/src/lib.rs)
  is constant-time over equal-length inputs (lengths are treated as public). These
  helpers are best-effort in portable Rust — see the timing caveat in §4.2's
  REPORT-ONLY counterpart, [§5.1](#51-timing-side-channels-are-report-only-not-gated).

### 4.3 Downgrade protection — NIST floor + signed policy, fail-closed — **ENFORCED (type/logic + unit-gated)**

Defends against: **ADV-POLICY**.

Two independent mechanisms, both fail-closed:

- **Downgrade floor.** [`Policy::meets_floor`](../crates/q-periapt-policy/src/lib.rs)
  rejects any leveled PQ algorithm below `min_nist_level` and rejects **unknown**
  identifiers outright (`None ⇒ fail-closed`); only recognized traditional partners
  (X25519/X448/P-256/P-384) bypass the PQ floor.
  [`Policy::kem_allowed`](../crates/q-periapt-policy/src/lib.rs) requires
  *listed* ∧ *not deprecated* ∧ *meets floor* — so a below-floor KEM placed in
  `allowed_kems` is still rejected. [`negotiate_kem`](../crates/q-periapt-policy/src/lib.rs)
  picks the **strongest** mutually-acceptable KEM and returns
  `Error::PolicyDenied` (aborts) if the peer offers nothing acceptable, rather than
  silently selecting a weak suite. Unit-gated in `cargo test --workspace`
  (`floor_rejects_below_level_kem`, `enhanced_floor_rejects_mlkem768`,
  `negotiate_prefers_strongest_and_aborts_on_downgrade`).
- **Signed policy, authenticating the exact bytes.**
  [`Policy::load_signed`](../crates/q-periapt-policy/src/lib.rs) verifies a detached
  signature over the **raw policy bytes** via an injected
  [`q_periapt_sig::Verifier`](../crates/q-periapt-sig/src/lib.rs) (SLH-DSA intended
  for a long-term root) **before** parsing/trusting the policy. The signature covers
  the exact bytes, so there is no canonical-encoding ambiguity. **Fail-closed:** any
  signature or parse failure is an `Err` (`PolicyError::SignatureInvalid` /
  `Malformed` / `UnsupportedSchema` / `UnknownProfile`).
  [`load_signed_or_failsafe`](../crates/q-periapt-policy/src/lib.rs) falls back to
  the **strongest** compiled-in posture (`Policy::enhanced()`: L5 + `ContextBound`)
  and returns the offending error for logging — an unauthenticated/malformed policy
  is a security event, not a silent downgrade. Unit-gated by
  `signed_load_accepts_valid_and_fails_closed` (tampered body, wrong key, and
  failsafe fallback all covered).
- **Profile/algorithm coupling (compile-time guard).** The fast `CompatXWing`
  profile omits the PQ ciphertext from the KDF, which is sound **only** for a C2PRI
  KEM. [`HybridKem::new`](../crates/q-periapt-kem/src/lib.rs) rejects pairing a
  non-C2PRI PQ KEM (X25519/HQC) with `CompatXWing` (`Error::PolicyDenied`),
  confining non-C2PRI components to `ContextBound`. The C2PRI bit is a
  per-backend `const` ([`Kem::C2PRI`](../crates/q-periapt-core/src/lib.rs);
  `true` for ML-KEM-768, `false` for X25519/HQC), and
  [`Policy::select_profile`](../crates/q-periapt-policy/src/lib.rs) independently
  forces `ContextBound` whenever a non-C2PRI KEM is allowed.

### 4.4 Secure zeroization — **ENFORCED (type-level + Drop)**

Defends against: residual exposure of **A1** after use (in cooperation with the
host memory model).

[`q_periapt_core::Secret`](../crates/q-periapt-core/src/lib.rs) wraps the 32-byte
combined key and is wiped on `Drop` with **volatile zero writes** (which the
optimizer may not elide) followed by a `compiler_fence(SeqCst)` — the audited
`zeroize` crate's technique, inlined to keep the core dependency-free. `Secret` is
deliberately **not** `Clone`/`Copy`, so no copy can outlive the wipe; it is read once
via `as_bytes`. The core is `#![deny(unsafe_code)]` with **one** documented
`#[allow(unsafe_code)]` block — the wipe — and nothing else.

**Honest limit:** this protects the `Secret`'s own storage. Component secrets
(`ss_pq`, `ss_trad`) live in caller-provided `&mut [u8]` buffers whose zeroization
is the **caller's** responsibility, and the technique cannot defeat secrets the OS
has already paged to disk or copied during stack spills.

### 4.5 Cross-platform byte-identical consistency — **ENFORCED (CI)**

Defends against: silent divergence between language bindings that could produce
inconsistent (and therefore exploitable) keys.

The same dependency-free core runs across C ABI / WASM / Swift / Kotlin. CI
decapsulates a shared reference vector on each binding and requires byte-for-byte
reproduction (`bindings-wasm` on a real Node wasm runtime; `bindings-swift`;
`bindings-kotlin`; the Rust+C-ABI path in `check`). The X-Wing byte-exact KAT
(`q-periapt-backends`) **reproduces the `draft-connolly-cfrg-xwing-kem` reference
output on its 3 happy-path vectors**, and the **full NIST ACVP set** (ML-KEM-512/768/1024
+ ML-DSA-44/65/87 + SLH-DSA) plus the `ContextBound` reference vectors now pass too —
this is conformance to the published vectors, not certification (see
[§5.5](#55-acvp-conformance-not-cmvp-certification)).

---

## 5. Out-of-scope / honest caveats

This is the part to read before trusting anything above. These are **not** defended,
or are only partially defended.

### 5.1 Timing side-channels are REPORT-ONLY, not gated

The dudect Welch-t timing test (`dudect_decaps`,
[`ctstats/src/lib.rs`](../ctstats/src/lib.rs)) runs in the `sidechannel` CI job with
`|| true` — it **never fails the build**. Shared cloud runners have too much
scheduling/frequency noise for a stable `|t| < 4.5` threshold; a hard gate there
produces flaky failures that get muted, which is worse than no gate. A real timing
gate needs dedicated, quiesced hardware
([`ctstats/README.md`](../ctstats/README.md)). **Do not read "side-channel-first" as
"timing is gated."** What *is* gated is failure-path *indistinguishability* (§4.2),
not wall-clock *equality*.

### 5.2 Binary-level constant-time: gated for our composition code; broader coverage TODO

A **dataflow constant-time hard gate** now runs in CI (`constant-time` job) on **both
x86_64 and aarch64** (matrix): the `ct_verify` harness marks secrets "undefined" and
Valgrind/Memcheck (TIMECOP) flags any branch or index that depends on them, over the
suite's **own** constant-time composition code — `ct_eq`, `ct_select32`, and the combiner
over secret shared secrets. A compiler-introduced secret-dependent branch *there* now fails
the build on either arch (the emitted assembly differs per target, so each is an independent
check), catching exactly the source→assembly gap that best-effort source-level CT cannot.
The aarch64 leg was also reproduced locally in a container
([`ctstats/scripts/ct-in-container.sh`](../ctstats/scripts/ct-in-container.sh)), with a
planted-secret-branch negative control confirming Memcheck catches leaks there.
Still **TODO**: extending Memcheck over the component-**primitive** paths. This was
investigated (marking the ML-KEM decapsulation key secret and running libcrux's
`decapsulate`): it yields thousands of reports that are **Memcheck limitations on a
verified-CT SIMD primitive, not demonstrated leaks** — Memcheck reports constant-time
`csel`/`cmov` selects identically to branches, and over-approximates shadow through
NEON-vectorized code; no secret-dependent branch was isolated, and libcrux ML-KEM is
HACL*-verified CT at source level (details in [`ctstats/README.md`](../ctstats/README.md)).
Also TODO: promoting a quiesced-hardware **timing** check to a gate (the statistical dudect
test stays report-only). Binary-CT tooling is mature on **x86_64-linux and aarch64-linux**
(both now gated); **riscv64 / wasm32** remain **source-CT + upstream-attestation only**.
CT posture is **per-backend**, not universal — swapping a backend changes the
guarantee. Known carve-out: **ML-DSA signing uses rejection sampling, so its
iteration count is secret-dependent by design** — an auditable, documented exception,
not a covert leak.

### 5.3 No third-party audit

Nobody outside this project has reviewed the design or the code. The mechanized
proof is a strong internal artifact, not an external attestation.

### 5.4 Pre-1.0 / unaudited backends

The cryptographic primitives come from external crates that are themselves pre-1.0
or carry their own caveats — notably libcrux 0.0.9, which states it is research
software and asks you to contact the maintainers before production use. A
known-unmaintained transitive dependency (RUSTSEC-2026-0163, pqcrypto-internals) is
**acknowledged in `.cargo/audit.toml` and surfaced by `cargo audit` in CI**, not
hidden — but it is a real residual risk.

### 5.5 ACVP conformance, not CMVP certification

The backends pass the **full NIST ACVP conformance set** — ML-KEM-512/768/1024 and
ML-DSA-44/65/87 (keyGen + the external/pure, hedged-context, SHAKE-128 pre-hash, and
internal-interface signature modes), plus SLH-DSA-SHA2-{128,192,256}s — reproducing the
authoritative vectors byte-for-byte (`q-periapt-backends/src/acvp.rs`,
`acvp_slhdsa.rs`). **But passing ACVP vectors is conformance evidence, not a FIPS
validation.** There is no CMVP/CAVP certification, no validated cryptographic-module
boundary, and no operational-environment accreditation. Do not read "passes the ACVP
vectors" as "FIPS-validated."

### 5.6 No spec↔implementation linkage proof

The EasyCrypt binding theorem is at the **abstract-spec level**. There is no
mechanized proof that the Rust in [`q_periapt_core::combine`](../crates/q-periapt-core/src/lib.rs)
refines the EasyCrypt model. The link between proof and code is **human review plus
a mirrored negative KAT**, nothing stronger. Equally, the proof models SHA3 as
collision-resistant (and as a PRF/RO for the KDF); the guarantee is only as strong
as that idealization.

### 5.7 Adversary-boundary exclusions

Explicitly **out of model**: host/OS compromise; a broken or backdoored RNG;
compiler/toolchain compromise; physical-access attacks (fault injection, power/EM,
cold-boot/paging); the simultaneous cryptanalytic break of **both** the PQ and the
traditional component (the hybrid degrades gracefully to its surviving half, but is
not magic if both fall); HQC's side-channel posture (HQC is wired for assumption
diversity, confined to `ContextBound`, and is **not** covered by any
constant-time claim here); and the application's own use of `K` after the suite
returns it.

### 5.8 No speed advantage is claimed (and none should be inferred)

This suite ships the **same** NIST primitives everyone else does, via vetted
backends, with **no** primitive/speed edge. `CompatXWing` is X-Wing byte-for-byte;
the generic combiner is within tens of ns of a streaming X-Wing reference (negligible —
the combiner is <1% of a handshake). `ContextBound` is *deliberately* ~19× more
combiner hashing in exchange for assumption-minimal binding and context binding —
it is **slower on the standard axes, not stronger** there. The value of Q-Periapt
is **auditability, crypto-agility, side-channel CI, cross-platform byte-identical
consistency, and the machine-checked binding proof** — never speed.

---

## 6. Summary table

| # | Guarantee | Adversary | Mechanism | Enforcement |
|---|-----------|-----------|-----------|-------------|
| 4.1 | Binding to CR(SHA3); no KEM binding assumption | ADV-MAL | `ContextBound` injective hash-everything encoding | **PROVED** (`bind_le_cr`, 0 admits) + no-admits CI gate + mirror KAT |
| 4.2 | No decapsulation oracle; failure-path indistinguishable; errors = public only | ADV-CCA | Implicit rejection; coarse `Error`; `ct_select32` | **ENFORCED** (ctstats hard gate) |
| 4.3 | Downgrade protection (NIST floor + signed policy, fail-closed); profile/KEM coupling | ADV-POLICY | `meets_floor`/`kem_allowed`/`negotiate_kem`; `load_signed`; C2PRI guard | **ENFORCED** (logic/type + unit-gated) |
| 4.4 | Secure zeroization of the combined key | post-use exposure | volatile wipe + fence; not `Clone` | **ENFORCED** (Drop + type-level) |
| 4.5 | Cross-platform byte-identical output | binding divergence | shared-vector consistency tests | **ENFORCED** (CI) |
| 5.1 | Empirical timing equality | ADV-TIME | dudect Welch-t | **REPORT-ONLY** (not gated) |
| 5.2 | Binary-level CT — our composition (`ct_eq`/`ct_select32`/combiner) | ADV-TIME | Memcheck/TIMECOP `ct_verify` | **CI gate (x86_64 + aarch64)** |
| 5.2 | Binary-level CT — libcrux primitive paths (Memcheck-on-SIMD false positives) | ADV-TIME | source-level HACL* attestation | TODO (investigated) |
| 5.2 | Binary-level CT — riscv64 / wasm32 + timing-as-gate | ADV-TIME | — | TODO |
| 5.5 | NIST ACVP conformance (full FIPS family) | — | X-Wing KAT + full ACVP set (`acvp.rs`) | **CONFORMANCE DONE** — not CMVP-certified |
| 5.6 | Spec↔impl refinement | — | human review + mirror KAT | **NOT PROVED** |
