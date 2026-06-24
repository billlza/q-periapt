# Competitive Analysis — Q-Periapt vs X-Wing and Apple PQ3 / mainstream PQC hybrids

> **Status:** honest positioning document. Q-Periapt is **research-grade** (pre-1.0,
> unaudited, "do not deploy" — see [`../README.md`](../README.md#status--disclaimer)).
> X-Wing and Apple PQ3 are **peer-reviewed and/or deployed at scale**. This document
> exists to state — precisely and without inflation — the *narrow* axes on which a
> research artifact can differ from a production construction, and the *broad* axes on
> which it cannot and does not compete.

## TL;DR

Q-Periapt ships the **same NIST primitives** everyone else ships (ML-KEM-768, X25519,
ML-DSA-65/87, SLH-DSA, HQC), through the **same class of vetted backends** (libcrux /
HACL\*-derived for ML-KEM/ML-DSA/SHA3, x25519-dalek, fips205, pqcrypto-hqc). There is
**no primitive edge and no speed edge.** Its `CompatXWing` profile *is* X-Wing
byte-for-byte (it reproduces the `draft-connolly-cfrg-xwing-kem` reference output on
the 3 official happy-path vectors —
[`crates/q-periapt-backends/src/xwing_kat.rs`](../crates/q-periapt-backends/src/xwing_kat.rs)).

What it actually offers is a different *engineering and assurance* posture around an
otherwise-identical construction: a machine-checked binding proof that reduces to
collision-resistance of SHA3 with **no binding assumption on the component KEMs**;
policy-driven crypto-agility with signed, downgrade-protected policy; side-channel CI
(with the honest caveat that the *timing* portion is report-only today); a single
byte-identical core across four non-Rust faces; and an HQC code-based assumption-diversity
hedge. None of these is "stronger crypto" than X-Wing on the standard axes — they are
**proof-coverage, agility, auditability, and consistency** wins around the same ceiling.

## 0. What we are comparing against

| Subject | What it is | Maturity |
|---|---|---|
| **X-Wing** | `draft-connolly-cfrg-xwing-kem` — ML-KEM-768 + X25519 hybrid KEM, lean combiner `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)`, `label = 0x5c2e2f2f5e5c` (`\.//^\`). Peer-reviewed (CiC). | Standards-track Independent Submission draft; peer-reviewed proof; multiple interoperating implementations. |
| **Apple PQ3** | iMessage end-to-end hybrid protocol (ECDH + ML-KEM-1024-class), with formal-verification effort (Tamarin/ProVerif by Apple + academic collaborators), shipping to billions of devices. | Deployed at scale; audited internally + externally; formally analyzed at the protocol layer. |
| **Q-Periapt `CompatXWing`** | byte-exact X-Wing (same combiner, same label, same fields). | Research-grade, unaudited. |
| **Q-Periapt `ContextBound`** | a *different, heavier* combiner profile (GHP/Chempat "hash-everything"). Not wire-compatible with X-Wing; a deliberate robustness trade. | Research-grade, unaudited. |

The honest baseline for any comparison is: **on the X-Wing wire, Q-Periapt and X-Wing
are the same bytes.** Everything below is about what surrounds that wire.

## 1. Same primitives, same combiner, no speed edge

This is the foundational honesty constraint and it is **not** negotiable.

- **`CompatXWing` is X-Wing byte-for-byte.** The combiner is literally
  `SHA3-256(ss_pq ‖ ss_trad ‖ ct_trad ‖ pk_trad ‖ XWING_LABEL)` over four hard-checked
  32-byte fields and the 6-byte label, a single 134-byte Keccak block, allocation-free
  ([`crates/q-periapt-core/src/lib.rs`](../crates/q-periapt-core/src/lib.rs), `Profile::CompatXWing`
  arm of `combine`; `XWING_LABEL` is the identical `0x5c2e2f2f5e5c`). The interop KAT
  reproduces the draft reference ML-KEM-768 public key, ciphertext, and shared secret
  byte-for-byte on the 3 official vectors.

- **The combiner micro-benchmark shows parity-to-slightly-slower, never faster.**
  [`crates/q-periapt-backends/benches/combiner.rs`](../crates/q-periapt-backends/benches/combiner.rs)
  asserts that our combiner, a streaming X-Wing SHA3-256 reference (RustCrypto `sha3`,
  5 incremental `update`s + finalize), and one-shot variants all produce **byte-identical
  output** over the same 134-byte block, then times them. Our generic trait-abstracted
  path runs roughly **tens of ns slower** than the streaming X-Wing reference through that
  abstraction. Forty nanoseconds is **< 1% of a single handshake** (which is dominated by
  ML-KEM lattice arithmetic + SHAKE and a network round-trip), i.e. **negligible**. We
  **do not** claim to be faster than X-Wing — we measured, and we are not.

- **`ContextBound` is *deliberately* slower.** It absorbs ~2.3 KB more (the full
  `ct_pq` ~1088 B + `pk_pq` ~1184 B, plus `suite_id`, `policy_version`, and a mandatory
  context), under an injective 8-byte big-endian length-prefixed encoding — roughly
  **~19× more combiner hashing** than X-Wing's lean absorb. This is a *robustness trade*
  (assumption-minimal binding), **not** a performance feature, and never marketed as one.
  More binding is strictly more hashing; the combiner is a tiny fraction of the handshake
  either way.

**Bottom line:** there is no cycles story here. Anyone choosing Q-Periapt for raw KEM or
combiner speed is choosing wrong.

## 2. The real differentiators (and exactly how far they go)

These are assurance / engineering properties around the same primitives. Each is stated
with its honest ceiling.

### 2.1 Machine-checked binding with assumption minimality

The binding theorem `bind_le_cr` is **machine-checked in EasyCrypt**
([`../formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec)):

```
Adv^{X-BIND-K-*}(A)  ≤  Adv^{CR}(H)
```

reducing **only** to collision-resistance of `H` (SHA3-256), with **no binding assumption
on the component KEMs** (no assumption on ML-KEM or X25519). Notably, the canonical encoding's
injectivity (`encode_inj`) is now a **proved lemma**, not an axiom — it reduces to two
elementary `be8` facts (8-byte fixed width + injectivity) plus CR of SHA3, with **0 admits**.
A CI `formal-proof` job hard-gates on the absence of `admit`/`sorry`
(`! grep -rnE 'admit|sorry' formal/easycrypt/`) and best-effort runs `make check`.

**What this is — and is NOT:**

- It **is** a proof-coverage / assumption-minimality edge. The same binding guarantee for
  X-Wing currently rests on a distributed argument (an IETF-draft assertion plus separate
  ML-KEM self-binding results), and X-Wing's *peer-reviewed* proof attains **CCR**, which
  the X-Wing authors themselves state is strictly weaker than `M-BIND-K-CT`. Q-Periapt's
  binding for `ContextBound` is provable from a single weaker primitive assumption (CR of
  SHA3) in one self-contained, machine-checked proof.
- It is **NOT** "stronger binding than X-Wing." On the standard CT/PK axes, a correctly
  implemented seed-format X-Wing already attains **both** `MAL-BIND-K-CT` and
  `MAL-BIND-K-PK` (Schmieg, eprint 2024/523). **Both constructions hit the same MAL
  ceiling.** Claiming otherwise is factually wrong (see
  [`BINDING_SECURITY.md` §5.2](BINDING_SECURITY.md)).
- `X-BIND-CT-*` notions (a ciphertext binding the key/pk) are **structurally impossible**
  for *any* implicitly-rejecting KEM (ML-KEM never returns ⊥), so they are off the table
  for both designs and are **not claimed**.
- The trust base is honest: SHA3 CR is a *modeling* assumption, IND-CCA2 robustness is
  argued on paper (not mechanized), and there is **no spec↔implementation linkage proof**.
  See [`BINDING_SECURITY.md`](BINDING_SECURITY.md) §4–§6, which is the authoritative
  treatment.

The orthogonal `MAL-BIND-K-CTX` (key binds a caller-supplied context) is a guarantee
X-Wing does not offer because X-Wing has no context input — but it is a *self-defined,
non-standard* notion, framed as a KEM-level lift of HPKE's `info` / AEAD key-commitment,
not as a higher point in the published lattice.

### 2.2 Crypto-agility with signed, downgrade-protected policy

X-Wing is a *single fixed construction*. Q-Periapt separates composition from primitive
selection so a deployment can negotiate without forking the spec
([`crates/q-periapt-policy/src/lib.rs`](../crates/q-periapt-policy/src/lib.rs)):

- `Policy::from_toml` loads a real TOML policy; `Policy::load_signed` authenticates the
  **exact policy bytes** via an injected `q_periapt_sig::Verifier` (SLH-DSA-intended,
  long-term root) **before** trusting it, with **fail-closed** semantics;
  `load_signed_or_failsafe` falls back to the conservative compiled-in default
  (L5 / `ContextBound`) on any verification failure.
- A **downgrade floor** (`meets_floor`, default NIST L3), `negotiate_kem` (aborts a
  peer's downgrade attempt rather than silently accepting a below-floor KEM), and
  `select_profile` are enforced — including the case where a below-floor KEM listed in
  `allowed_kems` is correctly rejected.
- The combiner can swap fast (`CompatXWing`, X-Wing-parity) vs strong (`ContextBound`),
  raise the floor, swap the PQ KEM, or add the code-based HQC hedge — **without a
  recompile**. The `Kem::C2PRI` guard (`HybridKem::new` returns `Error::PolicyDenied`
  if a non-C2PRI KEM like X25519/HQC is requested under `CompatXWing`) keeps the
  agility safe by confining non-C2PRI components to `ContextBound`.

### 2.3 Side-channel CI (with the honest caveat)

- **Hard gate:** failure-path indistinguishability / implicit rejection is a merge gate
  (`cargo test -p q-periapt-ctstats` in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)).
- **Report-only (NOT a gate):** the dudect-style Welch t-test **timing** test runs with
  `|| true` and never blocks a merge. Binary-level **dataflow** CT over our own composition
  code (`ct_eq`/`ct_select32`/the combiner) *is* a hard gate (Valgrind/Memcheck-TIMECOP,
  x86_64 + aarch64); extending it over the libcrux **primitive** paths is **TODO**.

So the accurate phrasing is "side-channel CI exists and gates the *failure-path
indistinguishability* property; the *timing* leg is informational today." We do **not**
imply timing is gated. Constant-time posture is also inherently **per-(backend, arch)** —
backend selection changes the CT story, and HQC is explicitly excluded (documented
data-dependent decoder timing).

### 2.4 Cross-platform byte-identical core

One dependency-free `no_std` core (`q-periapt-core`, `#![deny(unsafe_code)]` with a single
documented secure-wipe block; `Secret` is zeroized on drop via volatile write + compiler
fence and is **not** `Clone`) holds the entire composition logic and is reused unchanged
across four non-Rust faces (C ABI / WASM / Swift / Kotlin), plus bare-metal `no_std`. The
win is a **reduced audit surface and one fuzzed/differential-tested implementation**, not a
unique interop capability — ML-KEM and X25519 are deterministic standardized primitives, so
*any* conformant implementation already interops. The differentiator is auditability and
consistency, framed honestly.

### 2.5 HQC assumption diversity

A code-based KEM (HQC, via `pqcrypto-hqc`) is available as a **feature-gated, off-by-default
experimental hedge** against a future lattice break — assumption diversity that X-Wing's
single ML-KEM+X25519 construction does not structurally provide. It is confined to
`ContextBound` (non-C2PRI), excluded from the side-channel claim, and never a default.

## 3. Where X-Wing / Apple PQ3 are AHEAD

This is the larger, more important column. Q-Periapt is research-grade; these are
production constructions.

- **Peer review / deployment at scale.** X-Wing has a peer-reviewed proof (CiC) and
  multiple interoperating implementations. Apple PQ3 ships to billions of devices with
  internal + external review. Q-Periapt has **no third-party audit**.
- **Audited / production-grade backends.** Q-Periapt's own backends are pre-1.0 and
  unaudited to varying degrees — libcrux 0.0.9 explicitly says *contact maintainers before
  production*. Mainstream stacks ship FIPS-validated or production-hardened crypto.
- **Standards weight.** X-Wing is a standards-track draft with a wire format others
  implement; PQ3 is a deployed protocol with published formal analysis. Q-Periapt
  *tracks* these standards — it does not set them, and `ContextBound` is non-standard.
- **Formal scope at the protocol layer.** PQ3's verification covers the *protocol*
  (Tamarin/ProVerif). Q-Periapt's machine-checked proof is narrowly the *combiner binding*
  at the abstract-spec level, with no spec↔impl linkage and no handshake-level proof.
- **Maturity of the side-channel story.** Q-Periapt's timing CI is report-only and
  binary-level CT is unbuilt; production stacks have hardened, audited CT implementations.

**Plainly: do not deploy Q-Periapt. Use X-Wing / PQ3 / a vetted production stack for
anything real.**

## 4. Comparison table

Legend: ✅ present · 🟡 partial / report-only · ⛔ absent · — not applicable.

| Dimension | X-Wing (`draft-connolly`) | Apple PQ3 | Q-Periapt |
|---|---|---|---|
| KEM primitives | ML-KEM-768 + X25519 | ML-KEM(-1024-class) + ECDH | **Same** (ML-KEM-768 + X25519, libcrux + x25519-dalek) |
| Combiner on the X-Wing wire | X-Wing combiner | (own protocol) | **Byte-for-byte X-Wing** (`CompatXWing`) |
| Raw primitive speed | reference | production-optimized | **Same primitives, no edge** |
| Combiner speed | reference (lean, 1 block) | — | **~parity, tens of ns slower via generic abstraction (<1% of handshake)** — never faster |
| Heavier "hash-everything" profile | ⛔ (single fixed construction) | ⛔ | ✅ `ContextBound` (deliberately ~19× combiner hashing) |
| Binding proof | ✅ peer-reviewed, attains **CCR**; full MAL distributed across draft + ML-KEM results | 🟡 protocol-level formal analysis | ✅ **machine-checked** `Adv^{X-BIND-K-*} ≤ Adv^{CR}(H)`, **no KEM binding assumption**, `encode_inj` proved, 0 admits |
| Binding *ceiling* (K-CT / K-PK) | MAL (seed-format) | — | **Same MAL ceiling** (not stronger) |
| Context binding (`K-CTX`) | ⛔ (no context input) | (at protocol layer) | 🟡 self-defined non-standard notion, KEM-level |
| Crypto-agility | ⛔ fixed construction | 🟡 protocol-versioned | ✅ signed, downgrade-protected policy; swap KEM/profile/floor without recompile |
| Assumption diversity (code-based hedge) | ⛔ | ⛔ | 🟡 HQC, feature-gated, off by default |
| Side-channel CI — failure-path indistinguishability | n/a (impl-specific) | (audited) | ✅ **hard gate** |
| Side-channel CI — timing (dudect) | n/a | (audited) | 🟡 **report-only**, not a merge gate |
| Binary-level CT (ctgrind/TIMECOP) | — | (audited) | 🟡 composition-code gate landed (x86_64+aarch64); libcrux primitive paths TODO |
| Cross-platform byte-identical core | (per-impl) | — | ✅ one `no_std` core across 4 non-Rust faces (audit-surface win) |
| Third-party audit | 🟡 peer-reviewed proof; impls vary | ✅ deployed + reviewed | ⛔ **none** |
| FIPS validation | via validated backends | via validated backends | ⛔ (not the pure-Rust core; aws-lc-rs offered as a path) |
| Standards status | ✅ standards-track draft | ✅ deployed protocol | ⛔ tracks standards; `ContextBound` non-standard |
| Production-ready | ✅ | ✅ | ⛔ **research-grade, do not deploy** |

## 5. Honest one-paragraph summary

Q-Periapt does not beat X-Wing or Apple PQ3 on primitives, speed, audit status, or
production-readiness — on the X-Wing wire it *is* X-Wing, byte for byte, and its combiner
is at best at parity (measured tens of ns slower through a generic abstraction, negligible
against a full handshake). Its defensible contributions are narrow and assurance-shaped:
a machine-checked binding proof that reduces to CR(SHA3) with no binding assumption on the
component KEMs (a proof-coverage / assumption-minimality edge at the **same** MAL ceiling,
not stronger binding); signed, downgrade-protected crypto-agility that a single fixed
construction cannot offer; a side-channel CI pipeline (with the failure-path leg gated and
the timing leg report-only); a single byte-identical auditable core across five platforms;
and a code-based HQC assumption-diversity hedge. It is a research-grade composition-and-CI
artifact, not a production cryptosystem. Do not deploy it.

## References

- [`../README.md`](../README.md) — status, honest positioning, feature matrix.
- [`BINDING_SECURITY.md`](BINDING_SECURITY.md) — authoritative binding/committing security
  treatment; the §5 "what we may / must not claim" and the MAL-ceiling discussion are
  load-bearing for this document.
- [`../crates/q-periapt-core/src/lib.rs`](../crates/q-periapt-core/src/lib.rs) — the two
  combiner profiles, the C2PRI rationale, `Secret` zeroization.
- [`../crates/q-periapt-backends/benches/combiner.rs`](../crates/q-periapt-backends/benches/combiner.rs)
  — the byte-identical, measured combiner micro-benchmark.
- [`../crates/q-periapt-backends/src/xwing_kat.rs`](../crates/q-periapt-backends/src/xwing_kat.rs)
  — byte-exact X-Wing draft KAT (3 official vectors).
- [`../crates/q-periapt-policy/src/lib.rs`](../crates/q-periapt-policy/src/lib.rs) — signed
  policy, downgrade floor, `negotiate_kem`, `select_profile`.
- [`../formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec) — the
  machine-checked `bind_le_cr` theorem and proved `encode_inj`.
- [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml) — the side-channel and
  formal-proof CI jobs (note which legs gate and which are report-only).
</content>
