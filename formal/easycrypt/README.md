# Formal proof plan — ContextBound binding (EasyCrypt)

This directory holds the proof that is the project's actual **mathematical**
contribution. Per `docs/BINDING_SECURITY.md`, the defensible delta vs X-Wing is
**stronger proof coverage / minimal assumptions** (and the *mechanization
itself*), **not** a stronger primitive. Read `BINDING_SECURITY.md` first; this
file is the engineering plan for §4.

## File: [`BindingViaCR.ec`](BindingViaCR.ec)

Formalizes `bind_le_cr`: `Adv^{X-BIND-K-*}(A) <= Adv^{CR}(B(A))` for the
ContextBound combiner — reducing **only** to collision-resistance of the hash,
with no binding assumption on ML-KEM / X25519. It is generic over the observable
projection `proj`, so it instantiates to **MAL-BIND-K-CT** (ciphertext),
**MAL-BIND-K-PK** (public key), and **MAL-BIND-K-CTX** (context). The load-bearing
step is `encode_inj` (injectivity of the fixed-width length-prefixed encoding),
mirrored by the Rust negative-KAT in `pqt-core`.

> **STATUS: proof development, NOT machine-checked here.** No EasyCrypt toolchain
> is installed in this environment, so the script has not been run through the
> checker; minor tactic adjustments may be required. Until `make check` passes,
> this is a *formalization*, not a verified proof — do not claim otherwise (see
> `BINDING_SECURITY.md` §5/§6 and the honest effort estimate below).

```sh
make check   # runs `easycrypt BindingViaCR.ec` (install EasyCrypt via opam first)
```

## Tool

**EasyCrypt** — the only viable choice: the reusable ecosystem is all in EasyCrypt.
SSProve/Coq, Lean, CryptHOL have no PQ-KEM/binding artifacts.

Reusable artifacts to audit **before** committing (go/no-go gate):
- `sandbox-quantum/EasyCrypt-KEMs` — mechanizes CDM binding notions; confirmed to
  prove **`LEAK-BIND-K-PK` for ML-KEM** (scope the thesis to what is actually
  importable; the `MAL` game / monotonicity edges may need rebuilding).
- `formosa-crypto/formosa-mlkem` — verified ML-KEM IND-CCA (ePrint 2024/843).
- `formosa-crypto/formosa-x-wing` — **WIP** X-Wing IND-CCA proof. Do **not** take
  its completion as given.

## The single committed theorem (MVP success criterion)

> **`MAL-BIND-K-CT` for ContextBound, reducing only to collision-resistance of
> SHA3-256** (no binding assumption on ML-KEM or X25519).

Structure (the load-bearing, novel half):
1. Model SHA3-256 as collision-resistant (game `CR`, advantage `Adv_CR`).
2. **Injective-encoding lemma**: the fixed-width-BE length-prefixed concatenation
   over the canonical field order (`docs/BINDING_SECURITY.md` §3.2) is injective
   on the field tuple. Finite/combinatorial; low risk. This is the step the whole
   reduction hinges on, and it matches the implementation in
   [`pqt_core::combine`](../../crates/pqt-core/src/lib.rs) (`Profile::ContextBound`).
3. **Reduction**: two transcripts with `K0 = K1`, agreeing CT-set, differing in
   some element ⇒ either equal hash inputs (contradicting injectivity) or a SHA3
   collision. Bound: `Adv_MAL-BIND-K-CT ≤ Adv_CR`.

`MAL-BIND-K-PK` and `MAL-BIND-K-CTX` follow by the identical structure (each is
just another injectively-encoded absorbed field); the joint / `LEAK` / `HON`
corollaries follow by porting CDM monotonicity. These are **stretch**, not the
committed deliverable.

## What we explicitly do NOT mechanize

- **IND-CCA2 robustness** — argue on paper from the GHP18 combiner result and the
  published X-Wing IND-CCA proof; the extra hashed inputs do not break the
  reduction. Mechanizing it depends on the WIP `formosa-x-wing` and is high-risk.
- A verified-implementation linkage (abstract spec ↔ Rust) — out of scope.

## Declared assumptions / trust base

Collision-resistance (and, for the KDF, PRF/ROM) of SHA3-256/SHAKE-256; ML-KEM-768
IND-CCA and X25519 strong-DH (ROM) **only** for the IND-CCA paper argument — the
binding theorems assume **none** of these. FIPS 203 64-byte seed `dk` with import
validation is a spec requirement, not a proof dependency.

## Honest effort (single undergraduate)

Budget **8–12 weeks of EasyCrypt ramp-up before any thesis-specific proof**. Then
target the **one** committed theorem (`MAL-BIND-K-CT` via CR). Treat K-PK, K-CTX,
monotonicity corollaries, and the Tamarin protocol-motivation model as stretch.
Do not plan four parallel mechanization tracks.

## Open questions to resolve against primary PDFs first

- ePrint **2026/140** "On the Necessity of Public Contexts in Hybrid KEMs: A Case
  Study of X-Wing" — overlaps the context axis; reposition the novelty as the
  *mechanization* accordingly.
- ePrint **2025/1416** (generic hash-combiner binding, Thm 4) and **2025/1397**
  ("Starfighters", QSF generality) — confirm exact bounds / any combiner-level
  notion X-Wing fails before publishing the comparison.
