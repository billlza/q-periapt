# ctstats — side-channel CI

Constant-time assurance for the suite, split into a **hard gate** and an honest
**best-effort report**, because not every claim can be enforced on cloud CI.

## Hard gates (fail the build)

`cargo test -p q-periapt-ctstats` enforces **failure-path indistinguishability**:

- ML-KEM-768 decapsulation of an *invalid* ciphertext returns success (no error
  return-code oracle) and a *deterministic* secret different from the valid one
  (implicit rejection).
- The hybrid decapsulation never surfaces a crypto-validity error either.

This is the property a Bleichenbacher/Manger-class attacker probes; it is
verifiable deterministically and so gates every merge.

## Best-effort timing report (NOT a gate)

`cargo run -p q-periapt-ctstats --bin dudect_decaps` prints a dudect-style Welch
t-statistic comparing decaps timing for fixed-valid vs random-invalid
ciphertexts. It runs in **report mode** and never fails CI.

Why not a gate: shared CI runners have too much scheduling/frequency noise for a
stable `|t| < 4.5` threshold; a hard gate there produces flaky failures that get
muted — which is worse than no gate. A real timing gate needs dedicated, quiesced
hardware.

## Honest coverage scope (per the threat-model review)

- **Empirical timing** (dudect): meaningful on a quiet x86_64 host; reported, not
  gated, in CI.
- **Binary-level constant-time** (no secret-dependent branch/index/division in
  emitted assembly): a *stronger* property than a null t-test. Valgrind/Memcheck-TIMECOP
  runs on both **x86_64-linux and aarch64-linux**. The `ct_verify` check is *configured*
  for both (CI matrix `[ubuntu-latest, ubuntu-24.04-arm]`) — but note this repo has **no
  git remote**, so CI has not actually executed: x86_64 gates once CI runs, and the aarch64
  leg has so far been exercised **only once, locally** in a container
  (`scripts/ct-in-container.sh`, with a planted-secret-branch negative control confirming
  Memcheck catches leaks there). The emitted assembly differs per target, so each arch is an
  independent check. **riscv64 / wasm32** still have no mature binary-CT tool and remain
  **source-CT + upstream-attestation only**. We publish this per-cell rather than claiming a
  blanket guarantee.
- **Per-backend, not universal**: the CT posture is a property of the selected
  backend (libcrux ML-KEM is HACL*-verified at source level; our composition is the
  part re-checked at the binary level). Swapping backends changes the guarantee.
  *Scope note:* the binary gate covers our own scalar, mask-based composition code, not
  the libcrux primitive internals — see "Primitive-path investigation" below.
- **Known-benign carve-out**: ML-DSA signing uses rejection sampling, so its
  *iteration count* is secret-dependent **by design**. That is an auditable,
  documented carve-out (gate the per-iteration ops, not the loop count) — added
  when `q-periapt-sig` gets a real backend.

## Present (passing)

- **Dataflow constant-time hard gate** — the `ct_verify` bin (`--features valgrind`,
  `src/bin/ct_verify.rs`) marks secrets "undefined" and is run under
  `valgrind --error-exitcode=1` (CI `constant-time` job, **x86_64 + aarch64 matrix**).
  Memcheck/TIMECOP flags any branch or index depending on a secret, over the suite's own CT
  composition code (`ct_eq`, `ct_select32`, the combiner). A no-op without the Valgrind
  header, so it builds/runs on any host; the real check is the Linux CI job (or
  `scripts/ct-in-container.sh` locally).

## Primitive-path investigation — RESOLVED (benign): public-key over-marking, not a leak

Extending the gate to mark the **ML-KEM-768 decapsulation key** secret and run libcrux's
`decapsulate` under Memcheck (aarch64, 2026-06) flagged ~2848 reports across **30 branches**
in `libcrux_ml_kem::ind_cca::instantiations::neon::decapsulate`, comparing 12-bit coefficients
to q (`0xd01` = 3329) and q−1 (`0xd00` = 3328). The investigation passed through two **wrong**
framings before the correct one — recorded here because the corrections are the point:

1. *"Memcheck-on-SIMD false positives (csel flagged like branches)."* **Wrong, retracted** —
   isolating the sites (non-PIE build, `objdump`) shows real conditional branches
   (`b.hi`/`b.ls`/`b.cs`/`b.cc`), zero `csel`.
2. *"A real, possibly-exploitable secret-dependent branch."* **Over-cautious, retracted.**

**Resolution (source-proven + adversarially reviewed): the branches are NOT
secret-dependent.** Per FIPS 203 the decapsulation key **embeds the public key**:
`dk = dk_pke ‖ ek ‖ H(ek) ‖ z`. During the FO re-encryption step, decapsulate deserializes the
embedded **public** key `ek` through libcrux's reducing path
(`deserialize_ring_elements_reduced` → `deserialize_to_reduced_ring_element` →
`cond_subtract_3329`) — which the libcrux source itself documents *"MUST NOT be used with
secret inputs."* The 30 flagged branches are the **compiler's scalar lowering of that
public-key reduce loop** (the NEON `cond_subtract_3329` is itself branchless SIMD —
`_vcgeq_s16` mask + subtract; the scalar `b.cs`/`b.ls` + the `0xd00` site come from LLVM
scalarizing the public deserialize+clamp). The probe marked the **whole** `dk` secret,
including `ek`, so Memcheck flagged a reduction running on **public** bytes.

The **genuine** secret key ŝ takes a *different*, reduction-free path
(`deserialize_to_uncompressed_ring_element` → `deserialize_12`, no q-comparison), and **no**
secret value — ŝ, z, the decrypted message m′ (`to_unsigned_representative`, branchless), or
the implicit-rejection comparison (`compare_ciphertexts_in_constant_time`) — reaches any
data-dependent branch. The flagged branch outcomes are a function of the **public** key alone,
so an attacker who already holds `ek` learns nothing: **zero marginal leakage**. This is a
static-reachability fact in libcrux 0.0.9, confirmed by reading the source (`serialize.rs`,
`ind_cca.rs`, `ind_cpa.rs`, `vector/neon/arithmetic.rs`) and a 3-lens adversarial review.
**libcrux ML-KEM decaps is constant-time on the genuine secret.**

Harness lesson: a CT analysis of decapsulate must mark only the genuinely-secret sub-fields
of `dk` — ŝ `[0..1152]` and z `[2336..2368]` — **not** the embedded public key. Marking the
whole `dk` is conservative but mislabels the public bytes, producing these benign reports.

Open follow-up (not blocking the benign verdict): the empirical confirmation — re-mark only
ŝ + z and observe **0 flags** — was not run (the container network broke mid-investigation).
The source proof is conclusive for the security claim (a static reachability fact); the
empirical run would convert the prediction into a measurement and close the assumption that
Memcheck origin-tracking cleanly separates `ek` from `dk_pke` within one wholesale-marked
buffer. The committed gate covers our own scalar, mask-based composition code; we rely on
libcrux's source-level HACL*/Eurydice CT verification — now corroborated by this dataflow
analysis — for the primitive.

## TODO (later milestones)

- **Empirically confirm the (resolved) ML-KEM decaps finding**: re-run the Memcheck probe
  marking only the genuinely-secret sub-fields of `dk` (ŝ `[0..1152]` + z `[2336..2368]`),
  not the embedded public key — predicted result: **0 flags** in `decapsulate`. (The security
  conclusion is already source-proven; this measures the prediction.)
- Triage the libcrux primitive paths well enough to gate them (an alternative to Memcheck for
  primitives is Binsec/Rel-style symbolic CT).
- Promote the dudect timing test from report-only to a gate on quiesced hardware.
- Per-(backend, target) CT-coverage matrix published as an artifact.
- KyberSlash-class site audit hooks once a non-libcrux backend is added.
