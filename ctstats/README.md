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
  runs on both **x86_64-linux and aarch64-linux**, and the `ct_verify` gate now covers
  **both** (CI matrix; aarch64 also reproduced locally in a container via
  `scripts/ct-in-container.sh`, with a planted-secret-branch negative control proving
  Memcheck catches leaks there). The emitted assembly differs per target, so each arch is
  an independent check. **riscv64 / wasm32** still have no mature binary-CT tool and remain
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

## Primitive-path investigation (why the gate stops at our composition code)

Extending the gate to mark the **ML-KEM-768 decapsulation key** secret and run libcrux's
`decapsulate` under Memcheck was tried (aarch64, 2026-06). It produced ~2848 reports across
30 sites, all inside `libcrux_ml_kem::ind_cca::instantiations::neon::decapsulate`. These are
**Memcheck limitations on a verified-CT SIMD primitive, not demonstrated leaks**:

- Memcheck reports a constant-time `csel`/`cmov` select identically to a real branch — its
  message is literally "conditional jump **or move** depends on uninitialised value(s)".
- Its bit-level shadow tracking over-approximates through NEON-vectorized compare/reduce
  code, propagating "undefined" into structurally-public control flow.

No secret-dependent branch was isolated; the function's actual branches are stack-probe
loops, Keccak/hash loops, memcpy bounds checks, and slice-bounds panics — all on public
data — plus constant-time `csel` selects. libcrux ML-KEM is HACL*/Eurydice-verified
constant-time at the source level, and we rely on that attestation for the primitive.
Gating it would require deep per-site triage/suppression that is brittle across builds —
deliberately out of scope.

## TODO (later milestones)

- Triage/suppress the libcrux primitive paths well enough to gate them (blocked on the
  Memcheck-on-SIMD false positives documented above; an alternative is Binsec/Rel-style
  symbolic CT on the primitives).
- Promote the dudect timing test from report-only to a gate on quiesced hardware.
- Per-(backend, target) CT-coverage matrix published as an artifact.
- KyberSlash-class site audit hooks once a non-libcrux backend is added.
