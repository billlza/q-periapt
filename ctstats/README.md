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
  emitted assembly): a *stronger* property than a null t-test, and credibly
  tooled today only on **x86_64-linux** (ctgrind/Valgrind-TIMECOP; Binsec/Rel).
  aarch64 / riscv64 / wasm32 have no mature binary-CT tool — those targets are
  **source-CT + upstream-attestation only**. We publish this per-cell rather than
  claiming a blanket guarantee.
- **Per-backend, not universal**: the CT posture is a property of the selected
  backend (libcrux ML-KEM is HACL*-verified at source level; the binary is
  re-checked separately). Swapping backends changes the guarantee.
- **Known-benign carve-out**: ML-DSA signing uses rejection sampling, so its
  *iteration count* is secret-dependent **by design**. That is an auditable,
  documented carve-out (gate the per-iteration ops, not the loop count) — added
  when `q-periapt-sig` gets a real backend.

## TODO (later milestones)

- ctgrind / Valgrind-TIMECOP job on x86_64-linux over the libcrux/RustCrypto paths.
- Per-(backend, target) CT-coverage matrix published as an artifact.
- KyberSlash-class site audit hooks once a non-libcrux backend is added.
