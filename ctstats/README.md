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

## Primitive-path investigation — an UNRESOLVED binary-CT finding in libcrux ML-KEM decaps

Extending the gate to mark the **ML-KEM-768 decapsulation key** secret and run libcrux's
`decapsulate` under Memcheck (aarch64, 2026-06) flags ~2848 reports across **30 sites**, all
inside `libcrux_ml_kem::ind_cca::instantiations::neon::decapsulate`.

**An early write-up of this called the reports "Memcheck-on-SIMD false positives (csel/cmov
flagged like branches)." That was wrong, and is retracted.** Isolating the sites (build the
probe non-PIE with `cargo rustc -- -C link-arg=-no-pie`, so Valgrind's runtime addresses
equal the link-time addresses, then `objdump -d`) shows all 30 are **real conditional
branches** — 14 `b.hi`, 13 `b.ls`, 2 `b.cs`, 1 `b.cc`; **zero `csel`**. The basic blocks
load bytes from secret-key-derived memory (`ldurb`), assemble 12-bit coefficients (`bfi`),
and branch on `cmp w, #0xd01` (**3329 = q**, the ML-KEM modulus) and `cmp w, #0xd00`
(**3328 = q−1**) before conditional stores — a deserialize/serialize-with-reduction loop.
Memcheck's origin tracking traces the compared values to the marked decapsulation key.

So this is a **binary-level secret-dependent branch** — precisely the source→assembly CT gap
this gate exists to surface — **not** a tooling artifact. Two honest caveats keep it from
being a confirmed vulnerability: (1) no `udiv` (KyberSlash-class division) and no
secret-indexed load were flagged, only these coefficient-vs-modulus branches; (2) whether
libcrux's *source* is constant-time-by-construction (and LLVM lowered a conditional-subtract
/ `% q` reduction into a branch on this NEON target) versus a source-level issue, and whether
it is exploitable, is **not yet determined**.

Status: **UNRESOLVED, pending upstream follow-up with libcrux/Cryspen.** We do **not** gate
the primitive on this — we rely on libcrux's source-level HACL*/Eurydice CT verification as
the primitive's assurance. That is a *scoping decision*, and explicitly **not** a claim that
these reports are benign (source-level CT does not transfer to the compiler-emitted NEON
binary — the very gap this gate measures). The committed gate therefore covers our own
scalar, mask-based composition code only.

## TODO (later milestones)

- **Resolve the ML-KEM decaps finding above**: reproduce on x86_64, map the branches to
  libcrux source (Eurydice-generated decode/serialize), determine source-CT-vs-compiler and
  exploitability, and report upstream. Until resolved, do not claim the primitive is binary-CT.
- Triage the libcrux primitive paths well enough to gate them (an alternative to Memcheck for
  primitives is Binsec/Rel-style symbolic CT).
- Promote the dudect timing test from report-only to a gate on quiesced hardware.
- Per-(backend, target) CT-coverage matrix published as an artifact.
- KyberSlash-class site audit hooks once a non-libcrux backend is added.
