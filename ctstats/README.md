# ctstats — side-channel CI

Constant-time assurance for the suite, split into a **hard gate** and an honest
**best-effort report**, because not every claim can be enforced on cloud CI.

This scope is the current KEM/combiner backend. It does not establish constant-time,
traffic-shape, metadata, or end-to-end performance properties for a future prekey or
ratchet protocol. Continuity requires separate physical-device hot-path and PQ-epoch
measurements under the budgets in
[`../docs/CONTINUITY_RESEARCH.md`](../docs/CONTINUITY_RESEARCH.md).

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
ciphertexts. Run it locally on quiesced hardware and preserve its exit status.
It is intentionally absent from noisy shared CI; there is no current timing gate.

Why not a gate: shared CI runners have too much scheduling/frequency noise for a
stable `|t| < 4.5` threshold; a hard gate there produces flaky failures that get
muted — which is worse than no gate. A real timing gate needs dedicated, quiesced
hardware.

## Honest coverage scope (per the threat-model review)

- **Empirical timing** (dudect): meaningful on a quiet x86_64 host; local diagnostic,
  not run or gated in shared CI.
- **Binary-level constant-time** (no secret-dependent branch/index/division in
  emitted assembly): a *stronger* property than a null t-test. Valgrind/Memcheck-TIMECOP
  runs on both **x86_64-linux and aarch64-linux**. The `ct_verify` check runs in CI on both
  (matrix `[ubuntu-latest, ubuntu-24.04-arm]` in `.github/workflows/ci.yml`, job
  `constant-time`), and is additionally exercised **locally** in a container
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
`decapsulate` under Memcheck (aarch64, 2026-06) flagged 5696 reports across **60 branches**
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
secret inputs."* The 60 flagged branches are the **compiler's scalar lowering of that
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

Harness lesson (this is *standard* CT-harness practice, not a new pitfall — cf. KyberSlash
TCHES 2025 §7.1.2, which explicitly marks public-key bytes *initialized*): a CT analysis of
decapsulate must mark only the genuinely-secret sub-fields of `dk` — ŝ `[0..1152]` and
z `[2368..2400]` — **not** the embedded public key `ek` `[1152..2336]` (it is `ek`/t̂, reduced
via `deserialize_ring_elements_reduced`, that produces all 60 q-branches) or its hash
`H(ek)` `[2336..2368]`. Marking the whole `dk` is conservative but mislabels the public bytes,
producing these benign reports.

**Corroboration, not discovery.** The load-bearing fact is the *source-level* one above
(ŝ reduction-free; z reaches only PRF/SHA3 + a constant-time select; no secret hits a
data-dependent branch). libcrux already machine-checks exactly this secret/public partition at
compile time via its `libcrux-secrets`/hax typed discipline, so a dynamic Memcheck pass is
**corroboration of a proven property, not an independent result**, and the 5696-vs-0 contrast
is simply the expected before/after of correct vs. over-broad secret marking — not a finding
about libcrux. *Caveat on the secret-only run:* the original probe marked ŝ `[0..1152]` +
`[2336..2368]`, but `[2336..2368]` is `H(ek)` (public), not z — z is `[2368..2400]`. Both
`H(ek)` and z flow only into branchless SHA3/PRF + mask-select, so the run still yields **0**
`decapsulate` flags, but it corroborates **ŝ** (the reduction concern), not z. A corrected
secret-only run marking ŝ `[0..1152]` + z `[2368..2400]` is now **done** — see the
**source→binary CT gap probe** below (0 flags on aarch64 with the correct offsets). The
committed gate covers our own scalar, mask-based composition code; for the primitive we rely on
libcrux's source-level HACL*/Eurydice + libcrux-secrets CT verification, now also corroborated
dynamically.

## Source→binary CT gap probe (`ct_decaps_gap`)

libcrux proves ML-KEM secret-independent at the *source* level (its `libcrux-secrets` typed
discipline, machine-checked via hax/F*). The orthogonal *binary*-level question — does the
compiler reintroduce a secret-dependent branch/index on the genuine secret (ŝ + z) path despite
that guarantee? — is what `bin/ct_decaps_gap` answers: it marks **only** the genuinely-secret
sub-fields of the FIPS-203 expanded dk (ŝ `[0..1152]` + z `[2368..2400]`, **not** ek/H(ek)) and
runs the real libcrux `decapsulate` under Memcheck. Run `sh scripts/ct-gap-probe.sh` (also wired
into the `constant-time` CI job, x86_64 + aarch64):

**Canonical measurements** — one harness, one tool, BOTH native ISAs (raw logs in the repo:
`ct-gap-aarch64.log` for arm64; the x86_64 triple is in `paper/camera-ready-results.txt`):

| mode | marks (secret set) | aarch64 | x86_64 | role |
|------|--------------------|---------|--------|------|
| `control` | a planted secret-indexed table load | **caught** | **caught** | negative control — harness must catch a real leak |
| `ek`      | embedded **public** key            | **5696** / 60 | **1778** / 34 | positive control — Memcheck must flag the real libcrux q-branches |
| `wholedk` | all 2400 dk bytes (over-marking)   | **5696** / 60 | **1778** / 34 | same as `ek`: only the embedded-pk bytes drive branches |
| `probe`   | **genuine secret** ŝ + z           | **0** / 0     | **0** / 0     | THE GATE — no source→binary gap on the secret path |
| `leaky-control` | synthetic planted secret branch | **> 0** | **> 0** | dependency-free discriminator — harness must catch the planted leak |

(arm64: native colima Apple-Silicon VM, libcrux current, valgrind 3.24; x86_64: bare-metal Ryzen 7
7700, valgrind 3.22.) Within an ISA `ek`=`wholedk` (marking all of `dk` reduces to marking the
embedded pk, since only the pk bytes drive branches). **Read the contrast, not the absolute
counts.** The counts differ markedly BY ISA — for example, `ek` is 5696 (arm) vs 1778 (x86) —
because Memcheck error counts scale with the target's emitted instruction sequence. The
load-bearing signal is the **discrimination**, identical on both ISAs: `probe` = **0** for the
HACL\*-verified ML-KEM path vs `ek`/`leaky-control` **> 0** for code that genuinely branches on
marked data.
So libcrux ML-KEM-768 decapsulate's source-level secret-independence **survives compilation on both
x86_64 and aarch64** — no source→binary CT gap on the ŝ/z path, and the `0` is demonstrably
non-vacuous. (riscv64/wasm32 have no mature binary-CT tool and stay source-CT + attestation.) This
is an honest **negative (equivalence) result**, self-validating via the `ek`/`wholedk` attribution
controls and an explicit planted-leak discriminator — corroboration, not a discovered leak.

**The current probe discriminates (clean vs deliberately leaky).** `bin/ct_leaky_control` has no
cryptographic dependency: it marks one byte secret, performs a volatile read, and feeds it to an
explicit planted secret-dependent branch. Its only valid mode is `planted`, and the gate requires
a strictly positive Memcheck count. This proves that ML-KEM's zero is not an "always zero" harness
result without keeping a backend with a known timing defect in the current dependency graph. The
synthetic binary is not a production primitive and makes no claim about another algorithm.

**Historical HQC reproduction (not a current binary claim).** The archived arm64 log records 193
errors / 4 contexts, and the 2026-07-10 x86_64 capture recorded 22849 / 6 for the former PQClean
`vect_set_random_fixed_weight` reproduction. Those counts remain provenance for the old experiment
only. `ct_hqc_gap`, its `hqc` feature, and its PQClean dependency have been retired; current builds,
camera-ready bundles, figures, and gates must use `ct_leaky_control` and must not present 193/22849
as results of a current binary.

## TODO (later milestones)

- Triage the libcrux primitive paths well enough to gate them (an alternative to Memcheck for
  primitives is Binsec/Rel-style symbolic CT).
- Promote the local dudect timing diagnostic to a gate on quiesced hardware.
- Per-(backend, target) CT-coverage matrix published as an artifact.
- KyberSlash-class site audit hooks once a non-libcrux backend is added.
