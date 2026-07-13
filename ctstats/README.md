# ctstats — side-channel CI

Constant-time assurance for the suite, split into deterministic **hard gates** and an honest
**best-effort report**, because not every side-channel claim can be enforced on shared CI.

This scope is the current KEM/combiner backend. It does not establish constant-time,
traffic-shape, metadata, or end-to-end performance properties for a future prekey or ratchet
protocol. Continuity requires separate physical-device hot-path and PQ-epoch measurements under
the budgets in [`../docs/CONTINUITY_RESEARCH.md`](../docs/CONTINUITY_RESEARCH.md).

## Hard gates (fail the build)

`cargo test -p q-periapt-ctstats` enforces **failure-path indistinguishability**:

- ML-KEM-768 decapsulation of an *invalid* ciphertext returns success (no error return-code
  oracle) and a *deterministic* secret different from the valid one (implicit rejection).
- Hybrid decapsulation never surfaces a crypto-validity error either.

This is the property a Bleichenbacher/Manger-class attacker probes; it is verifiable
deterministically and therefore gates every merge.

The `constant-time` CI job also runs two Valgrind/Memcheck dataflow gates on x86_64 Linux and
aarch64 Linux:

- `ct_verify` marks secrets undefined while exercising the suite's own `ct_eq`, `ct_select32`,
  and combiner code. Any branch or memory index depending on those secrets fails the job.
- `ct_decaps_gap probe` separately marks the genuine secret fields of ML-KEM-512/768/1024
  expanded decapsulation keys while exercising valid and invalid ciphertexts through the shipped
  `q_periapt_backends` APIs. Each planted-secret control must be detected, and every
  genuine-secret probe must report exact `0 errors / 0 contexts`.

The emitted binary differs by target and toolchain, so each matrix cell is an independent
empirical check. riscv64 and wasm32 currently have no equivalent binary dataflow gate; no blanket
cross-target constant-time claim is made.

## Best-effort timing report (NOT a gate)

`cargo run -p q-periapt-ctstats --bin dudect_decaps` prints a dudect-style Welch t-statistic
comparing decapsulation timing for fixed-valid and random-invalid ciphertexts. Run it locally on
quiesced hardware and preserve its exit status. It is intentionally absent from noisy shared CI;
there is no current timing gate.

Shared runners have too much scheduling and frequency noise for a stable `|t| < 4.5` threshold.
A hard gate there would be flaky and eventually muted, which is worse than an explicit
best-effort diagnostic. A defensible timing gate needs dedicated, quiesced hardware.

## Honest coverage scope

- **Empirical timing:** dudect is meaningful on a quiet host, but remains a local diagnostic.
- **Binary dataflow:** `ct_verify` covers the suite's composition code; `ct_decaps_gap` covers the
  exercised decapsulation wrapper paths in the optimized shipped binary. Memcheck is strong at
  finding control-flow and addressing dependencies in an exercised path, but it is not an
  exhaustive source-level proof.
- **Provider-specific:** replacing the active ML-KEM provider, compiler, optimization profile, or
  target invalidates prior binary evidence and requires the gates to be rerun. The probe always
  calls the public shipped `q-periapt-backends` wrappers; it does not substitute a test-only
  primitive path. No upstream formal-verification property is inherited without a separate,
  source-bound justification.
- **ML-DSA carve-out:** signing uses rejection sampling, so its iteration count is
  secret-dependent by design. That behavior is outside this ML-KEM decapsulation probe and must
  be assessed with an algorithm-specific methodology.

## Shipped-backend binary dataflow probe (`ct_decaps_gap`)

The FIPS 203 expanded decapsulation-key layouts are:

```text
ML-KEM-512:  dk = ŝ[0..768]  ‖ ek[768..1568]   ‖ H(ek)[1568..1600] ‖ z[1600..1632]
ML-KEM-768:  dk = ŝ[0..1152] ‖ ek[1152..2336] ‖ H(ek)[2336..2368] ‖ z[2368..2400]
ML-KEM-1024: dk = ŝ[0..1536] ‖ ek[1536..3104] ‖ H(ek)[3104..3136] ‖ z[3136..3168]
```

Only ŝ and z are genuinely secret. The embedded `ek` and `H(ek)` are public. The binary derives
the offsets from each wrapper's public and expanded-key lengths rather than duplicating three sets
of magic numbers. It then exercises both a valid ciphertext and an invalid ciphertext through the
public wrapper. Run the complete self-validating family probe with:

```sh
sh ctstats/scripts/ct-gap-probe.sh
```

Use `DOCKER_DEFAULT_PLATFORM=linux/amd64` to request an x86_64 container on a non-x86 host.

| mode | marked data | required result | role |
|---|---|---:|---|
| `control` | a planted secret-indexed access | **> 0** | harness control; zero makes the probe vacuous |
| `probe` | genuine secret ŝ + z | **0 errors / 0 contexts** | hard gate for each exercised shipped-wrapper path |
| `ek` | embedded public key | none | diagnostic only; zero or non-zero is valid |
| `wholedk` | all 2400 key bytes | none | over-marking diagnostic only; zero or non-zero is valid |
| `leaky-control` | dependency-free planted secret branch | **> 0** | independent synthetic discriminator used by the full script |

`ek` and `wholedk` are deliberately **not positive controls**. The current backend's import and
public-field validation strategy may produce zero or non-zero reports, and compiler lowering can
change the count. Requiring those modes to be non-zero would couple the gate to an incidental
implementation detail. The planted-secret controls provide the load-bearing harness validation.

A 0/0 result from every parameter-set `probe` means that, for this optimized binary, target, toolchain, keys, and the
exercised valid/invalid paths, Memcheck observed no secret-dependent conditional control flow or
memory addressing derived from ŝ or z. It does **not** prove all possible inputs, all compiler
versions, or the dependency's source implementation constant-time. The CI matrix and planted
controls make this a useful regression gate without overstating it as a formal proof.

`ct_leaky_control` is synthetic and has no cryptographic dependency. It is not evidence of a
vulnerability in any production backend; it exists only to prove that the harness distinguishes
the shipped clean path from deliberately leaky code.

## Historical measurements (not current evidence)

The checked-in `ct-gap-aarch64.log` and older camera-ready material contain measurements from a
former provider. In those historical builds, `ek`/`wholedk` produced 5696 reports across
60 contexts on aarch64 and 1778 reports across 34 contexts on x86_64, while the corrected ŝ+z
probe produced zero. Those numbers describe only that former backend and compiler output. They
must not be quoted as results for the active shipped provider, and the current gate does not
require them to reproduce. Any results from the later `fips203` provider are likewise stale after
a provider or source-digest change.

The archived HQC reproduction counts (193/4 on arm64 and 22849/6 on x86_64) are likewise
historical provenance only. `ct_hqc_gap`, its feature, and the PQClean dependency are retired;
current builds and claims use the dependency-free `ct_leaky_control` discriminator.

## TODO (later milestones)

- Promote the local dudect timing diagnostic to a gate on dedicated, quiesced hardware.
- Add equivalent binary-CT coverage for riscv64 and wasm32 when mature tooling exists.
- Add an independent source-level audit of the active shipped primitive implementation.
- Extend dataflow coverage to the remaining primitive paths with algorithm-appropriate harnesses.
