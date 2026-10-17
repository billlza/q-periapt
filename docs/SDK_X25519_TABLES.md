# X25519 fixed-base tables in the 0.2.0 SDK

The backend enables `x25519-dalek` 3.0.0's `precomputed-tables` feature while
keeping default features disabled and retaining `static_secrets` and `zeroize`.
This restores the upstream fixed-base table used when deriving a public key.
It does not replace arbitrary-peer Diffie-Hellman multiplication or change the
ContextBound encoding, policy binding, entropy source or key-owner contract.

## Measured comparison

The [experiment record](../research/sdk-alpha1/evidence/20261007-x25519-precomputed/manifest.json)
retains the complete first successful capture, all five process blocks, both
pre-sampling setup failures, probe source, lockfile and artifact identities.
Seven exact 0.2.0 Cargo archives from `79b6459197e6aa9ff2402e2985e1304b80f30429`
were consumed through archive-derived path patches outside the checkout. Their
SDK source identity was rechecked against `47e201ad1b92ec2ec738d05555ff0ac3d46a0b29`.
These are candidate archives, not publicly installed registry packages.

The same probe, lockfile, package files, Rust 1.98.1 compiler and release profile
build both executables. A direct pinned X25519 dependency is present in both;
only the candidate enables its table feature through Cargo feature unification.
Resolved feature graphs differ only by the probe switch and `precomputed-tables`
on x25519-dalek 3.0.0 and curve25519-dalek 5.0.0. All 68 external package identities
match the source workspace lock. No production source was edited during capture.

Five fresh process blocks alternate baseline/candidate and candidate/baseline
order. Each process collects 1,000 observations per cell after 64 warmups, using
`std::time::Instant`; all builds and lint complete before sampling. This is
70,000 timed calls. The table reports the median of the five per-process P50s.
The ratio is the median of the five candidate/baseline P50 ratios, not a
confidence interval.

| SDK operation | Context bytes | Baseline P50 (µs) | Tables P50 (µs) | Median ratio |
| --- | ---: | ---: | ---: | ---: |
| Key generation | 0 | 43.625 | 21.959 | 0.502 |
| Encapsulation | 32 | 86.875 | 60.750 | 0.700 |
| Decapsulation | 32 | 48.875 | 48.291 | 0.986 |
| Encapsulation | 4,096 | 91.625 | 65.500 | 0.715 |
| Decapsulation | 4,096 | 53.708 | 52.333 | 0.999 |
| Encapsulation | 65,536 | 164.333 | 138.292 | 0.841 |
| Decapsulation | 65,536 | 126.334 | 126.333 | 1.000 |

Calls include the public SDK's validation and owner bookkeeping, platform RNG
for keygen/encapsulation, output materialization, explicit secret export,
zeroization and disposal. Policy verification and key setup are outside timing.
Decapsulation reuses a prepared key and ciphertext; it is not a fresh connection.
Every context cell has real roundtrip, changed-context and mutated-ciphertext
checks before and after measurement. Changed contexts and correct-length corrupt
PQ ciphertexts yield different secrets, not an explicit rejection error. Both
executables check the public RFC 7748 section 6.1 vectors and owner revocation.

The Apple M1 Max host's load and power state were uncontrolled; one-minute load
changed from 8.10 to 7.40. Tail behavior is retained: the 4-KiB decapsulation P99
ratio has median 1.021 and range 0.980–1.508; one 64-KiB baseline encapsulation
block also has a large tail excursion. No block is discarded. These measurements
support a local fixed-base benefit but do not establish tail non-regression,
energy savings, full connection/storage performance, or other-platform speedups.
Historical `paper/microbench-arm64.csv` timings are a different experiment and
must not be combined with these numbers to claim an absolute speedup.

The executable grows from 915,408 to 947,952 bytes: **32,544 bytes**. Its Mach-O
`__TEXT` segment grows by 32,768 bytes. These are whole probe-binary differences,
not a measurement of runtime RSS or the size of every language distribution.

## Correctness and side-channel boundary

The source path is `X25519::public_key` → `PublicKey::from(&StaticSecret)` →
`EdwardsPoint::mul_base_clamped`. With the feature disabled, dalek multiplies the
basepoint as an ordinary point; enabled, it uses the fixed table. The upstream
table selection scans its entries with conditional assignment and conditional
negation. This source observation is not a final-binary constant-time proof.
Existing Memcheck/TIMECOP probes do not cover all X25519 operations or detect all
data-dependent instruction timing; their scope is unchanged by this feature.

On the changed graph, 69 backend unit/integration tests, 27 SDK tests, seven
documentation tests, 41 FFI tests and 36 host-store tests pass locally. These
include the old X-Wing and concrete-hybrid KATs, independent differential tests,
low-order inputs, implicit rejection and sealed-operation/owner regressions.
Strict Clippy on all four crates' targets and workspace formatting also pass.
The [qualification record](../research/sdk-alpha1/evidence/20261007-x25519-precomputed/product-checks.json)
binds the commands, logs and source hashes. Current
platform builds, package consumers and scoped binary-CT receipts remain separate
release requirements. No protocol bytes, old KAT expectations, public exports or
security checks are relaxed for this optimization.
