# 0.2.0-alpha.1 implementation record — 2026-09-25

This records the first implementation checkpoint. Subsequent work and the user's
requirement to retain ABI major 2 are tracked in
[SDK_0_2_RELEASE_READINESS.md](SDK_0_2_RELEASE_READINESS.md).
The version/export counts and pending-work list below describe this first
checkpoint only. Subsequent work unified the workspace at alpha.1, implemented
the other owner bindings and expanded the SDK profile to exactly 43 exports,
while retaining ABI 2 and the original nine declarations. Use the linked
readiness ledger for current implementation and validation status.

**Status: first Rust/WASM implementation slice validated locally; alpha release incomplete.**

Base: `7ed1f96a7ec33732f02a989dd5a4669cdcce39ad`, matching the supplied source review.
Branch: `lza/sdk-020-alpha1`. Work is isolated from the original Xcode compatibility
branch. Source changes are uncommitted; no release, tag, upload, CI success or
physical-device acceptance is claimed.

The two new SDK crates are `0.2.0-alpha.1`, `publish = false`. Shared crates retain
the workspace's `0.1.5` versions and use local path dependencies. These changed
development sources are **not** the immutable published `0.1.5` packages. A
coordinated version/dependency update and new packaging evidence are required
before any alpha publication.

## Implemented

| Area | Concrete behavior |
| --- | --- |
| [Owned Rust SDK](../crates/q-periapt-sdk/src/lib.rs) | `Runtime::from_signed_policy` verifies ML-DSA-65 and monotonic policy state, fixes ContextBound/ML-KEM-768+X25519, and retains immutable configuration. No serialized-decision constructor. |
| Key ownership | Non-cloneable `HybridKey` owns both private components and paired public keys. Keygen uses platform entropy; decapsulation takes ciphertext and application context. No private-key getter/import. |
| Lifecycle and resources | Explicit close, runtime revocation, key-slot reclamation on failure/drop, and bounded in-flight operations. Safe Rust borrowing keeps key storage live through synchronous calls. |
| [Prepared ContextBound backend](../crates/q-periapt-backends/src/contextbound_key.rs) | Generated expanded ML-KEM key stays in a zeroizing heap owner. Decapsulation borrows that storage and ciphertext; native embedded-public-key canonicality and H(EK) checks still run every time. |
| [Streaming SHA3](../crates/q-periapt-backends/src/streaming_sha3.rs) | Reuses pinned RustCrypto SHA3-256 core, buffering and padding. No complete transcript allocation. Enables existing `sha3/zeroize` support for Keccak state and separately wipes the full residual block. No primitive version upgrade. |
| Context wrapper | `combine_policy_bound` / `HybridKem::new_policy_bound` absorb the exact existing LP(domain), LP(policy digest), LP(application context) encoding directly. The SDK avoids both wrapper and transcript materialization. |
| [Product WASM entry](../crates/q-periapt-sdk-wasm/README.md) | Verification and platform RNG are enabled by default. JS array lengths/types are checked before copying into WASM. Private keys stay owned; secrets transfer once and require an explicit protocol export. Export copies directly into JS, then erases the Rust temporary. |
| Expert WASM | Existing package and deterministic/KAT surface remain available. Its ML-KEM keygen now uses `generate_zeroizing`, removing the ordinary expanded-key return-array temporary. |
| Existing C ABI | Header unchanged; local dynamic export table still contains exactly the original nine symbols. ABI 2's existing staged execution path remains the benchmark baseline. |

No new hash construction, relaxed import check, classic fallback, or change to
ContextBound/X-Wing field semantics was introduced. The byte-equivalence tests
and retained KATs are implementation evidence, not a new computational proof or
a binary constant-time proof.

## Ownership and authorization boundaries

The host must pin the trust root and atomically persist `trusted_state()` before
using the runtime. Supplying a new root or rolling back that host storage remains
outside this in-process protection. New runtime objects do not automatically
revoke older ones: the host explicitly closes the previous runtime when applying
a policy transition. There is no cross-process authorization service.

Runtime close rejects new operations; already admitted work may finish. Retained
keys erase their secret storage on key close/drop, rather than immediately on
runtime revocation. Exported protocol secrets cannot be retroactively revoked or
erased. Reusing prepared storage does not authorize reuse of a protocol's
ephemeral key across connections. No asynchronous worker/cancellation adapter,
named-purpose application KDF, authenticated session or key confirmation is
included yet.

Quotas bound live key owners and active KEM work. The streaming hash uses bounded
storage, but policy parsing, initial owner allocations, the number of independent
runtimes and externally retained results do not have a process-wide memory
budget. Ordinary allocator OOM can still terminate the process. The old staging
XOF's abort behavior is not described as repaired for all legacy callers.

## Validation actually run

Raw logs and artifact hashes are in
[the validation directory](../research/sdk-alpha1/evidence/20260925-validation/).

| Command / boundary | Result |
| --- | --- |
| `cargo test --workspace --locked` | Exit 0. Log counters total 553 passes, including spawned test-process executions; one existing umask test was ignored by its normal annotation. |
| `cargo test --locked -p q-periapt-policy-agent failed_private_file_create_leaves_no_leaf_behind -- --ignored --test-threads=1` | The existing umask case passes when run alone as required. No test annotation was changed. |
| `cargo test --locked -p q-periapt-sdk` after final SDK edits | Six runtime tests and the non-cloneable-key compile-fail doctest pass. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass on final Rust changes. |
| `cargo fmt --all --check`; `git diff --check` | Pass. |
| `cargo build --locked -p q-periapt-core -p q-periapt-kem --target thumbv7em-none-eabihf` | Pass; core/KEM remain `no_std`. |
| `wasm-pack build crates/q-periapt-sdk-wasm --target nodejs --release --out-dir pkg-node -- --locked` with pinned local LLVM compiler | Pass; actual generated/optimized WASM then exercised by Node. |
| `node crates/q-periapt-sdk-wasm/tests/product.cjs` | Pass: real entropy round trips, policy rejection, rollback, quota/close, oversized/wrong-type input, implicit rejection, low-order rejection and a separate missing-entropy process. |
| `wasm-pack test --node crates/q-periapt-wasm --features signed-policy` | Eleven existing expert/KAT WASM tests pass. |
| ABI 2 header and local dylib named exports | Existing contract parser confirms exactly nine exports. This checks an unpackaged local library, not distribution/install-name/signing acceptance. |

The native runtime tests also compare the new owned/streamed path against the
original serialized/staged path with identical deterministic test inputs.
Ciphertexts and secrets agree at application-context lengths 0, 1, 135,
136, 137, 4096 and 65536. Corrupt expanded-key public encoding and H(EK) still fail
without publishing output. Entropy failure returns its quota; runtime close
during an admitted key generation does not free live storage or admit new work.

The CI workflow now includes the product WASM test. **Hosted CI was not run.**
Full release/proof-input gates, dudect/binary CT checks, formal-source refinement,
browser execution, foreign native bindings and fresh device acceptance were not
run for this slice.

Initial development failures were corrected: the new dependency feature required
a lockfile update, the JS type guard needed an explicit `JsValue`, a newly added
test module needed to follow production items, and one Rust formatting difference
needed correction. No lint level, assertion or test was weakened. wasm-pack's
local prebuilt-tool lookup reports `Unrecognized target!` and falls back to its
tool installation path; the complete warning and successful build are retained.

The full packaged ABI checker rejects Cargo's default output name
`libq_periapt_ffi_abi2.dylib` because a distribution must instead carry its
versioned filename/install identity. The library was not renamed to bypass that
gate; only the explicitly narrower header/export check is reported above.

## Local performance diagnostic

[Capture script](../research/sdk-alpha1/capture.py),
[final source/binary manifest](../research/sdk-alpha1/evidence/20260925-macos-arm64-final/manifest.json),
[raw paired samples](../research/sdk-alpha1/evidence/20260925-macos-arm64-final/samples.jsonl),
[summary](../research/sdk-alpha1/evidence/20260925-macos-arm64-final/summary.txt).

The final run alternates call order for 1000 paired observations per cell, after
32 warmup pairs. Both sides use the same authenticated ContextBound policy,
backends and dependency graph; the baseline calls the existing `extern C` ABI 2
from Rust, and the candidate calls the owned Rust SDK. Both export a combined
secret; encapsulation includes platform RNG. Policy verification and keygen are
setup costs excluded from both measurements. This is not a comparison against
an independently installed historical release or a foreign-language SDK.

Host: macOS arm64, Rust 1.96.1,
`mlkem-native-1.2.0/aarch64-native-arith+fips202-v84a`. Host load and power controls
were not controlled; the measured one-minute load was about 21.4. These samples
cannot establish a release performance or tail-latency guarantee.

| Context | Operation | ABI 2 P50 (µs) | Owned + explicit export P50 (µs) | Median change |
| --- | --- | ---: | ---: | ---: |
| 32 B | Decapsulation | 58.500 | 57.542 | −1.6% |
| 32 B | Encapsulation | 97.166 | 96.917 | −0.3% |
| 4 KiB | Decapsulation | 68.708 | 64.875 | −5.6% |
| 4 KiB | Encapsulation | 106.416 | 103.459 | −2.8% |
| 64 KiB | Decapsulation | 210.125 | 162.958 | −22.4% |
| 64 KiB | Encapsulation | 249.625 | 203.541 | −18.5% |

Small-context improvement is not established. In the final run the 32-byte
encapsulation P99 rose from 131.666 to 136.125 µs. The earlier exploratory
[owner-only observations](../research/sdk-alpha1/evidence/20260925-macos-arm64/)
also retain tail increases; that run omitted the candidate's explicit secret
export and is not pooled with the final data. Neither run supports a claim of
non-regressing P99, improved network establishment, energy use or video throughput.

Reproduce with a **new** output directory (existing attempts are never overwritten):

```sh
python3 research/sdk-alpha1/capture.py \
  --output research/sdk-alpha1/evidence/new-local-run --samples 1000
```

The capture rejects source/binary changes during the run, records per-file source
hashes and executable/sample hashes, and sets `release_claim_eligible=false`.

## Remaining alpha work, in dependency order

1. Define and implement additive ABI 2 SDK extensions for runtime/key/secret
   handles: stale-handle rejection, ownership transfer, operation/close races,
   failure outputs and aggregate resource bounds. Preserve existing signatures;
   retain the 0.1.5 nine-symbol contract and specify an exact 0.2.0 export table.
2. Bind that contract in Swift, Kotlin/JVM and Android/JNI; verify actual native
   library calls, close/concurrency/cancellation and policy parity. Existing
   language support remains intact but has not acquired the new owner contract.
3. Evaluate the vendored x86_64 AVX2 implementation in a fixed Linux x86_64
   candidate, with native execution, differential/KAT/import/implicit-rejection
   and side-channel checks. Review CPU/OS capability requirements before any
   portable dispatch; MSVC is a separate integration gate. No AVX2 selection was
   added in this slice.
4. Specify explicit expert import/export, named-purpose key derivation and policy
   transition rules; complete allocation/cancellation bounds and API parity.
5. Build and test actual alpha SDK distributions, capture controlled SDK and
   foreign-language measurements, update coordinated versions and proof-input
   records, then assess the alpha release gate. Packaging alone is insufficient.

Standard TLS interoperability belongs to the beta connection path. It must use
the standard construction separately from the private ContextBound groups;
[RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html#section-4.3) specifies a
64-byte concatenated secret for X25519MLKEM768, not this SDK's 32-byte combiner
output. The existing rustls private-group adapter was regression-tested, not
converted into that standard group. Continuity remains a later protocol effort.
