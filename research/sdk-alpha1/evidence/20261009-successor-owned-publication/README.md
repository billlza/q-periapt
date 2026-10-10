# Successor connection uses its owned publication

The successor workload previously registered the foreign device and exchanged
real application traffic, but prepared its prekeys and signed manifest directly
in the Rust harness. It now uses the registered-device publication operation.
The host retains the original next ID and complete plan before preparation;
another process retries the same operation and returns identical public bytes.
Both actual connection bundles contain exactly that manifest and its four proofs.
The shared native engine verifies signatures/proofs and consumes the corresponding
private inventory during the successful TLS/application flow.

On macOS arm64, eight component/private-Maven profiles passed: C and Swift
Debug/Release, plus Kotlin Debug/Release under Serial and G1. Each contains 23
distinct foreign processes: ten successor registration/activation steps, three
publication steps, eight old-device cleanup steps and two fresh-session traffic
steps. Each profile retains 37 independently read-back public records. Account
issuance and required-witness replacement authorization remain native controller
operations; they do not expose account-root signing authority to device clients.

The native full owned-service scenario also passed local-only replacement,
required-witness retirement/replacement, original unknown-delivery reconciliation,
restart, rekey, reverse traffic, cancellation, lease and SDK-revocation checks.
The extracted public-only decoder is shared with the earlier registration
workload; its Debug/Release C regressions both passed. Twenty-four artifact-reader
tests cover exact recovery, changed commitments, mismatching connection bundles,
missing publication processes and reused process identities. Strict Clippy and
the Rust 1.90 check passed for both affected harnesses. An initial Clippy refusal
of unchecked vector slicing was repaired with an explicit checked slice.

The current CI source `b1006eb3` separately exposed a C portability failure:
[job 113746359801](https://github.com/billlza/q-periapt/actions/runs/37907280524/job/113746359801)
stopped at GCC 15 compilation because an `if` and the subsequent `decode` shared
a misleadingly indented line. The uploaded diagnostic artifact was downloaded
and its size and SHA-256 verified. The same warning was reproduced with macOS
arm64 GCC 15; separating the statements passed the same strict syntax check.
Strict Clang Debug/Release builds and both real C workloads then passed with the
corrected source. **Linux CI confirmation of this repair is still pending.**

`QUALIFICATION.json` binds the exact harness and C client sources, library/client
hashes, commands, results and public readbacks. Swift and Kotlin client code is
unchanged from the previous publication component. The native library code is
unchanged from `a71195ec`; the C clients now use the existing qualified `@rpath`
library layout. `CAPTURES.zip` contains 627 members, 1,305,098 bytes, SHA-256
`2c978859f2d2e81db96590dbaee1f4cc6f60e53e85f5f18a2ab16bc2965b5ff7`.
Private journals, wrapping keys and signer state are excluded from these captures.

This closes the manually prepared successor prekey step in this workload. It is
source-component/private-Maven evidence, not complete current-archive,
independent-implementation, physical-device or release qualification. Local
publication preparation does not establish remote directory publication or
consistency. The [subsequent actual-old-reader study](../20261009-v22-old-reader/README.md)
qualifies the pinned prior Debug/Release build's v22 refusal on macOS arm64.
Broader platform storage, external security review and recovery-security
requirements remain separate release gates.

`PREFLIGHT.json` and `PREFLIGHT.zip` retain the clean standalone `f9ae04b9` source
gate, all 44 CodeQL-quality tests and all 2,667 artifact tests. The ZIP has 71,383
bytes and SHA-256 `45037d02d5c7db0edafb2df1e58d35f8016052c4aa290b8c3e51122e0a1d7854`.
Current-source installed Rust/C/Swift/Kotlin archive qualification was started
separately and is not claimed complete by this preflight receipt.
