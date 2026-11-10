# Current WASM archive and installed browser acceptance

The current WASM/npm candidate passes its original package, Node and Chromium
gates at source `5678d1019861fa1b04f3a219ba3fde7e0ddaaba8` on macOS arm64.
The same actual archive is consumed by Node 26.10.0 and the exact minimum
Node 24.0.0. Chromium 156.0.8078.80 passes storage, enrollment, local-policy
communication and required-Witness recovery. All original limits and refusal
checks remain in place. This is local candidate evidence; foreign-device,
independent-protocol, computational-proof, external-review and release gates
remain open.

## Package identity and execution

The actual `q-periapt-sdk-wasm-0.2.0.tgz` is 1,982,513 bytes, with SHA-256
`dea7351bd916d8bfc3c8e1bf3c2b0f8772864ddf48d175e1c8bea7d0af82970a`.
Its manifest digest is
`03e799c3429606d6918b66c678bb6f092befd955e261181b7e87972a07b6fd47`.
The package contains 242 files including its manifest and license information
for 103 packages. Both Node consumers install outside the source checkout.

The original producer command was
`sh artifact/python-run.sh artifact/wasm_sdk_package.py --output target/sdk-wasm-current-llvm-ar`.
It builds the Node and browser targets from the current workspace and candidate
sources, with browser ownership enabled for the web target. It does not consume
the Rust producer's `.crate` archives. Its SDK workspace digest nevertheless
matches the current SDK source identity:
`c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d`.
The 633 direct WASM source inputs and the workspace digest agree before and
after execution and in the independent reread.

| Boundary | Observed result |
| --- | --- |
| Installed Node 26.10.0 and 24.0.0 | Both original product and CJS/ESM consumer markers pass on each runtime; TypeScript 7.0.2 strict NodeNext checks pass. The minimum runtime consumes the same archive without rebuilding it. |
| Lean WASM compatibility face | All 10 original Node tests pass; the signed-policy configuration passes all 11 tests. Neither run ignores or filters tests. |
| Shared candidate WASM target | The original locked library check passes with warnings denied. |
| Original and transferred Witness Fetch | All 7 checks pass on each Node runtime, with zero failed, cancelled, skipped or todo cases. |
| Installed browser storage | All four original readers pass: public API, real quota failures, lifecycle/Worker termination, and held-completion deadline recovery. |
| Browser enrollment and original recovery | Both creation and late-completion phases pass. Nineteen original native verification receipts bind the captured requests and credentials across seven distinct signing identities. |
| Browser/local-policy native session | Schema 5 passes with a Debug native counterpart, 16 recorded commands and 8 peer frames. Original delivery recovery and reverse communication are checked. |
| Browser/required-Witness native session | Schema 6 passes with Release native counterparts, 16 recorded commands, 8 peer frames and 185 Witness exchanges. |

The required-Witness run includes missing-carrier and unenrolled refusal,
wrong-genesis rejection, actual Witness SIGKILL/offline refusal, preserved
operator keys/database and recovery of the original session. The original
readers retain the distinction between unauthenticated EOF and an authenticated
non-commit receipt. Exact client fulfillment and response bytes are checked
against retained wire frames; the deliberate lost reply remains a failure
before original-operation reconciliation.

Browser sessions use actual HTTP/TCP and OS time against source-built native
reference services on the same host. They use isolated test authorities and
the shared protocol engine. They do not establish Passkey authorization, remote
TLS, an independent session implementation, physical-device or power-loss
behavior. The Python issuer provider is cryptography 48.0.1 with OpenSSL 4.0.1;
native compilation reuses the separate OpenSSL 3.5.9 prefix, whose files remain
unchanged. Python is 3.14.10 locally, distinct from CI's pinned 3.14.7.

## Preserved preparation failures and tool configuration

The first local WASM build fails at linking. Apple clang 21 produces a valid
104,457-byte WASM object, but the default macOS BSD archiver omits it and leaves
a 96-byte empty symbol-table archive. The original object contains all expected
bridge functions. Re-archiving that unchanged object with the existing private
LLVM 22.1.8 `llvm-ar` produces a 106,216-byte archive containing the object and
all 12 bridge symbols. Setting only `AR_wasm32_unknown_unknown` for the fresh
second producer run fixes the link failure; the full producer then passes.
The first failed build, object, archive, command logs and diagnosis are retained.
The initial diagnostic summary counted nine KEM operations and omitted three
public-key checks; its failed assertion and the exact 12-symbol correction are
recorded separately from product verification.

The first browser controller passes storage and then fails the enrollment
tool-version preflight because wasm-pack is absent from its PATH. Adding the
existing project-local tool directory lets the original enrollment and session
gates execute. The successful storage run is retained and reread; it was not
rerun or relabeled as part of the failed enrollment attempt.

The producer uses the repository's pinned wasm-pack 0.15.0, locked wasm-bindgen
CLI 0.2.129, npm 12.1.0, Rust 1.98.1 and the optimizer selected by wasm-pack,
Binaryen 117. Both Node and web builds actually run wasm-opt. Binaryen and the
minimum Node runtime were downloaded from their official release locations and
checked against the published SHA-256 files. The existing private Rust target
and LLVM tools are reused without modification; new tools live under the
project's `target` directory. This local Apple clang/LLVM combination is
distinct from CI's Ubuntu clang-18 environment.

Build-tool diagnostics are preserved: wasm-pack reports that a newer version
exists, and the locked wasm-bindgen CLI dependencies `buf_redux 0.8.4` and
`multipart 0.18.0` emit future-incompatibility macro warnings. The latter packages
are absent from both product locks. Their upstream warnings are not repaired or
suppressed here; tool versions, product dependencies, compiler strictness and
test limits are unchanged. No global installation, signing, quarantine or
security-policy change was made.

## Independent readback and retained bytes

[WASM_READBACK.json](WASM_READBACK.json) records a fresh canonical extraction of
the actual archive, exact comparison of both installed package trees, runtime
and consumer input hashes, all recorded Node checks, and replay of the four
original storage readers. [BROWSER_READBACK.json](BROWSER_READBACK.json) records
the original enrollment and session readers, all command-stream hashes,
captured request/credential bytes and the actual native executable hashes.
These rereads do not rerun workloads or substitute new test results.

`CAPTURE.zip` contains 1,960 individually verified members, including the actual
WASM archive, eight actual native reference executables (72,735,328 bytes before
compression), public transcripts, failed preparations, tool receipts, and 1,009
source files checked against the exact Git commit. All members were reread
against `FILES.json`. Its 28,614,990 bytes have SHA-256
`4277c24543d9a460669eb36bef9645a3d200880b26c69b994f49a9a5a939471f`.
Private runtime states, authority secrets, browser profiles and build caches
are excluded. Native binaries retain their original same-host library needs;
this capsule is not a portable native SDK package.

The [current Rust SDK producer](../20261105-current-sdk-producer/README.md) and
[installed Rust candidate](../20261105-current-rust-installed/README.md) retain
their separate package boundaries. Earlier hosted C/JNI/Swift/Kotlin, device
and Windows evidence continues to identify its own source cohort. These local
results neither reclassify historical CI failures nor freeze a review candidate
or authorize publication.
