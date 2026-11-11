# Installed SDK connection qualification

`artifact/sdk_installed_connection.py` connects a Swift application built from
the complete SDK ZIP to a Rust peer built from the exact `.crate` archives.
Both application builds and their product dependencies live outside the source
checkout. The Rust peer and certificate-fixture program come from the shipped
`q-periapt-rustls` examples. The driver reuses the existing TCP scenarios;
it does not introduce another protocol or cryptographic implementation.

This producer runs its baseline on macOS and records both endpoint platforms.
The separate 2026-10-08 checkpoint below also executes the same cases against a
native Linux peer in a local VM. Independent physical-host qualification remains
open. The reference's wire and trust contract is described in
[SDK_CONNECTION.md](SDK_CONNECTION.md).

## Package selection and build

Select the complete Swift ZIP, its original XCFramework ZIP, and a completed
Rust cohort report with their independently retained SHA-256 values. Equal
SemVer alone is insufficient: both packages must bind the same current Rust
workspace input digest. The installed Swift wrappers must also match current
source. A mismatch stops before building either application.

The helper verifies the complete Swift payload against the pinned native ZIP,
then extracts nine exact Rust package archives into the external application.
Cargo uses only those product path patches and a selected offline registry cache
without configuration or credential overrides. Its actual metadata must resolve
every product to the extracted path and exact SDK version. External dependency
versions, registry origins and checksums must match the locked workspace.
This is consumption of packaged crates, not public-registry installation.

The builds use the explicitly selected Rust 1.98.1 toolchain's real binaries,
verify its sysroot and Cargo version, and retain before/after tool hashes.
They use Rust warnings denied, Clippy with warnings denied, and
Swift release compilation with complete concurrency checks and warnings as errors.
The Swift linker map must identify the selected packaged static archive; its
bytes must match the native ZIP. At runtime, dyld must identify the frozen
client executable and must not report a separate Q-Periapt dynamic library.
These checks keep a checkout library or another SDK installation from satisfying
the installed-client gate.

```sh
sh artifact/python-run.sh artifact/sdk_installed_connection.py \
  --output "$PWD/target/sdk-installed-connection-new" \
  --swift-zip "$SELECTED_SWIFT_ZIP" \
  --swift-sha256 "$SELECTED_SWIFT_SHA256" \
  --swift-native-zip "$SELECTED_XCFRAMEWORK_ZIP" \
  --swift-native-sha256 "$SELECTED_XCFRAMEWORK_SHA256" \
  --rust-report "$SELECTED_RUST_COHORT_REPORT" \
  --rust-report-sha256 "$SELECTED_RUST_REPORT_SHA256" \
  --cargo-home "$SELECTED_OFFLINE_CARGO_CACHE" \
  --toolchain-root "$SELECTED_RUST_1_98_1_TOOLCHAIN"
```

Use a fresh output directory. The input digests should come from the selected
producer/checkpoint, rather than from untrusted candidate metadata. Loader and
Rust compiler overrides are rejected. No command uploads a package, changes the
host's trust store or uses production credentials.
The resolved output destination must remain under the repository's `target`
directory. Existing output and symbolic-link leaves are refused; parent links
and `..` cannot redirect the attempt outside that directory.

The macOS CI job runs this installed-package boundary after the Apple producer
and a fresh Rust archive cohort. Its consumers use the two completed package
outputs, with Rust Clippy and Swift concurrency warnings treated as errors.
The standalone Rust manifest declares the imported examples' own dependencies,
including the Unix `rustix` readiness API; a dependency's dev-dependencies are
not inherited by this consumer. CI retains the package reports, build logs,
link map and connection observations, excluding generated TLS test keys and
policy databases. This wiring is separate from an observed hosted CI result.

## Runtime evidence

The shared driver freezes the executables and native archive, generates private
test credentials, and executes twelve real TCP cases:

- First connect/reconnect and 0-, 1- and 65,536-byte requests.
- Concurrent request rejection without cancelling or duplicating the admitted request.
- Handshake and request timeout/cancellation, plus runtime revocation during a request.
- Certificate-name and authenticated application-context mismatch rejection.
- Persisted signed revocation, process-restart rollback refusal, and later signed
  re-enabling with reconnection on both peers.

Raw stdout/stderr, bounded process results, the link map, actual dependency
metadata, source/archive pins, executable identities and policy database hashes
are retained. Generated private test keys stay in the private run directory.
Package sources and payloads are checked again after execution. An interrupted
or failed run retains `completed: false`; it cannot become release evidence.
The output always retains `release_claim_eligible: false` and explicitly records
whether a native Linux server ran.

The same archive-built `standard_peer` can also run through
`artifact/standard_tls_interop.py` against an independent OpenSSL endpoint.
That result covers standard TLS 1.3/X25519MLKEM768 authentication and rejection;
it does not claim that OpenSSL implements the SDK's application-policy protocol.

## Observed local candidate

The 2026-09-26 run completed all twelve installed-package cases on macOS ARM64.
The same Rust executable passed eight independent OpenSSL 3.6.3 cases across both
client/server directions, including classic-only, TLS 1.2, anonymous and hostname
rejections where applicable. Four actual artifact/log controls reject a wrong ZIP
pin, a different native ZIP, changed extracted Rust source, and an injected
Q-Periapt dynamic-load record. Original packages remain unchanged.

The [checkpoint](../research/sdk-alpha1/evidence/20260926-installed-sdk-connection/manifest.json)
retains the source, raw observations and rejected older cohort. Its refreshed
unsigned Swift package is 19,628,601 bytes with SHA-256
`09ca75158c4d9bb339617505d6e160fc48a6e7378e5e92ab9797cfa2d6124343`.
The native ZIP is bound separately by SHA-256
`cb30961c78c1bbb121a00e450cb95bff9e8e0bf361ebb9a828690c762ba9fab9`.
Native Linux, current devices/minimum OS, hosted CI and performance/energy
remain open in the [readiness ledger](SDK_0_2_RELEASE_READINESS.md).

The subsequent [loader-provenance checkpoint](../research/sdk-alpha1/evidence/20260926-installed-sdk-loader-provenance/manifest.json)
corrects an overbroad path-substring check in the diagnostic harness. A retained
old-accepts/new-rejects example uses `/frozen/client-extra` where the expected
image is `/frozen/client`. The verifier now requires exactly one complete dyld
UUID/absolute-path image record. Ordinary text, path prefixes, duplicate image
records and malformed dyld records cannot establish identity. The two observed
`move loaded to delayed` / `move delayed to loaded` messages are parsed separately
and never count as image identity; SDK dynamic-library transitions are also
rejected for the static client. Raw logs and the failed overly strict parser
attempt are retained.

After this correction, a fresh rebuild and twelve-case installed TCP run pass.
The failed intermediate run stays separate. The OpenSSL result identifies its
original archive-built peer binary and the same package cohort explicitly.

## 2026-10-08 native Linux checkpoint

The [installed macOS-to-Linux checkpoint](../research/sdk-alpha1/evidence/20261008-installed-macos-linux-connection/README.md)
passes all twelve cases with an installed Swift/macOS arm64 client and an
archive-derived Rust/Linux aarch64 server. The host driver is `b20cafd7`, the
Linux harness source is `33ca8c5c`, and both product inputs match the qualified
`de2c49e9` Rust cohort. A fresh complete Apple package at `33ca8c5c` supplies the
static client library and Swift wrappers. Source identities and the exact
installed baseline, executable and linker-map hashes are retained.

The Linux peer runs as UID 1000 in a Debian 12 container inside a native VZ VM
on the same Mac. A pinned private SSH TCP forward carries the SDK ciphertext
unchanged; the isolated adapter changes only the listener announcement. The
peers keep separate persistent stores. A hash-checked copy of the closed Linux
store is used only by the evidence collector and never sent back to the peer.
Original case predicates and deadlines are unchanged. Three failed harness
attempts precede the successful fresh run and remain in the checkpoint.

This establishes execution across different OS kernels and filesystems using
the same SDK implementation. It does not establish independent physical hosts,
an independent application protocol implementation, minimum-OS/device execution,
controlled latency/energy results or full Continuity/release readiness. The
main producer above still provides the same-host baseline; the isolated VM
adapter is a retained experiment, not a general remote-host setup interface.
