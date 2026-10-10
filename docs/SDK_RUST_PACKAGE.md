# Rust SDK 0.2.0 package gate

Run the SDK profile from a standalone Git checkout using Rust 1.98.1 and
cargo-audit 0.22.2:

```sh
sh artifact/rust-publish-contract.sh --profile sdk-020 --output target/sdk-rust-package
```

The output directory must not exist. A dirty development image requires explicit
`QPERIAPT_ALLOW_DIRTY_RUST_PACKAGE_CONTRACT=1` and produces a diagnostic candidate.
The existing provenance guard still requires a real, non-symlink `.git` directory;
local managed worktrees use a separate byte-matched build-only clone. The tool
does not commit, publish, sign or update registry credentials. Its Cargo home is
private and fresh; only the locked dependency fetch and dependency audit use the
network. Package reconstruction and the external consumer run offline.

The twelve-crate cohort, in production-dependency order, is:
`q-periapt-mlkem-native-sys`, `q-periapt-core`, `q-periapt-kem`, `q-periapt-sig`,
`q-periapt-backends`, `q-periapt-policy`, `q-periapt-sdk`, `q-periapt-host-store`,
`q-periapt-rustls`, `q-periapt-ffi`, `q-periapt-wasm`, and `q-periapt-cli`.
The six research/application/npm-producer crates remain non-publishable.
`q-periapt-sdk` and `q-periapt-host-store` are now explicitly registry-eligible
members; that metadata alone does not authorize publication or satisfy release
gates. Every internal dependency remains exactly `=0.2.0`. Native ABI
major and library identities remain 2.

Cargo packages the cohort together, preparing its temporary registry from the
actual new `.crate` files and rebuilding every package. This avoids resolving
unpublished 0.2.0 dependencies from the public index or source-path patches
during package verification. The reference-connection and native CLI CBOM
features are enabled explicitly; the opt-in AVX2 candidate remains off.
Each archive must match Cargo's package file list, source bytes, normalized
manifest/registry metadata, notices, and the existing versioned native-provider
source contract. The vendored provider is independently checked by its existing
inventory verifier. Warnings fail the gate.

The external test project uses nine archive-derived path patches, all outside
the checkout, to exercise the public owner, purpose derivation, explicit
plaintext transfer, signed policy transition, private store recovery and
fragmented authenticated reference-connection APIs. These are real crypto and
filesystem operations. The reference transport in this consumer is in memory;
it is not Swift-to-Linux network evidence. Cargo's resolved metadata must point
only at the extracted package manifests, with no mixed versions or checkout
dependencies. External versions, sources and checksums must match the retained
workspace lock. Workspace, fuzz and consumer locks are audited against the same
fresh RustSec database. No findings, severity ranges, platforms or informational
warning classes may be ignored or filtered. Tests and Clippy run before the
final consumer audit. All installed sources, including their exact file set,
and original archives are rechecked after every consumer/audit step completes.

`RUST_SDK_PACKAGE.json` records source identities, archive hashes, Cargo provenance,
consumer location and validation scope. It never sets `release_claim_eligible`
to true. The old ten-crate 0.1.5 contract, handoff and upload receipts remain
separate and are not rewritten to accept this candidate. Public registry
publication/observation, the complete MSRV and platform matrix, Linux/network/device
qualification, CT/performance and signed distributions remain
independent gates.

The shared uploader generator accepts these twelve archives through an explicit
SDK input profile. Pin the completed report before preparing a fresh output:

```sh
sh artifact/python-run.sh artifact/crates_io_uploader_build.py \
  target/sdk-rust-package/RUST_SDK_PACKAGE.json \
  --profile sdk-020 --input-sha256 <SHA256-of-that-report> --cargo-version 1.98.1
```

Preparation reads only the selected report, template and archives. It rejects
dirty/diagnostic inputs, missing or extra packages, changed archive bytes or file
inventories, mismatched Cargo source commits, mixed versions, private internal
dependencies and production edges pointing forward in the publication order.
Optional, build and target-specific edges count; dev-only edges do not determine
the upload order. All internal requirements must remain exactly `=0.2.0`.
The generated uploader embeds the report digest and each archive's exact bytes
identity and registry metadata. The CLI derives its output from the selected
report's hash at
`target/qperiapt-crates-io-uploaders/sdk-020/<report-SHA256>/qperiapt-crates-io-uploader`.
The legacy profile uses its own `abi2-legacy` directory. Different candidates can
coexist; existing output files are never replaced. An optional output argument
only confirms that derived path. It cannot grant another write location.
The CLI creates and verifies its owned mode-0700 candidate directories.
The generator pins the directory descriptor, commits bytes without replacement,
checks their identity before making the file executable, and rejects a changed
directory. It does not change the permissions of an existing output directory.
CI prepares it from the same archives used by the current and minimum compiler
consumers. The default input profile remains the ten-crate legacy handoff.
Generating this executable makes no registry request and grants no publication
authorization.

The producer fetches both the workspace and separate fuzz lock into its private
Cargo home before auditing. `cargo-audit` JSON mode must also produce empty stderr:
version 0.22.2 can return zero with empty JSON warnings while reporting that a crate
is missing from the registry index and its yank status was not checked. Such a run
is incomplete and rejected. Fetching the fuzz lock supplies its distinct registry
entries; no advisory, warning, or yanked-package check is disabled.

The private-store consumer group also runs an exact child invocation under a real
OS file-size limit. Only that child ignores `SIGXFSZ`, so the kernel returns a write
error to the packaged SDK; the parent process is unchanged. The test requires an
explicit storage failure, retained partial state, refusal of replacement and no
runtime admitted from malformed storage. It has a 30-second process deadline and
requires the child result marker. The same public store group now generates three
fresh policy issuers from OS entropy, enrolls independent recovery authority,
rejects an online-key-forged recovery, replaces an exhausted u32::MAX authority,
reopens the original signed request, and preserves a later normal update. All
three test issuers run in one consumer process; this tests role verification,
not operational offline isolation. It covers the opt-in Rust v2 contract, not
C/Swift or Continuity root migration. These cases supplement existing restart,
rollback, reenabling and owner-close cases without filtering any consumer test. An ambient
child marker outside the exact invocation is rejected.

## Coordinated registry transaction

Use the SDK coordinator with the report digest and its exact producer commit:

```sh
sh artifact/python-run.sh artifact/rust_sdk_publication.py dry-run \
  --report target/sdk-rust-package/RUST_SDK_PACKAGE.json \
  --report-sha256 <SHA256-of-that-report> --source-commit <producer-commit>
```

The coordinator requires a standalone, clean checkout of that commit. It checks
the producer's complete source-input map, the twelve archive hashes and Cargo
source identities, and the closed production-dependency graph. New package
reports record their actual completion time; reports without `completed_at`
must be regenerated. Inputs are rechecked before observations and uploads,
including after acquiring the publication lock. `dry-run` performs no registry
request and reads no credential. CI runs it against the freshly produced cohort
and retains `publication-dry-run.json`.

`verify` uses the same command arguments and additionally checks both the
official crates.io API and sparse index. Its immutable receipt is written below
`target/qperiapt-sdk-020-publication-receipts`. Only an exact non-yanked checksum
reported by both observers counts as published. Published packages must form
one prefix of the documented dependency order. The SDK receipt uses its own
`qperiapt.sdk_crates_io_publication_receipt` schema and `crates_io_v0_2_0` key;
legacy receipt validators reject it.

The `publish` mode additionally requires `--execute-real-upload` and
`--acknowledge-irreversible-publish`, plus explicit `--state-root` and
`--uploader-command` confirmations. Its sole state root is the POSIX account's
canonical home followed by `.q-periapt/publication-state/crates.io-v0.2.0`, outside
all registered Git worktrees. These real, account-owned directories must already
have mode 0700. The prepared exact-byte uploader must be the mode-0700,
single-link child named `qperiapt-crates-io-uploader`. Install the reviewed
candidate at that fixed path before selecting publish mode. Publication receipts and
journals live in that state's `receipts` and `journal` directories. The token is
read from `CARGO_REGISTRY_TOKEN` only when the first upload is necessary; it is
never placed in arguments or emitted in diagnostics.

The shared transaction engine holds a persistent-inode account lock, records
an immutable intent before each upload, and reconciles the remote checksum
before moving to the next package. A failed or interrupted upload with unknown
effect stops the transaction. Retain the report, exact archives, state directory
and emitted receipt paths. Resume using `--previous-receipt` from the publication
state. Remote visibility can resolve an earlier unknown intent without another
upload. If both observers still report absence, retry additionally requires
`--retry-unknown-intent <intent-SHA256>` and records the new absence receipt.
Never regenerate or replace the selected cohort to resume a partial publication.

These commands qualify and publish the Rust cohort only. The final supported
platform, signing, installation and release requirements still apply to the
complete SDK distribution.

Cargo's multi-package behavior is documented in the primary
[Cargo package reference](https://doc.rust-lang.org/cargo/commands/cargo-package.html).

## Minimum compiler and development toolchain

The product declares Rust 1.90. The repository's full development tests,
benchmarks, certificate generation, Clippy and package producer use the pinned
Rust 1.98.1 toolchain. These are separate support contracts: the current locked
storage dependency redb 4.3 requires 1.90. The producer and minimum-compiler
checks are separate: release qualification runs both without ignoring dependency
Rust-version requirements or disabling warnings.

The default workspace build retains its independent CI check:
`cargo +1.90.0 build --workspace --locked`. The package job also takes the exact
archives it has just produced and exercises the same four public API consumer
tests with the actual 1.90.0 compiler. To run that additional check with an
already installed toolchain and a completed, hash-pinned package cohort:

```sh
sh artifact/python-run.sh artifact/rust_sdk_msrv.py \
  --output target/sdk-rust-msrv \
  --report target/sdk-rust-package/RUST_SDK_PACKAGE.json \
  --report-sha256 <SHA256-of-that-report> \
  --cargo-home target/sdk-rust-package/cargo-home \
  --toolchain-root <absolute-Rust-1.90.0-sysroot>
```

The tool does not install or select a global default toolchain. It invokes the
chosen sysroot's compiler, Cargo and rustdoc explicitly, rejects other compiler
versions, uses a fresh consumer and build directory outside the checkout, and
runs offline with warnings denied. Its source manifest includes the consumer
and test inputs. Before compilation, Cargo must resolve all nine product
packages from the extracted archives; every registry dependency's version,
origin and checksum must match the workspace lock. All four tests must execute
without ignores or filters. Package/source/tool identities are rechecked on
completion, and failure logs are retained in `RUST_SDK_MSRV.json` and command
outputs.

The consumer's TLS identities are explicitly public test DER fixtures, including
their keys; they must never be deployed. Precomputing these certificates removes
the consumer's build dependency on rcgen. Live OS entropy, hybrid key exchange,
certificate verification, application policy confirmation, fragmentation,
private database operations and assertions remain real. Canonical tests still
exercise the same consumer, and other repository TLS tests retain rcgen.

### Historical qualifications before the dependency refresh

The following captures used Rust 1.85.0 and 1.96.1; their artifacts are unchanged.
They do not qualify the new compiler/dependency cohort.

The first actual minimum-compiler qualification passed on macOS ARM64: default
workspace build plus all four tests from nine archives, with 98 external
dependencies unchanged. The same consumer also passed its canonical-toolchain
tests and strict Clippy check. Hosted Linux CI, other architectures/targets and exhaustive
feature combinations remain separate evidence; one host does not establish
the full supported-platform matrix. See the
[release readiness ledger](SDK_0_2_RELEASE_READINESS.md) for source-bound results.

After the borrowed public-key storage change, a
[current-source follow-up](../research/sdk-alpha1/evidence/20260927-sdk-current-msrv/manifest.json)
again builds all eighteen default workspace packages with the actual Rust
1.85.0 compiler, offline and with warnings denied. Both the frozen-header legacy
C consumer and the current owner C consumer pass against that new macOS ARM64
debug library, whose ABI remains 2. This source/runtime check does not refresh
the earlier nine-archive consumer result.

The subsequent [current archive cohort](../research/sdk-alpha1/evidence/20260927-sdk-current-rust-package/manifest.json)
does regenerate all twelve crates and validates fresh external consumers of
the same nine extracted packages on Rust 1.96.1 and 1.85.0. Each runs all four
public API tests; canonical Clippy and workspace/fuzz/consumer dependency audits
also pass. This refresh includes the borrowed public-key storage and reference
listener changes, without changing external dependency identities between the
two consumers. The candidate is still a dirty local diagnostic, not a public
registry release or native Linux/platform qualification.
