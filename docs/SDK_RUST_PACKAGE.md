# Rust SDK alpha package gate

Run the alpha profile from a standalone Git checkout using Rust 1.96.1 and
cargo-audit 0.22.2:

```sh
sh artifact/rust-publish-contract.sh --profile sdk-alpha1 --output target/sdk-rust-package
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
gates. Every internal dependency remains exactly `=0.2.0-alpha.1`. Native ABI
major and library identities remain 2.

Cargo packages the cohort together, preparing its temporary registry from the
actual new `.crate` files and rebuilding every package. This avoids resolving
unpublished alpha dependencies from the public index or source-path patches
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
qualification, CT/performance, signed distributions and external review remain
independent gates.

Cargo's multi-package behavior is documented in the primary
[Cargo package reference](https://doc.rust-lang.org/cargo/commands/cargo-package.html).

## Minimum compiler and development toolchain

The product declares Rust 1.85. The repository's full development tests,
benchmarks, certificate generation, Clippy and package producer use the pinned
Rust 1.96.1 toolchain. These are separate support contracts: the current locked
development dependencies include Criterion requiring 1.86, Orion requiring 1.87
and rcgen/time requiring 1.88. `cargo +1.85 test --workspace --locked` is therefore
not supported by this lockfile. Do not use `--ignore-rust-version`, downgrade the
lock, skip tests or raise the product minimum just to hide that distinction.

The default workspace build retains its independent CI check:
`cargo +1.85.0 build --workspace --locked`. The package job also takes the exact
archives it has just produced and exercises the same four public API consumer
tests with the actual 1.85.0 compiler. To run that additional check with an
already installed toolchain and a completed, hash-pinned package cohort:

```sh
sh artifact/python-run.sh artifact/rust_sdk_msrv.py \
  --output target/sdk-rust-msrv \
  --report target/sdk-rust-package/RUST_SDK_PACKAGE.json \
  --report-sha256 <SHA256-of-that-report> \
  --cargo-home target/sdk-rust-package/cargo-home \
  --toolchain-root <absolute-Rust-1.85.0-sysroot>
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
