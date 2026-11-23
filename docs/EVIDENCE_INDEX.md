# Public releases, proofs and measurements

Q-Periapt **0.2.0 was published on 17 November 2026**. This index connects
the public packages to their frozen source, qualification records, research
proofs and measured results. For installation, use the maintained
[getting-started guide on main](https://github.com/billlza/q-periapt/blob/main/docs/SDK_GETTING_STARTED.md).
For version history, see the maintained
[changelog on main](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md).

## Release identity and public downloads

| Question | Direct evidence | Scope |
| --- | --- | --- |
| Where is the Apple SDK? | [0.2.0 Apple release](https://github.com/billlza/q-periapt/releases/tag/v0.2.0) | Signed XCFramework and complete Swift SDK; published 17 November 2026. |
| Where are the other SDK and Continuity packages? | [0.2.0 platform release](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.2.0) | Native, Android, JVM, WASM and Continuity distributions, checksums and retained evidence assets. SDK ABI 2 and Continuity `qpc-owner/1` are separate interfaces. |
| Are the twelve Rust versions published? | [Registry receipt](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/registry/crates-io-v0.2.0-publication-receipt.json) and [archive-download record](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/registry/REGISTRY_ARCHIVE_DOWNLOADS.json) | All twelve non-yanked `0.2.0` versions were checked against the official API and sparse index; unauthenticated downloads matched the admitted archive bytes. |
| What binds the complete release? | [Verified cohort](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/VERIFIED_COHORT.json), [admission](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/ADMISSION.json) and [package manifest](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/RELEASE_MANIFEST.json) | The manifest identifies 21 package rows; the later publication record binds 67 original GitHub assets and twelve registry versions. Preparation records retain their original stage flags. |
| Which source was qualified? | [Source commit `af4618c`](https://github.com/billlza/q-periapt/tree/af4618c8065d7133adfb86e1d116577089161ff0) and [release evidence description](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/README.md) | Source commit `af4618c8065d7133adfb86e1d116577089161ff0`, tree `4ee8fb082744d6f0fc9297fa31200f145df477c7`. Release evidence commits preserve that source identity. |
| Which CI run supports admission? | [Run 44036376133](https://github.com/billlza/q-periapt/actions/runs/44036376133) and [frozen CI qualification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/ci.json) | All 72 selected jobs succeeded. GitHub records PR head `8c77ea7`; producer records identify merge source `af4618c`. The qualification records that mapping explicitly. |
| Which Apple Continuity revision works beside the SDK? | [Apple Continuity 0.2.0 r1](https://github.com/billlza/q-periapt/releases/tag/continuity-apple-v0.2.0-r1) and its [SwiftPM verification](https://github.com/billlza/q-periapt/releases/download/continuity-apple-v0.2.0-r1/SWIFTPM_VERIFICATION.json) | Published 18 November 2026. This packaging revision permits SDK and Continuity products in one target while retaining the Swift names and `qpc-owner/1` interface. |

The immutable
[publication explanation](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/README.md)
describes release attestations, registry readback and retained platform
diagnostics. Read each runtime qualification with its original platform and
source scope; publication hashes identify the shipped bytes.

## Versioned API documentation

| Package | Rustdoc for 0.2.0 | Public registry version |
| --- | --- | --- |
| Composition core | [q_periapt_core](https://docs.rs/q-periapt-core/0.2.0/q_periapt_core/) | [q-periapt-core](https://crates.io/crates/q-periapt-core/0.2.0) |
| Durable host policy store | [q_periapt_host_store](https://docs.rs/q-periapt-host-store/0.2.0/q_periapt_host_store/) | [q-periapt-host-store](https://crates.io/crates/q-periapt-host-store/0.2.0) |
| TLS integration | [q_periapt_rustls](https://docs.rs/q-periapt-rustls/0.2.0/q_periapt_rustls/) | [q-periapt-rustls](https://crates.io/crates/q-periapt-rustls/0.2.0) |
| Hybrid KEM | [q_periapt_kem](https://docs.rs/q-periapt-kem/0.2.0/q_periapt_kem/) | [q-periapt-kem](https://crates.io/crates/q-periapt-kem/0.2.0) |

The maintained
[Rust package guide on main](https://github.com/billlza/q-periapt/blob/main/docs/SDK_RUST_PACKAGE.md#install-from-cratesio)
lists all twelve package names and exact installation commands. The
[Continuity source guide on main](https://github.com/billlza/q-periapt/blob/main/docs/continuity/SOURCE_DISTRIBUTION_0_2.md)
covers its separate GitHub-distributed Rust archive. To inspect a registry
version without changing a project:

```sh
cargo info q-periapt-core@0.2.0 --registry crates-io
cargo info q-periapt-host-store@0.2.0 --registry crates-io
```

**Published README correction.** Some frozen `0.2.0` crate READMEs retain
pre-publication wording, including a `0.1.5` current-release banner or an
installed-package/Linux qualification gate. Their repository-relative links
can resolve to nonexistent paths on docs.rs. Those package bytes remain
unchanged. This maintained index supplements them with versioned Rustdoc,
absolute evidence links and the completed publication records above; editing
main does not rewrite an already published crate README.

## Security claims and their proof artifacts

The links in this table pin the source snapshot. Each artifact identifies the
model, assumptions and statements it establishes.

| Research result | Read or reproduce | Evidence scope |
| --- | --- | --- |
| ContextBound composition binding | [Security definition](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/docs/BINDING_SECURITY.md), [combiner specification](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/docs/COMBINER_SPEC.md), [EasyCrypt proof](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/formal/easycrypt/BindingViaCR.ec) and [reproduction instructions](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/formal/easycrypt/README.md) | Mechanized encoding and collision-based binding argument for the combiner game. |
| Symbolic hybrid-handshake demonstration | [Tamarin handshake model](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/formal/tamarin/handshake.spthy) and [model description](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/formal/tamarin/README.md) | Authentication, context agreement and hybrid secrecy in the stated idealized handshake model. This demonstration is separate from the Continuity recovery results. |
| Continuity persistent-randomness recovery | [Manuscript PDF](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/paper/continuity/continuity.pdf), [proof and source index](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/paper/continuity/README.md), [native online composition](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/paper/continuity/artifacts/native-online-chain/README.md) | The computational manuscript connects persistent-source exposure, record simulation and ordinary primitive assumptions to the stated native message confidentiality and integrity bounds. It includes source correspondence and finite checks with their own execution identities. |
| Multi-epoch symbolic recovery | [Main-theorem replay and assumptions](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/research/sdk-alpha1/evidence/20261031-multi-epoch-secrecy/README.md) and [multi-epoch model](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/research/continuity-recovery-symbolic/multi-epoch.spthy) | The main secrecy theorem and all 24 reusable premises have a joint replay. The checkpoint separately records the remaining query inventory and finite execution witnesses. |

These are distinct proof layers. The computational manuscript's arguments,
symbolic certificates, finite Python checks and installed runtime executions
retain their own verification methods; this index does not convert one into
another. The maintained
[manuscript guide on main](https://github.com/billlza/q-periapt/blob/main/paper/continuity/README.md)
tracks subsequent research and author review.

## Measurements with reproducible inputs

| Measurement | Dataset and method | Interpretation |
| --- | --- | --- |
| X25519 fixed-base tables through the owned Rust SDK | [Experiment and result table](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/docs/SDK_X25519_TABLES.md), [capture manifest](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/research/sdk-alpha1/evidence/20261007-x25519-precomputed/manifest.json) | Five process blocks and 70,000 timed calls on Apple M1 Max; archive-derived candidate consumers. The record reports local key-generation/encapsulation gains, tail observations and the binary-size cost together. |
| Native/reference recovery comparison | [49-case workload and reproduction](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/paper/continuity/artifacts/matched-comparison/README.md), [complete CSV](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/paper/continuity/artifacts/matched-comparison/sources/results-49.csv) | Seven traffic schedules under 2,048 directed opportunities. Reports delivered applications, reconstructed message sets, wire bytes and native persistence work with each implementation's storage boundary. |
| Retry-readiness intervention | [28-execution paired experiment](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/paper/continuity/artifacts/retry-readiness/README.md), [fourteen paired rows](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/paper/continuity/artifacts/retry-readiness/sources/reviewed-analysis.csv) | Compares immediate retry with age-four readiness at the same opportunity budget; retains service gains, schedule-dependent byte costs and undelivered committed work. |
| Installed aggregate-capacity resource use | [Workload, host and results](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/research/sdk-alpha1/evidence/20261104-installed-resource-baseline/README.md), [summary](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/research/sdk-alpha1/evidence/20261104-installed-resource-baseline/SUMMARY.json) | Four installed-consumer captures on Apple M4 Max. Separates logical image capacity, database size and whole-process memory; wall time includes setup, recovery and observation waits. |

The source-pinned
[SDK performance record](https://github.com/billlza/q-periapt/blob/af4618c8065d7133adfb86e1d116577089161ff0/docs/SDK_PERFORMANCE.md)
collects further dated measurements. Each dataset preserves its measured source,
hardware, workload and baseline. The tables support those comparisons; they are
not a blanket speed, tail-latency or all-platform benchmark claim.

## Installed execution and later readback

| Evidence | Direct record | What was checked |
| --- | --- | --- |
| Linux native SDK packages | [Linux x86_64 readback](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/evidence/sdk-native/x86_64-unknown-linux-gnu/READBACK.json), [Linux aarch64 readback](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/evidence/sdk-native/aarch64-unknown-linux-gnu/READBACK.json), [original selected CI](https://github.com/billlza/q-periapt/actions/runs/44036376133) | Target-specific archive, source, ABI and license checks. The readbacks identify the original CI jobs for Linux runtime/loader execution. |
| Linux Continuity Rust/C lifecycle | [Original installed-consumer report](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/evidence/continuity-native/producer/CONTINUITY_PACKAGE.json), [relocated C probe](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/evidence/continuity-native/producer/CONTINUITY_NATIVE_PACKAGE.json), [retained-byte readback](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/evidence/continuity-native/readback/READBACK.json), [complete public capture](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/CONTINUITY_LINUX_LIFECYCLE_EVIDENCE.zip) | Original Linux Debug/Release Rust/C runtime results, relocated public C probe and later source/package/capture consistency checks. |
| Isolated independent consumers | [Qualification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/independent.json), [Linux installed readback](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/evidence/independent/independent-bootstrap-ubuntu-24.04-installed/READBACK.json) | Linux and macOS source/installed Python-wheel lanes. The record identifies source-built counterpart and directory executables separately. |
| Swift/Kotlin/Android Debug and Release | [Installed coverage qualification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/installed_coverage.json) | Six original profile executions and their required complete coverage join. |

A readback field such as `runtime_reexecuted: false` means that **that reader
checked retained evidence without executing the producer's binary again**.
The original runtime report supplies the execution result. Similarly, the six
foreign profile reports retain `completed: false` for their individual scope;
their same-source coverage join records completion of the full matrix. The
[package readback qualification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/package_readback.json)
keeps original execution, package inspection and publication observation
separate, with links to their exact records.
