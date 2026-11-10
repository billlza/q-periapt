# Continuity 0.2.0 package identity and source distribution

The Continuity companion has Cargo package identity **`q-periapt-continuity`
`0.2.0`** and ships through a versioned **Cargo source archive**. Its manifest
keeps `publish = false`: the selected distribution channel is an archive, while
the existing twelve SDK crates keep their registry publication topology. The
engine remains a separate workspace and consumes exact `=0.2.0` SDK dependencies.

This change assigns the package identity used by the producers and installed
consumers. The selected release archives, construction assessment, workload
budgets and coordinated specification lock retain their acceptance steps in the
[admission plan](RELEASE_0_2_ADMISSION_PLAN.md). A version in source metadata is
not a publication receipt. Existing platform receipts retain their recorded
source commits and artifact digests.

## Install the source archive with a public Rust alias

Extract the selected `q-periapt-continuity-0.2.0.crate` beside the consuming
application, and verify its digest against the selected release manifest. Cargo
archives contain one root directory, `q-periapt-continuity-0.2.0/`. For an
application whose `Cargo.toml` is beside `packages/`, use:

```toml
[dependencies]
continuity = { package = "q-periapt-continuity", version = "=0.2.0", path = "packages/q-periapt-continuity-0.2.0", features = ["connection-tls", "control-tls"] }
```

The dependency key is the name used by application code:

```rust
use continuity::Cancellation;

let cancellation = Cancellation::default();
assert!(!cancellation.is_cancelled());
cancellation.cancel();
assert!(cancellation.is_cancelled());
```

The explicit alias also applies to the owner API, for example
`continuity::DeviceEnrollment` and `continuity::DeviceInstallation`. The retained
library target `q_periapt_continuity_identity_candidate` keeps existing imports,
archive-shipped tests and native library filenames compatible. Applications can
use `continuity` without depending on that internal spelling. The source
directory `research/continuity-identity-candidate` and existing internal Cargo
aliases likewise do not define the public package name.

The normalized archive manifest uses exact SDK registry requirements and contains
no checkout-relative SDK dependency paths. To consume the selected SDK archives
before registry publication, or to reproduce their exact local installation,
extract these nine archives into the same `packages/` directory and add:

```toml
[patch.crates-io]
q-periapt-mlkem-native-sys = { path = "packages/q-periapt-mlkem-native-sys-0.2.0" }
q-periapt-core = { path = "packages/q-periapt-core-0.2.0" }
q-periapt-kem = { path = "packages/q-periapt-kem-0.2.0" }
q-periapt-sig = { path = "packages/q-periapt-sig-0.2.0" }
q-periapt-backends = { path = "packages/q-periapt-backends-0.2.0" }
q-periapt-policy = { path = "packages/q-periapt-policy-0.2.0" }
q-periapt-sdk = { path = "packages/q-periapt-sdk-0.2.0" }
q-periapt-host-store = { path = "packages/q-periapt-host-store-0.2.0" }
q-periapt-rustls = { path = "packages/q-periapt-rustls-0.2.0" }
```

Use the selected dependency lock and fetch its external registry dependencies
before an offline build. The
[installed package producer](../../research/continuity-identity-candidate/PACKAGE_CONSUMER.md)
already checks normalized manifests, every source member, exact external
versions/checksums, archive roots and Cargo's actual resolved origins. Its
consumer lives outside the source checkout and compiles the public workload
shipped in the engine archive. Both TLS features in the example are explicit;
the separate `anchor-tls` feature selects the encrypted witness carrier.

## Versioned adapter identities

| Surface | Identity in current source | Preserved interface |
| --- | --- | --- |
| Rust engine | `q-periapt-continuity` `0.2.0`, Cargo source archive | Existing library target and public owner/state API |
| C companion | `q-periapt-continuity-native-0.2.0-<target>.zip` Linux producer and ABI snapshot package version `0.2.0` | `qpc-owner/1`: 158 functions, 70 records, one callback, 112 constants |
| Swift | `QPeriaptContinuity-Apple-0.2.0.zip`; product `QPeriaptContinuity` | Module `CQPCOwner`, macOS arm64, iOS arm64, arm64 and x86_64 iOS simulators |
| Kotlin/JVM | `dev.qperiapt:q-periapt-continuity-kotlin:0.2.0` | Module `dev.qperiapt.continuity`, `qpc-owner/1` |
| Browser | Existing `q-periapt-sdk-wasm@0.2.0` `/web` surface | Existing `QPeriaptContinuity…` exports |

SDK C ABI **2** remains a separate namespace from Continuity **`qpc-owner/1`**.
The C consumer crate is an unpublished qualification harness; its own `0.0.0`
version is not the companion's distribution version. The
[Linux native producer](NATIVE_DISTRIBUTION_0_2.md) packages the exact qualified
Release library, independently reopens the archive and executes a relocated C
probe. Its distribution record and package row bind the actual source, engine
dependency, original C qualification and archive digest. The selected hosted
execution supplies that artifact for coordinated admission.

The Android adapter keeps
its actual Java/JNI API and accepted AAR/phone evidence; its formal
`dev.qperiapt:q-periapt-continuity-android:0.2.0` AAR identity and the selected
native archive retain their selected execution and artifact-digest binding in
the final release manifest.

The [Linux service distribution](SERVICE_DISTRIBUTION_0_2.md) selects
`q-periapt-continuity-services` `0.2.0` as a versioned tar archive. Its source remains the separate
`q-periapt-continuity-reference-app` `0.0.0` package. Its actual binaries include
`q-periapt-prekey-directory`, `q-periapt-continuity-witness`,
`q-periapt-policy-publisher` and `q-periapt-sdk-policy-authority`, alongside the
reference application's native device/session clients. The distribution includes
the four named services and the existing native-device wrapping-key provisioner.
Its producer binds the selected source, actual Release executable digests,
configuration/storage documents and extracted-process readback to the release
manifest's service row. The reference Cargo package and independent Python/OpenSSL
implementation retain their current research identities; the outer distribution
version identifies the selected service artifact.

## Compatibility carried by this package identity

The package rename and version do not alter the cryptographic domains, wire
bytes, Rust library target, public C declarations or persisted format tags.
`q-periapt-continuity` `0.2.0` carries the current readers and writers below.

| Persisted state | Exact retained format |
| --- | --- |
| Device journal | `continuity_device_candidate_v21`; `QPVLT021`/`QPVIMG21` through `QPVLT024`/`QPVIMG24` |
| Installation | `continuity_installation_v1`; `QPCINS01` |
| Session cleanup archive and index | `QPCSCA01`; `QPCSIX01` |
| Witness | `continuity_anchor_candidate_v1`; `QPANC001`–`QPANC004`, `QPANC006`–`QPANC022` |
| Witness handoff | Original `QPAHPL01` and `QPAHPL02` signed bytes |
| Unpublished maintenance control | `.private-attempt-v2-*`; `QPSTG002`, `QPSTGL02`, `QPSTGC02`, `QPSTGD02` |

The [upgrade contract](UPGRADE_MAINTENANCE_V1.md) defines the exact reader/writer
interpretations and current-authority requirements. Its retained
[program-replacement](../../research/sdk-alpha1/evidence/20261104-installed-program-upgrade/README.md)
and [maintenance replacement](../../research/sdk-alpha1/evidence/20261104-maintenance-program-upgrade/README.md)
receipts establish the listed same-format edges with their original builds.
Unknown previews, unsupported earlier journals and incomplete staging residue
retain the existing explicit refusal and original state. The package identity
adopts these compatibility boundaries without inventing a migration edge or
relabeling a historical execution as a new build result.
