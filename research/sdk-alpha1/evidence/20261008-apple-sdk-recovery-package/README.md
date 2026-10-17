# Complete Apple SDK package and simulator execution, 2026-10-08

Source `4d253e72399dcde331ec4da06b7d0f7bd0d0d676` passes the complete
`sh artifact/swift-xcframework.sh --profile sdk-020` build, package and external
consumer path. The source remains clean, its commit is unchanged, and the
private Rust compiler/Cargo/rustdoc binaries retain their pre-run hashes.
`QUALIFICATION.json` retains source identities, artifact identities, commands,
logs, failure controls and the exact scope of each observation.

The package has three slices: macOS arm64, iOS arm64, and iOS simulator
arm64/x86_64. All four native targets pass exact 50-export ABI 2 checks before
and after archive normalization. Intel macOS remains excluded. macOS linkage
uses the 13.0 deployment floor; iOS device and both simulator architectures
link at the 16.0 floor. These floor/link checks do not prove execution on those
minimum operating systems.

The exact complete Swift package is then extracted outside the checkout.
Five public-API consumer tests pass, including policy-authority recovery,
retention of a newer policy during original-operation replay and real store
close/reopen. SwiftPM's selected native archive matches the packaged slice.
The link probe, inventories, dependency/license notices, archive paths and
before/after input snapshots also pass. No signing, provisioning or publication
operation was performed.

Artifacts:

- Complete Swift SDK ZIP: `3fb15050c6335ac565da5239afa6f90d811d7b9a85ccfd27d9b94a18b9ed093d`.
- Native XCFramework ZIP: `f6857fca21f73174af1ae61965e7f020195200aac134af547539c520def4cc86`.
- Simulator fat static archive: `5dc868c125946fb8728d2c30e637ad00e95fdf419e6b564ae4d67a08e38f6d5a`.

The first full attempt's consumer checks passed, but its outer clean-source
assertion failed: Swift 6.4's `swift package compute-checksum` created a root
`.build` directory. An isolated real-tool control reproduces that behavior;
`--scratch-path` moves those writes into the owned build directory and returns
the same checksum. The verified generated files were retained with the failed
attempt. The builder now provides that scratch path and revalidates the source
commit/clean tree for unsigned packages as well as signed releases. Explicit
dirty unsigned diagnostics retain their existing allowance; changing commits
is always rejected.

An actual Git regression fails against the old unsigned guard and passes after
the change. All 97 related Apple tests pass. `source-drift-red-01` was a harness
canonical-path setup error; only `source-drift-red-02` is the target regression.
The initial `--no-update` toolchain command returned zero without adding the
requested targets, and is likewise not treated as successful preparation. The
subsequent explicit private-home installation supplies both missing simulator
standard libraries with self-update disabled and unchanged compiler hashes.
The final full package run completes in 172.377 seconds with clean source.
Its native XCFramework ZIP is byte-identical to the first attempt.

A separate diagnostic consumes this complete SDK ZIP in a new SwiftPM-dependent
iOS app on a run-owned iOS 27.0 arm64 simulator. It reuses the existing four
device workload groups, adding module imports and simulator-specific result
names to the entry point. The tests execute compatibility/signed policy,
owned keys and purpose derivation, expert transfer and policy revocation, and
resource limits/cancellation/concurrent decapsulation. The exact run-bound
result is checked; the selected static archive and app executable are rehashed.
The app and owned simulator are removed, and a fresh inventory confirms absence.
Only a sanitized summary and private-log digests are retained here. This run
emits no physical-device proof and does not claim on-device binary attestation.

Two paired physical Apple devices were observed unavailable. Physical execution,
minimum-supported-OS runtime acceptance, durable iOS policy storage, Continuity
identity/root migration and the remaining 0.2.0 protocol/security/performance
requirements stay open. The simulator workload uses an in-memory policy floor;
it does not establish iOS persistence. Hosted CI still evaluates `1ca9ba6b` while
its Rust CodeQL analysis is live, so this local package is not current-head CI
approval or a release claim.

Large logs and input snapshots are losslessly gzip-compressed. The qualification
inventory records both compressed and original hashes. Drivers preserve the
actual local diagnostic procedure; canonical package reproduction uses the
repository's unchanged `sdk-020` entry point and its stated toolchain requirements.
