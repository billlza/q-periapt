# Native SDK cryptographic inventory

The alpha native SDK has an explicit 37-asset CBOM profile. It includes the
retained backend catalogue, the existing ContextBound combiner, owned SDK
SHA-256/HMAC/HKDF use, and the standard TLS
configuration's AEAD, hash/key-schedule, hybrid group and certificate algorithms.
ABI major remains 2. This inventory does not make an SDK package releasable by
itself; package producers, installed consumers and release receipts are still
being updated.

## Producer and verifier

```sh
cargo run --locked -p q-periapt-cli --features sdk-cbom -- \
  cbom --native-sdk --out native-sdk-cbom.cdx.json
```

Without the build feature the command fails with no successful document. The
fixed native profile also rejects an optional SLH-DSA build. The existing
`cbom` command retains its separate backend-catalogue scope; it cannot describe
the full native SDK. The source correction from `key-agree` to `keyderive` in
`cryptoFunctions` applies to both emitters: the former is a primitive name,
but is not a function value in the official
[CycloneDX 1.6 schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json).
Previously captured/published BOM bytes have not been rewritten.

`package_bom.verify(..., profile=BomProfile.NATIVE_SDK_ALPHA1)` checks the new
closed inventory. Its historical default remains `BACKENDS_V0_1_5`, retaining
the old nine-asset acceptance scope. Neither profile can accept the other's
document. The native profile checks exact algorithm names, primitives, function
sets, category presence/values, metadata version/scope and a separately pinned
TLS snapshot. Missing KDFs, classic group substitution, omitted certificate
parameters, invented strength claims and broadening RSA-PKCS1v1.5 to a TLS 1.3
handshake operation are rejected.

TLS algorithm choices come from the same private provider factory used by the
client and server. The read-only inventory API cannot modify that configuration.
It reports three TLS 1.3 cipher suites, one standard hybrid group, thirteen
advertised signature schemes, and twenty-two complete certificate verifier DER
identifier pairs. A TLS SignatureScheme alone does not enumerate all accepted
certificate-chain combinations. Unknown configured identifiers fail emission.
The [pinned snapshot](../artifact/fixtures/sdk-native-alpha1-tls-inventory.md)
requires a separate package-profile review when these choices change.

The SDK's SHA-256/HMAC/HKDF labels are reviewed source declarations for its
`purpose.rs` and root-binding calls. Their presence is not inferred from every
library in Cargo.lock. TLS cipher/hash choices and certificate identities are
read from linked implementation objects. This is a product algorithm catalogue,
not a binary-wide census of every transitive internal hash, arithmetic routine
or operating-system entropy mechanism. It does not establish that any remote
peer negotiated PQ certificate authentication.

Post-quantum KEM/signature categories retain their implementation/policy source.
Traditional signature/key-agreement rows explicitly have category 0. The native
profile omits category claims for hash, MAC, KDF, AEAD and the composite TLS group
instead of converting an unreviewed strength claim into 0. In CycloneDX, 0 means
none of the categories are met; omission has a different meaning.

## Current verification

Real CLI emission passes the native verifier with 37 crypto assets and the
249-entry workspace Cargo.lock SBOM. The latter is the complete workspace lock
catalogue, not an exact per-target linked dependency census. Registry package
versions remain at 231; the two new CLI dependency edges use already-locked
TLS crates. No production dependency version was added.

The affected CLI/TLS suites pass 43 tests, including additive TLS 1.2 feature
unification. The final combined BOM/package/Rust-publishing/workflow suite passes
130 tests. Warning-denied workspace Clippy and affected-target rustdoc
pass after correcting initial private-method use, fallible JSON mutation and
documentation markup errors. The original failures and before/after function
enumeration results are retained in the
[checkpoint](../research/sdk-alpha1/evidence/20260925-native-sdk-cbom/manifest.json).

Native inventory generation/verification is declared in the existing BOM CI
job, but hosted execution has not been observed. Complete native package
producer and receipt profiles, target-specific installation, device/CT/performance
evidence remain open. The historical source results and
publication receipts are unchanged.

The first 36-asset draft omitted ContextBound itself. Review against the real
SDK operation identified that gap; the emitter now names the existing core
`Profile::ContextBound` as a separate combiner, and the current verifier rejects
the retained earlier document. No new combiner or protocol was implemented.
This correction illustrates why a valid schema and passing structural tests
alone do not establish a complete inventory.

The original default CBOM fails the official full CycloneDX 1.6 schema on its
function enumeration. Both corrected CBOMs and the workspace SBOM pass with
`jsonschema 4.26.0` Draft7 validation and its format checker. The validator and
format dependencies were installed only in a local diagnostic virtual environment;
their installation report/hashes and the exact schema bytes are retained. These
are local schema results, separate from the declared CI profile checks.
