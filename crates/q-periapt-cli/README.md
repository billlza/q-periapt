# q-periapt-cli (`qperiapt`)

Auditability & migration tooling for the PQ/T hybrid suite.

For the unpublished 0.2.0 native SDK, build with `--features sdk-cbom` and use
`qperiapt cbom --native-sdk`. This emits the distinct 37-asset
[native SDK inventory](../../docs/SDK_CBOM.md), including configured TLS choices.
The default command below remains the backend catalogue and is insufficient for
new native packages. Package validators must select `BomProfile.NATIVE_SDK_020`.

## Commands

```sh
# CycloneDX 1.6 CBOM — the suite's cryptographic assets (algorithms, parameter
# sets, NIST quantum-security levels, OIDs):
qperiapt cbom [--out cbom.json]

# CycloneDX 1.6 SBOM — every locked dependency, from a Cargo.lock:
qperiapt sbom [--lock Cargo.lock] [--out sbom.json]

# Migration scan — flag legacy / quantum-vulnerable crypto and recommend a PQ/T
# replacement. Exits 2 if any high/critical finding is present (use as a CI gate):
qperiapt scan <path> [--json]

# Explicit offline upgrade of an existing v1 host policy store, on macOS/Linux.
# Requires a build with --features policy-store-migration. Trust inputs must
# come from independently retained host configuration, not the target database.
qperiapt policy-store-upgrade /private/path/policy.redb \
  --root /trusted/path/root.bin --expected-state /trusted/path/state.bin
```

## Features

| Feature | Default | Effect |
|---|---|---|
| `slh-dsa` | off | Forwards to `q-periapt-backends/slh-dsa`, adding the `SLH-DSA-SHA2-128s/192s/256s` rows to `qperiapt cbom` |
| `policy-store-migration` | off | Adds the offline macOS/Linux policy-store maintenance command and its pinned legacy-format reader; not an in-process SDK API |

## Offline host policy-store upgrade

Build the maintenance executable from the selected release source with
`cargo build --locked -p q-periapt-cli --features policy-store-migration`.
Stop users of the target store first. Its parent must have mode `0700` and the
existing file must have mode `0600`, be owned by the user, have no extended ACL
and have exactly one link. The command uses the same private path and exclusive
file-lease admission as the host store. Missing files, symlinks and busy files
are errors; they never become first-use provisioning.

The root input is a raw ML-DSA-65 verification key. The expected state is the
exact 36-byte `TrustedPolicyState::encode()` value, obtained and retained
independently before the upgrade. Version alone is insufficient. The command
will not infer trust or freshness from the database it is converting, and it
does not allow a lower or different signed state. If independent state is lost,
recover it through the host's authorization procedure before attempting this
command; copying state from the suspect store is not that procedure.

Only the original five-field `QPeriapt-Host-Policy-v1` image is supported.
The command verifies both commit-slot checksums before provider selection,
authenticates the exact signed policy against the independent root and state,
converts redb format 2 to 3 under the same file lease, then validates the same
image with the current backend. Root, policy bytes, signature and state do not
change. Disabled policies and `u32::MAX` policy versions remain unchanged too.
It creates no runtime for the host application and performs no recovery-trust
enrollment, root replacement, Continuity migration or witness reconciliation.

Success prints one JSON `verified-format-3` observation only after the current
database has closed and the backend's final sync/close errors have been checked.
`legacy_provider_used: false` means an already-current image was reverified;
it is not evidence of a new conversion. An interrupted attempt may have changed
the storage format or allocator/recovery metadata. Any error, abnormal exit or
lost output means no successful receipt was obtained. Preserve the original
file and retry with the same independent trust and state; do not replace it,
lower the floor or automatically select a backup. A subsequently changed policy
needs separate reconciliation rather than treating a stale retry as success.

Slot checksums detect corruption, not adversarial provenance. Corrupt slots or
pages can require an authorized recovery procedure instead of another retry.
The legacy parser runs only in this maintenance executable; an upstream parser
panic terminates the command with failure and never becomes a success response
or an in-process SDK fallback. These are filesystem sync guarantees, not a
claim of physical power-loss qualification or cryptographic erasure.

`qperiapt cbom` does not carry a hand-written inventory: it derives every row
from the suite crates it links (`q-periapt-core`, `q-periapt-sig`,
`q-periapt-policy`, `q-periapt-backends`), taking each identifier from the
backend's own algorithm name, and each NIST level from the signature layer
(`SigAlg::nist_level`) or from the strength table the downgrade floor is
enforced against (`q_periapt_policy::nist_level`). The traditional hybrid
partner and the two FIPS 202 rows publish a declared 0, because no NIST level
ranks them — not because a lookup came back empty. The default build lists
exactly the nine assets the default
backend set ships — ML-KEM-512/768/1024, X25519, ML-DSA-44/65/87, SHA3-256 and
SHAKE-256 — and the three SLH-DSA rows appear only when `--features slh-dsa`
actually compiles those parameter sets (which also pulls in `fips205`).

Because the tool links the real backends, building it needs a working C
toolchain: `q-periapt-backends` depends on `q-periapt-mlkem-native-sys`, whose
build script compiles the vendored mlkem-native C/assembly tree with `cc`.

## What the scanner flags

| Severity | Examples | Recommendation |
|---|---|---|
| `critical` (broken) | MD5, SHA-1, 3DES, RC4 | SHA3-256 / AEAD |
| `high` (quantum-vulnerable) | RSA, ECDSA, ECDH, DSA, NIST P-256/384, secp256k1, PKCS#1 | ML-KEM-768+X25519 hybrid (KEX), ML-DSA-65 (sig) |
| `advisory` (hybrid-only ok) | X25519, Ed25519 | keep ONLY as a hybrid partner alongside a PQ scheme |

Matching is case-insensitive with word boundaries (`_` counts as a boundary, so
`rsa_sign` and `x25519_dalek` match, but `coarse` does not).

Each code file must be valid UTF-8 and at most 2 MiB. The byte limit applies to
the content read, including growth after the initial metadata check. Oversized
or unreadable files make the scan incomplete: JSON reports `complete: false`
and the command exits 1. The scanner does not report a truncated file as a
complete scan. A changing directory tree is not an atomic filesystem snapshot.

## Example

```sh
$ qperiapt scan ./my-service
my-service/tls.rs:42: [high] ECDSA (broken by Shor) (ecdsa)
    -> Replace with ML-DSA-65 (or SLH-DSA for roots/firmware).
my-service/hash.rs:7: [critical] SHA-1 (collision-broken) (sha1)
    -> Replace with SHA3-256.

2 finding(s): 1 critical, 1 high, 0 advisory   # exit code 2
```

> Note: running `qperiapt scan` over this crate's own source self-reports, because the
> scanner's pattern table literally contains the token strings. Point it at the
> code you are migrating, not at the scanner.

The CBOM/SBOM JSON is standard CycloneDX 1.6 and feeds any compliant consumer
(Dependency-Track, etc.).
