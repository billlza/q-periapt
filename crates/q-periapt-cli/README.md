# q-periapt-cli (`qperiapt`)

Auditability & migration tooling for the PQ/T hybrid suite.

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
```

## Features

| Feature | Default | Effect |
|---|---|---|
| `slh-dsa` | off | Forwards to `q-periapt-backends/slh-dsa`, adding the `SLH-DSA-SHA2-128s/192s/256s` rows to `qperiapt cbom` |

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
