# pqt-cli (`pqt`)

Auditability & migration tooling for the PQ/T hybrid suite.

## Commands

```sh
# CycloneDX 1.6 CBOM — the suite's cryptographic assets (algorithms, parameter
# sets, NIST quantum-security levels, OIDs):
pqt cbom [--out cbom.json]

# CycloneDX 1.6 SBOM — every locked dependency, from a Cargo.lock:
pqt sbom [--lock Cargo.lock] [--out sbom.json]

# Migration scan — flag legacy / quantum-vulnerable crypto and recommend a PQ/T
# replacement. Exits 2 if any high/critical finding is present (use as a CI gate):
pqt scan <path> [--json]
```

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
$ pqt scan ./my-service
my-service/tls.rs:42: [high] ECDSA (broken by Shor) (ecdsa)
    -> Replace with ML-DSA-65 (or SLH-DSA for roots/firmware).
my-service/hash.rs:7: [critical] SHA-1 (collision-broken) (sha1)
    -> Replace with SHA3-256.

2 finding(s): 1 critical, 1 high, 0 advisory   # exit code 2
```

> Note: running `pqt scan` over this crate's own source self-reports, because the
> scanner's pattern table literally contains the token strings. Point it at the
> code you are migrating, not at the scanner.

The CBOM/SBOM JSON is standard CycloneDX 1.6 and feeds any compliant consumer
(Dependency-Track, etc.).
