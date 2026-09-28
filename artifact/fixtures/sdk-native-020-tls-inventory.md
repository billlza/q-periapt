# Native SDK 0.2.0 configured TLS inventory

`sdk-native-020-tls-inventory.json` is the complete public algorithm-choice
snapshot from `q-periapt-rustls::standard::algorithm_inventory()` on the pinned
rustls 0.23.45 AWS-LC provider, after the product factory's TLS 1.3 / single
`X25519MLKEM768` restrictions. It was captured from actual CLI output, not a mock.
The algorithm-choice bytes are retained unchanged from the alpha.1 capture;
the 0.2.0 package metadata and CBOM profile are validated separately.
SHA-256: `d7ba7c197ae2820495a63b230a007536351c0745dfee050897bd53d494ba0bed`.

The three cipher suites, one group, thirteen advertised signature schemes and
twenty-two certificate verifier AlgorithmIdentifier pairs are deliberately
distinct sets. The certificate set includes alternate curves/hash combinations
and RSA NULL/absent-parameter encodings; it is broader than TLS 1.3
CertificateVerify. The file contains public algorithm identifiers, not keys.

The native package BOM profile pins this reviewed snapshot independently of the
producer. An upstream capability change requires explicit review; an unknown
identifier also fails the producer. The snapshot does not prove that any remote
peer negotiated these algorithms, that certificates use PQ signatures, or that
every internal primitive of AWS-LC, mlkem-native or the OS RNG was enumerated.

The schema vocabulary is checked against the official
[CycloneDX 1.6 JSON schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json),
whose SHA-256 at inspection was
`3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93`.
The historical 0.1.5 nine-asset package profile remains separate.
