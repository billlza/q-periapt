# q-periapt-kem

Generic post-quantum/traditional hybrid-KEM composition over two compatible
primitive backends and a combiner hash implementation.

```sh
cargo add 'q-periapt-kem@=0.2.0'
```

## API and profiles

The [0.2.0 Rust API](https://docs.rs/q-periapt-kem/0.2.0/q_periapt_kem/)
provides `HybridKem` and typed component key/ciphertext wrappers. Concrete
implementations are supplied by
[q-periapt-backends](https://docs.rs/q-periapt-backends/0.2.0/q_periapt_backends/).

`ContextBound` includes every component ciphertext and public key, together
with the suite, policy version and caller context. `CompatXWing` admits a first
component only when its backend declares both `C2PRI` and `COMPAT_XWING_SAFE`.
The ML-KEM seed-derived backend supplies that contract; expanded/imported
ML-KEM keys use `ContextBound`. `CompatXWing` requires canonical absence of
suite/version/context metadata and rejects supplied values.

Read the [exact combiner specification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/COMBINER_SPEC.md)
and [binding-security analysis](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/BINDING_SECURITY.md)
before selecting a profile. These low-level APIs accept explicit randomness;
the [owned SDK](https://docs.rs/q-periapt-sdk/0.2.0/q_periapt_sdk/)
provides the application entry point with platform randomness and signed policy.

## Release and evidence

- [Published 0.2.0 package and qualification record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0)
- [Proofs, performance results and reproduction entry points](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
- [Changelog](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md)
