# q-periapt-sig

The `no_std`, algorithm-independent signature interface for Q-Periapt.
It supplies the signer/verifier traits and signature-algorithm metadata used
by the policy layer. Concrete implementations live in `q-periapt-backends`.

```sh
cargo add 'q-periapt-sig@=0.2.0'
```

## API and backends

- [0.2.0 signature API](https://docs.rs/q-periapt-sig/0.2.0/q_periapt_sig/)
- [Concrete ML-DSA and optional SLH-DSA backends](https://docs.rs/q-periapt-backends/0.2.0/q_periapt_backends/)
- [Signed-policy verification](https://docs.rs/q-periapt-policy/0.2.0/q_periapt_policy/)

The backend crate wires ML-DSA through `fips204`; its `slh-dsa` feature enables
the `fips205` implementations. The caller selects the algorithm, trusted
verification key and signature purpose required by its protocol. The
[dependency policy](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_DEPENDENCY_POLICY.md)
records the selected implementations and their qualification boundaries.

## Release and evidence

- [Published 0.2.0 package and qualification record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0)
- [Proofs, performance results and reproduction entry points](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
- [Changelog](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md)
