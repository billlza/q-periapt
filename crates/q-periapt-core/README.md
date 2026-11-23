# q-periapt-core

The dependency-free, `no_std` composition core of Q-Periapt. It defines the
hybrid-KEM combiner, canonical context encoding, primitive traits and owned
secret buffers. Primitive implementations are supplied through those traits.

```sh
cargo add 'q-periapt-core@=0.2.0'
```

## API and construction

Use the [0.2.0 Rust API](https://docs.rs/q-periapt-core/0.2.0/q_periapt_core/)
for `CombineInput`, `Profile`, `Kem`, `Xof256` and the secret owners. The
[combiner specification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/COMBINER_SPEC.md)
defines the exact encodings of `ContextBound` and `CompatXWing`.
`ContextBound` includes the component secrets, ciphertexts, public keys and
external context. `CompatXWing` retains the construction's fixed input format;
its backend admission conditions are enforced by `q-periapt-kem`.

The [binding-security analysis](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/BINDING_SECURITY.md)
connects the construction to its field-binding reductions and executable
countermodels. A context digest binds bytes; the integrating protocol supplies
their authenticated meaning. The constant-time helpers and secret owners have
the compiler and memory-ownership scope described in the API.

For an application runtime with signed policy, platform randomness and owned
keys, start with [q-periapt-sdk](https://docs.rs/q-periapt-sdk/0.2.0/q_periapt_sdk/).

## Release and evidence

- [Published 0.2.0 package and qualification record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0)
- [Proofs, performance results and reproduction entry points](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
- [Changelog](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md)
