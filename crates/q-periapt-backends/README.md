# q-periapt-backends

The concrete primitive adapters for Q-Periapt: ML-KEM through the
target-selected `mlkem-native` integration, ML-DSA through `fips204`, X25519
through `x25519-dalek`, and SHA3 through RustCrypto. Optional SLH-DSA uses
`fips205`.

```sh
cargo add 'q-periapt-backends@=0.2.0'
```

## API and selection

The [0.2.0 Rust API](https://docs.rs/q-periapt-backends/0.2.0/q_periapt_backends/)
documents parameter sets, key formats and the exact randomness accepted by
each operation. `MlKem768XWingSeed` supplies the seed-derived key format for
`CompatXWing`; the expanded-key ML-KEM adapters use `ContextBound`.

The [native integration](https://docs.rs/q-periapt-mlkem-native-sys/0.2.0/q_periapt_mlkem_native_sys/)
owns the C/assembly boundary. Backend selection follows its target contract.
The off-by-default `linux-x86_64-avx2` feature is a separately qualified
candidate; `slh-dsa` enables the optional hash-based signature adapters.

The [dependency policy](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_DEPENDENCY_POLICY.md)
records the selected versions. Measurements of a particular backend or target
are identified by source, workload and platform in the evidence index below.
Applications seeking signed policy and platform-generated randomness should
use [q-periapt-sdk](https://docs.rs/q-periapt-sdk/0.2.0/q_periapt_sdk/).

## Release and evidence

- [Published 0.2.0 package and qualification record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0)
- [Proofs, performance results and reproduction entry points](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
- [Changelog](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md)
