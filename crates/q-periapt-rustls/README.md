# q-periapt-rustls

Q-Periapt's separately configured standard TLS and private-group integrations
for rustls.

```sh
cargo add 'q-periapt-rustls@=0.2.0'
```

## Select the integration

| Entry | Configuration | Contract |
| --- | --- | --- |
| Private-group provider | Default crate | Q-Periapt `ContextBound`/`CompatXWing` groups for endpoints configured with the same private group; 32-byte combiner output. |
| Standard TLS | `standard-tls` feature | rustls/AWS-LC's maintained `X25519MLKEM768` group and mandatory mutual certificate authentication. |
| SDK connection | `reference-connection` feature | Standard TLS plus explicit peer pins, authenticated application-policy confirmation and bounded framing. |

The standard group uses the standard TLS key schedule and its 64-byte
concatenated key-exchange secret. Private groups use their own group IDs and
Q-Periapt's combiner. Select the intended entry explicitly.

- [0.2.0 Rust API](https://docs.rs/q-periapt-rustls/0.2.0/q_periapt_rustls/)
- [Standard TLS configuration and interoperability evidence](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_STANDARD_TLS.md)
- [SDK connection contract](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_CONNECTION.md)

To include the optional modules in locally generated API documentation, run
`cargo doc -p q-periapt-rustls --features reference-connection --no-deps`.
The integrating host supplies independent certificate/peer trust and durable
policy state as specified by the selected entry.

## Release and evidence

- [Published 0.2.0 package and qualification record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0)
- [Proofs, performance results and reproduction entry points](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
- [Changelog](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md)
