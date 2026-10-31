# Native bootstrap key confirmation

Status: source-level correction with real TLS and durable-journal regression
coverage; final installed packages, supported platforms and the full construction
security argument are not admitted by these checks.

The former QPCNET01 READY carried only a public session ID. With the configured
TLS peer key and the device signature's P-256 component, an adversarial carrier
could replace the classical signature on a genuine Reply without changing its
ML-DSA signature or body/MACR. The initiator accepted the reply but derived a
different full-signed-wire root. The honest responder rejected Final. A public
READY nevertheless made the native client return Established. No business
plaintext decryption or quantum key extraction was demonstrated.

QPCNET02 now requires the existing epoch-zero acknowledgement MAC before client
success, and uses the `/v2/` SDK connection binding. Both peers must upgrade;
there is no old-version fallback. Original bootstrap/KDF, journal, archive, message
and control formats are retained. Failure may follow local activation; it does
not authorize a fresh operation or replacing the pinned signed transcript. See
[the carrier contract](../../../continuity-identity-candidate/CONNECTION_TLS.md).

## Reproducing the old failure

Extract `BASELINE_REPRODUCTION.patch` from `BASELINE_REPRODUCTION.zip` and apply
it to an isolated checkout of
`4ae5f77ad6e81dce956be24511d7f5e429924bde`. It adds only test code and module
registration. Use the locked dependencies and Rust 1.98.1:

```sh
cargo +1.98.1 test --locked --manifest-path research/continuity-identity-candidate/Cargo.toml --features control-tls,connection-tls,anchor-tls --lib connection_transport::ready_alias_probe::native_establish_accepts_public_ready_after_classical_reply_alias -- --exact --nocapture
cargo +1.98.1 test --locked --manifest-path research/continuity-identity-candidate/Cargo.toml --features control-tls,connection-tls,anchor-tls --lib bootstrap::alias_tests::classical_signature_alias_preserves_reply_authentication_but_final_rejects_root_split -- --exact --nocapture
```

The first diagnostic intentionally expects the undesired old success. Passing it
is a reproduced failure condition, not a security pass. The second exercises all
four prekey modes with honest controls and classical-only signature substitution.
The shipped regression instead requires rejection and separately supplies a
well-formed forged ACK to verify actual MAC authentication.

`VERIFICATION.json` records the baseline, source hashes, exact test commands and
49 final selected passing tests (zero ignored), including public Rust owner
connection/restart/rekey/unknown-delivery execution. The counts include existing
child-process helper entries; filtered tests are excluded. Formatting and strict
all-target Clippy passed for all three TLS features together and for control-tls
and connection-tls separately. This is macOS arm64 source execution, not installed
package or other-platform qualification. Raw red/green streams and the separate
900-second authentication-model timeout are retained in the SHA-identified review
archive. The timeout establishes no new theorem and does not alter the existing
multi-epoch MAIN model or certificate.
