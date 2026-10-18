# Hosted Linux public-input qualification

Run [39169730900](https://github.com/billlza/q-periapt/actions/runs/39169730900),
job `117800087126`, completed successfully at
`d6d434e5c928ef2d9c31c651cf2aeaa09e3de555`. Eighteen entrypoints and ten public
readers agree on the exact 88-source closure and Linux x86_64 executable.

Artifact `12151984286` contains 14,257 members and 46,037,985 bytes, SHA-256
`c8e97c21889bc26b3d152d99e6762f4641885256b27fc4cc223b6002591940af`.
The native counterpart SHA-256 is
`f38d21a47f708f8c3dc2c064453367501b3e0793f376530a15ef65c1746d4ced`.

The new lane checks the native-compatible public bootstrap bundle, independent
pins, original-context commitment and actual supplied time. It runs real Rust
imports and rejects wrong storage quality, expired advertisements and tampering.
Historical verification does not authorize expired session creation. Existing
session, rekey, renewal and pending-write recovery lanes remain included.

The first download guard correctly noticed `Error:` lines, but these were the
intentional native negative-import results. That attempt and its partial
extraction are retained. The repaired guard admits only the exact expected
Scope/Validity/Authentication error at the designated negative-case paths, with
exit code 1, empty stdout and matching recorded hashes. Other diagnostics still
fail. No runtime test or frozen source was changed for this readback.

`CAPTURE.zip` contains 142 members and 41,288,464 bytes, SHA-256
`d2fd1f6a14b029ae8dab3006aac165b70bcc1915139d21091bdfc13e7b550a51`.
It retains the terminal artifact, exact Git sources, metadata, readers, diagnostic
repair and verified manifest. Private images and wrapping keys are excluded.

This receipt qualifies the hosted Linux increment. Apple Silicon CI has a
separate job. Runtime private-storage assertions are not public MAC rederivation;
this is not deployed account authentication, an installed independent lifecycle,
power-loss or erasure evidence, a PCS proof, or full 0.2.0 admission.
