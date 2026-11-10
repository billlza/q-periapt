# Apple Silicon opening optimization qualification

[Job 117764262881](https://github.com/billlza/q-periapt/actions/runs/39157706232/job/117764262881)
completes all fourteen lanes at `73760183d28fd1c1f97c92a268f26376febc4144`.
Seven public readers pass with empty diagnostics against the exact 70 frozen
sources and actual ARM64 native executable, SHA-256
`74d68fb5cdf6361a3252148150bfb99a094ef8327c0901199463f34f7bec2ba4`.

The opening check requires one signed Query. Original recovery, current-authority
output admission, cancellation, peer revocation and required-witness local
renewal remain verified. Together with the [Linux receipt](../20261018-hosted-independent-opening-linux/README.md),
this completes the opening change's hosted matrix. The local three-to-one Query
comparison measures request/byte reduction, not latency or energy. Later
version-seven/eight local-only renewal changes are outside this source closure.

Artifact 12149928137 is 28,479,707 bytes with 9,140 members, SHA-256
`e936a38b94b918092cf94ad13bbb6392d890cc80929c1e0ccf83b59939c0a311`.
`CAPTURE.zip` contains the original artifact, terminal metadata, frozen sources,
seven readers and verified manifest. It is 25,550,735 bytes with 107 members,
SHA-256 `5da706fcf6ec48161e41c50d80259bc005575cfe88bf0c2859c7411b203748e7`.

Public replay does not rederive private journal MAC/AEAD or establish installed,
cross-host, whole-store rollback, power-loss, erasure or full PCS guarantees.
This bounded independent-reference result does not admit the full 0.2.0 release.
