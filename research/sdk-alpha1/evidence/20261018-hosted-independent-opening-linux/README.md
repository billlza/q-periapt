# Linux x86_64 opening optimization qualification

[Job 117764263304](https://github.com/billlza/q-periapt/actions/runs/39157706232/job/117764263304)
completes all fourteen lanes at `73760183d28fd1c1f97c92a268f26376febc4144`.
Seven public readers pass with empty diagnostics using the exact 70 frozen Git
sources and the artifact's actual x86_64 executable. The opening witness check
requires one signed Query. Current-authority checks, original-session recovery,
revocation, cancellation and required-witness local renewal still pass.

The local-renewal profiles retain 104 worker operations, 22 real kills, 384 valid
signed replies and 386 challenges. The earlier local before/after experiment
measures three opening queries becoming one, saving 14,682 framed bytes. This
hosted run confirms the resulting behavior; it does not measure latency or energy.

Artifact 12148385467 is 28,652,780 bytes with 9,140 members, SHA-256
`d8a4d8fb207f07080ae0012b0c5e8f9c3a3d44f45ade2f3c6e74105fa6d440fb`.
`CAPTURE.zip` includes the original artifact, terminal job metadata, frozen
sources, readers and manifest. It is 25,686,122 bytes with 107 members, SHA-256
`4fd06f1bdec938993f6fc4abc2064175e22a2b64e5427104347e93eed0a4a12d`.

The later local-only format-seven work is outside this source closure. The
subsequent [Apple Silicon receipt](../20261018-hosted-independent-opening-mac/README.md)
completes the same hosted matrix. Public
readback does not rederive private journal MAC/AEAD or establish installed,
cross-host, whole-store rollback, power-loss, erasure or full PCS guarantees.
