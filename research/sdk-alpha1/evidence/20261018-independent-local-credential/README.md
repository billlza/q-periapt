# Independent local-only credential renewal qualification

The [local-only contract](../../../continuity-openssl-peer/LOCAL_CREDENTIAL.md)
adds original-session credential staging, commit, expiry reconciliation and a
durable time floor in conditional `QPREFS07`. Required-witness coordination stays
separate. The base commit is `73760183d28fd1c1f97c92a268f26376febc4144`;
the capture identifies the exact 76 executed and staged source files.

All sixteen local runtime lanes and eight public readers pass. New local-only
profiles retain 148 worker operations and 29 real SIGKILL cuts:

| Profile | Worker operations | SIGKILL cuts | Native commands | Direct refusal controls |
| --- | ---: | ---: | ---: | ---: |
| Committed | 34 | 8 | 9 | 18 |
| Credential expired before commit | 39 | 7 | 9 | 16 |
| Roster expired while original authority is live | 39 | 7 | 9 | 16 |
| Local and peer renewal combined | 36 | 7 | 10 | 16 |
| Capacity admission | 3 | 0 | 6 | 2 |

The first four profiles preserve exact original sends and reserved operations,
receive real native consumption ACKs and complete four signed rekey flights in
the same session. Committed recovery remains historical after expiry; an absent
old outcome is not reclassified as noncommit. ExpiredUncommitted retains the
original observation and time floor. A later grant must name the actual
uncommitted predecessor. Backdated staging and ordinary output are refused.

The combined profile reconstructs 88,703 metadata bytes from genuine root grants.
The separate capacity test retains 122 real outbox rows and 2,004,375 traffic
bytes. Pending metadata is 27,241 bytes, while the completed identity needs
30,742 bytes. Staging refuses before any head/intent mutation. Explicit host
accounting of 64 old outboxes as DeliveryUnknown releases space while the old
authority is still valid; the same grant then commits and native decryption
accepts an unchanged surviving ciphertext. This is a measured boundary case,
not qualification of every maximum signed-input combination. A full store first
encountered after credential expiry remains a separate availability gap.

An actual creation failure is preserved: with an existing authority marker, the
previous initializer wrote a new head before refusing. Both initializers now
reject retained head/intent/authority records before publication. The repaired
observation has no new head or intent and preserves the original marker.
Required-witness regressions contain the same guard and reject local-only
coordination. Their four profiles retain 104 workers, 22 kills and 97 direct
controls; the witness lane retains 48 direct controls and one opening Query.

The first process prototype failed because its test attempted another original
outbox while a different send was Reserved. That was the correct implementation
refusal. The corrected harness expects it and resumes the original reservation
first. The original failed private state was continued with four fresh workers,
without replacement. Its native process had already exited during cleanup, so
that continuation does not prove whole-native restart. Failed public output,
the original continuation and before/after creation records are in the capture;
all private states remain outside it. A reader wrapper path error before reader
execution is also retained. Later prototype cohorts remain local diagnostics.

Strict native release build and all-target Clippy passed. Final Rust formatting,
actionlint, Python AST, executed/staged source-hash and diff checks pass. The Rust
source census remains 725. The actual ARM64 native fixture executable SHA-256 is
`313f303482a37c23a4de278fe408fff19c0e1cce1ebd6a80d6651cdcc9ce8513`;
the native changes issue genuine fixture grants, not alternate product authority.
Provider versions are cryptography 48.0.1 and OpenSSL 4.0.1.

`CAPTURE.zip` is 31,547,216 bytes with 10,232 members, SHA-256
`99f9d3a3d31c5fa6154021fe3ec93f453e4afd748dc5f5c47508206e8ba5fcc3`.
It contains public raw results, exact sources, native executable, readers,
diagnostics and a verified manifest. It excludes private journal images,
intents, authority records, wrapping keys and signer material. Public replay
checks root signatures, operation/target bindings, traffic, rekey and process
markers; private capacity, exact-target, callback and creation assertions remain
runtime observations rather than independently rederived private MAC/AEAD proofs.

Native traffic remains at fixture time 170; independent supplied times exercise
signed expiry. Same-account coordination, registration without fixtures,
policy/witness and device replacement, installed/cross-host lifecycle, whole-store
rollback, physical erasure, power loss, resource/energy qualification and full
retained-state PCS/refinement analysis remain open. Hosted qualification of this
source closure is pending; this checkpoint does not admit the full 0.2.0 release.
