# Apple Silicon required-witness qualification

The [Apple Silicon job 117741471439](https://github.com/billlza/q-periapt/actions/runs/39149991002/job/117741471439)
completes all eleven lanes at `09b226c444da394096017d2de0e0bc2c092764d7`.
Both hosted platforms finish successfully; each artifact has its own receipt.
Four local public readbacks complete without diagnostics and verify all 55
committed sources, original native records and the actual counterpart executable,
SHA-256 `f1b60e8c5e42026bec04bdfe387c6c3afe71b8ba132c4d9284bd35702532b667` (MachO64 ARM64).

The witnessed lane executes the actual persistent Rust witness, required-witness
Rust journal and independent Python session. It completes bootstrap, bidirectional
consumption and three PQ rekeys with 36 fresh-process operations, 244 native
commands, three real SIGKILL cuts and 47 direct negative controls. The 222 loopback
attempts plus one direct close control retain 223 distinct challenges and 221
valid signed replies, all verified in public replay. Refused requests and
intentionally corrupted or withheld replies remain recorded separately.

Exact AlreadyAppliedExact reconciliation succeeds after a lost response and
fixture authority expiry, while ordinary output is denied. The reservation keeps
its original identity and resumes after restoring the fixture's valid time;
this is not credential renewal. Old client images, stale challenges, corrupt
signatures, malformed frames, excess total duration and a writer fence applied
before output are refused. Closing the client in its host callback withholds an
otherwise valid signed result. Actual witness-store reopen preserves the original
head. The ten previous bootstrap/traffic/rekey/storage/control/outcome lanes also
pass with unchanged assertions.

The downloaded artifact is 10,917,415 bytes with 4,034 members,
sha256:9e235ec78dd8c7bd341db5e9efade1d99f16473875e2152d8d591e4478cf4533. `CAPTURE.zip` contains that original artifact, all source
files, four readers/outputs, download validation and terminal job metadata. Its
verified manifest covers 9,518,053 bytes and 79 members,
SHA-256 `7c3263b4397649e01580bd5df960c8fcedaa986a47def07d9a9ce0fbfdb17a75`.

Public replay loads no private journal or key and does not rederive secret
MAC/AEAD values. Direct rollback, close and timeout conditions remain runtime
assertions. The carrier is a loopback byte bridge to the real provider, not a
separate deployed witness; whole-service restart, witness-state rollback,
authority renewal/revocation/migration, installed independent lifecycle, physical
erasure, power loss and construction-wide PCS analysis remain separate work.
These results qualify this bounded hosted profile, not the entire 0.2.0 release.
