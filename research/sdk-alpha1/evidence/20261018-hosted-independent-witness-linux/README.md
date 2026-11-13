# Linux x86_64 required-witness qualification

The [Linux x86_64 job 117741471299](https://github.com/billlza/q-periapt/actions/runs/39149991002/job/117741471299)
completes all eleven lanes at `09b226c444da394096017d2de0e0bc2c092764d7`.
Both hosted platforms finish successfully; each artifact has its own receipt.
Four local public readbacks complete without diagnostics and verify all 55
committed sources, original native records and the actual counterpart executable,
SHA-256 `d9b9a96825d7437ebd6a2fab3ee83e96092d30df99411cf720056d8b3073e4a0` (ELF64 x86_64).

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

The downloaded artifact is 11,094,750 bytes with 4,034 members,
sha256:01487a036cbc4b9d8c415fbe78dcff7e843403872ff6dacffc2a0812e821013e. `CAPTURE.zip` contains that original artifact, all source
files, four readers/outputs, download validation and terminal job metadata. Its
verified manifest covers 9,672,585 bytes and 79 members,
SHA-256 `cb38314ce21a632182b129a1ac970744adaf313dd69b8ca43bc0380d8814cd54`.

Public replay loads no private journal or key and does not rederive secret
MAC/AEAD values. Direct rollback, close and timeout conditions remain runtime
assertions. The carrier is a loopback byte bridge to the real provider, not a
separate deployed witness; whole-service restart, witness-state rollback,
authority renewal/revocation/migration, installed independent lifecycle, physical
erasure, power loss and construction-wide PCS analysis remain separate work.
These results qualify this bounded hosted profile, not the entire 0.2.0 release.
