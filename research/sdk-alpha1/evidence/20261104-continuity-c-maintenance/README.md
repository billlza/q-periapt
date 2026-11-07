# Complete installed Rust/C maintenance-cohort qualification

The unchanged `continuity_package.qualify` gate completed both Rust and C
Debug/Release profiles on Apple Silicon macOS. The run started at
2026-11-04 21:43:08 UTC and finished at 2026-11-05 00:03:23 UTC, taking
8,414.374 seconds within the existing 9,000-second parent limit. Every component
retained its 900-second and 16-MiB-per-stream limits. Strict Cargo/Clippy and
scenario validators remained enabled; the final parent exit was zero.

The clean qualification checkout is
`ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`, with the 12 SDK archives from producer
`f560d803c43a24fff222daa5e5e5bd623bfdf874`. The SDK report SHA-256 is
`93fbef9dace1af6550a85095f6d2392285197a8fe589838f4d6f8447ba03c4f8`;
the candidate crate SHA-256 is
`9bd308702bbb922122ae9f69c40d0cd691f67da9ef0d7d6c2b5381adf2cce163`.
The candidate archive equals the prior installed-maintenance cohort. Complete
source, archive, compiler, native binary and dependency identities were checked
around execution. MAIN's selected input inventory was also identical at capture
time, before the separately recorded CI public-export correction.

Both profiles execute the existing installed ownership, configuration,
publication, enrollment, account/root lifecycle, communication, recovery,
cancellation, revocation, Witness, fault and process-interruption paths. This
includes the final cross-profile checks and all-target Clippy. It is the complete
existing local Rust/C gate, not just a repeated OpenSSL test. The 253 captured
top-level `argv` command receipts have zero exits; nested deliberate fault and
refusal outcomes retain their own original records and scenario checks.

The independent OpenSSL TLS carrier uses matched headers, CLI and libraries
for OpenSSL 3.5.9. Each profile passes:

- Server: exactly **146** Witness exchanges and exact TLS 1.3,
  `X25519MLKEM768`, `q-periapt-anchor/1` negotiation records.
- Client: exactly **2** exchanges, retaining its separate query/advance semantics.
- Wrong subject, trailing bytes, missing authenticated end and wrong protocol:
  all four cases reject with **zero store calls**.

All six public OpenSSL results were independently replayed during capture.
The older [P0 negative controls](../20261104-openssl-witness-census/README.md)
remain separate evidence; hosted runs of the old checker still fail and are
not relabeled as corrected-candidate passes. The TLS implementation is independent;
the Witness state and signature engine are still shared native code.

The capture rechecks 66 complete `PUBLIC_FILES.json` inventories covering
14,914 files, and independently replays both publication exports, 84 public
files each. It preserves the existing CI-selected output plus that exact
publication closure. Preflight found that the pinned workflow omitted
`c-publication-public/**`; retaining those verified public bytes here does not
change the original runtime receipt. A separate upload-path regression and
repair addresses that CI evidence omission.

`CAPTURE.zip` contains 35,728 members, including 35,713 original qualification
output files, original driver/command records, the producer report and the pinned
workflow. All members were reread byte-for-byte. Its 95,381,922 bytes have SHA-256
`571e704512bd0a7f2f2eaeccebbe6eeace49d37fea5795503b4c886cdb54da2d`.
`FILES.json` pins each member; `READBACK.json` records the public replay and input
identities. Private installation directories, credentials and stores are excluded;
the original outside-checkout native binaries remain available for the subsequent
binding qualifiers.

This closes local Rust/C qualification for this named maintenance cohort.
Apple/Swift, Kotlin, Android, GNU/Linux, other platform/device evidence, final
hosted CI and formal product admission retain their separate scopes. No
cross-host, physical power-loss, independent Witness-engine, external-review or
release claim follows from this gate. No remote workflow or branch was changed.
