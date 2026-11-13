# Cleanup-report MAC interface and native readback

The [conditional report argument](../../../../docs/continuity/CLEANUP_REPORT_MAC_V1.md)
isolates one fresh hidden report key and one immutable transcript, preserving
exact repeated tags and the zero-ID error. It uses the existing compression-QROM
HMAC reduction; it does not prove the complete native acquisition/validation
interface, multi-report composition or the multi-epoch theorem. The report hop
must occur while the simulator still knows the original reservation coins.
No product or Rust test source changed.

Source `c32362567e748787a64ab767769e811f62cb87d5` passed three existing cases
in each profile with Rust 1.98.1, locked offline dependencies and warnings denied.

| Profile | Case | Test result | Test runtime |
| --- | --- | --- | ---: |
| Debug | Session report, retained accounting and private-state tamper | 1 passed | 1.82s |
| Debug | Three pending rekey/cutover closure schedules | 1 passed | 3.12s |
| Debug | Fanout abandonment process cuts and tamper | 1 passed | 5.32s |
| Release | Session report, retained accounting and private-state tamper | 1 passed | 1.44s |
| Release | Three pending rekey/cutover closure schedules | 1 passed | 2.66s |
| Release | Fanout abandonment process cuts and tamper | 1 passed | 4.57s |

Each invocation filters 1,458 other library cases. The parent completed in
33.377 seconds with its 1,800-second limit, unchanged 900-second component
limits and 16-MiB stream ceilings. The isolated build directory is separate
from the concurrently running installed Android/JNI qualification foundation.
Selected source inputs and compiler identities match before and after execution.

Each profile terminates five owned children: one session reservation cut, and
one reservation/computation cut plus one abandonment cut in each of the two
fanout schedules. The latter cuts occur after the whole batch is frozen or
after terminal state is committed. Competing writers are checked for Busy.
Ten process terminations are not ten physical power-loss tests. Private fixture
stores are not exported. Source and result streams support these finite cases;
they do not establish generic malformed-state behavior or cryptographic security.

The source reader binds 18 files, checks the report/key-tail exclusion, first
key-draw and persistence/release order, exact retry branches and zero-ID error.
These are literal anchors for manual review, not a control-flow proof checker.
The zero-MAC event was not forced or observed in execution. The mathematical
ideal keeps this error branch; it does not resample until a nonzero tag appears.

The first capsule-builder attempt named a nonexistent `messages/validation.rs`.
`validate_image` actually resides in `messages.rs` and `fanout/codec.rs`, already
in the selected inventory. The original builder and a clearly labeled tool-return
observation are retained. Only that source-list entry was corrected; the six
successful tests were not rerun and their assertions were not changed.

`CAPTURE.zip` retains the original/corrected capsule builders, runtime driver and
launcher, exact command receipts/streams, source inventory, test binary hashes
and proof notes. All 58 members were reread byte-for-byte: 304,935 bytes,
SHA-256 `d1686f6867626e07f466e1824332fb4fd8aa51e40831472c38c36039a8673896`.
`FILES.json` binds each captured member; `SOURCE_AUDIT.json` records the limits.
No new Tamarin execution, hosted workflow, remote push or release occurred.
