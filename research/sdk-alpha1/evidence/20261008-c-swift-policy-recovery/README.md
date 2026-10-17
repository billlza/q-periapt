# C and Swift policy-authority recovery, 2026-10-08

Implementation `1f6e9edf6fe98a5ff4c572e69c346c7e088e17e5` adds seven
policy-recovery C functions and corresponding Swift owners. Commit
`046c0e4ccdea88b3bea619c41d771d9faf2c38c5` additionally requires the fifth
installed Swift consumer test. ABI major 2 and extension revision 1 remain;
the previous 43 declarations, structures and constants are retained. The
current unpublished table contains exactly 50 exports.

`QUALIFICATION.json` inventories the retained commands, source hashes, logs,
public fixture identity and native archive identity. Some native/source Swift
runs preceded the implementation commit and bind their actual dirty source
bytes. The clean package and artifact checks bind the commits stated in their
receipts. These are component observations, not complete 0.2.0 qualification.

The public flow provisions independent recovery trust, prepares one exact
request, checks recovery-approval and incoming-possession roles, replaces the
online root at policy `u32::MAX`, and reopens the original operation after a
later policy update. Only a newly applied transition transfers ownership.
Repeated operations preserve current keys and never restore an older policy.
Cancellation after an admitted commit closes a discarded new owner; cancellation
after an advanced replay preserves the caller's current owner. Native tests
also cover full handle capacity, invalid/aliased inputs, v1 refusal, actual
post-commit publication error and unwind.

The first real Swift Debug run failed with SIGBUS in a stack guard beside a
544 KiB worker stack. OS diagnostic symbols and static disassembly of the owned
library identified large by-value recovery images. No debugger or process-memory
inspection was used. Boxing the private owned image reduced the FFI constructor
frame from 123,936 to 12,592 bytes, and store provisioning from 56,576 to 25,648
bytes for the observed ARM64 Debug binary. The signatures, durable encoding,
commit order and cleanup contract did not change. The same Swift worker path
then passed. A child-process regression now performs the C recovery lifecycle
on a fixed 512 KiB native thread, passing on Rust 1.98.1 and 1.90.0. This is not a
universal maximum stack-use guarantee across all compilers and architectures.

Observed checks:

- 48 FFI tests on each of Rust 1.98.1 and the 1.90.0 minimum compiler; 42 host-store
  tests; SDK/host-store/FFI all-target strict Clippy and workspace formatting.
- Swift source Debug and Release: 12 SDK, two compatibility and four probe tests
  each. Diagnostic mirrors change only two library search paths and preserve
  all source/fixture bytes; they are separate from installed-package evidence.
- 189 artifact/ABI/package tests on clean `1f6e9edf`; 11 Apple profile tests and
  the current source gate on `046c0e4c` (254 current / 249 historical proof inputs).
- Actual C legacy, owned and recovery callers with Debug and Release dylibs.
- Clean C package creation, exact 50-export checks, outside-checkout pkg-config
  shared/static consumers, four CMake tests and frozen nine-function-header use.
- An additional C recovery consumer using each library extracted from that
  archive, with no ambient dynamic-library override. Its source is retained in
  `drivers/recovery_consumer.c`; role-swapped signatures fail before mutation.
- Independent SwiftPM consumer directories use the exact installed C static
  archive, source-identical public wrappers and a host-only diagnostic
  XCFramework. Five tests pass in each of Debug and Release; selected archive
  hashes match. This is **not the complete multi-slice Apple release package**.
- The generator reproduces all 19 public fixture fields byte-for-byte.

The C archive SHA-256 is
`127078c0244ce819ff9d781f9526cf02eadd52d1f8af39b0f0d85359cc0dc93a`.
It binds `1f6e9edf`; the next commit changes only the Swift test-count gates.
The installed static archive is
`d95474c8aee38acbc7c8fa9ac2a41bfa320f8f0b6a86051f50b69aded94b7f27`.

Apple Silicon macOS is the execution scope. Intel macOS remains excluded.
Linux/Windows execution, the complete iOS/simulator package, physical devices,
v1 migration, recovery-key rotation and Continuity account-root replacement
remain separate work. This does not prove post-compromise message secrecy or
constitute an independent security audit. Hosted CI still evaluates `1ca9ba6b`;
the new source has not been uploaded while its Rust CodeQL Analyze is live.
