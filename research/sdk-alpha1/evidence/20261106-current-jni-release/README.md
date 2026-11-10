# Current installed Release host-JNI qualification

The original Release Rust/C/host-JNI partition completes at source
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. Its controller exits zero at
2026-11-06 01:23:37 UTC with empty stderr. Independent checks bind the final
source/package/native/JAR identities and reproduce twenty public outcome groups.
This is the Release partition; the separate Debug run and full foreign-profile
join are not asserted complete.

The final report has `partition_completed=true`, `completed=false` and
`build_profiles=["release"]`, as required by the original one-profile contract.
It requests Rust, C and `AndroidJNI`, uses macOS arm64, and makes no publication
or release-eligibility claim. The retained earlier `ff072` aggregate timeout
remains a failed observation on its original lineage.

## Verified execution and identities

- All 1,401 package input files match both final source snapshots; all 146
  Android adapter source files match their recorded hashes.
- The SDK report is
  `1e40fc2ae0c7c113509ae2a5c5a858cbd73a8a6fd7f63e66203316c4c61e228d`;
  the 769-member candidate archive is
  `0730aa20794527b3947dc4734bf82d48516294c42018dc8dfd23ebc5f42fc2a6`.
  Both installed consumer graphs, their candidate trees and their nine SDK trees
  are independently checked against the actual archives.
- The original 70-test harness catalog is exact. Its 67 JNI-specific tests pass
  in exactly 36 invocations, without duplicates; the three shared Rust fixture
  entries remain outside this JNI census. The separate actual `BridgeProbe`
  process passes with `-Xcheck:jni` and empty stderr.
- All seven native binary byte sequences are verified and retained: C library,
  JNI bridge, C receiver, policy-target client, Android test helper and two
  recovery helpers. These total 37,786,536 bytes before compression. The JAR has
  131 Java 11 classes and SHA-256
  `4d4c77e63975a693155e3693e6c76349e8df54c930af3a807b31529800126d0a`.
  The 51 actual test class files and selected JDK identity are also checked.

The twenty reread groups include first registration, exact message retry, rekey,
reverse callbacks, cancellation, account delivery/recovery, retirement, five
account-root routes, roster changes, policy/credential renewal, pending-write
recovery, required-Witness outcomes and successive joint-policy cycles. Original
readers enforce their specific process counts, effects, identities and refusal
semantics. This does not make Witness logic an independent implementation, turn
process interruption into power loss, or extend individual scenarios' authority
and expiry conditions.

## Retained and independently replayed evidence

[CAPTURE.zip](CAPTURE.zip) has 16,107 members, 63,245,373 bytes and SHA-256
`925e2b530291cb1eddb89b32fb7f466d1896a6a3796b2b904cd09644e47bfae2`.
It contains the actual binaries/classes and ten consumed archives, final reports,
original public exports and commands, source/readers, and failed diagnostic
attempts. Private runtime stores and generated private keys are excluded.
[FILES.json](FILES.json) pins every member; all were reread after capture.

[IDENTITY.json](IDENTITY.json) records package/native verification.
[PUBLIC_READBACK.json](PUBLIC_READBACK.json) records twenty original-reader
results, 4,376 reconstructed public files and 69 Git-matched reader modules.
Its receipt-only labels describe that public reader's scope; the companion
identity check separately verifies and retains all seven native binaries.

[ARCHIVE_REPLAY.json](ARCHIVE_REPLAY.json) reproduces those twenty results from
15,543 materialized public/report/command members. A second
[standalone replay](STANDALONE_REPLAY.json) uses only the capsule's captured reader
source and public files through the captured isolated Python wrapper. Both match
the original public readback, require no private runtime state and execute no
native workload. [ARCHIVE_CHECKS.json](ARCHIVE_CHECKS.json) summarizes these checks;
the [archive mapper](archive_replay.py) and both replay streams are retained.

The original identity diagnostic used `Android` instead of the producer's exact
`AndroidJNI` enum. A later capture selector used an underscore instead of the
original `root-bound-transition` directory's hyphen and stopped before writing
the archive. Both failures and their corrected drivers are retained. No product
source, original validator, native test, timeout or result is changed.

This establishes current-source Release host JNI. The matching Android AAR/APK
build has its own evidence; ART/device execution remains separate. The complete
Debug/Release join, applicable final CI/platform qualification, resource budgets,
protocol proof, contract/ABI admission, external review and release remain open.
