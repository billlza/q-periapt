# Stage3 and Stage4 projection admission

The explicit installer admitted the Stage3+Stage4 candidate from a private copy of the authenticated official CodeQL pack. Its complete 1,357-file result equals the frozen compiled candidate. All 1,175 effective dependencies, 39 selected root query sources and 15 referenced stages were admitted; the other 38 compiled queries were retained. A private copy of the old Stage4 candidate was rejected under the new identity and remained byte-for-byte unchanged.

## Existing validation records

| Check | Recorded result |
| --- | --- |
| Source commit | `278d0312985dc0fa7e186397940baf233a1af7d0` |
| Source tree | `a32262b3a0c889b5eab181f038ede14ed0da19d3` |
| Fixed compiler input key | `6a7530eb694360655ab8331a895c9fcd` |
| Fixed capsule SHA-256 | `5b17fb41cd3c59fea564ec4e9cb49ef586c0ad06ccc3f2445e46b7b5ca8430cb` |
| Focused Python modules | Control, plan, projection and process-resource tests |
| Focused test outcome | 159 tests passed in 8.831 seconds; command exit 0 |
| Real-pack admission | `install`, `validate` and `expected_identity` agreed; 3.395469 seconds |
| Whole installed inventory | 1,357 files; SHA-256 `13705d5f8b164bd69a12219c41a7fe8ba7e304247a4b78d0150c4dd36882d441` |
| Old Stage4 negative control | Rejected on the effective dependency source identity; all bytes preserved |

The 159-test suite ran once. Its original command, timestamps and log digest are in `FOCUSED_TESTS.json`; the full output is `focused-tests.log`. The 8.831-second value is the unittest footer, distinct from the wrapper's start-to-finish interval. The admission script used Python file and installation checks only: it started no CodeQL CLI, JVM, query or compilation.

`REAL_PACK_ADMISSION.json` preserves the original and installed inventory identities, exact changed/added file sets, runtime-asset pins, negative-control rejection and unchanged shared input identities. Its original SHA-256 is `9efc1482fff74422f8c46b1f568e389540f9e83cf35e487545cbdfe6e5f1c901`. The original source pack has 1,342 files; admission changes the declared vendor source and full SummaryStats QLX and adds the 15 closed stage files.

## Replay and evidence scope

`methods.zip` contains the original `verify_real_pack.py` bytes. `SOURCE_IDENTITY.json` records its member identity and the fixed repository code, tests and assets. Restore those assets from the source commit and the separately authenticated official bundle in an isolated workspace before invoking the archived method. The accepted and old private packs, experimental database, official bundle and duplicate installation files are not copied into this packet; the original receipt binds their identities.

This packet establishes installer behavior and focused Python compatibility. The nonempty fixture and compiled-plan structure are recorded in the adjacent `20261111-summary-stage34-projection` packet. The retained-project full-query run is a separate experiment whose execution result is recorded independently. This packaging step ran no new tests or experiments.
