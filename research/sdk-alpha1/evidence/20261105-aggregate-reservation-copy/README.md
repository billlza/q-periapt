# An unchanged reservation in a later aggregate image

The actual native test now establishes two complete sessions in the same pair
of journals, using admitted reusable prekeys. After target epoch one completes,
the responder prepares the target's epoch-two offer and retains its generation
token in phase three. A send on the sibling session then commits a new aggregate
image through the normal SDK journal path.

The test observes an increased image revision, changed image digest and changed
outer nonce, while the target record remains byte-for-byte identical and the
sibling record changes. After close/reopen, the stored image and target offer
retry are exact. Only the target fields from this **later** snapshot, its wrapping
key, authenticated public policy and subsequent public wires enter the existing
predictor. The earlier images are used only for test equality assertions. The
predictor does not receive sibling private state, an identity signing owner or
later target state. A wrong wrapping key is rejected.

The honest peers then complete target epoch two. After another reopen, the
predictor decrypts six newly generated 128-byte application payloads, three in
each direction, while the honest endpoints accept the same messages. This
demonstrates retention of the original reservation's exposure despite the new
aggregate nonce. It is not a counterexample to MAIN's post-Cut reservation and
snapshot premises, a complete whole-journal refinement, or a cryptographic
security proof. No process kill, physical power-loss or hosted run is claimed
for this test.

The source base is `783739e4f1a9409ee50de71739d98411e5954cee`, plus exactly the
captured parent test-module declaration and new `aggregate_copy.rs`. Product
protocol code is unchanged. The new test is separate from the earlier
first-reservation process/pending-target and delayed-receipt experiments.

The bounded launcher ran from 2026-11-05 04:43:16.210977 UTC to
04:47:14.168294 UTC, finishing in 237.955 seconds with exit code zero. The
existing 5,400-second parent and 900-second component limits were unchanged;
each output stream remains capped at 16 MiB. The compiler is the existing
task-private Rust 1.98.1 toolchain, with offline resolution and two build jobs.
An APFS copy of the completed alias-test build cache was made; the Kotlin/native
qualification foundation was not used for this test build.

| Executed check | Result |
| --- | --- |
| Exact new test, all features, Debug | 1 passed, 0 failed/ignored; test runtime 4.00 s |
| Exact new test, all features, Release | 1 passed, 0 failed/ignored; test runtime 2.07 s |
| All-feature/all-target Clippy with warnings denied | Passed |
| Changed Rust files, rustfmt check | Passed |
| Runtime source/compiler input identity before and after | Unchanged |

Each focused run filters 1,458 other library tests; this is not a complete-suite
rerun. Comparison against the earlier full-native-release inventory checks all
1,155 recorded inputs: the changed previously recorded inputs are the CI workflow
and two test-module files; the additional candidate Rust files are the prior
alias test and this new test. No recorded production native source changed.
The broader package manifest contains additional selection categories; those
are not presented as newly created source files. Earlier full-suite counts
remain attached to their earlier source, and the new current aggregate is not
claimed to have run in full.

`CAPTURE.zip` retains both complete command streams, exact argv/environment
receipts, driver/launcher, original and final test sources, source identities,
the relevant unchanged implementation/model inputs and updated recovery notes.
`FILES.json` and `SHA256.json` record member/volume identity and full readback.
No private journal, key, token, application plaintext or binary build cache is
published in this capsule. The implementation/proof consequence is documented
in [recovery dependencies](../../../../docs/continuity/RECOVERY_DEPENDENCIES_V1.md#aggregate-image-lineage).
