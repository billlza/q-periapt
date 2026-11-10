# Installed consumer profile partitions

The prior Kotlin and Android JNI jobs both exhausted their 330-minute execution
budget while still advancing through the release profile. Their retained native
C receipts are complete; neither has a final foreign-consumer receipt. The
[observation](OBSERVATION.json) binds the downloaded artifacts and last commands
to the original jobs. Kotlin's 15 nonzero commands are named negative probes;
their presence alone is not evidence of an unexpected consumer failure.

The old serial arrangement ran both Rust profiles, both C profiles, and then both
foreign profiles inside one job. Native C commands occupied about 111 minutes in
Kotlin and 107 minutes in Android. The Kotlin debug command interval spans about
120 minutes, and Android debug about 144 minutes. These are artifact timestamps,
not controlled performance measurements or a guarantee about the next run.

CI now partitions Swift, Kotlin and Android JNI by `debug` and `release`. Each
partition builds and executes its own full Rust/C/foreign profile. Native binaries
are never reused from another runner. The default local command still runs both
profiles. The optional `--build-profile` selects one explicit partition and requires
C plus exactly one foreign consumer; Swift also requires its Apple package.

Every existing scenario inside all five profile loops remains unchanged. The
330-minute job limit, 900-second command limit, real policy/credential expiry,
Kotlin Serial/G1 collectors, Swift minimum-compiler execution and original outcome
checks remain in place. This changes scheduling, not the SDK deadlines or protocol.

One partition writes `kind=qperiapt.continuity_candidate_package_partition`,
`partition_completed=true` only after completion, and `completed=false`. Each
nested C/foreign consumer likewise keeps `completed=false` and explicitly records
its selected `build_profiles` and `partition_completed` status. The separate
coverage job requires exactly six receipts, both profiles per consumer, matching
source inputs/commit, SDK report and compiler, and completed matching native and
foreign results. It rejects missing, duplicate, interrupted, mislabeled and
mixed-source inputs. The join retains report digests rather than flattening the
underlying public scenario evidence into a new full-package claim.

Review of work outside the profile loops found Kotlin's Maven-publication owner
test hard-coded to the debug native library. A release-only native result makes
that old selector fail with `KeyError: debug`. The selector now verifies and uses
the first explicitly requested profile (debug for the default full invocation).
Its selected profile is recorded and checked by the join. A release-only
regression also checks wrong-profile admission and changed library bytes. This
selection test is not a replacement for the actual Maven/JVM execution in CI.

Local validation includes rejection tests for that join, the existing installed
consumer verifiers and the workflow contract. A static comparison also confirms
that the complete profile-loop bodies equal those at `7e6a2345`. This is not a
new full hosted runtime result: all six current-source jobs must still finish,
and the coverage job must accept their actual receipts.

The initial broad contract attempt was incorrectly run in the managed worktree;
the provenance guard rejected its `.git` file. It also detected a missing version
annotation on the new checkout step. The workflow annotation is corrected, and
the contract checks use a standalone committed checkout. The local actionlint
version reports the same two pre-existing unknown `ubuntu-26.04` runner labels on
the old and new workflow. No rule or assertion is disabled to hide them.

This checkpoint does not replace accepted Android/iPhone/iPad functional cohorts,
qualify mobile resource costs, freeze the protocol, or close the remaining 0.2.0
release requirements.
