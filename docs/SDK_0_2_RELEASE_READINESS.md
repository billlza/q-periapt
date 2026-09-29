# Q-Periapt 0.2.0 release-readiness ledger

Goal: finish the complete 0.2.0 product requirements, including the expanded
Continuity scope and quality and maintainability review before delivery.
No release-readiness claim is made until every applicable requirement has
current-source evidence. The user's latest direction is **retain ABI major 2**.

The current release quality gates are internal review of cryptographic
boundaries, ownership/error paths, code quality and maintainability, together
with source-bound tests, platform execution and the release transaction.
The user manages any independent external security review separately; it is not
an automated delivery task. Internal verification must still retain its exact
source, tested behavior and limitations, without claiming an external audit.
The current requirements table governs this release. Checkpoints below retain
source identities and observed outcomes; their release-gate references follow
the current requirements. The
[internal implementation review](SDK_INTERNAL_REVIEW.md) records inspected
contracts, validation and remaining code-review boundaries.

The 2026-09-28 scope update also requires persistent Continuity sessions,
fresh-PQ rekeying, disconnect recovery, revocation, continuous PQ recovery and
multi-device lifecycle in **0.2.0**. The
[expanded scope and completion evidence](continuity/RELEASE_0_2_SCOPE.md)
govern these additional requirements. Existing KEM/TLS checks do not close them.

The original nine entry points keep their signatures, layouts, existing status
codes and library identity. Package-version metadata reflects the new package;
new status codes receive their new names. Owner functions are additive ABI 2 extensions, with an
explicit version-specific export allowlist. The historical 0.1.5 nine-symbol
contract is retained; 0.2.0 must not claim its expanded table is still nine.
New bindings require the 0.2.0 SDK surface; old clients remain ABI-compatible.

The working release candidate now uses package version **0.2.0**, producer
profile **`sdk-020`** and native CBOM profile **`native-sdk-020`**. This transition
coordinates Cargo workspace/dependency versions, Maven/npm metadata, package
filenames, installed consumers, CI intake paths and the C contract snapshot.
ABI major 2, extension revision 1, all 43 C declarations and all 26 JNI
registrations are unchanged. The 0.1.5 contracts and historical results retain
their original bytes. Earlier alpha.1 observations below remain tied to their
recorded commits; the 0.2.0 candidate requires fresh source and package checks.

The last committed alpha.1 source, `f8a7c6d`, passes 2,280 local artifact tests
in 457.660 seconds without skips, with warnings treated as errors and passing
pre/post source gates. The 387 affected Android tests also pass. Its
[hosted CI](https://github.com/billlza/q-periapt/actions/runs/36361978517) and
[CodeQL](https://github.com/billlza/q-periapt/actions/runs/36361978526) remain
separate from the new version transition. The retained checkpoint includes the
old query failure, the corrected child-process cases, integrated fixture
failures and repairs, and the earlier primary/repeat runtime outcomes.

In that alpha.1 hosted run, the guest exit records work on API 23: an unavailable
Package Manager returns guest status 1 while host ADB reports zero, and the
observer requires subsequent complete successful replies before accepting
absence. Its full SDK Instrumentation workload passes all three groups. The
minimal run fails earlier in Android's `am` command VM: retained ART logs show
boot-image relocation failure, `com.android.commands.am.Am` class loading
failure and SIGABRT. API 35's full/minimal workloads also return their passing
results, but the minimal run loses its device transport during cleanup. These
are retained runtime failures; the version transition does not close them.

| Requirement | Required completion evidence | Current state |
| --- | --- | --- |
| Controlled hybrid owners in Rust/C/Swift/Kotlin/Android/WASM | Real calls with owned PQ/traditional keys, paired public keys, no default private getters, close/concurrency/cancellation tests | Implemented across all six surfaces; extracted Swift/macOS, C, Rust, product WASM and JVM packages have real external consumers. Hosted 2493ffe completes both Android full/minimal ART, cleanup and export gates on API 35 / 16 KiB / x86_64. Physical Android evidence remains open; JVM Java-source owner construction is closed |
| Rust compiler floor | Actual minimum-compiler build and public API execution from the same pinned packages; explicit development-toolchain scope | The current dependency contract selects Rust 1.90 and producer 1.98.1; see [dependency maintenance](SDK_DEPENDENCY_POLICY.md). Local candidate all-target compilation passes on 1.90. The older 1.85 package receipts remain historical evidence and cannot qualify the refreshed source. Current installed-package and target floors retain their own source-bound gates |
| Immutable verified runtime | Actual signature/root/state validation; no raw decision constructor; policy epoch/revocation rules and persistence boundary | Prepare/persist/activate, one-winner revocation, disabled-policy recovery and later re-enabling implemented across all six surfaces; shared Rust/C/Swift persistent runtime and both installed macOS peers have real-file/process recovery evidence; native Linux reference qualification remains open |
| Explicit expert access and named-purpose derivation | Separate APIs, specified formats/KDF/domain binding, rejection and interoperability evidence | Owned HKDF-SHA-256 purpose derivation and explicit expanded-key transfer implemented across all six surfaces; native integrity/PCT checks and foreign roundtrips pass locally; focused internal review remains required |
| Resource failures and budgets | Bounded inputs, in-flight workspace/live-object budgets, cleanup on entropy/allocation failure, no success-shaped error path | Per-runtime quotas plus native 1024-owner/64-call aggregate limits implemented; close and prepared activation exempt; full-budget activation and JNI failure/copy disposal exercised; process OOM recovery is not claimed |
| ContextBound efficiency without protocol change | KAT/differential/implicit rejection/import checks plus exact-byte transcript equivalence; state and scratch erasure review | Current local workspace/WASM conformance passes; binary CT, formal and device gates remain separate |
| x86_64 native candidate | Pinned source, CPU/OS capability contract, native Linux execution, differential and CT evidence; separate MSVC disposition | Opt-in GNU Linux candidate implemented with CPU/OS checks and portable dispatch. Hosted 830e381 differential tests and the binary CT gate pass for 512/768/1024. Controlled performance, broader CT coverage and separate non-GNU disposition remain required; this finite gate is not a general constant-time proof |
| Real SDK performance | Source/binary-bound paired primitive, Rust, C/foreign binding measurements; tail latency, allocation, concurrency, long-run/energy limits recorded | Rust/C/Swift comparisons, connection timing and allocation observations are retained. The installed Swift package and release archive-derived Rust peer add five timing blocks with 1,005 connections and 3,015 checked echoes. A native C run covers eight-thread work for 600 seconds, close races and 21 capacity-recovery probes. Controlled tail, foreign-wrapper/native-C allocator, peak memory, broader concurrency, longer runs and energy gates remain open |
| Standard TLS interoperability | RFC-compliant standard group, actual independent peer, auth/policy parity and no silent classic fallback | Separate opt-in TLS 1.3 + X25519MLKEM768 mutual-certificate path implemented. The archive-built Rust peer and hosted Linux 830e381 run pass eight independent OpenSSL client/server cases. Installed Swift/Rust macOS peers pass policy confirmation and failure scenarios; the actual macOS-to-Linux reference remains open |
| Full reference connection | Actual Swift/macOS client and Rust/Linux server packages; first connect/reconnect, auth, policy confirmation, failure/cancel/concurrency | Installed Swift/macOS and archive-derived Rust peers pass twelve local process/socket cases with persistence. Hosted macOS package/connection qualification passes at named checkpoints, including 51982a6. These same-host runs do not qualify the requested Swift/macOS-to-Rust/Linux connection; that boundary remains open |
| Coherent install and distribution | One current version/ABI/package revision matrix; actual installed consumers and current-source devices for supported targets | Version/ABI/package profiles and independent installed consumers are implemented. Named cohorts cover Rust, macOS C/JVM, Apple architecture links, WASM Node/Chrome/Firefox, native Linux C and Windows C packages. Both Windows runner package jobs pass at 830e381, including extracted direct/CMake consumers and archive-only reconsumption. Both Android full/minimal ART, retirement and export gates pass at 2493ffe. Each receipt keeps its source scope; public registries, signing and current/minimum-device coverage remain open |
| Security review and proofs | Updated threat/assurance boundaries, KAT/differential/CT/formal gates appropriate to changed source; internal security review | Local and hosted conformance, differential, binary CT and formal outputs are retained per cohort with their finite/model scopes. Internal boundary review remains required |
| Quality and maintainability | Dependency direction, explicit errors/ownership, no duplicate primitive paths, API documentation; required build/lint/tests and internal critical-path review | The clean 2493ffe snapshot passes 2,250 artifact tests in 482.705 seconds without skips and its post-test source gate. Hosted 830e381 passes 2,246 artifact tests with three macOS-only ACL skips, the source gate, workspace checks and installed C consumers. The later package-query diagnostic passes 171 command tests locally. The full workflow retains the pre-existing runner-catalogue lint diagnostic. The tracked Rust inventory is now 198 files, including isolated candidates; final exact-source CI/CodeQL and internal review remain required |
| Release transaction | Coordinated crate versions, frozen schemas/export lists, exact-source CI, signed packages where required, install/device evidence and maintenance policy | The twelve-crate 0.2.0 coordinator validates the clean producer, exact archives and closed dependency order, then uses the shared lock, durable journal and API+sparse reconciliation. Hosted `57334d4` produces the real cohort and passes the source-bound dry-run. Final platform, signing and publication requirements remain open; readiness alone does not authorize publication |

## Latest qualification checkpoints

The isolated [account-send candidate](../research/continuity-identity-candidate/FANOUT.md)
now binds every required device in the installed signed roster. It reserves all
pairwise input slots together, then commits all chain/outbox advances before
releasing any member. A real unary-loop counterexample discloses the first
recipient's plaintext before the second recipient exhausts its budget; the batch
API rejects that case before any reservation. v18 journal metadata and reverse
member links prevent unary release of a reserved prefix. The global batch counter
does not reset on retirement. Existing pairwise control and data wire bytes remain
unchanged; acknowledgement, unresolved delivery and retired history are explicit
per-member outcomes.

Eleven focused tests now cover peer and own-account rosters, mixed bootstrap roles,
scope/capacity/expiry/revocation, partial ACK plus durable closed-epoch accounting,
18 measured before/after sync faults, three process kills with deadline-bounded
competing writers and all 18 before/after losses across nine actual witness calls.
Both recipient journals decrypt real messages. The final complete runs pass
**186 tests each**, zero failures/ignored: debug 518.46 seconds and release
443.62 seconds. The overlapping runs are not a controlled performance comparison.
The preceding 184-test runs remain separate. Strict Clippy on Rust 1.90/1.98.1,
no-default-feature compilation, formatting, warning-strict docs and 45 standalone
source/inventory checks pass. Current public-only oracles verify 20 envelopes/100
signature negatives and 12 witness envelopes/60 negatives. This is
one sender's journal transaction, not atomic remote application execution or
coordination across independent sender stores. Full lifecycle, installed language
and cross-host/device qualification remain required.

At `5f324607`, the Continuity v6 candidate added an optional native
[standard TLS control carrier](../research/continuity-identity-candidate/CONTROL_TLS.md).
It reuses the SDK connection engine and exact journal outboxes, with explicit
finite retries, a fixed invocation deadline, fallible trusted time and cancellation.
Two native processes complete three alternating rekeys from either initiating
role. Five process kills after journal commit but before network reply recover
the original committed bytes. Live ClientHello cancellation closes the socket and
releases endpoint capacity; timeout, protocol expiry, wrong certificate pin,
clock failure, empty acknowledgement and old-target receipt tests also pass.
The old-target case first reproduced an incorrect successful epoch-1 return for
an epoch-2 request; checking the exact target at the transport boundary repairs
that classification without changing legitimate journal replay.

Both complete local all-feature runs pass **175 tests**, with no failures or
ignored tests: debug 466.19 seconds, release 368.31 seconds. They overlapped and
are not a controlled performance comparison. Strict all-target/all-feature Clippy
passes on Rust 1.90 and 1.98.1. Earlier Linux candidate jobs reached the unchanged
25-minute deadline in debug tests; debug dependencies are now optimized with
debug assertions and overflow checks retained, while the state-machine crate
stays unoptimized. A Rust 1.90 dependency probe records optimized compiler flags
and an actual caught overflow. Its later hosted run passes all **42 CI jobs**
and **six CodeQL analyses**. Both Linux compiler jobs and macOS pass all 175
debug and release tests. The tested merge `59f736480deb8af8c882861c9e593e9da14aacea`
has the same tree as `5f324607`. This closes the earlier Linux timeout for that
source; it does not qualify the later fanout changes.
The candidate's 55 added lock identities already occur in the root SDK lock;
no existing candidate version/checksum changed. This native optional feature
does not change v6 controls, v17 journals or any published binding.
These checks begin with admitted journals on one host; installed cross-language
connections, bootstrap transport, cross-host/device execution, multi-session
scheduling, periodic policy and matched performance remain open.

The preceding `a08a41c7` Continuity v6 candidate has a durable, identity-signed request
for an idle designated proposer and a control driver for one explicit target.
The driver reuses the existing flight transactions; repeated calls cannot silently
start another target after completion. Its bounded test schedules complete three
epochs in either one-way application direction while losing/duplicating each
control flight and cancelling dispatch before owner reopen. The final source
passes **166 release tests in 248.18 seconds**, including 42 measured request/offer
sync faults, three request process kills with deadline-bounded competing writers,
and lost required-witness release replies. Strict all-target Clippy passes on both
Rust 1.98.1 and Rust 1.90; formatting, warning-strict documentation and 45 standalone
source-contract checks pass. Current independent oracles verify 20 envelopes/100
signature negatives plus 12 witness envelopes/60 negatives. The
[control-progress contract](../research/continuity-identity-candidate/CONTROL_PROGRESS.md)
records v6, journal v17 and the remaining product transport/retry-policy boundary.
These in-process schedules and process/storage cuts do not qualify the installed
cross-language or independent network endpoint requirements.

The preceding Continuity v5 checkpoint enforces a policy-authority-signed,
nonzero application-send budget. Old and newly installed sending epochs share
the window until local receipt completion; already committed new-epoch messages
remain spent afterward. Exact pending work and outbox replay remain available,
while ACKs, reopen and closed-epoch resolution cannot refund slots. Authenticated
over-limit data and signed close counts are rejected before state mutation.
The [send-progress contract](continuity/SEND_PROGRESS_V1.md) records the rule,
versioned policy body and remaining independent control-scheduling requirement.
The final local run passes **161 release tests in 236.98 seconds**, including
34 measured last-slot sync faults, two budget-reservation process kills and lost
required-witness replies. Strict Clippy, formatting, Rust 1.90 all-target checking,
45 standalone source-contract tests and both independent public-byte/OpenSSL
oracles pass. The initial full run retains a stage-marker publication race
(160 pass, one failure); atomic publication of the complete test marker repairs
that cause. These are candidate checks, not installed product qualification.

The actual Continuity reservation-disclosure experiment now covers the two first
durable rekey reservations. After killing the process before KEM computation, a
predictor given that checkpoint's prior root, wrapping key and sealed token
reconstructs the later contribution and decrypts six confirmed epoch-one messages
in both directions per case. No later private input is passed to the predictor.
This finite counterexample enforces the distinction between reservation freshness
and later execution; it does not label a later epoch secure or establish a full
recovery proof. See [the experiment and its input boundary](../research/continuity-identity-candidate/RESERVATION_DISCLOSURE.md).
The integrated local run passes 153 release tests, strict Clippy and formatting,
Rust 1.90 all-target compilation and 45 standalone source-contract checks.

The preceding Continuity v4 checkpoint adds explicit closed-epoch outcome reports.
The application must durably account for the immutable report before its old
keys and retained data are removed. Unconfirmed sends remain `DeliveryUnknown`;
the old acknowledgement floor is never advanced to manufacture delivery success.
The reproduced old-chain poisoning trace progresses through epoch 6 after that
explicit accounting. Private per-report HMAC keys also repair a reproduced
plaintext-guess verifier in the unkeyed draft report ID. The fixed Rust 1.98.1
run passes 151 release tests, including all 16 measured resolution sync faults
and two new process kills. Format/strict Clippy, Rust 1.90 all-target compilation,
45 isolated source-contract checks and both independent OpenSSL oracles pass.
The [resolution contract](../research/continuity-identity-candidate/EPOCH_RESOLUTION.md)
records the tested behavior and limits. Continuous recovery analysis,
authenticated progress scheduling, full device lifecycle and installed
cross-language product integration remain open.

The earlier `4a78609` Continuity checkpoint implements four signed rekey flights,
epoch-scoped traffic and ACK authority, and v3 drained-prefix retirement. Eight
alternating exchanges with message traffic and restart pass while history stays
bounded to four epochs. Both Rust 1.94 and fixed Rust 1.98.1 pass 145 release
tests; fixed-toolchain format/strict Clippy, Rust 1.90 all-target compilation and
45 isolated source-contract tests also pass. The measured initial/retirement
cutover grids cover 94 before/after sync faults and 14 real process kills.
The [protocol record](../research/continuity-identity-candidate/REKEY_OFFERS.md)
retains the exact contract and limits. This remains an unpublished research
workspace. Its hosted CodeQL run completes all six analyses; its primary CI run
passes 41 jobs and cancels the Linux Rust 1.90 candidate job. A separate same-head
run fails the JVM installer at `PATH java must match JAVA_HOME`, while the primary
run passes that job. The subsequent [toolchain path investigation](SDK_DEPENDENCY_POLICY.md#jvm-executable-selection-after-gradle-provisioning)
reproduces the pinned Gradle action's shared-directory prepend on the new runner
image. Both JVM workflows restore the chosen JDK afterward and retain strict
identity checks; 51 local wiring/package-admission checks pass. At `b4ee99f5`,
both hosted Kotlin package jobs now pass installed Kotlin, Java module-path and
six native-loading negative controls. Both used Ubuntu image `20260920.303.1`
and downloaded Gradle; the newer image's reuse branch is locally reproduced but
does not yet have a post-fix hosted runtime result. The original failure remains
retained, and the other current-head CI jobs keep their own incomplete status.
These checks do not replace exact-source hosted CI or release qualification.

Source `57334d4` passes all 37
[CI jobs](https://github.com/billlza/q-periapt/actions/runs/36372546368).
Its Rust package job builds and consumes the real twelve-crate 0.2.0 cohort,
materializes the uploader and runs the coordinator's dry-run against the exact
producer commit and report digest. The received plan contains twelve packages
in dependency order, no upload attempts and no publication receipts. Locally,
the clean standalone source passes 2,311 artifact tests in 454.188 seconds,
without skips, with warnings treated as errors and pre/post source gates.

The subsequent uploader directory repair at `9dabb51` rejects a reproduced
parent-directory replacement instead of writing into the replacement. It pins
the private directory descriptor, preserves existing outputs, and checks the
new file's bytes and inode before enabling execution. Source `a07789f` then
derives CLI candidates from the report digest under a fixed profile directory;
the optional output argument only confirms that derived path. Its 214 affected
standalone tests and source gate pass. The
[current CI](https://github.com/billlza/q-periapt/actions/runs/36375293114) and
[CodeQL run](https://github.com/billlza/q-periapt/actions/runs/36375293123)
keep their own completion records. The completed Python analysis removes all
eleven path warnings activated by the preceding directory repair and adds none.
The remaining 41 alert IDs/rules match the earlier set; all thirteen reported
location files have the same Git blobs as `10de0c7`. No alert is dismissed or
suppressed. The current Rust package artifact binds report digest
`6d25c8f7bc34ae562720b747bd80e01b50e38699b51bdced5b0e9bbf657274ea`
to merge commit `d7d2aa1`, whose tree matches `a07789f`, and includes a passing
twelve-crate publication dry-run with no upload attempts.

The full-framework Android boot repair at `10de0c7` passes all 37
[primary CI jobs](https://github.com/billlza/q-periapt/actions/runs/36369866105)
and a separate same-source repeat of AAR plus both runtime jobs. Full/minimal
workloads, cleanup and export replay pass on API 23 / 4 KiB and API 35 / 16 KiB.
The received API 23 baselines show encrypted ext4 `/data` and
`vold.decrypt=trigger_restart_framework` for both consumers. The earlier
temporary-framework failure remains retained with its original source scope.

In the later `9dabb51` API 35 run, both SDK workloads return passing results,
but the minimal consumer loses its ADB transport while rechecking the installed
APK before cleanup. Both failed observations report `device offline` after
copying; one bounded reconnect restores the transport only temporarily.
Uninstall never begins, absence is not confirmed, and the job correctly fails.
The retained logs locate the failure but do not establish why the transport
dropped. This failure remains separate from the passing source-bound runs.

The Android SDK lane now selects one of two closed runtime profiles:
`api35-16k` retains the existing API 35 / 16 KiB target, and `api23-4k` adds the
API 23 / 4 KiB / x86_64 floor. Both CI jobs consume the same AAR and run the
existing full/minimal R8 workloads, installation checks, owned cleanup and
independent export replay. Verification requires a caller-selected runtime
profile; an API 23 result cannot satisfy API 35 acceptance. Crash cleanup uses
the admitted AVD identity stored in its receipt. The legacy default remains
API 35 / 16 KiB. The `10de0c7` checkpoint above supplies successful hosted
execution for both profiles; physical-device qualification remains separate.

At `47e7fcc`, all 2,274 local artifact tests pass without skips in 478.096
seconds, with warnings treated as errors and pre/post source gates. Hosted
API 35 completes both workloads. The API 23 job now passes its metadata
probes, installs the APK and verifies the installed bytes twice, but its
Instrumentation output is empty and the decoder rejects it. Cleanup separately
rejects the package-query output; app removal is not confirmed. The owned
emulator and ADB server are retired, and the failure diagnostics are retained.

The follow-up accepts only the exact expected package line ending in LF or
CRLF. API 23's shell service uses a PTY, and a real local PTY test reproduces
the CRLF rejection before the change and acceptance after it; extra lines,
other package names and embedded controls remain invalid. It also uses
separate `-b main -b system -b crash` options, because API 23 logcat treats the
previous comma-separated value as one unknown buffer. Both behaviors follow
the [API 23 shell service](https://raw.githubusercontent.com/aosp-mirror/platform_system_core/android-6.0.1_r81/adb/services.cpp)
and [logcat parser](https://raw.githubusercontent.com/aosp-mirror/platform_system_core/android-6.0.1_r81/logcat/logcat.cpp).

Bounded write operations now apply their declared stderr merge option, which
was previously ignored. A real child-process regression confirms capture and
the shared output limit, retaining the previous file when the limit fails.
These transport/diagnostic corrections do not establish why Instrumentation
returned no output; the next hosted execution must still supply that evidence.
The `712072a` implementation passes all 2,276 local artifact tests in 487.117
seconds without skips, with warnings treated as errors and pre/post source
gates. Its 196 affected tests include real PTY and child-process regressions.
The preceding `47e7fcc` hosted cohort finishes 36 of 37 CI jobs, with only the
API 23 runtime failing, and completes all six CodeQL analyses. Its 41 open
alert IDs/rules are unchanged and all thirteen reported location files match
the previously reviewed `99fb979` source. New-source hosted qualification is
still required for the transport corrections.

At `37dfdb7`, API 23 again installs and verifies the APK but produces no
Instrumentation result. The corrected system-log command now captures a guest
`SIGABRT` before the decoder failure, followed by an unavailable debuggerd
connection. The log does not identify whether the aborted process is the
command VM or SDK application, so no product-level cause is asserted. Package
cleanup separately returns malformed output even with LF/CRLF support.
The next diagnostic capture includes ART errors and ActivityManager process
starts within the same owned-emulator/time/size bounds. Failed package queries
retain escaped response bytes only for the disposable emulator; physical
responses retain size/hash metadata. Malformed responses still fail, and no
uninstall or successful runtime result is inferred from these diagnostics.

The `deb29ef` candidate passes all 2,277 local artifact tests in 464.964 seconds
without skips, all 37 jobs in [PR CI](https://github.com/billlza/q-periapt/actions/runs/36357747122),
and all six CodeQL analyses. API 23 completes both full/minimal SDK consumers,
owned cleanup and exported-evidence replay. The received runtime ZIP is bound
by SHA-256 `20abaec4eb541ad1b3448f8cc5d8e2c60f7836ad0e3e5a455bd120de7729e0db`.
Local reception checks its source, runtime/result, AAR and build records; the
SDK-tool replay is the recorded Linux CI execution, not a new macOS tool replay.

An independent run of the same commit reuses the cancelled push run's unused
Android artifact namespace. Only its AAR job and dependent runtime jobs are
rerun; the prior results are retained. AAR and API 35 pass again. API 23's three
full SDK workload groups pass, but package cleanup fails: after one empty
response, `pm` reports that the Package Manager is unavailable, while the host
ADB exit code is zero. This counterexample prevents treating the first green
run as evidence that the earlier service/VM failures were resolved.

The [API 23 package client](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-6.0.1_r81/cmds/pm/src/com/android/commands/pm/Pm.java)
returns status 1 for that missing service; legacy ADB shell does not transmit
the guest exit code. The package observer now requires a complete, run-bound
exit record from a fixed quoted guest command before interpreting empty output
as package absence. A real failing child plus simulated legacy exit-code loss
reproduces the old false-absence result; the corrected observer preserves the
nonzero result within its existing bounded query-retry policy. Missing,
truncated, mismatched or malformed completion records fail. Exact package
syntax, APK ownership and uninstall rules remain required.

Cleanup failure also captures owned-emulator system logs while preserving the
completed workload's app log and primary exit status. CI retains package-query
journals and errors on successful runs too, so recovered query failures remain
observable. The guest service/VM failure still requires causal diagnosis;
these changes repair query-result interpretation and diagnostic coverage.

The first complete local run at `99fb979` executes 2,271 tests and identifies two
integration failures: the isolated remote-consumer source list omits the new
runtime-profile module, and the workflow contract test still expects a single
literal system image. The follow-up adds the transitive module and checks both
fixed matrix targets, their shared AAR and per-target artifacts. A real isolated
validation call reproduces the old missing-module error; the corrected snapshot
loads that path and rejects the same empty projection at its intended boundary.
The initial import-only probe did not reach the lazy import, so it was not used
as validation. The corrected `b611beb` standalone checkout passes all 2,271 tests
in 413.836 seconds without skips, with pre/post source gates and Python warnings
treated as errors. All failed logs remain.

Hosted `99fb979` completes 35 of 37 CI jobs and all six CodeQL analyses. The
check job reproduces the same two local integration failures. API 35 / 16 KiB
completes both workloads, while API 23 stops before SDK execution: its newly
created `userdata.img` exposes group/other permissions. The follow-up restricts
only that new, canonical, singly linked owned file to mode 0600, then runs the
unchanged private-tree verifier. Seven real file-shape cases cover byte/inode
preservation and refusal of links, FIFO, writable modes and empty files. The
corrected API 23 workload still requires a hosted result.

The package-state command now uses the public `pm list packages` interface.
The API 23 AOSP `Pm` implementation provides it, while its Binder/package
service predates the shell-command entry used by `cmd package`. API 35 retains
`pm` as a wrapper over that service. Exact package-output parsing, combined
output bounds, deadlines, signer checks and removal rules are unchanged. The
API 23 lane uses a newly created single-user emulator; this source inspection
does not qualify physical or multi-user API 23 devices. See the
[Android command documentation](https://developer.android.com/tools/adb#pm) and
[API 23 implementation](https://android.googlesource.com/platform/frameworks/base/+/android-6.0.1_r81/cmds/pm/src/com/android/commands/pm/Pm.java).

The closed API 23 profile selects its own metadata probes before execution:
`cat /proc/self/auxv` supplies the kernel's `AT_PAGESZ`, and
`date '+%m-%d %H:%M:%S.000'` supplies the local calendar lower bound accepted by
its `logcat -T`. The AOSP API 23 toolbox/Toybox inventory has no `getconf`; its
date implementation has no nanosecond extension and its logcat parser expects
calendar time. The bounded aux-vector parser accepts exactly one complete
32- or 64-bit little-endian interpretation, one page-size entry and a terminal
null pair. Failed reads, truncation, duplicates and unsupported sizes fail.

API 35 retains its `getconf PAGE_SIZE` and epoch/millisecond probes: kernel
aux-vector pages must not replace the 16 KiB emulator's libc page-size view.
Both captured clock forms receive strict validation before installation and
before entering logcat arguments. The API 23 lower bound can include less than
one second of preceding, tag-filtered diagnostics; it is not a millisecond
measurement or an operation deadline. Existing log-size, time, owner and privacy
checks remain. These command changes still require execution on both targets.

The hosted `40f5bb6` minimum attempt confirms the preparation fix: its owned
2 GiB userdata file starts at mode 0644, is restricted successfully, and passes
full AVD admission. The runtime boots, then fails at the old metadata probe with
`getconf: not found`. Its owned server cleanup and failed-receipt retirement
complete with primary status 1. No SDK workload acceptance is recorded for this
attempt. The same source passes all 2,272 local artifact tests in 460.251 seconds,
without skips, plus its pre/post source gate.

The `0e2a670` source completes all 36
[CI jobs](https://github.com/billlza/q-periapt/actions/runs/36345633624) and all six
[CodeQL analyses](https://github.com/billlza/q-periapt/actions/runs/36345633631).
The PR merge `06db6468429b8097f2af0bb9087b49e0e2b55962` has the same tree,
`a2d00304d649af24440870f77f7d67dc33a22319`. All 41 open alerts retain their
preceding IDs/rules, and their thirteen source-location files are byte-identical
to the preceding candidate. No alert was dismissed or suppressed.

The clean standalone source passes 2,268 artifact tests in 453.901 seconds
without skips and its pre/post source gate. Hosted artifact `10940517353`
contains the passing Apple SDK host workload and iOS build logs; its downloaded
ZIP matches API SHA-256
`ce567e45fd0e4ecf771735a898ad5b332823d2c7d97089ee6ef98a1de0b9e1df`.
This completes hosted qualification for the Apple harness source. Physical
device execution, the macOS-to-Linux reference, controlled performance and the
release transaction retain their own acceptance requirements.

The `ba2cd3b` source completes all 36
[CI jobs](https://github.com/billlza/q-periapt/actions/runs/36340910445) and all six
[CodeQL analyses](https://github.com/billlza/q-periapt/actions/runs/36340910438).
The PR-scoped query retains 41 open alerts, bound to merge
`701b35031305298e363a52a8cc6bef5e31debbc2` with the same tree as that source.
No alert was dismissed. These results retain their preceding source scope;
the current Apple harness results are recorded above.

The [SDK Apple device profile](SDK_APPLE_DEVICE_ACCEPTANCE.md) now builds and
executes a distinct owner workload, with version/ABI/extension/test-group-bound
markers and separate proof kinds. The same four groups execute successfully on
macOS; the full iOS executable and unsigned app build locally without diagnostics.
This is source-workload/build evidence, not physical or packaged-device acceptance.
The initial iOS link failed because Rust defaulted to iOS 10 while C dependencies
defaulted to SDK 27; using the already-declared iOS 16 floor fixes that mismatch.
The first unsigned app build also found duplicate Info.plist resource processing;
the SDK target now excludes that input from its copy phase. Failed logs remain.

The initial receipt attempt rejects the installed App Store Xcode's different
signing chain. The new SDK profile pins that distribution explicitly,
retains Apple's Xcode identifier/team, root ownership, deep strict verification,
Gatekeeper and hash checks, and has a real local receipt. Legacy schema and
toolchain admission remain unchanged. No device installation, provisioning,
release signing or publication was performed for this preparation.
All 230 affected Apple artifact checks pass locally, including cross-profile,
source-change, matrix-route and signature-identity rejection cases. The repeatable
host/iOS check is now part of the Swift CI job; it retains build/host logs and
cannot emit a physical-device success marker. The broader artifact suite and
hosted qualification for this source are recorded above.

The preceding `caca8a7` source completes all 36
[CI jobs](https://github.com/billlza/q-periapt/actions/runs/36338497784) and all six
[CodeQL analyses](https://github.com/billlza/q-periapt/actions/runs/36338497702).
Both Android full/minimal consumers complete ART, ownership-checked cleanup,
retirement and export replay on the API 35 / 16 KiB / x86_64 emulator. The
analysis binds merge `b0b6da0b235abf5028a0d5a0460bfedc3485c5cb`, whose tree equals
that source head. Its 41 open alerts have the same IDs/rules as the preceding
analysis; none were dismissed. These results retain their source scope and do
not qualify the later example changes below.

The reference examples now expose explicit transport addresses: Rust accepts
`--listen IP:PORT` and Swift accepts `--host HOST`, while retaining loopback
defaults, independent certificate-name verification and all original budgets.
Both use the existing connection engine. Fifteen Swift tests, six Rust example
tests and nineteen affected harness checks pass. All twelve existing real TCP
cases pass; two additional IPv6 runs complete four authenticated connections
and twelve echoes across provisioning and process-restart recovery, with only
each role's own private TLS key in its directory. These are Darwin loopback
observations; they prepare the requested cross-host run but do not qualify a
native Linux server or new installed packages.

Rebuilding the old Swift probe from `caca8a7` also reproduces a CLI side effect:
an unknown scenario creates a policy database before reporting usage failure.
The new argument parser rejects it before persistence. An initial validation
mistakenly rejected the existing zero-port placeholder used by store-only
scenarios; the full connection regression detected it. The corrected parser
preserves that non-network contract while rejecting zero ports for network
scenarios. Failed captures and the original build diagnostics are retained.

The `715c52b` Android run failed before the SDK workload: the APK installation
reply reported `cmd: Failure calling service package: Broken pipe (32)`.
Cleanup subsequently observed the installed APK twice, verified its signer,
uninstalled it and retired the failed runtime with primary status 1. No runtime
success proof was produced. The retained host ADB log does not show a transport
loss before the install failure, and no guest system diagnostic was captured;
the package-service failure's root cause is therefore still unknown.

The producer previously captured its diagnostic clock only after successful
installation and ownership confirmation. A controlled invocation of that exact
shell phase reproduces the missing clock and logs on a failed install reply.
The follow-up validates the clock before installation and uses the existing
bounded failure logger for install, ownership and activity-launch failures as
well as Instrumentation failures. Only owned-emulator diagnostics add fixed
installer error tags, and the retained installation log includes stderr.
Original statuses, install count, time/output limits,
cleanup ownership checks and physical-device log scope are preserved. The
180 focused checks pass; these control-flow and boundary tests do not establish
a repaired native package service or a current-source Android runtime pass.

The shared binary-freeze helper used by connection acceptance and performance
drivers still opened caller-selected input as an ordinary stream. A real CLI
invocation with a FIFO blocked on the `921cada` source until its bounded parent
terminated and reaped it after 1.026 seconds. The helper now uses the existing
regular-file snapshot reader with the same 256 MiB input limit as the TLS
diagnostic. The same FIFO is explicitly refused with nonzero status after
0.276 seconds, before any peer execution or completed proof. These elapsed
times are observations, not a general filesystem-latency guarantee.

Twenty affected checks cover special-file refusal, the exact size bound,
preserved prior output and immutable copied bytes. Twelve real Swift/Rust TCP,
cancellation and durable-policy cases also pass with the repaired driver and
the same hash-verified native/Swift binaries. Their product sources are
unchanged from the retained binary checkpoint. This is driver validation on
Darwin loopback, not a new installed-package or native-Linux run; final-source
hosted qualification remains required.

The installed-connection output check also accepted two lexical paths whose
resolved destinations escaped `target`: a `..` traversal and a parent symlink.
Real isolated directory fixtures reproduce the old predicate's false accepts;
the probes create no escaped output. Admission now checks the resolved path,
retains existing-output and symlink-leaf refusals, and returns the canonical
destination to all later writes. Twenty-two focused connection/installation/
performance checks pass after both input-boundary repairs. This is a local
tool-path contract, not isolation against a hostile process sharing the builder
account; the later source needs its own complete and hosted qualification.

The clean `2493ffe68ad99920880a9bd4c70be79dc37c1850` snapshot passed all 2,250
artifact tests in 482.705 seconds, without skips, and the post-test exact-source
gate. The [persistent RAM checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-owned-pstore-retirement/manifest.json)
retains the previous native failures, upstream implementation, source-bound
red/green regression and both retirement paths. Its hosted Android follow-up,
[job 108654977850](https://github.com/billlza/q-periapt/actions/runs/36331368956/job/108654977850),
completed both full/minimal ART workloads, exact APK ownership and cleanup,
owned-runtime retirement, proof publication and exported APK-tool replay.
The downloaded runtime artifact has SHA-256
`c4bb2d6aa7813e1053e0953fc40fe617738c02f13f57d1091c04e04e2e28b641`.
Both records bind PR merge `88bc75ef26670e6d6e2a2b81b15d0659df4d82d3`,
whose tree equals this head, and API 35 / 16 KiB / x86_64 emulator execution.
Both consumers completed cleanup in this run. Successful uploads omit the
per-attempt transport diagnostics, so this does not establish that no recovered
disconnect occurred; the earlier unresolved cleanup failure's cause remains
open. A separate macOS replay of the downloaded closure was
refused because the local `dexdump` hash differed from the recorded Linux tool.
That failed attempt is retained and no tool identity check was relaxed. The
native Linux export replay passed; cross-OS APK-tool replay is not claimed.

Tracing the remaining transport failure found that failed `pm path` responses
were collapsed into the typed `package-unavailable` state without retaining the
underlying exit code or reply. The command now writes bounded diagnostics to
the existing per-attempt stderr file, identifying whether failure preceded or
followed the APK copy. Only the owned emulator's reply is included, with control
characters escaped; physical-device replies remain represented by metadata and
a digest. Timeout is explicit. The typed result, deadlines, recovery budget and
uninstall authorization are unchanged. Both missing-log stages reproduce on the
old source and pass after repair; 171 command tests and 155 producer/consumer
regressions pass. The underlying guest
transport failure is not attributed without its native diagnostic evidence.

At `830e3813a61cec8009875b3602ad4cab5bb1da7a`, the completed
[CI cohort](https://github.com/billlza/q-periapt/actions/runs/36328485723) passed
35 jobs and failed Android runtime. Both Windows package jobs now pass,
including the Windows 2022 static consumers that previously rejected volatile
metadata. Each producer strips 12 reviewed CodeView objects and preserves
651 other objects plus five short imports. The downloaded MSVC 19.51 archive
has SHA-256 `bc2a4a17c1bfdbff887677a3d3483a7411882547858f8bd47ec13d8cfacd9ac1`;
its manifest binds the matching PR tree and ABI 2 / 43 exports. It remains
unsigned. Swift package/connection, Linux MSRV, eight independent OpenSSL cases
and the scoped AVX2 differential/binary-CT gates also pass. All six
[CodeQL analyses](https://github.com/billlza/q-periapt/actions/runs/36328485780)
completed; the matching PR ref still has 19 open alerts, with no dismissals or
rule suppression. Scanner completion does not replace finding review.

The same Android run completed the full ART/export gate and the minimal
Instrumentation workload. During minimal cleanup, its emulator transport
disappeared twice; the one permitted identity-checked recovery succeeded once,
but two fresh exact APK samples were never obtained. No uninstall was
authorized, and no minimal success proof was published. This transport failure
remains unresolved. Retirement additionally identified a regular 0600,
current-owner, single-link, 65,536-byte `pstore.bin`. The pinned upstream
[header](https://android.googlesource.com/platform/external/qemu/+/ba29194f97e72ffe770bd56e4e5c5c620598004b/include/hw/misc/goldfish_pstore.h)
defines that RAM size and private file mode; its
[device teardown](https://android.googlesource.com/platform/external/qemu/+/ba29194f97e72ffe770bd56e4e5c5c620598004b/hw/misc/goldfish_pstore.c)
saves the RAM file even without a crash. The follow-up admits only this fixed
private file or an empty directory after proven owned-runtime shutdown. It
preserves file identity/content while restoring directory privacy, rejects
partial/shared/linked/unknown entries, and rechecks content after restoration.
The old source reproduces the exact valid-file refusal; 219 local state/command
tests pass after repair, including both successful and failed retirement.
Native execution of this follow-up remains required.

The clean `5ec7fc01bd49915e40620b50ad70858b5e780dd6` snapshot passed all 2,243
artifact tests in 441.545 seconds, without skips, and passed the exact-source
gate again afterward. Its Windows 2022 producer completed CBOM/license checks,
two byte-identical ZIP builds, manifest verification and the extracted legacy
dynamic consumer. Static linking then failed with `LNK1400` on the rewritten
jitterentropy object's volatile metadata. The follow-up limits LLVM rewriting
to the reviewed CodeView NASM section layout; all other objects remain
byte-identical to the fixed-length filename copy. Unknown debug layouts still
have to pass the complete producer path scan. The real mixed-archive helper,
eight ring objects and 79 Windows tests passed locally before the successful
native MSVC follow-up recorded above.

Both `6f62f22` and `5ec7fc0` hosted Android runs completed the full consumer's
final gate and received the minimal consumer's valid runtime result. Minimal
retirement then refused nonempty `pstore`, so its proof was not published.
The `830e381` follow-up preserved this refusal and added bounded, read-only metadata to
the error; only a regular private `pstore.bin` can be hashed, and neither its
contents nor unrecognized entry names are printed. The 215 state/command tests
pass. [Upstream emulator code](https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/android-qemu2-glue/main.cpp)
creates a persistent RAM block on Linux/x86 while
disabling it on Apple Silicon. The subsequent native observation and narrowly
scoped persistent-file repair are recorded above; the prior refusal remains
part of the retained failure evidence.

The `6f62f22` Windows 2022 run processed 663 ordinary COFF objects, preserved
five short import records and passed the complete DLL/import/static producer
path scan. It then rejected the Windows CBOM invocation's nonexistent
`--profile` option. The producer now uses the CLI's `--native-sdk` option with
the existing `sdk-cbom` build feature. Actual PowerShell argument construction
and the locally rebuilt Rust CLI reproduce the old rejection and generate a
verified 37-component CBOM / 249-component lock-bound SBOM after repair. This
does not yet qualify the complete native package.

The same cohort exposed a new diagnostic regression's direct Python startup,
which created repository bytecode and correctly failed cache/source checks.
The regression now uses the canonical launcher. The failed local run was
interrupted after the cause was confirmed; its logs and cache files are
retained separately. Head `99487f5` passes the clean source gate before its
fresh full run. The workflow's exact diagnostic-upload contract also needed
the newly added emulator crash-log leaf; its closed allowlist remains exact.

At `51982a6bcac222bbb9a6cf1d233c0bbfb3acd5c0`, the hosted
[CI cohort](https://github.com/billlza/q-periapt/actions/runs/36323838117)
completed 33 jobs successfully and failed both Windows package jobs and the
Android runtime job. The complete Swift package/connection job passed. All six
[CodeQL analyses](https://github.com/billlza/q-periapt/actions/runs/36323838125)
completed; the PR merge ref has 19 open alerts. The new static-copy path alert
starts at the explicit local CLI output option, not an archive member name.
Alert/data-flow review remains distinct from scanner completion and independent
security review; no findings were dismissed or rules disabled.

The clean standalone `a24e3c0c876bca44a212dcf8ab051c0b7e52545b` snapshot passed
all 2,233 artifact tests in 398.539 seconds, without skips, and the exact-source
gate. Its local Swift/Rust run passed all twelve socket cases, with the
silent-peer failure and repair retained in the
[connection/transport checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-silent-peer-and-transport-repair/manifest.json).
Hosted MSVC confirmed both long-path compiler maps worked, but the DLL still
failed the producer scan. The pinned AWS-LC source also converts paths to 8.3
aliases; these now receive explicit maps and preflight checks. This is not yet
evidence that the final native package scan passes.

At `0ab5091a96ecc18c3521a76e3be1b5c524d4b32c`, Windows 2022's native preflight
passed both long and short C paths. Its DLL and import library passed the path
scan; the static archive then exposed upstream workspace names in the bundled
NASM objects' COFF `.file` auxiliary records. A local review of all 26 objects
from the hash-verified `aws-lc-sys 0.45.0` crate confirms that removing these
debug records preserves every section's bytes, non-file symbol and relocation
target. The producer now retains the raw archive and creates a distribution
copy with unchanged external symbols. Native archive consumption is still a
separate gate.

The subsequent `eebadda` native run exposed Rust's mixed archive: LLVM rejects
its short DLL import records when asked to strip the whole library. A minimal
Rust static library reproduces that failure. The `328bf90` copy operation instead
replaces only COFF FILE auxiliary filename bytes with a fixed placeholder;
all offsets, indexes, import records and other bytes are preserved. Both the
26-object NASM archive and a real Rust mixed archive retain exact external-symbol
listings. Cross-linking the original and normalized minimal Rust archives yields
byte-identical PE DLLs; this is not native Windows execution.

The `51982a6` native diagnostic locates the remaining path in a `.debug$S`
section. Its member hash and byte offset exactly match the normalized
`ring 0.17.14` prebuilt ChaCha object. The producer now runs LLVM debug stripping
on copied ordinary COFF objects and rebuilds the index, preserving duplicate
members, their order and byte-identical short imports. External symbol names,
types, values and sizes must remain unchanged. All eight ring objects pass the
local section/symbol comparison and path scan. The production PowerShell helper
also passes with a real mixed Rust archive (296 ordinary objects and four short
imports); its minimal cross-linked DLL remains byte-identical to the original.
The 78 affected Python tests and PowerShell boundary fixtures pass. Native MSVC
archive consumption remains required; these local checks do not replace it.

The `a24e3c0` Android full SDK consumer completed its ART workload, owned-runtime
cleanup and proof publication. Portable evidence export then failed because
the collector's `umask 077` created 0600 copies while the bundle contract requires
0644. A local red/green regression reproduces the same refusal. The exporter now
sets only newly created copies to 0644 through their open descriptors, preserving
0700 enclosing directories and the original 0600 receipts. Both full/minimal
profiles and architectures replay in the 46-test local follow-up; actual ART
completion of both consumers remains required.

At `eebadda`, the hosted full Android consumer completed ART execution, cleanup,
portable export and the final `ANDROID_AGP_RUNTIME_PASS` gate. The minimal
consumer then failed before workload execution because its new emulator reported
KVM permission denial. The workflow now applies the same existing runner-only
ACL before each consumer, records the prior/current device permissions and runs
the emulator's bounded acceleration preflight. The earlier job did not retain
enough ACL state to attribute the permission change to a particular host event;
the minimal consumer still needs a successful native run.

The `328bf90` run confirms that the runner ACL was absent before the second
launch and that reapplying it restored usable KVM. The minimal consumer then
lost its emulator transport after one exact APK observation; a nonempty pstore
also prevented retirement. Neither condition is bypassed. At `51982a6`, the full
consumer instead returned `INSTRUMENTATION_ABORTED: System has crashed.` after
two exact installed-APK observations. Its owned uninstall and retirement
completed, but the workload did not. The producer now collects scoped failure
logs before exiting on a rejected Instrumentation response. System-crash tags
are available only from the same live, receipt-bound emulator, under the
existing time/output limits; physical-device logging is unchanged. The real
response decoder and producer shell flow reproduce the missing-log defect and
its repair while retaining exit status 1 and publishing no successful result.
The crash's underlying cause and both-profile ART qualification remain open.

The subsequent hosted checkpoint at `7c7a76343d724c889286b594e47a8398aa63bf06`
([CI](https://github.com/billlza/q-periapt/actions/runs/36315599184)) completed
32 jobs successfully and failed four. Linux's complete check job now passes.
The native Windows build has verified the exact 43-export contract and run both
legacy and SDK C consumers; both Windows package jobs remain blocked by the
producer-path scan. The redacted diagnostic retains the offending file's hash,
byte offset and root index. It does not yet identify a repaired Windows package.
All six [CodeQL analyses](https://github.com/billlza/q-periapt/actions/runs/36315599181)
completed with 18 open alerts on `refs/pull/111/merge`, without dismissals or
suppressed rules. Source/data-flow review is recorded separately from analysis
completion, including each finding's reachable path and applicable trust boundary.

Hosted Swift qualification passed at `4349c6aebbc18cac971a5ceff31cee7d3c6fb307`,
but the next cohort exposed a cancellation diagnostic that assumed TCP accept
within a fixed 40 ms sleep. The diagnostic now waits for an actual peer
observation. Its silent-peer variant then exposed a product defect: runtime
revocation during pending Network I/O returned timeout after five seconds.
Swift now rechecks native state every 100 ms during pending establishment or
request I/O, retaining the original operation deadline. The repaired local
12-case Swift/Rust run observes the revocation error with no response from the
peer; current-source hosted package qualification remains required.

Android's full SDK workload and exact run-bound log marker succeeded in the
preceding cohort, but an ADB disconnect prevented cleanup confirmation. The
latest cohort lost the owned emulator transport before its first exact package
observation. The repair distinguishes observed transport absence from package
unavailability and permits the existing one-shot, identity-checked recovery
before that first sample. Two fresh exact APK observations and signature checks
are still mandatory. The complete ART job remains unqualified until rerun.

The clean standalone `4349c6a` snapshot passed the complete 2,226-test artifact
suite without skips. The `7c7a763` snapshot passed 172 focused tests and the
exact-source gate; neither result is relabelled as execution of subsequent edits.

The hosted checkpoint at `f0214466bb1364aea0cfdf369f8291b29eb7900a`
([PR 111](https://github.com/billlza/q-periapt/pull/111),
[CI](https://github.com/billlza/q-periapt/actions/runs/36312252550)) completed
31 jobs successfully and failed five. The failures identified the explicit
Python binding, SDK static-link dependencies, AWS-LC's private DLL exports,
conflicting Xcode warning flags, and missing Android SDK log markers. The
Android full consumer returned its run-bound result on API 35 with 16 KiB pages,
but its evidence verifier correctly refused the missing log marker; this is not
completed ART qualification. The subsequent fixes require another native run.
All six [CodeQL analyses](https://github.com/billlza/q-periapt/actions/runs/36312252921)
completed, with 19 open alerts requiring review. Analysis completion is not a
zero-finding result.

The diagnostic input review also reproduced a blocking FIFO read in
`standard_tls_interop.py`. Identity and executable sealing now use the existing
bounded regular-file snapshot reader. A real FIFO changes from a parent-enforced
timeout to an immediate nonzero rejection; the eight OpenSSL loopback cases
still pass with the revised harness. This fixes diagnostic input handling and
does not reinterpret earlier binary or release evidence.

The alpha CI source check uses the explicit `sdk-alpha1` profile of
`source_results_assembler.py ci-source-gate`. It checks a clean exact commit,
the alpha workspace version, both ABI 2 header contracts, and the current 254
proof-input paths. The published 0.1.5 results ledger remains byte-frozen at
`9974f5a3d2cb754817aa857a10859582d329c97edd61a44d41a2fb701d564bda`;
its 249 inputs are historical evidence, not evidence for the SDK build. The
source check emits `release_claim_eligible=false`. The separate legacy source
transition/finalizer retains its exact initial and installed requirements.
Native package, runtime, formal and CodeQL jobs still qualify the current SDK
source independently; source readiness alone does not authorize a release.

- [Complete artifact regression](../research/sdk-alpha1/evidence/20260927-sdk-android-repair-quality/manifest.json):
  2,220 tests with warnings as errors, after the Android notice repair. The
  private build-copy index mismatch and its metadata-only repair are retained.
  This is the complete run's source snapshot, not a new execution after later
  consumer/CI/documentation edits.
- [Current Apple package](../research/sdk-alpha1/evidence/20260927-sdk-current-apple/manifest.json):
  five native builds/final Swift links and two actual macOS ARM64 consumer runs,
  including extraction outside the checkout. iOS and simulator destinations
  were build/link only; minimum-OS and physical-device execution are still open.
- [Installed connection and consumer repair](../research/sdk-alpha1/evidence/20260927-sdk-current-installed-connection/manifest.json):
  twelve real Swift/Rust TCP scenarios and eight independent OpenSSL cases from
  the current packages. It retains the failed and repaired standalone Cargo
  manifests, dependency origins, binaries, linker map and runtime observations.
  The subsequent CI wiring and documentation change are identified separately
  from the runtime snapshot. Both endpoints ran on macOS, not native Linux.
- [Installed-package timing](../research/sdk-alpha1/evidence/20260927-sdk-installed-connection-timing/manifest.json):
  the existing installed Swift client and a release build of the extracted Rust
  peer pass twelve acceptance cases, five fixed timing blocks, and eight
  independent OpenSSL cases. Raw first/setup observations and per-block
  P50/P95/P99 are retained. This closes the missing local installed-path baseline,
  while controlled tail, CPU/energy and other platform qualification remain open.

The full-workflow lint diagnostic is an external tooling gap: on 2026-09-27,
the [latest actionlint release](https://github.com/rhysd/actionlint/releases/tag/v1.7.12)
is still 1.7.12, and the
[pinned upstream runner catalogue](https://github.com/rhysd/actionlint/blob/011a6d15e749bb3f2d771eed9c7aa0e7e3e10ee7/rule_runner_label.go)
has no `ubuntu-26.04` entry. GitHub has
[announced that runner as generally available](https://github.blog/changelog/2026-09-17-ubuntu-26-generally-available-and-latest-migration/).
The complete before/after diagnostic is retained without a label alias or
disabled check. A locally passing job subset is not a full-workflow lint pass.

Continuity's persistent session, ongoing PQ recovery and multi-device protocol
are now part of the 0.2.0 release requirements. Their protocol, implementation,
storage, binding and performance evidence must be completed in this release;
the existing KEM or TLS results do not establish those properties.

Implementation order: native ABI 2 ownership and cross-language adapters;
purpose derivation/import/lifecycle completion; native x86 candidate; reference
connection and standard interop; the Continuity protocol, persistence, recovery
and multi-device service; package/device/performance gates; final quality
and requirement-by-requirement release audit. Remaining verification stays visible
while independent implementation work continues.

The current [ownership contract](SDK_OWNERSHIP.md) and
[purpose-key schedule](SDK_KEY_DERIVATION.md) record per-language disposal,
async cancellation, error and erasure boundaries. In particular, runtime revocation
now also rejects exports from retained secret owners (observed old-fail/new-pass).
The new JVM binding shares the legacy library loader; Android extends the same
JNI registration table and preserves both ABI 2 library names. The runtime's
extension version is a feature-contract revision, not a new ABI major.

The [x86 candidate](SDK_X86_CANDIDATE.md) adds no vendored changes or global
`target-cpu=native` setting. Disassembly exposed additional SSSE3/SSE4.1/POPCNT/BMI2
requirements beyond AVX2; their admission counterexample and repair are retained.
The user has been asked for an available native Linux execution endpoint. Other
implementation work continues while that evidence gap remains open.

Release-tooling status: all eighteen workspace packages and exact internal pins
use 0.2.0-alpha.1. Rust, C, Apple, JVM, Android and product WASM have explicit
alpha package profiles and local checks within the scopes above. The unsigned
alpha receipts do not authorize a stable 0.2.0 release transaction. Historical
0.1.5 contracts, export lists and device results remain separate; a clean final
source/package cohort, hosted gates and applicable signing/publication receipts
are still required. Existing publication provenance validators require a
standalone Git checkout; their linked-worktree rejection is retained.

## Historical implementation and qualification record

The entries below preserve the source, binary, test count and open gates at
each checkpoint. Later implementation or verification may supersede those
states. Use the requirement table and latest checkpoints above for the current
qualification summary; historical passing runs do not qualify later source.

Local checkpoint: 2,132 artifact-tool tests passed in a standalone checkout
containing the uncommitted source snapshot. The subsequent versioned JNI/DEX
validator changes passed their focused tests. Final Rust/WASM/native binding
reruns include the corrected policy-input length classification and rejection of
retained secret export after revocation. These checks are not hosted CI or a
release-package qualification. Raw logs, source snapshots, failures and binary
identities are in [the ABI 2 binding checkpoint](../research/sdk-alpha1/evidence/20260925-owned-abi2-bindings/manifest.json).

The [version/source-profile checkpoint](../research/sdk-alpha1/evidence/20260925-versioned-source-contract/manifest.json)
records the coordinated alpha versions, the immutable 0.1.5 fixture and separate
16-file alpha sys profile, and the diagnostic `.crate` rebuild. All 569 workspace
tests passed; the existing process-umask test also passed in its required isolated
single-thread run. Clippy, formatting, the legacy C consumer compiled with the
frozen header, and the owner C consumer passed. The local unpackaged dylib has
exactly 18 named exports; its distribution identity was correctly rejected by
the full package validator and is not claimed qualified.

The standalone source snapshot's 2,140 artifact tests found two stale wiring
assertions (the versioned validator entry point and the additional pinned x86 CI
toolchain step). Both were corrected, and the affected 89-test classes passed on
the updated snapshot. The original full-run failures and follow-up source hashes
are retained; this is not reported as a second full-suite run. The Windows C
consumer script now selects C11 explicitly, but Windows execution is pending.

Subsequent purpose-derivation work extends the unpublished alpha table to exactly
20 ABI 2 functions and 20 JNI registrations; the previous 18-symbol checkpoints
remain historical. Derived keys have their own owner type and cannot be reused
as KEM secrets. Core KATs include RFC 5869 and an independent framing vector;
host C/Swift/JVM/JNI and Node tests exercise the real implementation. The updated
boundary tests cover aliasing, invalid purposes/labels, quotas and revocation.

A fresh advisory scan found the existing TLS dependency `rustls 0.23.43` affected
by [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html).
A retained regression constructs a real ServerHello followed by plaintext
EncryptedExtensions in the same TLS record. The old dependency accepts this
record across a key change. The source dependency floor and lock now require
the upstream fixed 0.23.45. The same regression rejects it with
`KeyEpochWithPendingFragment`; private-group and RFC 10024 baseline handshakes
also pass. A fresh `cargo audit --deny warnings` using advisory database commit
`913a741345c1df04dd8ee83f4304f439caa30ccc` reports zero vulnerabilities and warnings.
These observations are separate from earlier audit receipts and do not audit
the vendored C provider or establish standard-peer interoperability.

The [purpose-key/TLS checkpoint](../research/sdk-alpha1/evidence/20260925-purpose-keys-tls-fix/manifest.json)
retains source and binary identities, actual host binding results, the independent
KDF vector, both TLS regression outcomes and the failed/fixed advisory scans.
The full workspace run (575 passed, one existing isolated-umask test excluded)
preceded the TLS patch; the affected TLS suite including its optional standard
baseline was then rerun on 0.23.45. Final affected-target Clippy includes both
the KDF and patched TLS adapter. Linux x86 candidate test executables and all
four Android JNI objects compile; this does not claim native Linux or ART execution.

The key-transfer/policy checkpoint had **26 C exports and 26 JNI methods**;
the original nine signatures/status values/library identities remain unchanged.
Earlier 18/20-symbol checkpoints are historical. [Expert key transfer](SDK_KEY_TRANSFER.md)
uses a closed 2440-byte expanded representation and the existing provider's
embedded-public-key/hash checks plus a fresh random pairwise consistency test.
It is neither encrypted storage, entropy certification nor a seed-derived X-Wing key.

[Policy transitions](SDK_POLICY_UPDATES.md) prepare an authenticated successor,
expose the host's expected/next state pair, and activate after host persistence.
A retained red/green regression found that rejecting every unsupported policy
would leave old permissions active even when a valid newer policy revoked the
fixed suite. Authenticated revocations now install a disabled runtime, survive
reconstruction from persisted state, and can accept a later re-enabling update.
Invalid signatures/rollback/equivocation remain errors. In-process revocation
does not establish a cross-process persistent authority or cancel admitted calls.

The [key-transfer/policy checkpoint](../research/sdk-alpha1/evidence/20260925-key-transfer-policy-updates/manifest.json)
records the original counterexample, final local source/binary identities, and
actual C/Swift/JVM/JNI/WASM consumers. The full workspace passed 585 tests; its
existing umask test ran separately. Final affected Rust tests, workspace and
WASM Clippy, formatting, 47 artifact-boundary tests, eight Swift tests, fifteen
JVM tests, eight actual host-JNI scenarios and the Node product/entropy-failure
checks pass. The JNI fault boundary covers 193 legacy and 80 SDK cases. Four NDK
JNI objects and GNU Linux candidate tests compile; macOS/Linux dynamic export
sets match all 26 symbols. No package/install identity, native Linux/ART run,
current-source performance, hosted CI or independent TLS peer
qualification is inferred from these local results.

Subsequent [standard TLS work](SDK_STANDARD_TLS.md) adds an explicit
`standard-tls` feature using rustls's maintained AWS-LC provider, with immutable
mutual-authentication configurations and no classical/TLS 1.2 fallback,
resumption or early data. Nineteen Rust tests and strict Clippy pass with additive
`rustls/tls12` enabled. Eight actual loopback scenarios pass against independent
OpenSSL 3.6.3 in both endpoint roles. The private provider's codepoints, combiner
and policy selector remain separate. TLS certificate authentication does not
claim PQ identity authentication or Q-Periapt policy agreement. The initial
macOS socket-mode failure is retained, and an unexecuted Ubuntu 26.04 CI job
records the intended native hosted gate. The previous SDK checkpoint precedes
this optional-feature change; [the standard TLS checkpoint](../research/sdk-alpha1/evidence/20260925-standard-tls-interop/manifest.json)
identifies its source, peer binaries and observed results separately.
The [denial-reason follow-up](../research/sdk-alpha1/evidence/20260925-standard-tls-denial-reasons/manifest.json)
reruns all eight scenarios with a sealed executable and requires the expected
authentication/group/version error; generic connection failure cannot count as
the intended rejection.

The [connection checkpoint](../research/sdk-alpha1/evidence/20260925-reference-connection/manifest.json)
adds the [specified application protocol](SDK_CONNECTION.md), shared Rust/C
engine and Swift TCP adapter. That checkpoint's unpublished alpha table has
**40 C exports and 26 JNI registrations**, retaining ABI major 2, the original
nine declarations/status values and library names. Four NDK C compilations also
check the new structure layouts on 32-bit and 64-bit targets; they do not qualify
the newly expanded native library on Android.

Actual macOS ARM64 Swift/Rust TCP runs pass nine scenarios, with frozen binaries,
dyld library identity, strict Swift concurrency and real cancellation/deadlines.
The new native connection tests cover replay/confirmation/identity/framing and
owner bounds; the affected Rust suites pass 83 tests including compile-fail
doctests and additive TLS 1.2 feature unification. The complete default workspace
passes 602 tests; the existing process-umask test passes separately. Workspace
Clippy, header freshness, legacy/fresh C consumers, eight Swift tests, seven
binding-boundary tests and 41 workflow-wiring tests pass. OpenSSL's eight real
independent-peer cases pass again after the standard constructor change.

Review of the upstream key loader found that owned `PrivateKeyDer` alone does
not wipe on Drop. Standard constructors now transfer it into AWS-LC's zeroizing
loader before any trust-root/configuration error and require certificate/key
consistency. The first Swift build hit a compiler inference diagnostic; explicit
continuation/event types fixed it without reducing concurrency checks. Both
the failed build and the passing runs are retained. Historical 26-export Linux
and Android observations predate the added TLS dependency and do not qualify
that 40-export library. At that checkpoint, durable host policy state, actual installed
Swift/macOS-to-Rust/Linux execution, updated package/CBOM profiles, performance,
and device qualification remain open. No publication has occurred.

The [host-store checkpoint](../research/sdk-alpha1/evidence/20260925-host-policy-store/manifest.json)
adds the unpublished `q-periapt-host-store` crate and reuses its private-file/ACL
boundary from the policy agent. The Rust connection diagnostic now provisions
and reopens real state, verifies the configured policy against its recovered
floor, and creates no listener for a valid revocation or a rollback. Twelve
Swift/Rust process/socket cases pass, including persistent revocation, restart
rollback refusal and later re-enabling. At that checkpoint the Swift client used
in-memory test state; C/Swift persistence integration remained unfinished.
ABI 2, its then-40 C exports and the 26 JNI registrations were unchanged.

Thirteen host-store tests include real-file sync failure, runtime closure during
commit, subprocess lock exclusion and abrupt exit after a successful commit.
The old runtime is revoked on mutation failure, and activation failure after
commit cannot revive its old policy on recovery. The complete workspace passes
609 tests; the existing process-umask case passes separately. The agent's six
filesystem tests moved into the shared crate, so its remaining suite has 259
tests; they were not removed from validation. Strict affected-target Clippy and
90 source-map/workflow/dependency-contract tests pass.

Source binding now includes the moved implementation, macOS adapter, agent
re-export and new store source: the current map has 254 inputs. Its historical
249-input results file remains byte-identical and cannot pass either current
baseline mode. The lockfile tripwire now accounts for the four registry versions
introduced by prior purpose-key work (227 to 231) and the rustls replacement;
host persistence reuses the existing redb/rustix versions. Initial compile,
fixture, lint and stale-baseline test failures are retained with their fixes.
No new source transition/publication record was manufactured. Local filesystem
durability, cross-process advisory locking and these bounded fault tests are not
hardware snapshot-rollback protection, power-loss qualification or a production
IPC authority. Linux execution, persistent Swift integration and the remaining
package/device/performance gates were open at that checkpoint.

The [persistent-runtime binding checkpoint](../research/sdk-alpha1/evidence/20260925-persistent-runtime-bindings/manifest.json)
adds three C functions, bringing the alpha table to **43 exact exports** while
retaining ABI 2, the original nine declarations/status values and all library
identities. JNI remains at 26 registrations. C and Swift now share Rust's host
store; configured-policy reconciliation is required on open. Other native
platforms keep the symbols but explicitly reject this macOS/Linux storage API.

Swift's persistent owner performs disk work and cleanup on a worker, waits for
admitted writes on cancellation, and closes an undelivered successor. A cancelled
operation may already have committed. Updates reserve their identity before
persistence and reuse the old registry slot; old queued operations recheck their
epoch under the store lock. Mutation/publication failure or unwind closes the
store and its previous runtime. Five new FFI tests exercise these boundaries,
including close/unwind after commit and recovery of the new policy. Three new
Swift tests include actual commit followed by cancellation and a child retaining
the file lease until disposal.

A retained regression found that an unwind had closed a runtime while its state
getter still returned success. The getter now checks liveness and returns
`ERR_CLOSED` with cleared output; no KEM hot-path validation was removed. The
full workspace passed 614 tests before this repair; all 40 affected FFI tests
then passed with it. The isolated umask test, workspace Clippy, warning-denied
rustdoc, exact header/export checks and legacy/fresh C consumers pass. All eleven
Swift tests pass with strict concurrency and warnings as errors. iOS compilation
and four Android C structure-layout checks pass without claiming device runtime.

Twelve actual TCP cases pass again using frozen Swift/Rust executables and the
reported loaded dylib, now with persisted state on both peers. Both reject an
older policy after a stored revocation; both accept a subsequent re-enabling
policy and complete new connections. The initial Swift fixture-path/build and
format failures are retained. A full distribution validator still rejects the
unpackaged Cargo dylib's filename; the separate exact export-set check passes
all 43 names and does not confer package identity. No publication or current
Linux/package/device/performance qualification is inferred.

The [SDK performance checkpoint](../research/sdk-alpha1/evidence/20260925-sdk-path-performance/manifest.json)
adds actual compiled C and public Swift owner/compatibility consumers of the
same frozen dynamic library. Five blocks per consumer, each with 1000 paired
samples in seven cells, preserve the measured cost of export, erasure and owner
disposal. Policy/key setup remains excluded. Cross-path key/state and roundtrip
checks run before/after collection; every process must report the frozen dylib.
The [measurement contract and all local results](SDK_PERFORMANCE.md) retain
small-context P99 regressions/variation rather than assigning a release pass.

A coarse macOS C clock was detected from raw samples and `clock_getres`; the
corrected raw-uptime clock is also source-bound. The coarse-clock run, initial
feature-macro compile failure and final corrected capture are all retained.
No cryptographic implementation or security validation was weakened. This is
uncontrolled local evidence and does not qualify installed packages, native
Linux, energy, long-run behavior or the final small-context tail budget. CI
wiring is declared only; hosted execution remains unobserved.

The [native SDK CBOM checkpoint](../research/sdk-alpha1/evidence/20260925-native-sdk-cbom/manifest.json)
adds an explicit producer feature/command and a distinct package-verification
profile. It covers 37 product/backend algorithms and retains the configured
provider's complete cipher/group/signature/certificate-identifier snapshot.
The same TLS factory supplies both configuration and inventory; its mutable
provider is not exposed. A new unknown algorithm cannot be silently omitted.
The historical nine-asset verifier remains separate, and no old receipt is
rewritten. This is not an exhaustive transitive primitive census or a security
audit; [the precise scope](SDK_CBOM.md) remains part of the verified metadata.

The current CLI also fixes a reproduced CycloneDX enumeration error in the
X25519 function field. Real producer output and strict native verification pass
with 37 CBOM / 249 workspace SBOM entries. Forty-three affected CLI/TLS tests,
130 combined BOM/package/publishing/workflow tests, strict workspace Clippy and
rustdoc pass. Feature-disabled or optional-SLH native emission fails explicitly
without a partial successful document. Complete package producer/receipt
integration and the existing platform/device/performance/review gates remain
unfinished; generating a BOM is not evidence of a released or installed SDK.

The first native catalogue draft had 36 assets and omitted the existing
ContextBound combiner. Direct review of the SDK path found that gap; the current
37-asset profile explicitly includes it and rejects the retained earlier output.
Full official CycloneDX 1.6 schema validation rejects the original default CBOM
and accepts the corrected outputs. Both schema evidence and algorithm coverage
are required; neither substitutes for installed-package or security assurance.

The [Apple SDK packaging checkpoint](../research/sdk-alpha1/evidence/20260925-apple-sdk-package/manifest.json)
extends the shared builder with an explicit unsigned alpha profile. ABI **2**,
all 43 alpha exports and the original nine declarations/status values/library
names are retained. Five native Apple targets compile; every single/fat archive
is checked one architecture at a time by the existing strict symbol verifier.
Two assembly attempts using the same native build produce the same XCFramework
ZIP hash; independent clean-toolchain reproducibility is not inferred.

The complete 19,627,772-byte Swift SDK ZIP has SHA-256
`b825c9700f971ba30624e7a57547360fd2f3d9b7b944acae21a43d2aa44cc48b`.
Its closed inventory includes both Swift products, all XCFramework slices,
37-asset native CBOM, 249-entry workspace SBOM, per-target dependency notices
and Rust standard-library notices. Four public API tests pass inside the
builder's consumer and again after extraction outside the checkout, with strict
Swift concurrency and warnings as errors. The outside consumer's selected
static library matches the packaged macOS slice and the executable rejects an
invalid policy through the public owner API.

This is **component-level host installation evidence**, not a completed full
Apple producer run. The component probe reuses the exact validated XCFramework
from attempt 5; it checks that the native Rust inputs and shipped wrapper/notice
bytes are unchanged, then records the updated packaging-tool source snapshot.
The full builder has no completed alpha release manifest. macOS x86_64 and iOS
final-link checks, minimum-OS/device execution, signed receipts and hosted CI
are still unverified. An ARM64 final executable/link map passes independently;
the updated default-SwiftPM link-map gate still needs its full pipeline rerun.

Real build failures exposed mismatched Rust/C Apple deployment defaults,
Xcode 27's single-architecture `lipo -verify_arch` behavior and the thin-only
symbol parser's rejection of a fat archive. Native floors now match macOS 13 /
iOS 16; fat slices are extracted and checked separately. A fresh minimal build
also reproduced the system loader rejecting a host procedural-macro dylib with
a misaligned LINKEDIT string pool when the SDK floor leaked into host tools.
Host/target compiler-environment separation passes the fresh-build check.
The former SwiftPM copy/link progress strings are replaced, for alpha only, by
an actual linker object map plus selected-byte and final-executable checks;
the deprecated native-engine experiment was rejected on its warning and is not
part of the implementation. All failures and diagnostic logs are retained.

The affected Python suites pass 126 tests with warnings treated as errors;
25 workflow-source checks pass again after the CI retention wiring. Shell syntax
and diff checks pass. No Rust implementation changed in this packaging step,
so prior Rust test/Clippy evidence is not presented as a new full run. Available
disk space fell below the builder's 2 GiB reserve (about 1.5 GiB remained), and
the final full build stopped at that guard. More build space has been requested.
No cache, prior failed attempt, historical result or publication receipt was
deleted or relabeled; no signing, deployment or publication was performed.

The [complete unsigned Apple producer checkpoint](../research/sdk-alpha1/evidence/20260926-apple-sdk-pipeline/manifest.json)
supersedes the previous component-only gate status. Available disk space recovered
without any cleanup by this task. Attempt 8 completes the shared producer with
exact source snapshots before/after, both macOS final executables, an iOS ARM64
final executable and both simulator architectures. Selected static archive bytes,
defined ABI 2 symbols and platform/minimum-OS load commands all match. Swift's
four public API tests pass in the generated consumer and after extraction outside
the checkout, with strict concurrency and warnings as errors. Revalidation of
the retained consumer evidence also passes.

The completed unsigned SDK ZIP is 19,628,007 bytes, SHA-256
`0dbe19e850f286308e94dcca559336d611814e2bd67f7e12e15a1e74709c133c`.
It has a schema-6 producer manifest and verified checksums; the prior
component-only ZIP and failed attempts remain distinct. The native XCFramework
ZIP remains byte-identical to the earlier validated native build. A C consumer
compiled with the frozen 0.1.5 header also links that exact macOS static slice
and passes metadata, signed-policy and real KEM roundtrip/atomicity checks.
No macOS x86_64 runtime, iOS simulator/device execution, minimum-OS runtime,
signing or hosted CI claim is inferred from link checks.

Source review found a packaging identity gap: the finalizer used a freshly
generated content manifest without comparing the native payload to the checked
XCFramework. A retained actual-package negative control appends bytes to a copy
of the iOS library and rehashes its content manifest; the old verifier accepts
it. The finalizer now requires the original ZIP digest, verifies its immutable
snapshot and matches all ten native/header/module-map/plist entries before and
after installation. The same changed/rehashed package is rejected; the original
passes. This is a pipeline consistency repair, not malicious same-user isolation.

Xcode 27 exposes the consumer package scheme instead of the older executable
scheme. The producer selects only the two known schemes from a retained, parsed
inventory and still requires the exact final link probe. All 137 focused
packaging/ABI/BOM/remote-consumer tests pass with Python warnings as errors.
Another 58 historical Apple publication/verification regressions pass; the
25 workflow-source checks pass after adding scheme-inventory retention.
The immutable prior checkpoints and historical proof results are unchanged.
Other language/platform packages, installed Swift-to-Linux networking, native
x86/CT/performance qualification and devices remain open.

The [C SDK package checkpoint](../research/sdk-alpha1/evidence/20260926-c-sdk-package/manifest.json)
adds the explicit `sdk-alpha1` mode to the existing C producer. Its schema-3
manifest, 43-export ABI 2 contract and native 37-asset CBOM remain distinct from
the historical schema-2 / nine-export / nine-asset profile. Both static and
versioned shared libraries are built from the same copied source image, with
source-byte snapshots before and after packaging. Existing standalone Git
provenance validation is retained; the primary worktree is unchanged by the
build-only copy and no clean commit identity was manufactured.

The actual macOS ARM64 package passes four pkg-config consumers (legacy/owner,
shared/static), the frozen old-header consumer, and four CMake tests after
extraction outside the checkout. Three additional loader observations identify
the exact packaged dylib at runtime. Installed files and the outer archive are
rechecked against the pre-extraction manifest/archive digests. Package-name and
wrong CMake compatibility-version controls still fail as required. There are
no compiler warning/error diagnostics in the completed producer log.

The package is diagnostic-only because its source image contains uncommitted
implementation changes. Real public-admission controls reject the wrong archive
digest, target, manifest digest and the correctly hashed dirty candidate. No
positive clean-source public run is claimed. Native Linux CI now selects the
alpha profile and distinct archive/version/contract values with fresh verify
directories, but hosted execution has not been observed. The portable Linux
manifest tests cover profile separation, missing/extra payloads, altered source
fixtures and explicit diagnostic admission; they are not native Linux tests.

The affected C package/ABI/BOM/source-wiring suite passes 83 tests with Python
warnings as errors; another 63 shared archive/license/Apple-tooling checks pass.
The retained macOS archive is 5,870,014 bytes, SHA-256
`e7ee6c8ea2ba8de9ea0f4bff374bab42007c0835bfca7e52aac3c5807dd93453`.
The initial standalone copy omitted ten ignored WASM
generated files counted by the existing Rust source digest; the attempt was
stopped, those same bytes were copied and equality was established before the
next build. Historical digest semantics were not weakened. All attempts,
schema/import assertion failures and diagnostic identities remain retained.
Other platforms/languages, installed Swift-to-Linux networking, CT/performance,
and devices still block a complete 0.2.0 release claim.

The [WASM package checkpoint](../research/sdk-alpha1/evidence/20260926-wasm-sdk-package/manifest.json)
adds one product npm candidate with a closed default owner export set, separate
explicit expert-transfer subpaths and both generated Node/web entries. CJS and
ESM share one Node instance; concurrent browser initialization shares one promise,
and loading failures stay rejected without an automatic retry. The actual
archive was installed offline outside the checkout with scripts disabled.
Package/manifest digests and all 153 installed files were rechecked after Node,
TypeScript and browser consumption. It includes 64 target-filtered dependency
license records and Rust standard-library/vendor notices.

Two real binding counterexamples are retained: JS integer ABI conversion admitted
fractional/wrapped/coerced runtime limits, and the WASM trusted-state getter
returned data after runtime close. Purpose selection also coerced strings and
booleans. Original JS values are now validated before conversion without invoking
coercion hooks, and closed/revoked state reads reject. Fresh real WASM calls
preserve signed policy, KEM/derivation and implicit rejection behavior. With the
same regression file, the retained old module fails the runtime-limit rejection
assertion and the new module passes the complete suite. Explicit `free()` revokes
children, rejects stale wrapper use, and leaves the instance
usable for a newly created runtime; no same-realm isolation claim is made.

The final producer passes Node 26.3.0 CJS/ESM consumers and TypeScript 5.9.3 strict
NodeNext compilation. Three expected TypeScript diagnostics independently reject
default expert imports and string-valued limits/purposes. Chrome 153.0.8010.54
passes five actual installed-web cases: roundtrip/policy revocation, missing
entropy, throwing entropy, HTTP 404 WASM initialization, and missing WebAssembly.
Each case records one WASM request and its real status; the deliberate 404 is
retained as an expected negative, with no unhandled page exceptions. Owner
cleanup completes before results are accepted.

The affected Python package/license/Apple/C/workflow/ABI checks pass 58 tests with
warnings as errors. Shared SDK Rust tests pass 18 unit and two compile-fail docs;
WASM Clippy passes with `-D warnings`, and formatting/diff checks pass. wasm-pack's
prebuilt-installer platform warning remains visible and is also present in the
earlier sealed 2026-09-25 logs; it is not a new compiler warning. A browser-runner
attempt failed because its execution sandbox did not expose `URL`; URL handling
was moved into the page environment and the failure is retained.

The final npm archive is 351,032 bytes, SHA-256
`524d5a43b95606e94e54e0494b5f8ccf0f5b10aa3ceeb6ee791463ebd7a33caa`.
Node and web payloads are the same 330,555-byte WASM, SHA-256
`8cb8796a33d73cbf24bcf9cd0371c1d599978f78bc8d5c14db9ec996b25d0d6e`.
No npm publication, signing, commit or push was performed. Hosted CI is updated
for installation/type checks but not observed. Node 24 minimum, other browser
engines/bundlers, Web Worker cancellation, full distribution/security review,
native Linux reference execution, device and CT/performance gates remain open.

The [Rust SDK package checkpoint](../research/sdk-alpha1/evidence/20260926-rust-sdk-package/manifest.json)
adds the `sdk-alpha1` profile to the existing Rust package entry point. It classifies
twelve product crates and six non-publishable application/research/npm-producer
crates, keeps internal dependencies at exactly `=0.2.0-alpha.1`, and preserves the
frozen 0.1.5 ten-crate handoff/upload contract. Two new product crates previously
had `publish = false`: Cargo could pack them individually but could not expose
them in its temporary dependency registry. Their explicit crates.io eligibility,
complete metadata and existing project license texts now permit coherent
pre-publication package verification. No upload authorization follows from that
metadata. All product source archives now include their license texts.

The final macOS ARM64 run uses a fresh private Cargo home and a standalone Git
build copy whose input bytes match the primary worktree. It rebuilds all twelve
Cargo archives, with reference-connection and native-CBOM features explicitly
selected; the AVX2 candidate remains off. Cargo file lists, normalized manifests,
source bytes, dependency requirements and the pinned native-provider inventory
are checked. The existing real `.git` directory provenance guard was retained;
the build clone remains honestly dirty, with no manufactured clean commit.

An external Rust project resolves nine exact extracted `.crate` trees and runs
four real public-API cases: owner/derivation/plaintext transfer/revocation, signed
policy failures and transition, private-store restart/rollback rejection/re-enable,
and mutual-identity reference connection with fragmented encrypted I/O and a
64-KiB request. The last uses an in-memory transport and is not Linux or
Swift-to-Rust network evidence. Cargo metadata rules out checkout dependencies
and mixed versions. Clippy passes with `-D warnings`; exact installed file sets
and bytes plus every original archive are checked after tests, lint and audit.

The workspace (249 packages), fuzz lock (43) and consumer lock (139, including
129 external packages) pass against the same fresh RustSec database commit
`e2111519ba6d14a5da59a7b2e5c8083ae8a37c01`: zero vulnerabilities and warnings,
without advisory, severity, platform or informational-class filters. This remains
a Rust dependency advisory check, not a vendored-C or cryptographic audit. In
`cargo-audit 0.22.2`, `--no-fetch` emits null database-commit metadata; the retained
failed attempt showed this was not a changed lock/database. That mode now binds
the checked clean Git database before and after the audit, rejecting changed or
unbound identities. The actual replay and a negative identity test are retained.

The affected package, frozen handoff, metadata, license, workflow and ABI suites
pass 163 Python tests with warnings as errors. Four actual preflight controls
reject an unknown profile, dirty source without opt-in, existing output and
registry credentials. Three controls using copies of the real installed archives
reject an extra source file, a modified source file and an altered archive digest;
the original consumer remains intact. Formatting, shell syntax and diff checks
pass. The twelve archives total 5,635,333 bytes and the package report SHA-256 is
`6e9dff48f9ba12dd23abd7c982bfd3be06e1aaad53e77d9293606eec5b314e6b`.

Public-registry installation and version-specific publication receipts remain
open. The local compiler was Rust 1.96.1; declared dependency MSRVs do not replace
an actual minimum-toolchain run. Hosted CI selects the new profile but has not
been observed. Other platform packages, installed Swift/macOS-to-Rust/Linux,
current devices and CT/performance still prevent
formal 0.2.0 release readiness. ABI 2 and the native interface source bytes are
unchanged from the preceding checkpoint.

The [JVM SDK package checkpoint](../research/sdk-alpha1/evidence/20260926-jvm-sdk-package/manifest.json)
adds the fixed Maven coordinate `dev.qperiapt:q-periapt-hybrid:0.2.0-alpha.1`,
binary/sources JARs, existing license texts, JDK 25 bytecode and automatic-module
metadata. Publication is to a file staging repository only. The producer consumes
the existing C SDK format, pins its archive/manifest, matches all native source
inputs and the closed 43-export ABI 2 contract, and packages it with the Maven
version directory. No automatic native download, extraction or fallback loader
was added. Binary/source JAR contents, POM/Gradle dependencies, package inventories
and SHA-256 identities are checked before and after outside-checkout consumption.

A retained Java source compiled against the old JAR because Kotlin `internal`
constructors/getters were JVM-public. It could fabricate owner wrappers or alias
another wrapper's handle. Owner constructors are now private; internal factories
and accessors use `@JvmSynthetic`. The same source is rejected with six access
errors and one hidden-getter error, while public signed factories still compile.
This closes accidental Java API misuse, not reflection or hostile same-JVM
access, and does not imply that fabricated IDs previously bypassed native checks.
The original nine C signatures, ABI major 2 and 26 JNI registrations are unchanged.

The macOS ARM64 run uses Temurin 25.0.4.1 and Gradle 9.2.1 with Kotlin 2.4.10.
All 17 source tests run against the matching extracted native C library. A fresh
external Gradle project resolves the exact Maven coordinate under the existing
strict upstream checksum policy, with only the candidate's own checksum entries
appended. Real installed calls cover 0/32/65536-byte contexts, implicit rejection,
all five KDF purposes, explicit expanded-key transfer, signed disable/recovery/
re-enable, tamper/rollback rejection, queued cancellation, executor rejection,
input freezing, quotas, concurrent use and close. The JVM fixture's persisted
state is in memory; no durable host-store claim is made.

A Java caller loads the SDK on the module path with native access granted only
to `dev.qperiapt.hybrid`. The first attempt failed because the classpath main had
not resolved the named Kotlin stdlib module. The corrected documented invocation
explicitly resolves both modules; no permission relaxation was used. Six fresh
processes reject absent/relative/missing/directory library configuration,
ungranted native access under `--illegal-native-access=deny`, and a deliberately
incompatible library's missing symbol. Default JDK 25 warning mode is not claimed
to enforce denial. A separate actual JDK 21 probe rejects the SDK's class version
69.0 before any native call; JDK 26+ execution remains unverified.

The package/license regressions pass 26 Python tests with warnings as errors.
Three CLI controls reject existing output, malformed digest and wrong native
archive digest. Four controls against copies of the real installed bundle reject
a wrong manifest pin, changed JAR, changed native archive and extra file; the
original installed candidate is rechecked unchanged. Java/Kotlin compilation uses
warnings as errors. The affected JVM CI job passes actionlint; full-workflow
actionlint 1.7.12 retains one pre-existing `ubuntu-26.04` label diagnostic. The
prior sealed source contains that label, and the current [official runner list](https://github.com/actions/runner-images#available-images)
documents it. No rule suppression or runner downgrade was applied, and hosted
execution is not claimed.

The final bundle SHA-256 is
`a2f6042bcfd2151a2a62fa9678fd93f76214ea1ea28a67ff6e4b8b067756af9c`;
the JAR is `2ad460d2fd14bddc9e0320301d9c93a7c4a500def8cd882df7e1197958f1ec85`.
The matching native C archive is
`88c8908796ad11db5991f30cf8f64b297f0f25be39f2bb5fb4e1bdcde62b6729`.
Initial failed attempts and their causal corrections are retained separately.
No Maven Central upload, signing, commit or push was performed. Linux/Windows
JVM execution, Android ART/devices, installed Swift/macOS-to-Rust/Linux reference,
and native x86 CT/performance still prevent stable
0.2.0 release readiness.

### Current C and JVM packages (2026-09-27)

The [C/JVM refresh checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-current-c-jvm/manifest.json)
rebuilds the native macOS ARM64 C package from the current source, including the
borrowed public-key storage. All four external pkg-config consumers, the
frozen-header consumer and all four CMake tests pass. The archive retains the
43-export ABI 2 contract, its shared/static library identities, the native CBOM,
workspace SBOM and third-party notices. This is a dirty diagnostic build, with
current-source fingerprints verified before and after packaging.

A new JVM bundle embeds that exact C archive. Its JAR remains byte-identical to
the earlier candidate, while the native library and bundle identities change.
All 17 source tests run with zero failures/errors/skips; fresh external Kotlin
and Java module-path consumers pass, along with six expected loader rejections.
The same JDK 25.0.4.1, Gradle 9.2.1 and strict/offline dependency checks are used.
The run logs contain no warning diagnostics. An additional actual Java
module-path run records dyld loading the exact extracted new native library,
without another SDK image or transition; its byte identity is rechecked.

The initial diagnostic wrapper mistakenly passed the native staging directory
to an installed-payload verifier. It rejected the staging dylib's 0755 mode;
the archive had already passed its real extraction/installation checks with
0644 files. The wrapper now verifies that extracted directory. The failed
preflight and prior wrapper are retained; no product validator or file-mode
requirement was changed. No source commit, remote publication, native Linux/
Windows, Android ART, broader JVM/OS matrix or release approval is claimed.

The [Android SDK package checkpoint](../research/sdk-alpha1/evidence/20260926-android-sdk-package/manifest.json)
adds `--profile sdk-alpha1` to the existing Android AAR producer and verifier.
The [current-source Android refresh](../research/sdk-alpha1/evidence/20260927-sdk-current-android/manifest.json)
records the subsequent native rebuild and Maven/R8 consumer outcomes separately;
those build results do not establish ART or physical-device execution.
That rebuild exposed a producer integration defect: copying every top-level
`LICENSES` file also staged the Windows compiler's Rust 1.97 notice, which the
unchanged closed AAR inventory correctly rejected. The producer now copies
the required Apache/MIT base notices and the existing profile-specific notice
map only. The actual notice-staging regression rejects the old behavior for
both profiles and passes after the repair; required notice bytes and the
strict archive inventory remain unchanged. The real failed four-ABI attempt
is retained separately from subsequent package results.
The default retains the frozen 0.1.5 nine-export/nine-JNI/schema-4 contract.
The explicit SDK profile requires 43 C exports, 26 JNI methods, all owner classes,
non-preview Java 11 bytecode, minSdk 23 and the exact native/Rust notices. Its
manifest has kind `qperiapt.android_sdk_aar_manifest` and schema 5; the native ABI
remains 2. Existing output directories are rejected in the SDK profile. No
source, ELF, signature/shape, hardening, alignment, license or R8 check is skipped.

All four Android architectures rebuild with Rust 1.96.1 and NDK 29.0.14206865.
Their FFI export sets, `JNI_OnLoad`-only JNI export, 16-KiB ELF load alignment,
stripping, system dependencies and library identities pass the existing verifier.
The real compiled Java descriptor table matches all 26 registrations, and a
version-only R8 consumer retains every native declaration and the exception
callback constructor. The production license closure contains 69 packages in
the x86_64 superset and covers all four target closures.

The new local-only Gradle publisher stages
`dev.qperiapt:q-periapt-android:0.2.0-alpha.1`, its sources JAR and licenses. The
package helper pins the original AAR and manifest, checks Maven metadata/source
bytes/checksums, and installs the resulting archive outside the checkout. It
uses the existing AGP 9.4.0 / Gradle 9.7.1 template with an explicit SDK/Maven
mode; legacy file-AAR consumers remain the default. Both full and minimal
nondebuggable Release APKs build through that coordinate with R8 and warnings
treated as failures. Actual JavaCompile input sets and JVM properties, resolved
AAR bytes, normalized merged keep-rule origins/bodies, 26 DEX native methods,
exception callback, eight identical native payloads, uncompressed native loading,
`extractNativeLibs=false` and 16-KiB ZIP alignment are checked. The full workload
uses public owners, KDF, plaintext transfer, cancellation/input freezing and
signed revoke/recover/re-enable. Its state persistence is an in-memory fixture.

The APKs are unsigned and have **not run on ART**. Their build success does not
qualify API-23 runtime support, the canonical 16-KiB emulator, a physical device
or the source-bound runtime proof profiles. At that checkpoint the Android
CI/runtime collector still targeted the legacy contract. The subsequent SDK
profile integration is recorded below; no hosted CI success is claimed.

The retained failures explain the changes. Reusing the Rust build copy failed
the source guard because an ignored WASM-generated `.gitignore` remained there;
a fresh build-only source copy with the selected source bytes resolved it without
weakening the guard or deleting that copy. Gradle 9.7.1 rejected deprecated task
delegate syntax, fixed with `tasks.register<Jar>`. The initial consumer assumed
one runtime artifact; the actual graph contained AGP's built-in Kotlin stdlib
2.2.10 and annotations 13.0, now captured in an exact three-artifact application
closure. The AAR POM itself adds no dependencies. This is consistent with
[AGP's built-in Kotlin model](https://developer.android.com/build/migrate-to-built-in-kotlin).
The new sources-JAR reader handles Gradle directory entries without relaxing the
canonical AAR parser. Every failed attempt remains separate from the final run.

The final affected suites pass 101 Python tests with warnings as errors, plus
ShellCheck, shell syntax and diff checks. Seven actual admission controls reject
a wrong schema, missing JNI registration, wrong export count, changed Java source
pin, SDK manifest supplied to the legacy profile, wrong bundle pin and mutated
installed AAR. The original installed bundle is rechecked unchanged.

The 14,778,624-byte AAR is identical across the three successful native builds,
SHA-256 `55fe9f89c9a30ca1179e583220c3f4ca0ed8ff392b43427b67936e5538cf6621`.
The final 6,268,967-byte SDK bundle is
`64192fcbc8fe7dc704f7b4e6ad646e4734e55ed3f905f813c626a2fc6379505b`;
its manifest is `41151558657e6500d816e97c923a2dac254c5b81d77a64cd5930df8f30f1d40a`.
The build source tree is
`2bebd9ba4446cf69bafe9bfa48ed7a1a9bb4a9c06e73cf365560665cef5642ad`.
Its 819-file source copy matched the primary worktree at build freeze; this
readiness update is recorded separately as a post-build status-document change.
No public upload, signing, device operation, commit or push was performed.
About 1 GiB remained free after the final build; no existing caches/candidates
were deleted. SDK runtime/CI integration, installed Swift/macOS-to-Rust/Linux,
device and minimum-version execution, and CT/performance
continue to block formal 0.2.0 release readiness.


The [Android SDK runtime contract checkpoint](../research/sdk-alpha1/evidence/20260926-android-sdk-runtime-contract/manifest.json)
adds explicit full/minimal SDK profiles to the existing collector, AGP builder,
receipt verifier and raw-artifact intake. Package version remains
`0.2.0-alpha.1`, ABI major remains **2**, and both library identities remain
unchanged. Legacy maintenance profiles retain their old proof kinds, projection
shape and arm64 scope. SDK callers must explicitly select arm64-v8a or x86_64;
the projection binds architecture, emulator kind, API 35 and 16-KiB page size.
Missing or unsupported SDK architectures fail before the runtime lane is taken.

The SDK proof checks the separately typed AAR manifest, current SDK source and
ABI contract hashes, all 26 JNI declarations/callbacks in actual DEX dumps,
exact JavaCompile inputs, tool/JVM identities, pinned R8 rule origins, all eight
native library payloads, uncompressed native loading and workload-specific
assets. SDK full/minimal sources are separate from their legacy counterparts.
The added `verify-export` command replays the entire exported profile closure
without the original AAR/run paths. Source, private ADB, owned emulator, signer,
installed-APK ownership, cleanup and clean-tree guards remain mandatory.

CI now builds the SDK AAR, uses the closed `android-sdk-alpha1-aar` intake,
qualifies the Maven consumer to prepare the offline AGP cache, and runs both
SDK workloads against the same x86_64 API-35/16-KiB candidate. Available evidence
is retained if a later step fails; a partial closure does not pass the paired
gate. The 60-minute job limit bounds both profiles and package qualification.
The [maintainer guide](SDK_ANDROID_RUNTIME.md) records selectors and replay.

Actual local Gradle/R8 file-AAR consumers built both APKs outside the checkout.
Both APKs are byte-identical to the preceding installed Maven consumers:
`7527e6d49264763106762a8de54f9bc985492de67edefe4c061777a3206f5cf0`
(full) and `b5cdf8769f2cbfd4e136543e306680d2bda7672ee0d1823062f84769549360bc`
(minimal). Both retain 26 JNI methods and the original eight AAR libraries,
with 16-KiB ZIP alignment and no application keep rules. These remain unsigned
build artifacts, not ART execution. The exact template/build source snapshot
is retained separately from the final collector/CLI changes and documentation.

The final relevant suites pass **426 tests with warnings as errors**, including
legacy runtime, maintenance/export transactions, SDK scope/mutation rejection,
JNI/ELF/R8 checks and raw-container intake. The maintenance suites were rerun in
a standalone Git source copy after the linked-worktree guard correctly rejected
the initial environment; the guard was not changed. An actual collector CLI
control rejects the uncommitted SDK source before creating any build directory.
A real raw ZIP containing the frozen AAR is rejected by the old intake and
accepted byte-for-byte by the SDK intake. No test fixture is ART evidence.
Current 43-export and frozen nine-export header contracts both report ABI 2.

Shell syntax, ShellCheck, diff checking and the two Android jobs' actionlint
checks pass. Full-workflow actionlint 1.7.12 still reports the prior
`ubuntu-26.04` label as unknown; the [current official image table](https://github.com/actions/runner-images#available-images)
confirms that label. That tool-version limitation is retained, not suppressed,
and the whole workflow is not reported lint-clean or hosted-CI verified.

No implementation commit, push, package signing, device operation or publication
was performed. Read-only host observation still finds an existing ADB listener
on port 5037. Exact-source hosted CI, the canonical arm64 emulator, minimum/current
API and physical-device runs, release-source freeze, cross-platform/reference
execution and performance/CT remain open. **0.2.0 is not ready
for formal release.**


The [installed SDK connection checkpoint](../research/sdk-alpha1/evidence/20260926-installed-sdk-connection/manifest.json)
adds a package consumer around the existing TCP driver, with no duplicate
protocol implementation. The Swift application resolves only the complete SDK
ZIP's binaryTarget and wrappers. The Rust application resolves nine exact crate
archives outside the checkout; both peer programs come from shipped crate
examples. Cargo metadata and lock checks bind 127 external packages to the
workspace's versions, registry origins and checksums. Rust 1.96.1, warnings-denied
compilation/Clippy, and strict Swift release/concurrency compilation pass.

An actual preflight rejected the old Swift ZIP paired with the newer Rust
cohort because their native workspace fingerprints differed, despite identical
alpha SemVer. The retained differences include SDK/host-store manifest metadata
and product WASM updates. A complete Swift producer rerun (`sdk-apple-run-9`)
rebuilds/checks all five Apple architectures, verifies the exact 43-export ABI 2
surface, links macOS/iOS targets and passes both four-test host installation
consumers. The resulting native ZIP is `cb30961c78c1bbb121a00e450cb95bff9e8e0bf361ebb9a828690c762ba9fab9`;
the full SDK ZIP is `09ca75158c4d9bb339617505d6e160fc48a6e7378e5e92ab9797cfa2d6124343`.
Both it and the Rust cohort now bind native workspace digest
`b9a658eca7e1131576ed6981450ffc6fe16c25df2653854b8f108bed45f566ac`.

The installed Swift linker map identifies 222 objects from the exact packaged
static archive, SHA-256 `0814830ed774e2f244f65125617bfb4b4d5d2152dc54f9e31067e629d0870a6f`.
Each actual client process identifies the frozen executable through dyld and
loads no separate Q-Periapt dynamic library. The twelve real TCP cases pass:
reconnect and empty/maximum payloads; concurrent busy rejection; handshake and
request timeout/cancellation; runtime revocation; hostname/context mismatch;
persisted revocation, process-restart rollback refusal and re-enabling on both
peers. Reusing the same archive-built Rust executable against OpenSSL 3.6.3
passes eight independent standard TLS cases, without treating those as the SDK
application-policy protocol.

Twenty focused Python regressions pass with warnings as errors. Four additional
real artifact/log controls reject an incorrect ZIP pin, an old native ZIP paired
with the refreshed wrappers, changed extracted Rust source and an injected
separate SDK dynamic-load record; originals re-verify unchanged. Inputs, raw
logs, link map, complete package pins, consumer source and binary identities,
and the rejected older cohort are retained. Generated private test keys remain
in their private run directory and are excluded from the checkpoint.

Both runtime endpoints in this result are **macOS ARM64 on loopback**.
`native_linux_server_executed=false` and `release_claim_eligible=false` remain
explicit. This closes the local installed-package boundary and strengthens the
standard interop evidence; it does not substitute for the required native Linux
server, target-device/minimum-OS, controlled performance/CT, exact-source hosted
CI or final release transaction. No implementation commit,
push, signing or publication was performed.


A [loader-provenance follow-up](../research/sdk-alpha1/evidence/20260926-installed-sdk-loader-provenance/manifest.json)
fixes a concrete verifier counterexample: a filename with the expected client
path as a prefix was accepted by the original substring test. The retained old
function accepts `/frozen/client-extra` as `/frozen/client`; the corrected
function rejects it. Only an exact UUID-qualified dyld image record counts as
identity, and it must occur once. Unknown dyld formats fail; the two actual
macOS delayed-loading transition forms are explicitly parsed without counting
as image identity. They remain subject to the static client's prohibition on
separate SDK libraries. The first strict-parser run failed on those legitimate
transition messages and is retained with its unsuccessful status. The updated
parser passes all twelve original real logs and the added prefix, plain-text,
malformed-record and dynamic-library counterexamples. Final fresh-run status
is recorded in the follow-up checkpoint rather than inferred from this replay.

The corrected collector then completed a fresh third installed-package run:
all twelve TCP cases pass after rebuilding both external consumers, with
warnings-denied Rust/Clippy and strict Swift compilation. The final four
artifact/log controls also pass against those unchanged installed packages.
The second run's `completed=false` receipt remains distinct from this success.
The independent eight-case OpenSSL result remains bound to the first run's
archive-built Rust binary and the same pinned Rust cohort; no binary identity
is silently substituted. The follow-up source snapshot and final run receipt
are the current evidence for loader admission.

## Actual Rust minimum-compiler qualification (2026-09-26)

The [minimum-compiler checkpoint](../research/sdk-alpha1/evidence/20260926-rust-sdk-msrv/manifest.json)
keeps the declared product minimum at Rust 1.85 and the native ABI at 2. An
isolated, task-local official Rust 1.85.0 toolchain actually built the default
workspace with its existing lock and warnings denied. No user-global toolchain
or dependency version was changed. The retained full-workspace test admission
fails before compilation because Criterion, Orion, rcgen and time require newer
compilers. Full repository development tests and package production continue to
use the pinned Rust 1.96.1 toolchain; that failure is not relabeled as a pass.

The previous installed consumer had a certificate-generator dependency on rcgen.
Its exact manifest and source, recovered from the previous source checkpoint,
were run with the same nine crate archives and Rust 1.85.0. Cargo rejected rcgen
0.14.10 and its time dependencies. The current consumer uses newly generated,
explicitly public TLS test identities instead. All four existing test behaviors
and their assertions remain: owned hybrid keys and purpose derivation, explicit
transfer and revocation, signed-policy transitions, real private-store recovery
and rollback rejection, and mutual authentication with fragmented reference
connection traffic. OS entropy and hybrid key exchange remain live; only the
certificate generation was moved out of the consumer build. These fixed test
keys are not deployed credentials.

The current consumer compiled outside the checkout using the actual minimum
compiler and passed all four tests, with no ignored or filtered cases. Its nine
product packages came from the same pinned Rust cohort report
`6e9dff48f9ba12dd23abd7c982bfd3be06e1aaad53e77d9293606eec5b314e6b`.
All 98 external dependency versions, registry origins and checksums match the
workspace lock; no resolver downgrade was used. The resolved consumer lock hash
is `dc69c92a743f86069127eefc7d17a33a43104464cfcaa3d9bdc23399d68876a2`.
The same consumer and lock also passed four tests and strict Clippy on 1.96.1.
Both runs used macOS ARM64. The reference transport here is in memory; the
separate installed TCP/OpenSSL evidence above retains its original compiler and
binary identities.

The package CI job now follows canonical production with this minimum-compiler
consumer, using an explicit 1.85 sysroot and retaining success or failure logs.
The separate default-workspace MSRV build remains intact. Inspection of the
previous pinned `1.85` action showed that its embedded installer selected 1.85.1.
Both minimum-version jobs now use the pinned generic action with an explicit
1.85.0 input and command selector, matching the compiler actually qualified here.
Archive extraction and
product/dependency resolution checks are shared with the installed connection
qualifier. New package production still requires exact current-source archive
correspondence. The gate additionally requires all four consumer tests to have
actually executed. Twenty-six focused Python regressions, Rust formatting and
Git whitespace checks pass. CI contract checks exposed an earlier inventory
mismatch and Kotlin's missing explicit compiler selector; the selected compiler
is now pinned there too, and the exact job inventory assertions remain enabled.

The three affected CI jobs pass actionlint. The installed actionlint 1.7.12 still
rejects the pre-existing `ubuntu-26.04` label elsewhere in the full workflow; its
full diagnostic is retained, without suppressing the check or changing that
runner. No hosted CI result is claimed. Native Linux, the remaining platform and
feature matrix, device/browser execution, CT/performance,
signed distribution and registry publication remain open. No source commit,
push, device operation, publication or release was performed.

### Current source and C ABI follow-up (2026-09-27)

The [current-source MSRV checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-current-msrv/manifest.json)
refreshes the compiler check after the borrowed public-key storage change.
The exact task-local Rust 1.85.0 compiler builds all eighteen default workspace
packages offline with the unchanged lock and warnings denied. The build takes
59.66 seconds on this macOS ARM64 host. Its new debug library has ABI major 2,
extension revision 1, package version 0.2.0-alpha.1 and exactly 43 C exports.
The legacy C consumer compiled against the frozen 0.1.5 header and the current
owner C consumer both execute successfully. Each loader log identifies this
exact newly built library, and source/tool/library hashes remain unchanged.

This follow-up checks current source and an unpackaged native library. It does
not refresh the earlier installed Rust archive cohort or claim distribution
identity, other targets, exhaustive features or a new full development suite.
CodeQL still needs its exact-source hosted execution: the Rust gate binds the
Linux runner's same-run database and linked CLI 2.26.2, plus the 1.94.0 analysis
sysroot. This Mac has neither that database nor a CodeQL command on its PATH;
the gate has not been weakened or substituted with local compilation.

### Current Rust archive cohort (2026-09-27)

The [current Rust package checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-current-rust-package/manifest.json)
now refreshes the archive evidence separately. Cargo 1.96.1 packages and rebuilds
all twelve product crates, then a fresh project outside the checkout consumes
nine of those exact extracted archives. All four public API tests and strict
Clippy pass. A second fresh external consumer passes the same four tests using
the actual Rust 1.85.0 compiler and the same archives. Both retain the same 98
external dependency versions, sources and checksums, and the same consumer
lock. No test is ignored or filtered. The native ABI remains 2.

The workspace, fuzz and external consumer locks pass unfiltered dependency
audits against RustSec database commit
`e2111519ba6d14a5da59a7b2e5c8083ae8a37c01`, covering 249, 43 and 108 packages,
respectively. These scans concern the represented Rust dependency graphs;
native-provider review, binary CT and other security gates remain separate.
The retained source-control check rejects the old cohort as stale and accepts
the new cohort for current workspace digest
`1572a7bd84a09e4734e01ed568ce57e7e432a6bc6fb376144c3533bcc8a80ea2`.

The build-only standalone checkout is byte-matched to the primary source.
Its initially missing ten ignored WASM generation files are copied and retained
by hash because the existing workspace digest includes them. No digest rule
was weakened, and those files were not added to the Git source index. The new
candidate remains explicitly dirty and diagnostic: this is macOS ARM64 archive
consumption through external path patches, not public registry installation,
hosted CI, Linux execution or a clean committed release. Other language package
cohorts retain their own source identities and qualification requirements.

## Complete artifact quality check and installation entry (2026-09-26)

The [quality checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-quality-and-install-entry/manifest.json)
records a complete run of all 88 `artifact/test_*.py` modules: **2,205 tests pass**
on macOS ARM64 / CPython 3.14.7, with warnings treated as errors. It used the
existing standalone build-only checkout, whose 833 selected source files were
matched byte for byte and whose index includes all 137 current Rust files. The
build copy's prior files and index-status records were retained; the primary
worktree, its adjacent cache and its index were not cleaned or reset. No source
commit was created. The final ledger paragraph is a documentation-only addition
after that run; the tested source manifest is retained separately.

The first complete attempt in the managed worktree recorded 12 failures and 96
errors. Most were the existing standalone-Git requirement and a retained local
bytecode cache, but it also found actual SDK integration defects: 16 direct JSON
parse sites in eight new artifact modules bypassed the shared strict parser,
and several wiring assertions still described legacy package profiles. The
parsers now reject duplicate keys and non-finite values through the existing
`evidence_io` boundary. An actual malformed Rust cohort report and an actual
packaged Maven module with duplicate fields were accepted by the retained old
verifiers and rejected by the new ones. Rehashing all Maven checksum files did
not bypass the new rejection. The original Maven package still passes and its
bytes remain unchanged; this is metadata admission evidence, not a fresh JVM
execution or a claim of an exploitable cryptographic flaw.

Profile wiring checks now require the exact SDK Android artifact, both full and
minimal AGP workloads, the bounded runtime job, and the selected Linux/Android
alpha filenames while preserving legacy publication contracts. The Swift
manifest test checks both sides of its existing schema-6/schema-5 selection.
CodeQL's required Rust inventory increases from 106 to the actual 137 files,
including the SDK, host store and external consumer; its exact-path and
extraction-quality requirements remain enforced. No CodeQL database analysis
was executed. Rust 1.94.0 successfully checks the entire workspace and all targets
with warnings denied. The actual Rust 1.85.0 outside-checkout consumer was rebuilt
with the updated tooling and again passes four tests from nine pinned archives,
with all 98 external dependencies unchanged. Current and historical ABI header
contracts pass at 43 and nine exports respectively, both ABI 2. These header
checks do not claim a new dynamic-library execution.

The [single installation entry](SDK_GETTING_STARTED.md) now separates library
version, ABI, platform packaging revision and observed support for all six
language surfaces. README no longer directs new Android/Linux 0.1.5 consumers
to a supposedly unpublished r2 candidate. Current GitHub release metadata and
the retained r4 verification record agree on the producer commit and all seven
asset names, sizes and digests. This was a read-only observation; no historical
device run, release attestation or anonymous-download check was rerun. All 66
relative links in the entry documents resolve.

A concrete implementation gap remains in Windows packaging:
`windows-package.ps1` selects 0.1.5 and explicitly rejects a different Cargo
package version, while `windows_package.py` still verifies the nine-export
legacy payload. The current workspace is 0.2.0-alpha.1. Both Windows CI jobs
therefore still need a separately closed SDK producer/consumer profile; the
unit-suite pass does not make those jobs or a Windows package valid. This is the
next packaging implementation task. Final packages/receipts must then be
regenerated from frozen source. Hosted CI, native Linux, devices, other runtime
floors and controlled performance/CT remain open. No
publication, signing credentials or device operation occurred.

## Windows SDK profile implementation (2026-09-26)

The [Windows profile checkpoint](../research/sdk-alpha1/evidence/20260926-windows-sdk-profile/manifest.json)
advances the packaging gap identified above. `windows-package.ps1` and
`windows_package.py` now share an explicit `sdk-alpha1` selector for
0.2.0-alpha.1. Its separate schema-4 manifest requires 43 C exports, the 37-asset
native SDK CBOM, exact shipped owner/frozen-header fixtures, target-specific
notices and the actual Rust 1.97.0 standard-library notice. The legacy default
still requires 0.1.5, schema 3 and nine exports. ABI major **2**, the original
declarations/status values and all three Windows library filenames remain
unchanged. The alpha manifest explicitly rejects a release-ready relabeling.

Both Windows CI jobs now select the alpha producer and archive consumer. The
producer requires clean source, a fresh output directory and the pinned MSVC/
Rust toolchain checks. Its private Cargo cache is below the mapped source root;
locked dependency fetching precedes offline native/BOM/license construction.
Unpacked consumers live outside the checkout and exercise legacy and owner APIs
through direct dynamic/static links and four CMake tests. The import library
must expose every SDK thunk and import-address symbol; DLL/static-library checks
remain separate. Archive/payload digests are checked again after consumption,
and failed attempts are retained. Windows provision/open/update-store calls are
explicitly tested for unsupported-platform errors and zeroed output handles.

Local validation uses macOS ARM64. All 89 artifact modules pass, totaling 2,210
tests with warnings treated as errors. Actual PowerShell 7.6.4 execution checks
the production command boundary and synthetic import-symbol admission, including
missing, extra and duplicate entries. A retained zero-status CMake-warning
reproducer was accepted by the initial output filter and rejected after the
filter was corrected; ordinary, developer and deprecation warnings are covered.
The latest shared C fixture compiles and runs through both retained macOS
libraries outside the checkout. Its headers and native Rust source digest match
that retained package; the Windows branch is additionally syntax-checked by
Clang. This is not an MSVC build or native Windows execution. No replacement
macOS package is claimed from recompiling that consumer.

After the second complete suite, the PowerShell import-list comparison gained
an explicit cardinality check and a merged-name fixture. The final PowerShell
sources and all 52 Windows profile regressions were executed again with their
input hashes recorded. The checkpoint preserves that small source delta and
its focused validation separately from the full-suite source snapshot.

Both affected CI jobs pass actionlint. Full-workflow actionlint still reports
the existing `ubuntu-26.04` label unsupported by local actionlint 1.7.12; the
unfiltered diagnostic is retained. No hosted CI run is claimed. The
[Windows guide](SDK_WINDOWS_PACKAGE.md), unified installation entry and C README
now distinguish the implemented profile from native qualification; the C README
also corrects its obsolete 26-export and pre-r4 distribution descriptions.

Windows/MSVC production and archive execution, Linux reference execution,
minimum-runtime/device coverage, CT/performance,
source freeze and final package regeneration remain open. Source was not
committed or pushed, and no device, signing or publication operation occurred.

## Exact Node 24 minimum runtime (2026-09-26)

The [minimum-runtime checkpoint](../research/sdk-alpha1/evidence/20260926-wasm-node24-minimum/manifest.json)
records actual installed WASM consumption under Node **24.0.0** and **26.3.0** on
macOS ARM64. Both run the same newly produced archive
`c27d60b8fc571da51cddfbdddbb63fda50ab56fc6c4facb84fe6112b7316004a`, with manifest
`2098af7b2481556a437d31900a30885f14c0363dcb046d0e24d30d1ea38465e9`. The minimum
runtime is the official Node 24.0.0 macOS ARM64 distribution; its published
archive checksum and executed binary hash are retained. It is installed under
the task's tool directory and does not replace the host Node installation.

The producer and archive qualifier now share one installation/execution path.
It pins archive and manifest digests, requires matching current source inputs,
uses the explicitly selected Node executable for npm and SDK calls, records its
actual path/version/hash, and rechecks tools, source and installed payload after
execution. Both consumers run outside the checkout with offline installation,
scripts disabled, verified package inventory and strict TypeScript 5.9.3
NodeNext checks. Owner quotas, close/revocation, expert transfer, five derivation
purposes, implicit rejection, strict numeric inputs and missing-entropy behavior
pass. CJS and ESM share the same classes and WASM instance. The entropy-failure
child also checks spawn failures and diagnostics.

Four actual negative invocations reject an incorrect archive digest, incorrect
manifest digest, a historical source cohort and a newer Node executable offered
as the exact minimum. All fail before npm installation and produce no success
receipt. A separate real-package control shows that the previous verifier
accepted boolean/float schema versions; the current verifier rejects both.
The original packages remain unchanged.

All 89 artifact modules pass: **2,213 tests**, with warnings treated as errors.
The complete run uses 837 byte-matched source files in the retained standalone
build copy. Only this ledger update follows the test snapshot. The affected WASM
job passes actionlint and now switches to exact 24.0.0 after production to
consume the same archive; no hosted result is claimed. The existing wasm-pack
0.15.0 prebuilt-platform warning is retained in both build logs and remains
separate from SDK/compiler diagnostics.

The new archive's 152 payload files are byte-identical to the previous WASM
candidate; its manifest now binds current source and tooling. Previous Chrome
execution keeps its original archive identity and is not relabeled as a new
browser run. Native ABI 2, 43 C exports and 26 JNI registrations are unchanged.
The [installation entry](SDK_GETTING_STARTED.md) and
[WASM package guide](SDK_WASM_PACKAGE.md) now report the observed minimum.
Linux/Windows runtime floors, other browsers, bundlers/workers, native platform
and device coverage, performance/CT, source freeze and final
release coordination remain open. The earlier request to submit/push the
candidate for native CI is still pending; this checkpoint involves no remote
write, device operation or publication.

## Stock Firefox and current Chrome execution (2026-09-26)

The [browser-engine checkpoint](../research/sdk-alpha1/evidence/20260926-wasm-browser-engines/manifest.json)
adds actual stock Firefox 156.0.1 / geckodriver 0.37.1 execution on macOS ARM64.
Chrome 153.0.8010.54 was also rerun. Each completes the same five installed-package
cases: roundtrip, missing entropy, throwing entropy, actual WASM HTTP 404 and
missing WebAssembly. Both observe the expected single WASM fetch/status and
complete owner cleanup. Firefox has no SDK-page error or warning; Chrome has
only the expected HTTP 404 console error in the initialization-failure case.
The actual browser/profile identities and protocol records are retained.

The first Firefox run passed SDK assertions but exposed privileged browser
diagnostics. Three fresh-profile, no-SDK controls distinguish their sources.
An empty `data:,` favicon alone reproduces the MIME-sniffer error; a valid SVG
does not. The fixture now supplies that SVG, and the final Firefox run has no
favicon error. Sandbox-extension denials, storage-backend warnings, remote
experiment configuration errors and actor/shutdown messages also occur without
loading the SDK. Those unfiltered logs and unresolved environment limitations
remain recorded. No sandbox or system protection was disabled to remove them.
Functional success does not establish complete browser/OS security qualification.

The updated fixture is bound to a freshly generated archive
`9eaf0d196fbf7ca043976cb8adb91559d2e3100e72b8589f5620d5fe224a458b`, with manifest
`a723e08ec49d3e4b59d6114246ed596aa0bcda8a98b4344698508c1de078142c`. Node 24.0.0
and 26.3.0 consume that same archive and again pass lifecycle/entropy and strict
TypeScript checks. All 152 shipped payload files equal the previous candidate;
the new manifest captures the fixture/source change. Native ABI 2, 43 C exports
and 26 JNI registrations remain unchanged. Seven relevant package regressions
and Git whitespace checks pass. The earlier complete 2,213-test run remains
bound to its prior source snapshot; this one-line fixture correction is covered
by actual Node and browser execution rather than a claimed new complete suite.

Safari 27 was probed with the system driver and returned an explicit refusal:
its Allow remote automation setting is disabled. It remains unchanged, and no
Safari result is claimed or replaced with Playwright WebKit evidence. The
[browser guide](SDK_BROWSER_RUNTIME.md) and installation matrix expose this gate
and the Firefox host diagnostics. Test browsers use task-owned or isolated
profiles, and the started sessions/fixture servers are closed afterwards.
Safari authorization, remaining browser/platform/runtime floors, bundlers and
workers, native CI, devices, performance/CT and final release
coordination remain open. No source commit, push or publication occurred.

## Dedicated browser Worker execution (2026-09-26)

The [Worker checkpoint](../research/sdk-alpha1/evidence/20260926-wasm-dedicated-workers/manifest.json)
closes the local dedicated-module-Worker execution gap in Chrome 153.0.8010.54
and stock Firefox 156.0.1 on macOS ARM64. The window and Worker execute one
shared acceptance module, each covering all five installed-package scenarios.
The suite verifies the actual global type, real entropy/cryptography, strict
numeric/length/policy boundaries, derivation, revocation and explicit owner
cleanup. Each case records one exact WASM request and its required status.

The parent rejects Worker startup/message errors and malformed completion,
enforces a 15-second deadline and terminates its owned Worker in every outcome.
Four actual Chrome negative controls cover startup exception, malformed result,
cleanup exception after all real SDK assertions, and absent completion. Each
fails as intended and leaves no Worker. Chrome's ten real SDK scenarios pass
again after removing the interceptions. Firefox records the Worker owner realm,
destruction and no remaining worker realm after each case.

A first Firefox collector attempt incorrectly expected an origin-only value
from BiDi's Worker realm metadata. The driver supplied the complete script URL,
matching Mozilla's implementation. Its failed run is retained; the corrected
collector requires that exact URL, owner realm and destruction. SDK assertions
were not weakened. Existing Firefox/macOS privileged-process diagnostics remain
unresolved and do not become a browser-security qualification.

The archive is
`783820ca9feae5d0db97d241e6f7c74b63e10800a4aa76dd5b49b219b8747c81`, with manifest
`6a3a7c1893f3f66d8b9b7007a4a7fbad3139253eff91c90d9cd43e4566fff1e7`. Node 24.0.0
and 26.3.0 both consume that same archive with strict TypeScript checks. All 152
shipped payload files are identical to the previous browser archive; the
manifest binds the new shared fixture and producer input list. Seven affected
artifact tests and JavaScript syntax checks pass. The earlier 2,213-test full
suite is not represented as a new full-suite run after this fixture change.

ABI major remains 2, with 43 C exports and 26 JNI registrations. Source changes
are limited to shared browser fixtures, their consumer-copy list and guidance.
Forced termination/erasure, shared/service workers, Node worker threads,
minimum/mobile browser versions and bundlers remain separate gaps. Native
Linux/Windows CI, current devices, performance/CT, final
source freeze and release publication remain open. Neither pending CI nor
Safari-setting authorization has been assumed.

## Shared dynamic-loader evidence check (2026-09-26)

A current-code quality review found that the performance diagnostic still used
path-suffix text matching for its dyld evidence, while the shared connection
verifier's dynamic mode only required the selected library to be present. Four
retained controls show the old performance guard accepting ordinary log text,
duplicate selected-image records, an additional SDK image and an additional
SDK transition. The latter two also pass the old shared dynamic verifier.

The [dynamic-loader checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-dynamic-loader/manifest.json)
replaces the parallel performance guard with the shared strict verifier and
requires that no other named SDK image/transition is present. SDK-name matching
uses basenames, fixing the observed false rejection of an unrelated library
inside a `qperiapt`-named directory. New regressions fail on the old code and pass
after the repair; all nine affected tests pass. These controls concern evidence
attribution, not a demonstrated attack on the SDK's cryptographic implementation.

A fresh current-source C/Swift run completes five full 1,000-pair blocks across
all seven cells in both surfaces, totaling 140,000 measured calls plus warmup.
All ten real process logs identify the frozen library under the repaired gate;
source and binaries remain unchanged during the run, and compilation is free of
warnings/errors. Existing ten performance and twelve installed static-client
logs are separately revalidated against their retained identities. That replay
is not presented as a new installed connection run. Only documentation changes
follow the new measurement snapshot.

No cryptographic implementation, Rust/Swift product API, ABI major, export table
or package version changes in this follow-up. The uncontrolled host capture is
a diagnostic and does not close small-context P99, installed-package timing,
allocation/concurrency/long-run/energy, CT, native platform/device, hosted CI
or final publication gates.

## Full reference connection timing (2026-09-26)

The [connection-timing checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-connection-timing/manifest.json)
adds a bounded measurement mode to the existing Swift/Rust reference probes and
a source/binary-bound driver. It reuses the same connection engine, mutual pinned
TLS authentication and policy/context confirmation. Only per-request diagnostic
printing is disabled in the explicit Rust measurement mode. Legacy diagnostic
counts and all handshake/request deadlines remain unchanged; measurement counts
are separately bounded. ABI major remains 2 and the product SDK implementation
is unchanged.

The release-mode executables first pass all twelve existing actual TCP,
cancellation, denial and durable-state scenarios. Five new process blocks then
complete 1,005 connections and 3,015 echo requests. Setup, first connect,
reconnect, three payload sizes and graceful disposal have distinct intervals.
All raw samples survive; incomplete output, wrong order/payload/phase, malformed
times or wrong server counts cannot become a completed capture. New process
blocks have only five first-connect observations, so no first-connect tail claim
is made. Reconnect P50/P95/P99 and their scope are documented in
[the measurement guide](SDK_CONNECTION_PERFORMANCE.md).

On this uncontrolled macOS ARM64 host, reconnect P50's block median is 8.451 ms;
P99's median is 8.971 ms with range 8.893–9.422 ms. The five first connects span
55.423–60.803 ms. These include reference-server accept polling and real transport
scheduling. They are descriptive observations, not a protocol-matched speedup,
controlled non-regression result, cryptographic-only latency, CPU or energy claim.

Thirteen focused artifact tests, formatting, warning-denied Rust example Clippy,
strict Swift release compilation, all twelve actual acceptance cases and five
real CLI budget-rejection controls pass. The affected Swift workflow lints;
the entire old and new workflows retain the same actionlint 1.7.12 runner-label
catalogue error for an officially listed Ubuntu 26.04 runner. Hosted CI remains
unobserved. The complete artifact suite subsequently passes **2,219 tests across
90 modules in 584.438 seconds**, with warnings treated as errors, using the
standalone build copy and task-local JDK 25. All 843 selected source files match
the primary worktree during execution, and its Git index is unchanged. Only
this ledger and the connection-measurement guide are updated after the full run.

This change updates reference-example source and the full workspace source
digest. Earlier package cohorts retain their original identities and are not
promoted to qualification of the new snapshot; final package regeneration and
installed/device/hosted acceptance remain required after source freeze. Native
Linux reference execution, allocation/concurrency/soak/energy measurements,
controlled tail comparison and publication remain open.

## First-connection CPU attribution (2026-09-26)

The [connection-profile checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-connection-profile/manifest.json)
retains isolated client CPU/stage probes and client/server call-stack samples.
Each of the CPU and stage probes completes five blocks of 201 connections and
603 authenticated requests per block against the frozen reference peer. The
native library and original SDK sources are unchanged; the stage stamps exist
only in a private diagnostic copy. ABI major remains **2**, with 43 C exports,
26 JNI registrations and unchanged legacy declarations/status values.

The first client engine construction consumes 24.190–24.963 ms process CPU.
Captured client and server stacks independently enter AWS-LC's one-time global
jitter-entropy initialization, on client connection construction and server
ClientHello processing respectively. These observations identify a concrete
provider startup cost. They do not precisely allocate the complete handshake
interval or establish algorithm-only latency. The shorter initial client sample
missed that initializer; its raw result remains available. Sources are checked
against the locked provider crate archives, and all profile binaries and raw
records have retained identities. The [measurement guide](SDK_CONNECTION_PERFORMANCE.md)
details the counter scope and instrumentation overhead.

No entropy/health check, protocol, deadline or production code is modified, and
no warmup-based improvement is claimed. Only the measurement guide and this
ledger change in the selected source snapshot; isolated diagnostic scripts and
records are retained as evidence. Targeted ABI/binding/measurement checks run
again. The preceding 2,219-test suite remains the latest full-suite run; it is
not represented as a new run after these documentation changes. Native
platform/device/hosted CI, controlled performance, allocation/energy/soak/CT,
final source freeze/package regeneration and publication remain open.

## Bounded reference listener readiness (2026-09-26)

The [listener checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-listener-readiness/manifest.json)
replaces the reference Rust peer's 5 ms accept polling with readiness waiting
under the same ten-second absolute admission deadline. The listener remains
nonblocking and rechecks its deadline after interruption, readiness and accept;
expiry cannot deliver a late stream. The old loop fails the queued-after-expiry
and idle-timeout regression controls; the new loop passes all three real socket
tests. The only lockfile change is a dev-dependency edge to the already pinned
rustix 1.1.4. ABI 2, 43 C exports, 26 JNI registrations, cryptographic checks and
product runtime APIs remain unchanged.

The same frozen Swift client and native library run against both server binaries.
Each peer passes all twelve existing actual connection boundary cases, followed
by five paired timing blocks with a recorded AB/BA schedule. All 2,010 measured
connections and 6,030 requests complete with exact echoes, server counts,
dynamic-library identity and source/binary checks. Reconnect P50's block median
changes from 8.522 to 1.202 ms; P99's median changes from 12.020 to 1.880 ms.
The [guide](SDK_CONNECTION_PERFORMANCE.md) retains every block and the observed
ranges, including first connections whose provider entropy initialization stays
inside the timed span. Host conditions remain uncontrolled; no algorithm-only,
CPU/energy, installed-package or release-level tail claim is made.

Release compilation, socket tests, example/test Clippy, formatting and 57
affected artifact checks pass. Both native Linux and Swift CI jobs now declare
the listener tests. The changed Swift job lints; full old/new workflows retain
the same actionlint Ubuntu 26.04 catalogue diagnostic, without a bypass. Native
Linux and hosted CI remain unexecuted. The comparison reuses verified SDK
binaries and rebuilds the changed peer; it does not claim a new full SDK build
or the previous 2,219-test complete artifact suite. Disk space remains below the
full connection build's unchanged 2 GiB guard. Previous package/source cohorts
retain their identities; final package regeneration, native/device/controlled
performance/CT and publication are still required.

## Rust allocation observation and full quality rerun (2026-09-26)

The [allocation and quality checkpoint](../research/sdk-alpha1/evidence/20260926-sdk-allocation-and-quality/manifest.json)
retains an isolated, single-threaded Rust allocator observer. It compares the
compatibility C entry points and public owned Rust calls with the same policy
and imported hybrid key. Each cell verifies both cross-decapsulation directions
before and after measurement. All 12,000 final calls succeed; at the three
context lengths, the compatibility path records two Rust allocations per call
and the owned Rust path records none in the measured operation window. The
[performance guide](SDK_PERFORMANCE.md) gives requested layout-byte counts and
the exact exclusions. Native C/foreign-wrapper allocations, C owner-handle
registry costs, peak memory, concurrency and energy remain open.

The observer forwards unchanged to `System` and calibrates all four allocator
methods. Its 107-package resolution matches the workspace lock. Initial Clippy
rejected a parity idiom; the corrected, explicitly canonical-toolchain observer
passes strict Clippy and a complete second capture with identical distributions.
Both attempts and the original disk-space block are retained. These diagnostics
do not modify SDK product code, entropy, cryptographic validation or ABI 2.

Free space recovered without this task deleting the requested incremental
cache. A fresh current-source Rust/C/Swift build then passes all twelve actual
connection boundary cases and 1,005 connections/3,015 requests. Its native
library is `d709fdc27fcc84baa3054a7e09704c6e2e83f7a9701e67d615e6aa3017e73821`,
with verified ABI 2, extension 1 and exactly 43 project exports. Earlier package
and binary identities are retained separately.

The full standalone artifact suite passes **2,219 tests across 90 modules in
496.991 seconds**, treating warnings as errors with the task-local JDK 25.
All 843 selected sources match the primary checkout at execution, including
the listener changes; the primary Git index is unchanged. Only the three
performance/readiness guides change afterward. No source commit, push or
publication occurs. Native Linux/Windows, current and minimum-OS devices,
controlled performance/CT, exact-source hosted CI,
final freeze/package regeneration and publication remain open.

## C owner allocation cost and paired public view (2026-09-27)

The [public-key-view checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-public-key-view/manifest.json)
extends the observer to the actual existing C consumer, compiled as a separate
non-LTO object. Both before/after captures use identical C and observer inputs,
the same authenticated policy/imported key, and both cross-decapsulation
directions. Each completes 14,000 measured calls, allocator calibration and six
actual budget/phase rejection controls. All 107 diagnostic dependency identities
match the workspace lock. The sole measured product delta is the prepared
ContextBound key's public view.

The expanded key already contains its paired public key. Removing the duplicate
1,184-byte public cache makes access borrow that stable owned field. Generation
checks it against the provider's public output; checked import and every native
decapsulation retain their original validation. No secret import/export default,
primitive, protocol encoding, unsafe native path or lifecycle rule changes.
The [allocation table](SDK_PERFORMANCE.md) keeps both costs and savings visible:
C owner key generation still uses three allocations, with requested layout bytes
falling from 4,888 to 3,704; its encapsulation/decapsulation plus secret export and
close still use one 80-byte Rust allocation. The earlier direct-Rust observation
does not make the C owner surface allocation-free.

The current native library returns ABI **2**, extension **1** and package
`0.2.0-alpha.1`; exact export inspection finds 43 symbols and retains all nine
legacy declarations. The frozen old-header C consumer and owner consumer both
run against that exact library, with dyld identity checked. Its SHA-256 is
`adc254da5636f59d974ccffcd754e7a66830dbfdee410ec6702fd1dfb0741248`.
Affected Rust tests total 132 passes, and strict Clippy/format checks pass.
The fresh Swift build passes 11 tests, the JDK 25 JNI host runs eight cases, and
the rebuilt Swift/Rust reference path passes twelve actual connection scenarios.
JNI host execution is not Android ART evidence.

The rebuilt WASM package passes installed consumers in Node 24.0.0 and 26.3.0,
including strict TypeScript compilation. Its exact archive identity and the
separate historical browser identity are recorded in the
[package guide](SDK_WASM_PACKAGE.md). The existing wasm-pack installer warning
remains visible; it is also present in the preceding candidate's logs. Browsers
have not executed the newly rebuilt WASM binary in this checkpoint.

The complete artifact suite passes **2,219 tests across 90 modules in 440.273
seconds**, with warnings treated as errors. Its owned standalone copy contains
the current product bytes; only these performance, WASM-package and readiness
guides change afterward. The primary index remains unchanged and no source
commit, push or publication occurs. ABI 2 is retained. Native Linux/Windows,
devices, controlled performance/CT, current-source browser/hosted CI evidence
and final freeze/package regeneration remain open.

## Browser execution of the rebuilt public-view package (2026-09-27)

The [current browser checkpoint](../research/sdk-alpha1/evidence/20260927-wasm-public-view-browsers/manifest.json)
closes the Chrome/Firefox binary-currentness gap from the preceding checkpoint.
The installed archive is the exact package already consumed by Node 24.0.0 and
26.3.0 after the public-key storage change. Chrome 153.0.8010.54 and stock Firefox
156.0.1 each pass all ten window/dedicated-Worker cases. Chrome also executes four
real failure controls and repeats all ten cases after removing interceptions.
Worker identity, expected WASM request/status, explicit disposal and browser/
driver/server cleanup are checked; source, package and tool identities are
retained. Neither test runner uses the user's normal browser profile.

Firefox still emits privileged-process storage, sandbox-extension and shutdown
diagnostics. The same three classes are present in the sealed no-SDK baseline;
their OS/browser integration and security impact remains unresolved. These
functional tests do not authorize suppressing those messages or disabling a
sandbox. Safari automation remains disabled and untested, pending the existing
authorization request; other/minimum browsers and platforms remain open.

Only the browser/package/readiness guides change in this source checkpoint.
The preceding 2,219-test artifact result remains the latest full quality run for
these unchanged product bytes; it is not represented as a new test execution.
ABI 2, 43 C exports, 26 JNI registrations and version 0.2.0-alpha.1 are unchanged.
Native Linux/Windows, physical devices, controlled performance/CT, exact-source
hosted CI and final freeze/package regeneration still block
formal release. No source commit, push, global setting change or publication is
performed.

## Bounded native concurrency and resource reuse (2026-09-27)

The [native resource checkpoint](../research/sdk-alpha1/evidence/20260927-sdk-native-resources/manifest.json)
adds a ten-minute observation against the current frozen C ABI 2 library. Eight
threads exercise three context lengths and all five derivation purposes. The
consumer checks real KEM and derived-secret equality, explicit disposal and
failed-output zeroing. It accepts only the contract's success/closed outcomes
in 5,120 scheduled close-race calls. Complete registry capacity is restored in
all 21 probes after worker completion and parent disposal.

The [performance guide](SDK_PERFORMANCE.md) retains the full scope and observed
costs. Physical footprint changes from 6,209,944 to 6,308,248 bytes, with the last
seventeen post-drain samples identical; resident memory also reaches a plateau.
These process values include runtime/allocator/thread storage and do not prove
that every possible leak, lifetime race or platform failure is absent. The
host load is uncontrolled, and no after-the-fact memory or speed threshold is
used to claim a release pass.

The diagnostic compiles with warnings as errors, passes six actual argument
rejection controls and verifies the loaded native image and source bytes.
Product source, ABI 2, the 43 exports and the package version remain unchanged;
only these guides change after execution. The source-review patch retains its
original identity and must be refreshed before a future commit to include these
documentation updates. Native/installed/device coverage, controlled performance
and energy, and exact-source hosted CI remain open.
