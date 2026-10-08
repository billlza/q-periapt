# Q-Periapt 0.2.0 release-readiness ledger

Goal: finish the complete 0.2.0 product requirements, including the expanded
Continuity scope and quality and maintainability review before delivery.
No release-readiness claim is made until every applicable requirement has
current-source evidence. The user's latest direction is **retain ABI major 2**.

The 2026-10-04 platform decision makes 0.2.0 macOS **Apple Silicon (arm64)
only**, including Continuity. Intel macOS is outside this release's support
matrix. Linux/Windows x86_64 and the existing iOS simulator targets remain in
scope. The `sdk-020` Apple package uses `macos-arm64`; the historical 0.1.5
universal package and signing contract keep their own versioned requirements.

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
ABI major 2 and extension revision 1 remain. All prior 43 C declarations/layouts
and all 26 JNI registrations are retained; eight explicit native policy-recovery
helpers/entry points bring the unpublished C table to 51. Earlier 43/50-export
package observations below do not qualify this expanded surface. The 0.1.5 contracts and historical results retain
their original bytes. Earlier alpha.1 observations below remain tied to their
recorded commits; the 0.2.0 candidate requires fresh source and package checks.

The [2026-10-08 C/Swift policy-recovery qualification](../research/sdk-alpha1/evidence/20261008-c-swift-policy-recovery/README.md)
records the additive 50-export implementation (`1f6e9edf`) and installed Swift
five-test gate (`046c0e4c`). It retains a real Swift Debug stack-guard failure and
the private boxed-image repair, 48 FFI tests on canonical/minimum Rust compilers,
42 host-store tests, strict Clippy, Swift Debug/Release calls and 189 package
contract tests. A clean Apple Silicon C archive has real outside-checkout
shared/static, pkg-config, CMake and frozen-header consumers. The additional
recovery consumer and five-test SwiftPM consumer use that exact installed native
archive. The Swift test assembly is a host-only diagnostic XCFramework, not the
complete Apple release package. Original-operation replay/cancellation preserves
the current owner unless a new transition applied. v1 migration, Continuity
account-root migration, current-head hosted CI and other platform/device/security/
performance release gates remain open. The seven recovery entries do not change
the original scope of the retained nine stateless functions.

The [complete Apple package checkpoint](../research/sdk-alpha1/evidence/20261008-apple-sdk-recovery-package/README.md)
adds source `4d253e72`: all four native targets and three SDK slices pass their
50-export checks; device/simulator consumers link at the stated deployment
floors, and five installed Swift tests pass outside the checkout. It also fixes
an observed SwiftPM checksum cache that dirtied the source checkout, adds the
unsigned source-drift guard and passes 97 related tests. The full rerun keeps
source and compiler identities unchanged. A separate run-owned iOS 27 arm64
simulator app consumes that exact package and completes the four existing SDK
workload groups, followed by verified app/simulator cleanup. This is simulator
execution and complete package evidence; physical/minimum-OS runtime acceptance
and durable iOS policy storage remain open. No Intel macOS support is added.

The [explicit policy-store enrollment checkpoint](../research/sdk-alpha1/evidence/20261008-policy-store-enrollment/README.md)
adds `194124cb`'s Rust/C/Swift entry for existing v1 images. It preserves the
original signed policy and exact floor, requires independently retained recovery
trust/proof, and reconciles an unknown result without replacing the store or
clearing authority history. ABI 2 has 51 exports with every prior declaration
retained. Canonical/minimum Rust tests, actual process/sync faults and Swift
post-commit cancellation pass. C archive `0ffd7c2b` has actual installed shared/
static enrollment consumers; complete Apple package `5b3cbfa0` passes all four
targets, 51-export slices and six outside-checkout Swift consumers. Redb file-
format migration, Continuity account-root migration, current-head hosted CI and
physical/platform/security/performance gates remain open.

The [scanner content-budget checkpoint](../research/sdk-alpha1/evidence/20261008-cli-bounded-read/README.md)
fixes an actual read after a stale file-size check: growing files can no longer
bypass the 2 MiB content limit. The old reader fails the retained regression;
both Rust 1.98.1 and 1.90 pass 20 tests and strict Clippy, and eight real CLI
processes verify JSON/exit behavior at the size and UTF-8 boundaries. This is
tooling hardening, not a filesystem-confinement or overall security claim.

The [2026-10-08 installed macOS-to-Linux checkpoint](../research/sdk-alpha1/evidence/20261008-installed-macos-linux-connection/README.md)
passes all twelve reference connection cases across actual macOS and Linux
kernels, with separate persistent policy stores. Swift uses the complete SDK
ZIP; the native Linux Rust peer uses exact cohort archives. Linux runs as an
unprivileged user in a local VZ VM/container on the same physical Mac, through
a pinned private TCP forward. Independent physical hosts and protocol
implementations, device/minimum-OS execution and controlled performance remain
open. The failed harness attempts, source/package identities and unchanged
acceptance predicates are retained.

The [native Linux maintenance checkpoint](../research/sdk-alpha1/evidence/20261008-linux-policy-maintenance-package/README.md)
adds seven installed scenarios on each Ubuntu 22.04 arm64/x86_64 CI runner and
on a separate local Debian 12 arm64 VM. CI uses PR merge `6766bca4`, whose full
tree equals branch `33ca8c5c`; both exact downloaded artifacts match the API
digests. The ordinary SDK still refuses legacy database formats pending explicit
offline maintenance. This does not qualify Continuity journal migration or
physical power-loss recovery.

That PR run also retains an [Android 16 KiB failure](../research/sdk-alpha1/evidence/20261008-android-16k-cleanup-failure/README.md).
The full and minimal Instrumentation workloads pass, but the minimal consumer's
second cleanup ownership copy is truncated (5,291,520 of 13,702,871 bytes), then
ADB loses transport. Uninstall is unconfirmed and the job correctly fails.
The transport cause is unresolved; workload success does not qualify the pair's
cleanup/export/replay boundary. The current Rust CodeQL run remains separate.

The [parallel push-run comparison](../research/sdk-alpha1/evidence/20261008-android-16k-ci-comparison/README.md)
retains an existing success at the same Git tree: both Android 16 KiB consumers,
ownership-checked cleanup, export and independent hosted replay pass. AAR/native
library, ADB, emulator and system-image hashes match the failed PR run. The AAR
manifest differs only in commit/time fields; consumer APKs retain distinct run
IDs and signing material. This establishes observed intermittency under those
recorded inputs, not its cause or stability. No retry, RAM/image change, or
acceptance relaxation was used to obtain the comparison.

The [restricted C device-retirement checkpoint](../research/sdk-alpha1/evidence/20261008-c-device-retirement/README.md)
adds eight actual cleanup processes in both Debug and Release, preserving the
complete original report, independent host acknowledgement and logical
journal/signer erasure across lost completions. Native report readback, the
original registration gate, Rust 1.90 compilation and strict Clippy pass. This
is source-based C consumption; installed archives, Swift/Kotlin retirement and
complete foreign replacement remain open. The unpublished candidate now has
119 C exports, separate from product ABI 2's 51.

The [Swift retirement checkpoint](../research/sdk-alpha1/evidence/20261008-swift-device-retirement/README.md)
adds a typed restricted owner over that same engine. Debug and Release each pass
56 tests and eight Swift cleanup processes, including wrong-purpose signature
refusal and exact reopening across lost completions. The original registration
gate and 12 affected tooling tests pass. These are source-consumer results;
fresh installed Swift archives, Kotlin retirement and the complete foreign
device-replacement flow remain open. Prior `737ca3ec` Rust CodeQL completed its
quality/upload stages and has retained diagnostics, without a new-source security
claim or completed disposition of its findings.

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
| Immutable verified runtime | Actual signature/root/state validation; no raw decision constructor; policy epoch/revocation rules and persistence boundary | Prepare/persist/activate, one-winner revocation, disabled-policy recovery and later re-enabling implemented across all six surfaces; shared Rust/C/Swift persistent runtime has real-file/process recovery evidence. The 2026-10-08 installed macOS/Linux peers pass persistence and restart cases with separate stores in a local VM; independent physical-host qualification remains open |
| Explicit expert access and named-purpose derivation | Separate APIs, specified formats/KDF/domain binding, rejection and interoperability evidence | Owned HKDF-SHA-256 purpose derivation and explicit expanded-key transfer implemented across all six surfaces; native integrity/PCT checks and foreign roundtrips pass locally; focused internal review remains required |
| Resource failures and budgets | Bounded inputs, in-flight workspace/live-object budgets, cleanup on entropy/allocation failure, no success-shaped error path | Per-runtime quotas plus native 1024-owner/64-call aggregate limits implemented; close and prepared activation exempt; full-budget activation and JNI failure/copy disposal exercised; process OOM recovery is not claimed |
| ContextBound efficiency without protocol change | KAT/differential/implicit rejection/import checks plus exact-byte transcript equivalence; state and scratch erasure review | Current local workspace/WASM conformance passes; binary CT, formal and device gates remain separate |
| x86_64 native candidate | Pinned source, CPU/OS capability contract, native Linux execution, differential and CT evidence; separate MSVC disposition | Opt-in GNU Linux candidate implemented with CPU/OS checks and portable dispatch. Hosted 830e381 differential tests and the binary CT gate pass for 512/768/1024. Controlled performance, broader CT coverage and separate non-GNU disposition remain required; this finite gate is not a general constant-time proof |
| Real SDK performance | Source/binary-bound paired primitive, Rust, C/foreign binding measurements; tail latency, allocation, concurrency, long-run/energy limits recorded | Rust/C/Swift comparisons, connection timing and allocation observations are retained. The installed Swift package and release archive-derived Rust peer add five timing blocks with 1,005 connections and 3,015 checked echoes. A native C run covers eight-thread work for 600 seconds, close races and 21 capacity-recovery probes. Controlled tail, foreign-wrapper/native-C allocator, peak memory, broader concurrency, longer runs and energy gates remain open |
| Standard TLS interoperability | RFC-compliant standard group, actual independent peer, auth/policy parity and no silent classic fallback | Separate opt-in TLS 1.3 + X25519MLKEM768 mutual-certificate path implemented. The archive-built Rust peer and hosted Linux 830e381 run pass eight independent OpenSSL client/server cases. The 2026-10-08 installed Swift/macOS and native Rust/Linux peers pass policy confirmation and failure cases; both use the same SDK application protocol |
| Full reference connection | Actual Swift/macOS client and Rust/Linux server packages; first connect/reconnect, auth, policy confirmation, failure/cancel/concurrency | The 2026-10-08 installed Swift/macOS and archive-derived Rust/Linux peers pass twelve cases across OS kernels with separate persistent stores. Linux runs unprivileged in a local native VM on the same Mac. Independent physical hosts and independent protocol implementations remain unqualified; prior same-OS checkpoints retain their own source scope |
| Coherent install and distribution | One current version/ABI/package revision matrix; actual installed consumers and current-source devices for supported targets | Version/ABI/package profiles and independent installed consumers are implemented. Named cohorts cover Rust, macOS C/JVM, Apple architecture links, WASM Node/Chrome/Firefox, native Linux C and Windows C packages. Both Windows runner package jobs pass at 830e381, including extracted direct/CMake consumers and archive-only reconsumption. Both Android full/minimal ART, retirement and export gates pass at 2493ffe. Each receipt keeps its source scope; public registries, signing and current/minimum-device coverage remain open |
| Security review and proofs | Updated threat/assurance boundaries, KAT/differential/CT/formal gates appropriate to changed source; internal security review | Local and hosted conformance, differential, binary CT and formal outputs are retained per cohort with their finite/model scopes. Internal boundary review remains required |
| Quality and maintainability | Dependency direction, explicit errors/ownership, no duplicate primitive paths, API documentation; required build/lint/tests and internal critical-path review | The clean 2493ffe snapshot passes 2,250 artifact tests in 482.705 seconds without skips and its post-test source gate. Hosted 830e381 passes 2,246 artifact tests with three macOS-only ACL skips, the source gate, workspace checks and installed C consumers. The later package-query diagnostic passes 171 command tests locally. The full workflow retains the pre-existing runner-catalogue lint diagnostic. The tracked Rust inventory at c46695b6 contains 261 files, including isolated candidates; final exact-source CI/CodeQL and internal review remain required |
| Release transaction | Coordinated crate versions, frozen schemas/export lists, exact-source CI, signed packages where required, install/device evidence and maintenance policy | The twelve-crate 0.2.0 coordinator validates the clean producer, exact archives and closed dependency order, then uses the shared lock, durable journal and API+sparse reconciliation. Hosted `57334d4` produces the real cohort and passes the source-bound dry-run. Final platform, signing and publication requirements remain open; readiness alone does not authorize publication |

## Latest qualification checkpoints

At `56ae4e099dca2ae5aaf5b868fb001b9307c3d8ad`, actual extracted Debug archive
consumers exercise credential renewal through existing C, Swift and Kotlin
owners. Three real-clock cases cover committed renewal after expiry, explicit
expired-uncommitted reconciliation and same-session peer renewal with retained
outbox identity. The installed Swift package passes 26 tests and all three
cases; Kotlin passes 23 tests and runs all three under both Serial and G1.
The C consumer also repeats original enrollment/TLS/unknown-delivery coverage.
The [sealed package evidence](../research/sdk-alpha1/evidence/20261004-foreign-credential-renewal-4a9f8c46/)
binds source, archive, library and executable hashes. These Debug macOS checks
do not qualify Release packages, renewed application TLS, required-witness
local renewal, physical devices or independent protocol implementations.

A subsequent Swift/Kotlin integration adds typed original registration,
independent trust inputs and same-credential roster continuation. It reuses the
existing owner-transfer mechanism: successful activation retains the whole native
enrollment owner in the device while the old language wrapper can be released.
Current development checks cover 24 Swift and 19 Kotlin tests, plus local,
signed-TCP and mutual-TLS authority traces; Kotlin executes these under both
Serial and G1. The archive gate now requires these three traces per profile,
language-specific ARC/GC readback and Java refusal of raw enrollment construction.
Those development runs do not replace fresh installed-package qualification,
supported-version devices, Android/WASM persistence or the complete replacement
and upgrade lifecycle.

A subsequent C integration exposes original native enrollment through nine
additional exports (64 in the unpublished `qpc-owner/1` interface). It persists
its own signer/request, accepts independently supplied trust, retains the whole
enrollment owner through device/peer operations, and refreshes the same credential's
roster before restoring the original session. Current development traces exercise
real C-to-Rust TLS delivery after receiver exit, signed-TCP activation cancellation,
and required-witness authority refusal over TCP and mutual TLS. A cancelled failed
activation initially masked its consumed handle as Cancelled; checking the empty
slot before cancellation now returns Closed in the same real TCP test. The package
collector requires all three traces in debug and release. The separate clean
`76fb13b7` checkpoint passed the complete Rust/C archive run, including legacy
connections, sync/EIO cuts and OpenSSL interoperability; the source/compiler
identities remained unchanged. Minimum Rust 1.90 also ran the real C registration
traces. See [the C enrollment record](../research/sdk-alpha1/evidence/20261004-c-enrollment-c28cc7d5/RESULTS.json).
That cohort does not qualify the later Swift/Kotlin increment. SDK policy/store,
TLS configuration, authority transport and complete replacement/upgrade remain
separate obligations. Product ABI 2 and legacy KAT behavior are unchanged by this
C adapter increment.

A subsequent native enrollment increment adds `DeviceEnrollment` before
credential-dependent installation. The original signing ID/request, accepted
credential/roster/policy and future journal ID are retained across restart; explicit
Activating/Active phases reconcile the two durable records. Actual SDK prekey work,
required-witness admission, returned sync errors and process cuts exercise this
path. Independent review found a live-policy closure window across the final
new commit; a concurrent-close regression fails before the release-fence repair
and passes afterward. Source-bound commands and limitations are retained in
[the enrollment record](../research/sdk-alpha1/evidence/20261003-enrollment-c28cc7d5/RESULTS.json).
That earlier enrollment increment was not covered by the preceding installed-package
receipt. The current ordinary public TLS workload now uses the enrollment transaction
through original-state restart, real bidirectional delivery and rekey, retaining its
lease during communication. Its package gate requires 46 public registration/connection
readbacks per profile and ten real database-lease checks, including enrollment. Explicit
loss of the active enrollment record is refused without installation fallback. Foreign
adapters, authority transport and credential/root/policy replacement remain required;
archive and device qualification are source-bound gates, not implied by this code change.

A subsequent native increment adds a durable same-credential roster-refresh
intent to enrollment, followed by original-journal CAS and completion before service
release. Registered session restoration now retains the original enrollment owner
after roster/advertisement expiry and uses the original archived context/outbox.
Required-witness enrollment activation additionally requires a fresh signed exact
authority confirmation; an ordinary head query cannot establish this. Command 4
and outcomes 5/6 extend the unpublished witness grammar without changing existing
1–3 commands, 1–4 outcomes or frame sizes. Older witnesses cannot satisfy the new
registered-activation requirement. Credential/root/policy replacement, conflicting
control-plane resolution, foreign enrollment and supported-version upgrades remain
separate open obligations; prior package receipts do not qualify this new source.

The archive consumer now requires public-API witness roster refresh and original
installation recovery before its existing connection workload can pass. Current
Rust 1.98.1 and minimum Rust 1.90 execute all three public consumer tests, including
three separate device processes for expiry refusal, recovery and revoked replay.
The reader checks two native validity refusals of the same pending command, one
subsequent advance, unchanged journal/fence and exact bootstrap outbox. It exports
only the checked public closure and re-verifies it after copying; CI retains that
closure. The source-level runs and package qualification have separate receipts in
[the roster package record](../research/sdk-alpha1/evidence/20261003-roster-package-c28cc7d5/RESULTS.json).
A development run exposed inherited nonblocking mode on an accepted test-server
socket; the final fixture explicitly selects blocking I/O with three-second
read/write timeouts. The original failed run is retained. Independent reader review also demonstrated
that equality alone admitted two identically malformed outboxes, and that an
operation-only trace could omit query observations. The final collector requires
the canonical bootstrap envelope, retained context and signed queries at explicit
expiry/refresh/recovery phase boundaries. Both counterexamples are retained and
covered by refusal tests. These are same-host
native Rust checks with injected protocol time, not credential replacement,
foreign-package requalification, deployed operator transport or release readiness.

The witness roster-authority increment based on `c28cc7d5` adds the explicit native
`AnchorStore::update_roster_authority` control-plane operation. It accepts the
original retained subject and predecessor checkpoint plus a currently verified
successor with the same credential/key/policy. It preserves genesis, journal head,
writer fence and last data-plane command. The predecessor is a compare-and-set
expectation; it does not revive an expired identity object. Current target checks
precede idempotent readback. The existing authority-binding encoding is shared with
identity verification and checked against an independent fixed SHA3-256 vector.

Current Rust 1.98.1 passes **38 witness/transport tests, 18 journal-witness tests
and the authority-binding vector**, with no failures or ignored tests in those
selections. Minimum Rust 1.90 passes all **seven refresh-path tests**. All-feature,
all-target Clippy passes with warnings denied, as do formatting and diff checks.
The new fault matrix measures two real commit syncs and returns the exact injected
error before/after each. A separate process is killed after refresh commits but
before its result returns, then resumes from its retained public subject/checkpoint.
The original data command still reconciles with a fresh challenge and unchanged ID.

The actual encrypted client journal trace first fails its roster write against an
expired witness and preserves the original intent. Explicit witness refresh changes
no journal head; original reopen applies that one intended roster commit and releases
the same retained bootstrap outbox. A subsequently observed device revocation still
refuses replay after restart. The [scoped local record](../research/sdk-alpha1/evidence/20261003-witness-roster-c28cc7d5/RESULTS.json)
retains the source hashes, command outputs and earlier failed test-development runs.
These are native source tests with real storage/signatures; the new renewal trace
does not claim deployed administrative transport, fresh installed packages, full
credential/policy/root replacement, physical power loss or release readiness.

The preceding fanout-borrow snapshot based on `c28cc7d5` borrows each reserved fanout
member's plaintext and associated data through the same traffic send engine.
It removes two temporary nonempty vectors per recipient without changing journal
encoding, original intent checks, whole-account commit or release checks. For two
recipients at the 16 KiB plaintext/1 KiB AD limits, this removes 34,816 copied bytes
per resume calculation; that is source accounting, not a measured peak-memory or
allocator result. Per-recipient persisted reservations remain unchanged.

Current Rust 1.98.1 passes **50 fanout tests and 91 other message tests**, with zero
failures or ignored tests in those selections, plus all-feature/all-target Clippy
with warnings denied. Rust 1.90 passes the added payload-boundary/restart test.
The new regression compares exact ordinary/fanout ciphertexts for empty, ordinary
and maximum inputs, rejects changed AD and restores exact output after restart.
Existing real sync/process/witness faults, revocation and epoch isolation remain
covered by the selected suites. The retained-reservation disclosure counterexamples
still recover six messages after confirmed epoch one under their stated compromise
cuts; passing those tests does not establish post-compromise recovery.

Matching isolated source snapshots also build both Release test executables.
Eight alternating-order runs retain **96 native journal send samples**, with eight
samples per variant/account/input group. Candidate/baseline median ratios range
from **0.987 to 1.025**, so no stable latency advantage is established. This local
diagnostic includes the original durable journal path, but not an installed archive
consumer, TLS/witness/FFI timing, controlled tails, allocator measurement or energy.
The [local scoped record](../research/sdk-alpha1/evidence/20261003-fanout-borrow-c28cc7d5/RESULTS.json)
retains commands, source/binary hashes and raw observations. Fresh package/CI
qualification and the complete release requirements remain open.

The shared host-store admission correction removes filename-based deletion after
an initial file validation or sync error. A pinned parent directory does not pin
the leaf's name: another writer can replace that name while the failing operation
still holds the original descriptor. An isolated reproducer uses the actual
installed C setup client, moves the just-created empty inode, installs a distinct
replacement, and returns EIO from the original file's first sync. The old library
returns 204 but deletes the replacement. The corrected component library returns
the same 204 and preserves both inodes and the unrelated control file. No journal
or archive child is released. Client and fault-probe bytes are unchanged between
the two runs; native endpoints and transaction checks are not bypassed.

All **19 host-store tests** pass under current Rust 1.98.1 and minimum Rust 1.90.0,
including a regression for both original-empty and replaced-leaf failures; current
all-target Clippy passes with warnings denied. This is component red/green evidence:
the corrected library was rebuilt from retained dependencies with the selected
host-store source changed. A fresh SDK archive cohort and all affected installed
consumers remain required. Admission errors now preserve an incomplete empty leaf,
which stays refused on reopen and exclusive create. Safe explicit reconciliation
of incomplete first-install state and the complete initial-creation fault matrix
remain open. The running full `7342f4a0` cohort predates this correction and cannot
qualify its changed SDK source.

The required-witness installation fault increment adds mandatory signed-TCP and
mutual-TLS workloads to the C/Swift/Kotlin installed collectors. A native controller
keeps the original witness alive across process interruption or returned EIO,
enrolls the original prepared genesis and reads the original anchored state before
activation, after the fault and after recovery. Each foreign recovery must use its
explicit original carrier; omitting the witness refuses 216. TLS phase admissions
and unchanged plaintext counters rule out fallback during those foreign calls.
Public replay binds original subject/genesis, signed queries, native observations,
the selected sync phase and exact client/controller exits. Authentication occurs
at the native endpoints; replay is not another cryptographic implementation.

Current Debug/current Release/minimum-Rust Release packages pass **540 cases**
across 36 matrices: three languages, three native profiles, two carriers and two
fault actions. They retain **7,326 client/probe/marker commands** and **540 live
controller executions**, with original Creating/Active recovery, missing-witness
refusal and no replacement journal/account state. Each carrier/action matrix
exports 888/918/933/963 selected public/log files respectively; TLS private keys
are excluded. The shared local observer also passes 30 process/EIO regression
cases. The focused 62 artifact contracts and 13 mutations of actual public evidence
pass. C uses strict compilation warnings, Swift's 18 owner tests pass in all three
package builds, and the unchanged actual Maven SDK retains its previous 15-test
publication. A first Kotlin development build compiled but failed runtime closure
validation because its reused cache was outside this run; the retained v2 build
uses an isolated cache and the original strict validator. Two new native fixture
sources bring the tracked Rust inventory to 277. Complete current source-bound
archives/CI, initial intent/child creation faults, witness-process crashes, arbitrary
storage faults, supported devices and the broader release scope remain open.

The preceding **`ecc1eb03`** full Rust/C/Swift/Kotlin installed cohort completed in
**3980.760 seconds**, independently replaying **286 committed source inputs**,
actual packages/binaries and the mandatory local process/EIO workloads. Both C
profiles retain nine admission tests and exactly 55 exports. The seal contains
**43,695 files / 650,000,236 bytes**, inventory
`6c008164fd87931e16abe1b1219797b06faef3a1449051bd61089fe9881d29e7`.
It predates required-witness fault qualification. Its hosted installed-Swift job
was cancelled at the 45-minute job limit, while both local complete cohorts took
over 66 minutes. **`621d15da`** changes only that outer CI job budget to 120 minutes;
native/transport/child/test deadlines remain unchanged. That commit's CodeQL
workflow passed; CI was still in progress at the last recorded observation.
Neither workflow status nor these finite same-host traces establish power-loss
safety, independent-engine interoperability or a continuous-PQ security proof.

The returned-I/O increment adds a separate mandatory `setup_io` workload to the
installed C/Swift/Kotlin collectors. The test-only sync probe returns EIO before
or after the selected real sync; consumer phase receipts bind opening, activation
and close. Nine current Debug/current Release/minimum-Rust Release configurations
pass **135 cases / 1,989 commands**, including 9 baselines and 126 injected errors.
The errors comprise **18 opening failures (204)**, **36 uncertain activation
commits (207; 18 Creating and 18 already Active)** and **72 post-commit close-sync
errors**. Each configuration exports **783 public/log files**. Error owners must
refuse further work and remain disposable; no successor is released on failure.
Original resume preserves the journal, account position, absent operation and
empty archives. Close is resource disposal, not another durability receipt for
redb shutdown metadata. A commit error cannot be relabeled as a close error.

Ten mutations of actual exported evidence are rejected. The original process-exit
mode remains mandatory alongside EIO, with its own calibration and controls.
Development discovery first assumed all errors would be 207, which was wrong for
opening and prevented later close injections. That failed assumption is retained;
phase-bound qualification now records actual boundaries. The SDK library, wire
and exports are unchanged. Complete current archive production, witnessed commit
cuts, initial intent/child preparation failures, arbitrary storage faults and
physical power loss remain separate requirements. All broader 0.2.0 scope remains.

The installation activation/close fault increment adds a calibrated, test-process
sync probe workload over the actual installed C/Swift/Kotlin entry points. In each
current Debug/current Release/minimum-Rust Release configuration it observes seven
installation syncs and executes the baseline plus every before/after interruption.
Across the nine configurations, **135 cases / 1,944 commands** pass: 9 uncut
baselines, 102 unknown-result interruptions and 24 interruptions after a complete C
activation result was already observed. Of the unknown results, **66** reopen as
Active and **36** as Creating. Every case retains its original journal identity,
next account position, absent account operation and empty archives. Creating
rejects ordinary device access; explicit create rejects retained state; original
resume reconciles both phases and Active refuses storage recreation.

Each configuration exports **753 verified public/log files**. Independent replay
binds original observations, exact commands, all sync receipts and actual response
visibility; known replies are not counted as unknown outcomes. Seven mutations of
actual public evidence are rejected. All six original local/witness setup
regressions pass. Strict current Clippy and minimum Rust all-target checking pass;
the new native observer increases the tracked Rust inventory to **275**. A first
prototype incorrectly assumed every interruption had no output; preserved evidence
shows C prints its complete activation result before close syncs. The corrected
oracle separates those observed results and still requires both unknown durable
phases. Collection review also reproduced a Debug/Release output-directory
collision before fixing profile ownership. The shared-root regression exercises
both actual profile collections. No SDK assertion, timeout or safety check is
weakened. Full current archives/CI, returned I/O errors, required-witness commit
cuts, initial setup creation/preparation faults and all broader release requirements
remain open; this local process-cut evidence is not power-loss qualification.

The typed setup increment adds Swift/Kotlin `ContinuitySetup`, original
Creating/Active status and journal/genesis values, and activation into the existing
device owner. The transfer moves one native owning reference without registering
another destructor or Cleaner. Closed old-setup aliases cannot close the successor;
other operations refuse Closed. During activation, repeated transfer and ordinary
calls refuse Busy, while cancellation remains available outside wrapper locks.
Cancellation already admitted may affect the successor and must be joined.

Actual extracted Swift packages pass **18 tests** in Debug, Release and Release
with the minimum-Rust native library. The actual Maven SDK passes **15 tests**,
and Java compilation against that JAR rejects raw setup construction. Development
runtime replay covers **20 local/witness configurations** across C/Swift/Kotlin,
current Debug/Release and Rust 1.90 Release native libraries; Kotlin explicitly
uses both Serial and G1 for the two Release libraries. Swift release and bounded
Kotlin GC observations check old-setup disposal followed by successor use. Each
configuration retains 20 local or 36 witnessed public files, original identity,
required-witness refusal, cancellation and original TCP/mutual-TLS admission.
All six Swift/Kotlin original client, server and complete-account regressions pass,
as do 47 focused artifact contracts. The first Swift build's C-enum/Int32 type
error and the first JVM driver's overbroad Maven staging inventory failure remain
retained; neither failure is recorded as a successful qualification. The full
source-bound archive cohort for this increment is still separate from these
development results. Activation-commit faults, public enrollment/renewal, mobile
owners and the remaining release requirements are still open.

The preceding **`bddfae14`** C setup checkpoint completes its full installed
Rust/C/Swift/Kotlin producer in **3417.696 seconds**. Independent readback binds
275 committed inputs, both C profiles' nine admission tests and 55 exports, Swift
15 tests, Kotlin 12, and every existing required runtime/fault trace. Its seal
contains **25,986 files / 606,531,031 bytes**, inventory
`857234d520ec9dda2a419a30c4e245c2fb77ebf4ccef3a68fe32972cf93de8af`.
Both C profiles also pass the original setup trace; this full cohort predates the
typed setup increment above. Its push CI and CodeQL workflow completed successfully;
open security findings and current-candidate release admission remain separate.

The C installation setup increment adds explicit create/resume, original phase
and identity queries, Creating-only storage preparation and activation into the
same device handle. It reuses native transactions and the device authority loader;
key generation, credential issuance and trust installation remain independent
inputs. Actual C Debug processes pass both local and required-witness setup.
Missing witness and corrupted signature return no service; held-query cancellation
checks Busy close/concurrent calls, releases the owner and retains Creating before
the original activation is retried. The same Active installation then reopens
through mutual TLS, with no plaintext witness request during that operation.

Independent public replay checks **20 local / 36 witness** files, original journal
and genesis, 14 signed queries with one interrupted response and zero advances,
five TLS admissions and a sub-second held-call cancellation observation. Current
Clippy/minimum Rust checking and the 32 focused artifact tests pass. All nine C
admission tests and original client, device, witnessed-device and account-owner
traces pass against the new **55-export** C candidate. The source census becomes
**274**. An initial regression driver incorrectly supplied an explicit C language
marker to a harness whose C path uses the absent default; it failed before runtime.
The corrected driver preserves that failure. Earlier compile/driver failures are
also retained. Those initial C development results did not establish a current
archive, Release/MSRV execution or typed setup ownership; the newer checkpoints
above record the subsequent work. Activation-commit cuts and complete public
enrollment/provisioning still remain required.

At `0c84a7c2`, the complete Rust/C/Swift/Kotlin archive producer succeeds in
**3368.858 seconds**. Independent replay checks 271 committed inputs, actual
archives/binaries, both own/peer layouts and both delivery/four-loss workloads in
every Debug/Release foreign profile. C passes nine admission tests and exactly
50 exports, Swift 15 owner tests and Kotlin 12. The seal has **25,824 files /
586,491,808 bytes**, inventory
`7d095e7b534bccebc9734434f49ae27de6f94ef3e039b7bb24246cf2b860123b`.
This qualifies the own-account checkpoint below and predates the new setup owner.
Current CI and open security findings retain their separate gates.

At `0c84a7c2`,
The current own-account increment executes actual C/Swift/Kotlin owners with three
distinct devices in one original signed roster, alongside the existing two-account
layout. Both delivery layouts refuse an omitted recipient before reservation,
preserve the next operation ID and make no application connection. They then
recover the original message after receiver application commit/exit and complete
both members. The cleanup workload reconciles four encrypted witness replies lost
after native commitment, preserving the complete original loss report through SDK
revocation, acknowledgement and retirement.

All **36** development combinations pass: own/peer layout, delivery/four-loss
cleanup, C/Swift/Kotlin and current Debug/Release/minimum-Rust Release libraries.
Delivery checks nine phases, **283/289/288** TLS admissions and **69/69/70** public
files; cleanup checks **178/184/183** exchanges, 36 advances, four exact losses and
**90/90/91** public files. Schema 2 retains original public account roots and signed
rosters. Independent parsing checks account commitments, canonical roster pins,
exact membership, generations and credential-digest uniqueness; native endpoints
verify signatures. Two controls execute the peer layout successfully under an
own-account test name: the collector refuses the layout, and changing the public
label still fails original-root/roster checks.

The nine original signed-TCP, mutual-TLS-baseline and local-cleanup regressions
pass. Three native public-connection tests and independent readback also pass.
Their first driver failed only when its exclusive final JSON writer tried to
overwrite the preliminary receipt; that failure is retained, and a separately
named readback records the successful runtime without relabeling the driver.
Strict current Clippy and minimum-Rust checking pass without warnings. Product
library/ABI/wire and foreign implementation are unchanged; the Rust source census
remains **272**. Fresh archive production, platform/device execution, enrollment,
authority renewal, broader faults/concurrency and final product/recovery-analysis
admission remain separate requirements.

The complete `d8d66253` archive-produced Rust/C/Swift/Kotlin cohort finishes in
**3293.782 seconds**. Independent replay checks 271 selected inputs, archives,
actual binaries, account reports, 9 C / 15 Swift / 12 Kotlin owner tests and the
50-export candidate. Its seal has **24,553 files / 584,298,469 bytes**, inventory
`aea15bf2e6b0fc46db669252f8c50091d1fa3393007e13a1e08993bce6814680`.
It predates the own-account and complete-recipient additions above. Its push and
PR CI runs (`37085335094`, `37085338977`) both fail the Android 16-KiB runtime
step; dependent runtime replay is skipped. Other jobs succeed. No complete CI or
resolved-security-findings claim follows from the separate CodeQL workflow.

The earlier complete `03cac3a2` cohort finishes in **3242.230 seconds**, with 269
selected inputs and **24,201 files / 583,594,784 bytes**, inventory
`6ae714865bde6d7241580f6ae52a1e9c2384311fa00d05e4f6970b950c80a6c5`.
Both 46-job CI runs pass. Its downloaded native Linux x86_64 Rust/C artifact
`11259510377` matches SHA-256
`ab2f45299935f2933c20e0d84263f230976e9be07c28d1c08826842553f8c5ce`.
Frozen-source public replay passes both C profiles, including four encrypted
losses. The separate Linux seal has **7,697 files / 43,530,073 bytes**, inventory
`1ffaee1b374234729c242f4f709b13247a52fc198256da384d41ca0de46fa803`.
Hosted executables/private stores were not uploaded; this is public-artifact
replay, not a local binary rerun, Linux Swift/Kotlin or macOS-to-Linux connection.

At `d8d66253`,
Complete peer-account delivery now runs through all three foreign owners with the
original required mutual-TLS witness. The first receiver persists application
bytes then exits 77 before native consumption. Original batch/message retry
repeats the idempotent callback with zero new application records, confirms that
member and completes the second member. Retained confirmations use zero further
application-network exchanges while original witness admission remains mandatory.
Current Debug/Release and minimum-Rust Release libraries pass all nine development
configurations, retaining **50 C / 50 Swift / 51 Kotlin** public files and
**266 / 272 / 271** TLS admissions. The actual exit receipt, pre-restart application
snapshot, original identities, post-restart bytes and all eight phase ranges are
required by the public reader. No foreign phase contacts the plaintext witness.

The two isolated controls fail: an incorrect expected exit code, and a caller
replacing its retained batch with a fresh one. The latter creates a second business
record and fails the existing complete-delivery check before the fixture's later
ID assertion. The original negative-driver failure is preserved and its expected
failure boundary is corrected from this observation; no product check is relaxed.
Earlier probe failures also remain: an empty diagnostic file was incorrectly read
as nonempty private configuration, and application-only commit was incorrectly
treated as prior native consumption. The existing native pending/consumed contract
and callback-retry test establish the corrected explicit outcomes.

All nine original signed-TCP, encrypted baseline and four-loss encrypted account
regressions pass, as do all three local account-cleanup paths with **28 commands /
139 public records** each. Current Clippy and minimum Rust 1.90 all-target checks
pass without warnings. The helpers share server readiness, exact process exit and
the existing TLS phase observer. Native library, ABI and foreign implementation
remain unchanged; the Rust source census becomes **272**. This finite development
qualification is separate from complete current archive production, remaining
platforms, own-account lifecycle, the broader failure/concurrency matrix,
independent witness deployment and final product/recovery-analysis admission.

At `03cac3a2`,
The new encrypted unknown-outcome workload covers reservation, freeze,
acknowledgement and retirement through actual C/Swift/Kotlin owners. A test-only
relay withholds ciphertext after the unchanged native witness has committed and
produced its TLS reply. Each foreign process reconciles through the original TLS
authority before native report readback. Current Debug/Release and minimum-Rust
Release libraries pass all nine configurations: **178/184/183** exchanges,
**36** native advances, four retained loss positions and **72/72/73** public files
for C/Swift/Kotlin. The reports preserve two reservations, two older unknown sends,
five unconsumed deliveries, two skipped positions and the original batch/report IDs.

Both controls fail as required: disabling the armed loss returns an unexpected
available result; losing a read-only query stops admission before the intended
commit. The relay has bounded wire/image memory and one deadline, joins its workers,
zeroizes private database snapshots and exports only public receipts. It does not
decrypt TLS or export a plaintext command/challenge transcript. Native endpoints
enforce original-command reconciliation; public replay checks the exact workload
census, command outcomes and loss accounting. The same helper still passes all
three original signed-TCP traces and encrypted baseline traces (67/67/68 files).
Strict current Clippy and minimum Rust 1.90 all-target checks pass without warnings.
The Rust source census is now **271**. The Debug helper drives every configuration;
these are correctness observations, not a compiler-performance comparison.

Retained initial failures exposed a redundant socket shutdown after a peer had
already closed, and then an omitted public-certificate export. Dropping the final
socket after joining the request reader fixes the fixture lifecycle; the shared
certificate exporter supplies the required evidence. No protocol, ABI, assertion,
deadline or foreign implementation was relaxed. A separate regression also exposed
that the package's before/after source inventory omitted both account-TLS Python
readers. They are now explicitly included, and the new test fails on the previous
inventory. Historical receipts retain their original selected-input scope.

The complete `91644585` archive-produced Rust/C/Swift/Kotlin cohort finishes in
**3118.402 seconds**; independent replay checks 265 selected source inputs, archives,
actual binaries, all account reports, 9 C / 15 Swift / 12 Kotlin owner tests and the
50-export C candidate. Its sealed evidence has **23,714 files / 582,500,256 bytes**,
inventory `cb53507c0964742510fa6859ec58635b33871f70ef1462c7a0fcf12be0241849`.
It includes the encrypted baseline below, but predates the four encrypted losses
and source-inventory correction above. Its 46-job push CI passes; the PR CI and
unresolved security findings remain separately tracked. CodeQL workflow success
does not mean findings have been resolved. Complete current-source archive
production, hosted CI, current/minimum physical devices, own-account lifecycle,
required-witness account delivery, broader failure/concurrency coverage and all
remaining product/recovery-analysis gates remain open. No release is claimed.

The earlier full `b7551db7` cohort completes in **3132.813 seconds** with independent
source/package/runtime replay. Its seal retains **23,260 files / 581,408,951 bytes**,
inventory `78e70cf1138d71608bfc79738565c1252562e7a0c605bce8fd1869f6a435bd95`.
The downloaded Linux x86_64 public artifact also replays both C profiles and their
original signed-witness account evidence. Hosted executable bytes were not
uploaded, and that run includes Rust/C only; it is not Linux Swift/Kotlin execution
or a macOS-to-Linux connection. The separate PR Android 16-KiB minimal-consumer
attempt installed successfully but lost ADB transport before instrumentation.
Bounded recovery and cleanup failed; the full-consumer instrumentation had passed.
The cause remains unproven and the failed run is preserved. Later passing runs do
not erase this stability counterexample.

At `91644585`,
The complete-account encrypted path now runs through C, Swift and Kotlin using
the existing native mutual TLS witness. Three exact certificate/subject bindings
cover the original installations. Current Debug/Release and minimum-Rust-library
Release each pass: **154 C / 160 Swift / 159 Kotlin** admitted exchanges, exporting
**67 / 67 / 68** public files respectively. Eleven phase records prove zero plain
witness requests during foreign TLS operations. Wrong signing pins, TLS names and
certificate subjects fail; missing/unreachable original authority still fails
after retirement. Every loss field remains identical to the native report oracle.

The lost-reservation fixture is explicitly signed TCP; native preparation and
readback are also separate from the TLS phases. This closes encrypted original
account bootstrap and revoked cleanup in these development configurations. Lost
TLS commit responses, completed witnessed account delivery, own-account lifecycle,
power loss and other release obligations remain open. No product protocol, native
owner, ABI or foreign implementation changes. The original TLS fixture is shared
across test targets instead of duplicated, and the collector/hosted exports require
the separate account-TLS evidence. Strict current Clippy and minimum Rust 1.90
all-target checking pass; the Rust source inventory becomes **269**.

The new helper also replays all three signed-TCP account traces (67/67/68 files),
legacy signed recovery (59), constructor cancellation (37), native TLS recovery
(34) and independent OpenSSL server/client/refusals (29/7/5). Its first staging
attempt omitted archive path patches in the copied Cargo manifest; the retained
failure does not become a runtime result. Initial shared-fixture unused imports
and credential-copy warnings were fixed directly before warning-free compilation.

The full `8242246a` installed Rust/C/Swift/Kotlin producer completes in **4259.627
seconds**. Independent source/archive/binary/runtime and admission/export replay
passes, including 15 Swift owner tests and complete-account cleanup in both Swift
profiles, plus Kotlin Serial/G1 and all original fault paths. Its sealed cohort
contains **22,324 files / 539,343,966 bytes**, inventory
`fc755a9cec4d57d4bcb94b7de1c9a8b57602ac8d000f3a7be4a3e01d60a90fbe`.
That commit predates Kotlin aggregate cleanup and the later account-witness work.

The later full `fac193fa` producer remains failed: its G1 server deadline measured
75,656 ms. Retained system events show low-power sleep at 1% battery during that
measurement and a later hibernate wake on AC. A focused replay with unchanged
installed binaries, JARs, JVM flags and the original 18–23-second assertion passes
at **20,243 ms**, with 13 verified C2 invocations, eight callbacks and seven returned
slot checks. Only the compilation-log destination changes. The original failure
and 47 public replay files are retained in a 95-file / 91,077,999-byte cohort,
inventory `313225b8050b113e5f24f8917cc89238d4cfed878d8cd9d7265f9a31498bf0a3`.
This does not reclassify the failed full producer or qualify physical power loss.

C, Swift and Kotlin now execute complete-account cleanup under the original required
witness after operational SDK revocation. The real signed-TCP witness withholds a
committed response at each of reservation, freeze, acknowledgement and retirement.
Current native Debug/Release and minimum-Rust Release configurations all pass,
retaining **67 C / 67 Swift / 68 Kotlin** public files each. Independent replay checks
all four phase ranges, original command IDs, fresh challenges, three subjects and
every loss field. Kotlin also retains its parent collection/close/64-slot receipt.
Strict Clippy and the Rust 1.90 all-target check pass without warnings. Existing local
account cleanup (28 commands/139 records), signed-witness recovery (59 records) and
constructor cancellation (37 records) still pass after sharing the fixture/oracle.
The Rust inventory becomes **267**. This closes a development signed-TCP cleanup
boundary, not encrypted witness account delivery/cleanup, own-account lifecycle,
power loss, independent-engine validation or final distribution admission.

Two initial C fixture assumptions were corrected from the existing contract and
actual state transitions. Recovery output is undefined on failure and must not be
read; an early test incorrectly compared uninitialised output with zero. After
unknown retirement, the first reopen can reconcile pending state and return a
selected owner with Retired status; only the next reopen returns the Retired error.
The reference consumers now explicitly verify both results under the original ID.
Native behavior and the 50-export ABI are unchanged. Failed execution and readback
attempts are retained; neither an unknown result nor a partial report becomes success.

The full `63b0e824` installed Rust/C/Swift/Kotlin producer completes in **3873.546
seconds**. Independent archive/source/binary/runtime replay and admission/export
checks pass, including nine C tests, exactly 50 exports and both 139-record C account
cleanup profiles. Its sealed cohort contains **21,847 files / 538,300,190 bytes**,
inventory `a8b81958b216fd3cad37ce3f302c9a98a8f9848656662ca8f589c83b994c38bd`.
That source predates Swift/Kotlin aggregate cleanup and the new witnessed account
trace. It cannot replace their current-source distribution qualification.

Kotlin now carries the same whole-account cleanup contract through the existing
recovery owner, explicitly aligned FFM layouts and unsigned `Counter64` values.
The separately published local Maven JAR and installed consumer pass 12 boundary
and owner tests, then actual cleanup against current native Debug/Release and
minimum-Rust 1.90 Release libraries: **28 commands / 139 public records** per
configuration. Each run preserves all two-member loss classes and original report
identity across freeze, cancellation, acknowledgement, retirement and reopen.
Both legacy single-session recovery profiles pass with 31 independently replayed
public files. Twenty-three focused artifact contracts pass. The collector pins
the JVM/JAR closure and injects process cuts directly into Java; the hosted upload
lists include its public account-cleanup evidence. New complete archive-produced
qualification remains separate and required.

The first Kotlin development reader incorrectly used the Gradle Maven parent
directory, whose extra metadata violates the exact coordinate inventory; it now
stages the same coordinate subset as the distribution collector. A second attempt
correctly refused dependencies recorded under the previous development cache.
A fresh dedicated cache and dependency-resolution record preserve the original
location check. These failed harness attempts remain retained; validation was not
relaxed. This local profile does not close required-witness, own-account, Android,
durable-WASM, power-loss or independent-engine release obligations.

Swift now exposes complete original-account cleanup on its existing typed recovery
owner. The complete report traversal retains original IDs, unsigned 64-bit counters
and optional-field meaning. Selection cannot acquire operational or independent
session authority. Cancellation, explicit close and ARC use the original native
registry; no raw handle becomes public. Current Debug/Release and a Swift Release
client linked to the minimum-Rust 1.90 library each pass **15 Swift tests** and the
real interrupted-reservation cleanup: **28 commands / 139 public records** per
configuration, with two reserved inputs, two unknown sends, five unconsumed
deliveries and two skipped positions independently read back. Twenty-eight artifact
contracts pass, including explicit language-scope rejection. This is development
qualification against the retained C libraries; a new complete archive-produced
Swift cohort remains required. Witnessed/own-account aggregate cleanup and the
other foreign surfaces remain open.
The pre-existing single-session Swift recovery trace also passes in Debug and
Release, with **31 public files** independently exported and replayed per profile.

The first full installed run at `11efbd82` stopped after compiling the new account
helper: the package selector still admitted only the three historical test-target
names. At `63b0e824`, the selector explicitly admits `account_cleanup` while keeping
exact source, target-kind and profile-path validation. The expanded regression
fails on the old selector and passes with the fix; all 20 C consumer/account-report
contracts and the source gate pass. The failed full run is retained; a fresh full
cohort is running. Packaging and runtime results remain distinct.

The C candidate now exposes [complete original-account cleanup](../bindings/c/ContinuityPackageConsumer/README.md#complete-account-cleanup)
through 11 additive functions, for exactly **50 exports**. It consumes original
discovery, retains all three native owners, freezes the whole member set and offers
complete nested loss accounting before exact acknowledgement and metadata retirement.
Current Debug/Release and minimum-Rust 1.90 Release each pass the actual C process
path: **28 commands / 139 independently replayed public records**, including two
reserved inputs, two older unknown sends, five unconsumed deliveries and two skipped
positions. A measured pre-sync process exit at cut three leaves Reserved; cuts one
and two remain Absent, while the no-cut control commits. Persistent SDK revocation
precedes cleanup. Original ciphertext commitments and all report fields match native
and Python readbacks; wrong-ID and cancellation refusals remain strict. Both release
compilers pass nine owner/admission tests, and strict Clippy passes. Twenty-four
artifact tests include eight report controls that reject omitted members/items,
substituted ciphertext and incomplete lifecycle observations. The tracked Rust census
becomes **264**. This is development qualification; the standard collector/upload
path is extended, but a new complete archive-produced cohort is still required.

The first C fixture attempts remain: a configuration-file reader rejected legitimate
empty stderr, and peer directories intentionally lacked the parent family field.
The log reader is bounded and permits empty logs; configuration validation remains
strict. Peer verification explicitly receives the original parent's family. An old
single-session regression initially refused a mode-0755 evidence parent before any
work; its continuation uses a fresh private parent without changing validation.
None of these fixture corrections relaxes protocol, status or loss-report assertions.
The old single-session C recovery trace also passes in both Debug and Release,
including independent replay. Its first export attempt omitted the separately
stored top-level public report; a fresh explicit export retains that verified JSON
alongside the selected records. Private stores are not exported.

The complete `d9638d1b` installed Rust/C/Swift/Kotlin producer finishes with exit 0
in **2886.499 seconds**, followed by successful independent byte/runtime replay and
admission/export checks. The sealed cohort has **21,227 files / 491,214,180 bytes**,
inventory `38eb548a50ffb4f8a9c25e2fdbbaabd68c09a324c42c983ac197a75243f52ff0`.
It retains the 39-export C surface and does not qualify the later C cleanup extension.
Both hosted push/PR CI runs and CodeQL at `d9638d1b` complete successfully. This
includes the macOS installed workload that previously exposed the socket-error race.
The same source passes the four `sdk-020` groups on a USB iPad Pro M4 / iPadOS 27.0.1.
Independent proof/signature/binary/result readback passes; the run-owned app is
uninstalled, with three recorded absence observations and an independent live check.
Provisioning updates and registration remain disabled. Its sealed device cohort has
**58 files / 57,586,989 bytes**, inventory
`86c19942c2f012819f40e720a24a001f7391085418eb7f6e5030659e2a516616`.
This SDK workload uses test-only in-memory policy-update state; durable mobile
Continuity and the full current/minimum iPhone/iPad matrix remain unqualified.

At `f8efba8f`, the native [original-installation account cleanup](../research/continuity-identity-candidate/INSTALLATION.md#complete-account-cleanup-under-the-original-installation)
entry now retains all three storage owners and authenticates installation scope
before pending writes can be reconciled. It admits the complete authenticated
member set, including under the original required witness after operational policy
closure. Five new tests pass on Rust 1.98.1 Debug and 1.90 Release. Related fanout,
installation and archive-index suites pass **49 / 30 / 3** tests with zero ignored;
strict all-target/all-feature Clippy and the no-TLS build pass. The 455 qualification
inputs match before/after execution. The runner's substring guard erroneously
matched `30 passed` as `0 passed`; its successful product result and failed driver
are retained, exact summary replay confirms 30 successes, and only the unexecuted
three-test suite is continued. An isolated late-admission integration returns the
expected Conflict but changes the pending journal, establishing why refusal must
precede recovery. These are native tests, not installed aggregate-cleanup binding
or full current-source regression results. The tracked Rust census becomes 262.
The sealed native cohort has **1,132 files / 115,152,755 bytes**, inventory
`513489b80ad0319fb5095225711f224839aa0398ed938ed4235a61690d82a6b5`.

The complete `20e22a41` installed producer finishes with exit 0 in **3101.257
seconds**. Independent replay checks **250** unchanged inputs and the actual
Rust/C/Swift/Kotlin package/runtime closure. Both Kotlin profiles have **254 files**,
11 owner tests and nine refusal controls; Serial/G1 each replay **73 account public
records** per profile. Swift remains 238 files, 12 tests and 72 account records;
C retains nine admission tests, exactly 39 exports and account/parent/witnessed
parent records (72/36/17). Every foreign profile completes 59 sync cases/771
commands and the retained restoration/GC/C2 qualifications. The sealed cohort has
**21,226 files / 491,303,099 bytes**, inventory
`d8d67688497eb2f2258ed57116a0c9f543a07a2b72c39c43868d4a235c726220`.
This source predates the native aggregate recovery entry and does not qualify it.

At `c6668fb9`, hosted push Linux installed-package and Android 16 KiB jobs pass,
while both push and PR macOS package tasks fail. The push fails in the Swift
account trace; the PR passes C/Swift and fails in Kotlin G1 Debug. Both retained
failures expose native status 310 with `Invalid argument (os error 22)` while an
expected-refusal assertion is active. A local isolated real-socket diagnostic
reproduces the native error: **787 of 4,096** closed-listener attempts return
EINVAL from the initial `peer_addr()` observation while the same socket retains
ECONNREFUSED. The committed implementation's new regression fails on attempt zero.
The repair reads the socket's original error when peer observation fails, both
before polling and after readiness, and preserves the observation error if no
socket error exists. Existing retry categories, limits, deadlines, TLS and exact
account outcome assertions remain unchanged. All nine real connection/cancellation
tests pass on Rust 1.98.1 Debug and 1.90 Release, including 256 closed-listener
attempts per IP family; 13 TLS durable-session regressions and strict Clippy pass.
The 455 qualification inputs match before/after execution. This establishes the
local defect and repair; fresh installed-package and hosted macOS results remain
required. The older `c9d713d2` C failure lacks enough diagnostics to assign the same
cause. Apple's [getpeername contract](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getpeername.2.html)
permits EINVAL for a shut-down socket; it does not make all EINVAL errors retryable.

The actual `c6668fb9` Linux artifact `11230645535` matches its GitHub SHA-256.
Frozen source modules independently replay both profiles' restoration, witnessed
restoration, device parent, witnessed device parent and account traces, with
**24 / 39 / 36 / 17 / 72** verified public records per profile. All 250 recorded
inputs match the commit. Including ten manifests, all **386** previously omitted
files survive upload and readback. The first readback attempts incorrectly assumed
empty harness diagnostics and used a wrong report filename; both are retained.
The final reader compares the two intentional harness diagnostics byte-for-byte
with their verified reports, while consumer stderr checks remain strict. The
sealed readback cohort has **1,526 files / 29,218,049 bytes**, inventory
`60a77c306ba4bec41ce541eff027f6a7d3d10f51bc1b60aab7b2c66f3e9a1ddb`.
This closes those public-export gaps, not full retained-binary or macOS-to-Linux
qualification.

The complete `c9d713d2` installed Rust/C/Swift/Kotlin producer finishes with exit
0 in **3075.250 seconds**. First independent replay verifies **246** unchanged
source inputs, archives, actual binaries and JVM closures. Both Swift profiles
now contain **238 files**, pass **12** strict owner tests and replay the complete
account path with **72 public records**, including the closed-alias store-reopen
check. C retains nine admission tests, exactly 39 exports and account/parent/
witnessed-parent records (72/36/17). Each C/Swift/Kotlin profile passes 59 sync
cases/771 commands; Kotlin remains the earlier 251-file/eight-test pairwise
interface, including its existing GC, C2 and seven refusal checks. This source
predates Kotlin device/account owners. The sealed cohort has **20,892 files /
469,163,566 bytes**, inventory
`4ef958d7a0e511be2b18353003900367a0e754eeb3db6cc52bd8501a7d038779`.
The later `20e22a41` result above includes the new Kotlin owners.

At `c9d713d2`, the hosted push Linux installed-package and Android 16 KiB jobs
complete successfully, and CodeQL succeeds. Push CI completes successfully; PR CI
fails in the macOS installed task's C account refusal/output-initialization check
before Swift/Kotlin execution, and in Android 16 KiB cleanup. The retained C
diagnostic does not identify the mode, actual status or output predicate; its
root cause is not established. Local package success does not override either
hosted failure. The downloaded Linux artifact
`11226214231` matches its GitHub SHA-256 but lacks five new C public directories:
restoration, witnessed restoration, device parent, witnessed parent and account
delivery. Source `84707ad4` adds them explicitly to both Linux/macOS upload lists.
Replaying old/new selections on the actual local exports changes coverage from
zero to **386 files per lane**. The workflow source/toolchain contract passes.
Local actionlint reports the same two pre-existing `ubuntu-26.04` catalogue
diagnostics before and after; it is not counted as a clean lint run. The retained
initial test-selector error is corrected using the actual parsed test class.
The CI retention cohort has **22 files / 7,821,603 bytes**, inventory
`76540c7633780dc237b996a26d6727e224dfd7570232c8fdaa26436dd417a94f`.
The later `c6668fb9` readback above closes these five export gaps. One successful Android run does
not establish stability, and hosted job success cannot replace missing readbacks.

Source `b41f91fe` adds mode, expected/actual status and zero-output diagnostics to
the C account qualification client without changing its assertions or deadlines.
Strict GCC syntax and Clang Debug/Release compilation pass. Four repetitions per
installed `c9d713d2` native profile pass, each independently replaying 72 public
records. These eight local runs do **not** reproduce or resolve the hosted account
failure. Its original failed artifact and direct job log remain retained; the
GitHub CLI cached-log ZIP failure is also preserved without changing global caches.
The PR Android artifacts show full/minimal instrumentation passing (three/one
groups), then device loss and unresolved cleanup; their underlying cause remains
unknown. The diagnostic cohort has **653 files / 17,897,978 bytes**, inventory
`b59d28d143d0e09ca4ac5bc32c67f416791fb5b7de9abc60a291b32d9f0f596e`.

Source `249c40a5` adds Kotlin device parents, fresh/restored peer children, typed
account status/results and complete-set member delivery. An atomic parent
reference and call reachability fences retain live/in-flight native ownership;
successful close or known CLOSED clears the stored link, while BUSY and unknown
failures retain it. The public device may be collected before its peers activate.
Deterministic store release still requires retaining and explicitly closing the
device; Cleaner scheduling after the last hidden link is nondeterministic.
Both installed `b809638c` native profiles pass 11 strict Kotlin owner tests.
Debug/Release with Serial/G1 pass four actual account workloads, independently
replaying **73 public records each**, including public-parent collection before
activation, one-winner concurrent close, held closed aliases, all 64 native slots
reclaimed and original-store reopening. Each profile passes eight prior real
workloads, with **31/32/31/24/37/39/59/34** public records. Both collectors/profiles
also pass the 16-round prepared-owner GC workloads and the in-flight server
workloads; each latter run has **13 verified C2 compilation logs and 47 public
files**. Account frames use normal JVM compilation and have no forced-C2 claim.
All **16** compiled Kotlin/Java/test inputs match the commit. Independent replay
verifies the Maven coordinate and actual runtime JAR closure; three actual Java
compilation controls refuse raw operational, device and native-owner construction.
All **91** artifact tests pass. The sealed development cohort has **2,670 files /
309,759,933 bytes**, inventory
`ecc468a893c8fc6dcf31853ff1e261eac133cdeb5b23da5bcff75f05a28e6b88`.

Two isolated one-line faults each still pass all 11 unit tests but fail real
account bootstrap under both collectors: removing parent retention yields CLOSED
on peer activation; retaining the parent link after explicit close strands native
capacity while closed peer aliases remain alive. They are deliberate controls,
not historical released defects. The development prototype's Kotlin-mangled
method name is recorded with `javap`; final source preserves the `NativeOwner.call`
name checked by the existing C2 verifier, and all relevant flows were rerun.
The first independent reader incorrectly applied the closed-coordinate inventory
verifier to raw Gradle staging, which also contains repository metadata. Its
failure and partial exports remain retained. The corrected reader copies the same
version coordinate as the producer and applies the unchanged strict verifier.
This cohort uses new Kotlin/Maven overlays on installed native bytes; full current
archives, required-witness/own-account delivery, aggregate lifecycle and broader
platform/provisioning qualification remain open. The completed `c9d713d2` package
cohort above predates this Kotlin change; its hosted workflows retain their own
recorded status and evidence limits.

Source `dba721b8` corrects Swift peer lifetime after explicit close. The earlier
`a8ae179a` implementation passes its 12 unit tests but a stronger real account
bootstrap retains closed peer aliases while reopening the original installation;
it fails with native 703 because the hidden parent still owns the policy store.
The fix snapshots the parent under a private lock for each call and releases the
stored reference on successful close or known CLOSED, preserving BUSY and unknown
failures. Native work and reference disposal occur outside the lock. Debug and
optimized Release each pass 12 strict unit tests and the full account workload,
with 72 independently replayed public records/profile. Two concurrent closes
have exactly one winner, stale aliases refuse calls, and the original store
reopens while closed aliases remain alive. This is finite concurrency evidence
with a source-level locking argument, not a general race-freedom proof.
The sealed cohort has **225 files / 63,520,219 bytes**, inventory
`f60d86bcc2761a369d1c88d4eeebc947254b047aab44103f4f92bfff1686fc04`.

Source `a8ae179a` adds Swift device parents, fresh/restored peer preparation,
typed account status and complete-set member delivery. The actual Swift CLI
uses the original three installations and two recipient devices, with dropped
public-parent references, receiver termination after application commit,
original-ID replay, refused unary replay, reordered targets and cancellation of
an unselected member. Both profiles pass 12 strict unit tests, the account trace
and eight earlier real workloads/profile. Independent replay checks 72 account
records and 31/32/31/24/37/39/59/34 legacy records/profile. All 19 selected Swift
and shared-harness inputs, plus 128 compiled native inputs, match the source;
strict native Clippy and 90 artifact tests pass. Removing only the hidden parent
reference still passes all 12 unit tests but fails real peer activation with
CLOSED, demonstrating the integration boundary. The original loader failure
from an absolute Cargo library install name is retained; successful overlays
use hash-checked installed `b809638c` native libraries. The sealed development
cohort has **1,425 files / 114,311,587 bytes**, inventory
`4c27a4431a3323bbbb5f0c47837821b17cf6127174f869cb56b4630dcf3fb34e`.
It predates the explicit-close correction above. Both Swift cohorts are source
overlays on installed native bytes; new full installed packages remain required.
Required-witness and own-account delivery, aggregate abandonment/report traversal,
Kotlin parent owners, provisioning and credential lifecycle remain separate gates.

The complete `b809638c` installed Rust/C/Swift/Kotlin producer finishes with exit
0 in **2862.595 seconds**. Independent replay verifies **243** unchanged inputs,
archives, runtime closures and native/JVM artifacts. Both C profiles replay the
account, parent and required-witness parent paths with **72/36/17** public records,
nine admission tests and exactly 39 owner exports. Each C/Swift/Kotlin profile
passes 59 sync cases and 771 commands. Swift runs nine owner tests/profile;
Kotlin runs eight, seven refusal controls, Serial/G1 collection checks and 96 raw
sync receipts/profile. The sealed cohort has **20,727 files / 468,199,252 bytes**,
inventory `0e652ebcebf17d7f44f31a5da532d213a1e7b386150cdd9a7612e5bf0fd08eb4`.
This qualifies installed C account delivery and marker publication, but predates
Swift device/account owners and the later account-record schema/language tag.

Both `b809638c` hosted Linux installed-package jobs fail before runtime: GCC
rejects three misleadingly indented C account-client statements under `-Werror`.
Source `896868fd` adds explicit control blocks. Local GNU GCC 15 reproduces the
three failures before the change and accepts the corrected source with the same
strict flags; a new Linux runtime run is still required. The push Android 16 KiB
job passes full/minimal instrumentation but fails cleanup when owned-ADB server
validation expires and subsequent queries lose the device. Final package cleanup
is unresolved; the underlying disappearance is not established. PR Android lanes
pass, but both workflows fail overall; CodeQL succeeds. The retained CI/GCC cohort
has **57 files / 2,866,976 bytes**, inventory
`5db2e096fdd143418759e12956a665142b26f3855ead4e6f0654ed6654a7fe3a`.
These observations do not establish Android stability or current-source device
qualification. Same-host package traces and elapsed qualification times do not
establish cross-host, independent-engine or controlled-performance claims.

Source `c46695b6` exposes complete-account C operations through the original
device parent. Calls retain every selected peer/context, reject another parent,
and invoke native `FanoutInput`/`send_account_member` with the complete original
input. They deliver one member and preserve distinct local aggregate and remote
member outcomes. Current Rust 1.98.1 Debug and minimum Rust 1.90 Release pass the
real three-installation/two-recipient workload; each independently replays **72**
public records and checks **39** exact owner exports. The trace covers missing,
duplicate, cancelled, closed and foreign-parent targets, receiver exit after
application commit, original-message retry, refused unary replay, reordered
targets and cancellation of an unselected member. All involved owners return BUSY
during that call, while an idle peer outside the set can close. Current source
also passes **13** account/native/device/legacy/witness traces, nine default-
scheduler unit tests, strict Clippy and **90** artifact tests. Minimum Rust passes
nine unit tests separately. All **128** compiled source inputs match the commit.
The sealed development cohort has **624 files / 68,695,248 bytes**, inventory
`8df78b5d2df0bf019316e51a7df8aff5b53d74687fb5a3b390460c6fcf0665c3`.
This remains an overlay on checked SDK archives. Fresh installed packages,
required-witness account delivery, own-account C fanout, language-level parent
owners and provisioning/lifecycle integration retain their separate gates.

The same change fixes qualification marker publication after an existing fresh-
constructor workload reports `invalid socket barrier`. Its old writer exposed
the final path before writing. A controlled pause in that window reproduces the
unchanged C reader's failure on an empty file, followed by a valid final marker.
The original failure did not record the individual read results. Markers now
reuse write/sync-before-publication, with a retained deterministic visibility and
no-replacement check; the full constructor/socket regressions pass. No marker
retry, weaker assertion or longer timeout was added. The first account trace's
strict newline-framing error and two pre-execution driver filename collisions
also remain retained.

The complete `e3b4da54` installed Rust/C/Swift/Kotlin producer finishes with exit 0
in **2832.653 seconds**. Independent replay verifies **240** unchanged source
inputs, archives, actual native/JVM artifacts and runtime closures. Both C
profiles replay device-parent and required-witness parent paths with **36/17**
public records, nine admission tests and exactly 36 exported owner symbols.
Each C/Swift/Kotlin profile passes 59 sync cases and 771 commands, expiry and
witness restoration. Swift's 235-file packages run nine owner tests/profile;
Kotlin's 251-file packages run eight, seven refusal controls, Serial/G1 prepared
and in-flight collection, compilation checks and 96 raw sync receipts/profile.
The cohort has **20,572 files / 465,280,277 bytes**, inventory
`dc71a591f00e564a9f944f8550822b797a14e341f9c09c77dbb1289f6455b120`.
This closes installed qualification for C invocation/device-parent additions;
Swift and Kotlin still wrap their earlier pairwise interface. It predates the
account addition and marker fix above. CodeQL and push CI succeed; PR CI fails
in `bindings-android-runtime-16k`, with its exact terminal job log retained in
the CI/GCC cohort above. Its cause is not inferred from another Android run.
Same-host execution and qualification durations
do not establish independent-engine, cross-host or controlled-performance claims.

Source `e708c03f` adds a C device parent and prepared peer children under the
original active installation, signer, policy, witness and storage leases. Both
roles support explicit fresh admission and session restoration; peer configuration
cannot replace local authority. Closing a child preserves its parent, cancelling
one child preserves siblings, and parent cancellation wakes an active child.
Parent close releases original stores and invalidates retained children. Current
Rust Debug and minimum Rust 1.90 Release each pass both new real C workloads,
with independent replay of **36 and 17** public records respectively. They cover
input copies, registry capacity, local identity/signer refusals, concurrent close,
signed TCP/mutual TLS witnesses, durable policy revocation and original-message
retry after application commit. The current default-scheduler unit run, eight
legacy C traces, strict Clippy and **86** artifact tests also pass. All 126
compiled inputs match the commit; the unpublished C owner export set is 36.
The sealed development cohort has **470 files / 76,242,236 bytes**, inventory
`5fca6b9eb9d52da575f82739908d1620ac0c29d0d4ed86e47604db6d68b4c139`.
These tests use multiple handles for one context at each endpoint; distinct-device
fanout, foreign complete-account transactions, Swift/Kotlin parent ownership,
explicit provisioning and credential lifecycle remain open. This cohort uses
development overlays on checked archives; fresh installed packages and CI for
this change remain separate. Retained fixture failures include a pre-I/O BUSY
observation race and a physical-byte oracle that incorrectly spanned redb
close/open. A peer-free control reproduces the latter; the corrected oracle
checks unchanged bytes while the same parent remains open and separately checks
lease reopening. The original private database dump stays outside public evidence.

Checkpoint `feccce96`, preceding the device-parent implementation, completes
[push CI](https://github.com/billlza/q-periapt/actions/runs/36975578774),
[PR CI](https://github.com/billlza/q-periapt/actions/runs/36975586337) and
[CodeQL](https://github.com/billlza/q-periapt/actions/runs/36975586289) successfully.
These runs do not establish stabilization of the retained intermittent Android
failures below, or qualify the later device-parent source.

Source `cde348b8` binds the C witness carrier to each active invocation's
cancellation token and absolute deadline. Independently configured endpoints and
credentials remain retained; no configuration is reread or cancellation reset.
Existing public owners still use their original permanent token. This prepares
shared-device operation but does not expose foreign parent/child handles. Current
Rust Debug, minimum Rust 1.90 Release and current default-scheduler runs each pass
**nine** admission/deadline/cancellation tests. Strict Clippy and **82** artifact
tests pass. Four real C workloads cover fresh/restored constructors, signed TCP
and mutual TLS witnesses, partial admission cancellation, original-state recovery
and revoked cleanup; independent public replay verifies 37/39/59/34 selected files
respectively. All 125 compiled Rust/C/header files match the commit, and the
candidate C export set remains 34. The cohort has **418 files / 82,561,585 bytes**,
inventory `ed98e7a480546cf16f568472c1a5e41aa6ff9d5fb3a3e79a4607fe05545ce7f1`.
These are development overlays on checked SDK archives, not a newly completed
installed-language producer or a controlled performance comparison. The first
socket-fixture failure and a driver-environment failure remain retained. The
latter invoked global rustup accidentally; it reported failed automatic recovery
and rollback. Re-running with every subprocess bound to the isolated toolchain
passes all 82 tests; no global repair was manually performed.

Source `18d6fcc9` completes the full **342-test native library regression**, all
features, one test thread and no skips, in **1842.558 seconds**. The 454-file
before/after source maps and executed binary hash agree. The sealed cohort has
**468 files / 35,249,091 bytes**, inventory
`433552cb102062f32f58a54e9a68d7e3c9ec1d76ab8a2ad57b009c30c9fbf246`.
This covers shared-service restoration and fresh peer admission. It predates the
C invocation change above. Its CodeQL workflow succeeds; full hosted CI remains
separately tracked.

The full `18d6fcc9` installed Rust/C/Swift/Kotlin producer also completes with
exit 0 in **2848.864 seconds**. Independent replay binds 238 unchanged source
inputs, archives, executables and JVM closures. Each C/Swift/Kotlin profile passes
59 sync-fault cases and 771 commands, real-clock expiry restoration and required
witness restoration. Swift runs nine owner tests per profile; Kotlin runs eight,
seven refusal controls, Serial/G1 prepared and in-flight collection, compilation
checks and 96 raw sync receipts per profile, including eight Reserved sends.
The sealed cohort has **20,444 files / 462,626,750 bytes**, inventory
`e98a6ba66c083ab15c8848b37e138cf73b3cf12e1648ad3e464b46749f0bacd8`.
This is same-host macOS execution with one native Continuity protocol engine.
It covers the native admission/restoration additions, predates both later C
changes above, and supplies no controlled performance comparison.

Source `469ccf31` adds `DeviceService::admit_peer` and `BootstrapPeer` for a freshly
verified context under the original active service. It checks the exact local
owner, policy/witness scope, current advertisement/credential/runtime authority,
current local and known-peer rosters, and the original witness. An unknown account
uses its independently verified initial snapshot without installing or advancing a
roster. Admission reserves no operation or session; actual bootstrap repeats all
native checks and first persists that roster with its operation reservation.
Rust 1.98.1 Debug and Rust 1.90.0 Release each pass **30 installation tests, six
roster tests and the two-peer account transaction test**. They cover unchanged
storage bytes, both roles, full roster capacity, expiry versus explicit restoration,
later revocation, loss of either required-witness exchange and policy/runtime
closure after either authenticated reply. All three public TLS harness tests,
strict Clippy and no-TLS compilation pass. All 454 compiled input hashes match
the commit. The sealed cohort has **570 files / 98,942,877 bytes**, inventory
`0a12373b893fc14247bbeb69f332f5f01b7ab624645396e620d2e65910e74920`.
The later `18d6fcc9` checkpoint above closes the full 342-test library regression.
Fresh foreign packages, parent/child owners and product provisioning remain open.

The preceding `b32c046c` hosted push and PR workflows both finish with an Android
16K runtime failure; CodeQL succeeds. The push run's full consumer passes, but its
minimal consumer installs successfully but Android records the exact instrumentation
process PID 5340 as `LOW_MEMORY`; the matching lowmemorykiller record reports a
minimum-watermark breach. Instrumentation returns `Process crashed`. The PR run
fails APK installation with a null `PackageManagerInternal.freeStorage` reference.
The failed-run cohort contains **162 files / 1,155,218 bytes**, inventory
`8eea50ef3f278820d6fd45e558ad61ad6a9f2d5cfa04c525716e330ac33c6cd6`.
These retained failures do not establish an SDK defect or
the cause of the memory-system decision. At `1741866e`, the full push workflow succeeds, while
the PR workflow's current-Rust Linux candidate job loses communication with the
hosted runner. GitHub's annotation reports that loss; its job log is unavailable
(HTTP 404). Neither the annotation nor the successful push identifies the cause.

Source `caf5ab1e` adds `DeviceService::reopen_peer` and `ReopenedPeer`: established
peer contexts can be restored under one original installation/journal/archive
lease. Admission requires the exact local owner, policy/witness scope, session,
role and archive, with the existing current-authority checks. The original key
commitment is retained privately in memory; durable scope and protocol formats
are unchanged. Rust 1.98.1 Debug and Rust 1.90.0 Release each pass all **25**
installation tests plus the complete two-peer account transaction test. The latter
covers own-account and peer-account recipients, omitted-recipient refusal without
partial mutation, delivery to independent receiver journals and original
ciphertext replay after restart. Public TLS passes all three harness tests;
strict Clippy and no-TLS compilation pass. All 454 compiled input hashes match
the commit. The cohort has **498 files / 45,918,300 bytes**, inventory
`950fb7b1e544b4ec51352818c61d58455e2829804f5cb57fcfb558d4b8431553`.
The later `469ccf31` checkpoint supplies native fresh admission. Foreign
parent/child owners and current-source complete library/package qualification
remain separate requirements.

The complete `a897ba54` Rust/C/Swift/Kotlin installed-package producer finishes
with exit 0 in **3114.736 seconds**. Independent replay binds 238 unchanged source
inputs, candidate/package archives, native executables and JVM closures. Every
foreign language/profile pair passes both the 24-public-file real-clock expiry
restoration trace and the 39-public-file required-witness constructor trace.
Each C/Swift/Kotlin profile completes 59 sync-fault cases and 771 commands.
Swift's two 235-file packages run nine owner tests each; Kotlin's two 251-file
packages run eight owner tests, seven refusal controls, Serial/G1 prepared and
in-flight collection and checked compilation evidence. Its 96 raw sync receipts
per profile include eight Reserved sends. The first readback driver failed on
the older native verifier signature; the corrected driver supplies the separate
restoration directory and passes without rerunning or weakening the producer.
The cohort has **20,452 files / 462,488,561 bytes**, inventory
`ebf925916b48de75ccaeefc0aeb7481a34aafb3a398d5eac269052ef8044cc9d`.
Private runtime keys/journals/databases are excluded. This is same-host execution
with one native protocol engine, predating the shared-service addition.

Source `1741866e` separately passes all **333** current-Rust Debug native library
tests, all features, one test thread, no skips, in **2014.799 seconds**. Before/after
source maps and the binary hash agree. The cohort has **468 files / 35,067,123
bytes**, inventory
`c8d37f4ffd3f465d46dc479751219c02a5d2facbe8f66dca09143c382021c364`.
Its hosted [push check job](https://github.com/billlza/q-periapt/actions/runs/36963673665)
also passes 2,456 artifact tests with three macOS-ACL-only skips and the exact
source gate. The Git-maintenance red/green regression passes locally and there:
all five maintenance workers exit before their owning commands return. The full
workflow outcomes are recorded above; neither 1741866e result covers
the later 336-test shared-service source. Qualification durations are elapsed
times, not controlled performance comparisons.

Source `65c0b5c0` integrates explicit existing-session restoration into C
`qpc_owner_v1_prepare_reopen` and the Swift/Kotlin `prepareReopen`/`reopen` owners.
Local development runs use the actual current foreign clock after advertisement
expiry, reject fresh/wrong-session admission, cancel before work, retain an unknown
external application commit and reconcile its original message ID through real TLS
receiver processes and two application-file readbacks. Six C admission tests,
nine Swift owner tests and eight Kotlin owner tests pass. The mixed Serial/G1
prepared-owner workloads each run 16 rounds with 21 restoration preparations per
64-slot round; each records 1024 forgotten/live/stale/queued owner observations.
The matching native library has exactly 34 exported candidate symbols. Product
ABI 2 and legacy primitive contracts are unchanged.

Source `a897ba54` adds separate required-witness responder-restoration workloads.
C, Swift and Kotlin each perform real foreign-to-foreign TLS bootstrap, select
the same persisted session, refuse missing/wrong witness pins and corrupt
signatures, cancel a held signed-TCP query reply and stalled mutual-TLS handshake,
then reopen the original session. Independent replay validates 39 selected public
records per new workload; the original constructor workload also passes and is
independently replayed in each language. Strict native Clippy, strict C/Swift/JVM
builds and all **82** related artifact tests pass. Expiry and witnessed constructor
cancellation are separate finite workloads, with the same native protocol engine.

The full `65c0b5c0` archive producer stopped after 378.932 seconds at the C Debug
sync-helper inventory gate: the public fixture had eight tests while the validator
still required seven. Its failed run and partial output are preserved. The fix
derives the exact names from the canonical public fixture contract, still refusing
missing/duplicate/extra names, with negative regression coverage. The fresh clean
`a897ba54` source gate passes; its subsequently completed full archive producer is
recorded above. The earlier sealed development cohort has **1224 files /
50,023,141 bytes**, inventory
`27c6ecaa60995a4889bdfebb17acc9e0f8a81b3dcf311a818362b8fb1fa64e13`.
It retains source snapshots, SDK inputs, actual foreign binaries/JARs, selected
public records and failed drivers. Private runtime databases, journals and keys
are excluded. This evidence does not admit the unpublished `qpc-owner/1` candidate
as the 0.2.0 product.

A 2026-10-02 live registry check finds the locked native dependency versions equal
to the current stable releases: `aws-lc-rs 1.18.1`, `aws-lc-sys 0.45.0`, `cc 1.5.1`,
`cmake 0.1.58` and `rustls 0.23.45` (`0.24.0-dev.1` is a prerelease). The actual
independent TLS endpoint reports OpenSSL **3.5.9**, matching the latest patch of
the [official 3.5 LTS branch](https://openssl-library.org/source/), supported until
2030-04-08. Registry replies, lock hash and endpoint binary/version output are
retained in that cohort. Version recency does not establish relative performance,
unbounded stability or completion of the final dependency/security review.

Source `b60c76ee` adds explicit restoration of an existing native session after
prekey-advertisement and original roster-snapshot expiry. The retained old-path
counterexample admits a message session at time 170, then fails reconstruction
with `Validity` because its advertisement ended at 160. An opaque
`SessionReopenRequest` now authenticates the original snapshot; only the original
Active installation can release its exact context/service after checking the
persisted message session, local role, closure archive, current rosters, policy,
credential/runtime lifetime, signed send budget and required witness. It creates
no missing files and grants no expired advertisement permission for a new bootstrap.

Current Rust 1.98.1 Debug and minimum Rust 1.90.0 Release each pass **23**
installation tests. Bundle regressions independently distinguish current device
credential expiry from policy expiry. All-target/all-feature strict Clippy,
no-TLS library compilation, seven package-evidence tests, 43 clean-clone CodeQL
gate tests and the clean source gate pass. Three current-source public API
harness tests pass using separate fixture roots. The new independent-process TLS
scenario reconciles an unknown application commit after explicit protocol-clock
advancement and both peer restarts: original ciphertext bytes and two application
readbacks match, and a further restart retains Acknowledged. This is a controlled
clock/process-loss experiment, not elapsed deployment or physical power-loss proof.
The **2,029-file / 92,587,042-byte** native cohort has inventory
`e6eeff194256173885717a79731f3216eb4e76bfa34105b541b6e2a7b7e3cb54`.
Full 333-test regression was not rerun for this change; these are targeted scopes.
The actual clean `b60c76ee` Rust archive producer subsequently completes in
**320.556 seconds**, exit 0. Debug and Release each execute all three public API
harness tests and strict installed-consumer Clippy passes. Independent readback
binds **238 source inputs**, a **140-file candidate archive**, actual surviving
binaries, exact ciphertext and application records. Its separate sealed
**456-file / 37,674,969-byte** cohort has inventory
`52293aaf14588e8d22713934b2059793c751e71a36d9ab14650387fa3d4849fe`.
A current-source Rust **1.90 Release** run of the public restoration TLS scenario
also passes; its raw output, exact source map and binary are retained in that
cohort. It is not an installed minimum-SDK package run. C/Swift/Kotlin restoration
owner integration remains required, distinct from the completed older package
cohort below.

The preceding `47a476f6` hosted CodeQL run refused its stale exact source count
(254 required, 255 tracked). `b60c76ee` updates the requirement and guide to the
current **259-file** Rust inventory while retaining exact extracted-path equality
and every quality metric. Local gate tests pass in a real clean clone; a managed
worktree's `.git` file remains refused by the unchanged provenance boundary.
This is not a passing new hosted CodeQL result.

The complete actual Rust/C/Swift/Kotlin producer at clean `5d782f94` has now
finished in **2,629.997 seconds**, exit 0. Independent readback binds **234**
source inputs, the installed candidate, both **235-file Swift** packages and
both **251-file Kotlin** packages, actual binaries/runtime closures and public
records. Both profiles of each C/Swift/Kotlin matrix execute **59** calibrated
sync-fault cases and **771** commands; the Kotlin raw **96** receipts/profile,
eight Reserved sends, Serial/G1 prepared/in-flight GC and C2 invocation evidence
are replayed. Swift runs nine owner tests/profile; Kotlin runs eight owner tests
and seven refusal controls/profile. The C public sync records are exported and
replayed from this exact fresh producer, closing the earlier exporter-only scope.
The **20,002-file / 448,490,281-byte** sealed cohort has inventory
`dfec60e64508ed0f8ff6ba68647ccbdebee3275ed59f3bbd5d093296f493dda1`.
This remains same-host macOS arm64 execution with a shared protocol engine and
does not include the later `b60c76ee` restoration API. Private runtime state and
keys are excluded from the cohort. Neither checkpoint grants release admission.

Source `5d782f94` fixes a complete-account authority bypass: after aggregate
commit and revocation of another mandatory recipient, the old unary
`send_message` and `resume_message` paths both still returned 137 ciphertext
bytes for an unrevoked member. The retained failing test and source snapshot
establish that counterexample. Live aggregate slots now require complete-account
replay; current context/owner, roster/checkpoint, every live member's signed
budget and witness checks precede release. Terminal sessions retain `Retired`;
independently closed members retain exact outcomes while other admitted members
continue. A session awaiting closure accounting yields `ResolutionPending`.

The native `send_account_member` TLS API delegates every attempt to the same
original aggregate transaction and checks all target archives before reservation.
It preserves original IDs, bounded retries/cancellation and distinct consumption,
unknown-delivery and retired-history outcomes. It does not imply atomic remote
execution or provide the still-missing foreign multi-peer owner interfaces.

The final implementation passes all **322** all-feature Debug library tests on
Rust **1.98.1**, zero failures/ignored tests (1,784.01 seconds of test execution;
1,959.627 seconds including compilation). Rust **1.90.0** Release passes all
**43** fanout tests, zero failures/ignored tests (553.46 test seconds;
621.163 seconds including compilation). The public owned-service integration
scenario and its child helper also pass: real process/socket TLS, one rekey,
unknown external-commit reconciliation, three independent application readbacks,
eight competing leases, pre-cancellation and durable revocation. Strict all-target
Clippy, targeted formatting and 20 hardened package/contract/context checks pass.
Independent readback checks the final input map, compiler identities, actual
test-binary bytes and raw logs. Earlier failed fence/lint/test-driver attempts
remain retained with their scopes. The 133-file / 57,323,609-byte cohort has
inventory `5d4de98bff8673b488684013416ec8f0ab7181a8412e8613f6a645dc9b1a161b`.
This qualifies local native macOS arm64 behavior. The separate completed
Rust/C/Swift/Kotlin producer at the same source is recorded above; foreign
multi-peer integration and release admission remain open.

Clean source `7997282c` completes the full local macOS arm64 Rust/C/Kotlin
installed-package producer in 2,082.055 seconds, exit 0. Independent readback binds
233 source inputs, the candidate Cargo archive, two 251-file Kotlin archives,
Maven/native/license bytes, actual surviving tools/binaries/JARs and public
execution records. Both native C profiles and both Kotlin profiles complete
59 calibrated interruption cases and 771 commands each. Every Kotlin profile
also verifies eight owner tests, seven refusal controls, ordinary and witnessed
connections, explicit controlling-thread interruption, prepared-owner GC and real
callback GC under Serial/G1 with selected C2 frames. Its 699 selected public files
per profile include 342 interruption records and 94 in-flight lifetime records.
Both profiles preserve the existing callback, unknown-commit, duplicate and rekey
assertions. The complete local package cohort has 12,804 files / 392,245,363 bytes,
inventory `3716cc9911101bedb84c997d5b2797209ca31f892ecb824fc17b336bf934269e`.
This closes that exact source's local installed-package checkpoint; it does not
admit the unpublished candidate as a 0.2.0 product.

The same `7997282c` source completes an actual USB iPhone 16 Pro workload on
iOS 27.0 (24A437), including existing-profile signing, installation, execution,
device-result readback and proof verification. All four sdk-020 groups pass;
the owned test app is uninstalled, with three recorded absence observations and
a subsequent independent live absence check. Automatic provisioning updates and
device registration remain disabled. The 60-file / 57,474,051-byte cohort has
inventory `dc8fb4418b6d7a2304aac86c30e4ad0732d1d0b81717757631739b6402146900`.
That capture initially left the iPad lane open: its localNetwork route failed the
wired preflight before running an app. The original iPhone cohort preserves that
observation unchanged.

After USB reconnection, the same clean `7997282c` source completes the physical
iPad Pro 11-inch M4 workload on iPadOS 27.0.1 (24A446), in 133.123 seconds. All four
sdk-020 groups pass, with existing-profile signing, actual installation/execution,
device-marker readback and independent proof verification. Its owned app is
uninstalled, followed by three recorded absence observations and an independent
live absence check. Provisioning updates and device registration remain disabled.
The canonical matrix emitter and independent verifier qualify byte-identical
copies of both original child proofs: distinct devices/runs, wired transports,
matching clean source and Xcode provenance, and the default 24-hour age bound.
Both bind native static library
`756a73e6590727e1f3985b4123bf3d58586932fd5b4bbaaac303c4eb98aac4bd`.
The new 99-file / 65,402,188-byte matrix cohort has inventory
`ccb2e3cb6926ce982ec463d0240eafe045f291a065c9672d506ad840dc5d4256`.
This closes the exact source's current-OS USB iPhone/iPad SDK matrix. The two
retained sequential runs were assembled using the canonical proof commands;
`apple-device-matrix.sh` was not rerun as one combined invocation. Test-only
in-memory policy state, minimum-OS coverage and durable Apple Continuity remain
distinct boundaries. The later evidence-export commit is not the runtime source.

Source `7997282c` also completes [push CI](https://github.com/billlza/q-periapt/actions/runs/36937435741),
[PR CI](https://github.com/billlza/q-periapt/actions/runs/36937442924) and
[CodeQL](https://github.com/billlza/q-periapt/actions/runs/36937442938). Its
[installed macOS Swift/Kotlin job](https://github.com/billlza/q-periapt/actions/runs/36937435741/job/110623201473)
retains artifact 11201701023, 49,008,567 bytes, SHA-256
`cd2db8fd4813cfb1dca33f17b8dc423b7a9eaabe3140ae395ac8118eab8ba663`.
Independent local replay of the Kotlin portion binds 233 committed inputs, two
251-file archives and all 1,398 selected public records. Each profile verifies
eight owner tests, seven refusal controls, Java module execution, ordinary and
witnessed connections, controlling-thread interruption, all 59 sync-cut cases /
771 commands / 96 raw sync receipts, and eight real Reserved sends. Serial and
G1 each complete 16 prepared-owner rounds and 1,024 forgotten/live/stale graphs;
each in-flight run preserves eight callback receipts, seven returned native-slot
checks and 13 verified C2 invocation logs. Original hosted processes and tool
installations are not rerun locally. The 7,192-file / 321,505,587-byte cohort has
inventory `9b5cb7e38ab39c7a7fe9e8743e95132ac04733b0f6ae523593a9dd8f12e3ff3c`.
This closes the exact source's hosted Kotlin lifetime/package checkpoint; it does
not extend the tested JVM/GC scope or establish a repair for the older Android
transport failure.

Hosted source `0511ce84` also completes [push CI](https://github.com/billlza/q-periapt/actions/runs/36928969828)
and its macOS installed Swift/Kotlin job. Artifact 11199326147 matches SHA-256
`c59b8e42cd4ea3ef3a7b3fca6de2aa9605b8011ba0454f34cddabbe49435268e`.
Independent replay checks 231 committed inputs, both 249-file Kotlin archives,
1,210 selected public records, and all 59 cases / 771 commands / 96 raw sync
receipts per profile, including eight Reserved sends. Its sealed cohort has
6,916 files / 91,142,828 bytes, inventory
`e4c2b63a909324d30f2017289f07ae4596a78c0e92751e4f0a006ac1c825a846`.
The earlier c3 Android failure remains preserved; this successful later run does
not establish its root cause or a stability repair.

The C collector now exports its separately verified public sync-fault records,
and both native CI lanes upload them. Applying the actual export path to the
completed 7997282c matrices verifies 342 records/profile and independently replays
all 771 commands and 96 raw sync receipts/profile. A private canary stays outside
the export; removing a required public record from a separate public-only copy
fails before a destination is created. The top-level Kotlin scope wording now
also reflects its implemented in-flight checks; the original 7997282c report's
understated scope string remains unmodified in its cohort.

The [product-admission review](continuity/PRODUCT_ADMISSION.md) identifies a
structural integration gap: current foreign owners retain one pairwise context,
whereas native account fanout needs all verified recipients under one device
journal transaction. Opening one current owner per peer or looping pairwise sends
does not implement that contract. Device-scoped multi-context ownership, explicit
enrollment/provisioning, authority renewal and platform persistence must be
implemented and qualified before product admission.

Prepared Kotlin owner lifetime now has a separate installed-JAR workload under
Serial GC and G1, each with a 128-MiB heap cap, in both native Debug/Release
profiles. Each JVM completes sixteen rounds: 1,024 forgotten owner graphs are
observed in a reference queue and their native capacity is reclaimed; full
strongly reachable pools survive an observed collection; stale cancel/finish/close
calls fail after slot reuse without changing replacement-owner admission.
Direct C controls establish operational missing-configuration status 500,
recovery private-file status 203 and cancellation status 302 in both profiles.
The first test's shared-500 assertion fails and remains retained. Its corrected
role-specific oracle passes all four combinations, while an isolated SDK copy
with the Cleaner release action disabled fails in round one. Normal SDK JAR bytes
are unchanged. Existing constructor and controlling-thread interruption regressions
also pass. This is development evidence against retained f753e75d native inputs;
current-source package collection and in-flight/callback GC stress remain open.

The Kotlin installed-owner collector now requires the existing positive-reservation
journal sync-interruption matrix. Development execution against the unchanged
f753e75d native Debug/Release libraries and helpers completes 59 cases / 771 commands
per profile in 309.132 / 308.407 seconds. Each profile calibrates 13 send, six freeze
and nine acknowledgement syncs, covers both sides of every boundary, and observes
all three send dispositions plus open/pending and pending/closed cleanup outcomes.
Eight send cases retain a real Reserved outcome. Independent replay checks all
96 raw sync receipts, 771 command records and 342 public records per profile,
including original IDs, complete reserved lengths, ciphertext commitments, loss
reports, revoked operation authority and closed-archive retirement/restoration.
The fixed JVM command bypasses the shell for fault injection and binds the launcher,
JVM, four JARs, installed native library, native helper and probe identities.
An injection preflight retains the shell route's missing probe receipt and the
direct JVM route's 13 actual syncs. This is process-interruption development evidence;
the full current-source package collector, power-loss/EIO behavior and broader
JVM in-flight GC/interruption qualification remain separate.

The `c3c217e1` [Android 16-KiB job](https://github.com/billlza/q-periapt/actions/runs/36926187676/job/110586234113)
fails after APK installation and before instrumentation: package ownership does
not converge before the existing deadline, transport is lost, and app cleanup
remains unresolved. Independent diagnostics readback matches 54 lowmemorykiller
text/killinfo pairs; their relationship to transport loss and any memory-unit
defect is unproven. The failure is retained separately, as detailed in
[Android qualification](SDK_ANDROID_RUNTIME.md). No current Android runtime pass
or all-matrix CI success is claimed.

The Kotlin collector now extends `artifact/continuity_package.py` with explicit
JDK/Gradle installations, isolated Gradle state, closed Maven/JAR/source/license
checks, extracted Debug/Release native packages, exact runtime dependency records,
three required client/server/recovery traces and Java module/error-path controls.
A development execution completes in 155.973 seconds against the retained f753e75d
native libraries and the separately recorded Kotlin-aware Debug controller. Both
247-file ZIPs independently replay; each profile executes eight owner tests,
94 selected public trace files and seven negative controls. The initial development
source-intake, fixed-repository and localized-javac failures are retained. Private construction was already
correctly refused; the collector now checks the locale-independent diagnostic
code and absence of an emitted class. That development evidence remains separate
from hosted run `36918986946`: commit `2523be07` now completes the full macOS arm64
collector in job `110563064062`. Artifact `11192493090` has SHA-256
`4dcea9819b849d1b67852e7c07f69c274c2469e76cd196d5894c33c615ce63ee`.
Independent local readback verifies all 229 collector source inputs against that
commit, both 247-file Kotlin archives, all 188 client/server/recovery public files,
eight owner tests and seven refusal controls per native profile, and Java module
execution. The original hosted JVM processes are not rerun during this readback.
This closes that commit's installed Kotlin package checkpoint, not subsequent
source changes or full release readiness.

The next Kotlin consumer increment requires signed-TCP and mutual-TLS witness
traces and two-stage activation in the same collector. A separate controlling-thread
interruption variant explicitly cancels and joins the native activation, preserves
native error 218 and the JVM interrupt flag, closes the original owner, and emits
two exact public receipts only after cleanup. Development execution and independent
replay cover both retained f753e75d native Debug/Release libraries; the controller
delta only admits the explicit Kotlin language. Ordinary activation and send-cancel
regressions also run. This is a same-host/shared-engine development checkpoint;
current-source collection of the new increment remains required. It does not
establish automatic JVM interruption of synchronous native calls or GC safety.

For the separate b62ff9bf TLS refusal test correction, native Ubuntu 24.04 Rust
1.90 and 1.98 CI each complete 311 candidate tests in Debug and Release with zero
failures/ignored tests. The exact truncated/pipelined refusal case passes in all
four executions. Push run 36908770489 concludes success. The original f753e75d
failure remains retained; this is not a deterministic paired same-host experiment
or qualification of later Kotlin packaging changes.

The unpublished [Kotlin/JVM Continuity candidate](../bindings/kotlin/ContinuityPackageConsumer/README.md)
now provides separate operational/recovery owners over the existing `qpc-owner/1`
engine. Its local Maven JAR is consumed by an independent project outside the
checkout on macOS arm64 / Temurin 25.0.4.1 / Kotlin 2.4.20 / Gradle 9.8.0, with
strict dependency checks and warnings-as-errors. Eight native owner tests and an
independent Java consumer pass; direct Java raw-owner construction is refused.
The actual installed Kotlin client, server and recovery executables complete the
existing Rust-driven workloads against the f753e75d native package. These cover
TLS bootstrap, exact-ID lost-ACK reconciliation, rekey, concurrent close/cancel,
callback failures and commit uncertainty, application-process exit, duplicate
callback suppression, revocation and complete prepared two-epoch recovery.
Command logs, receiver effects, all loss rows and closure archives are separately
read back. The test executable alone contains a raw-ABI owner-kind negative
control; the public JAR exposes no raw handle. Shared-engine, same-host execution
does not establish independent endpoints, and the prepared recovery history has
zero reservations. Kotlin positive-reservation interruption is qualified separately
by the development matrix above. GC/interrupt stress, final-source Debug/Release package collection and
CI, other JVM platforms, Android JNI and WASM Continuity remain open. This
development checkpoint adds no product ABI exports or release-admission claim.

The C witness carrier now observes the owner's shared one-way cancellation
between connected socket reads/writes, with at most 25-ms socket timeouts and
one unchanged absolute exchange deadline. The signal is available without TLS
features or operational SDK activation; existing TLS re-exports remain valid.
An in-progress connect still has its original deadline, and arbitrary filesystem
work is not preempted. Cancellation never proves that a witness mutation was absent.

The retained old-library counterexample waits 2,982 ms after cancellation when the
real witness has committed an advance, sent a partial signed reply and held the
socket. The corrected development run returns in 42 ms. Clean runtime snapshot
`547fe920` then qualifies actual installed Rust/C packages with Rust 1.98.1 and
Rust 1.90 in Debug and Release. The four C cancellation intervals are respectively
14/43 ms and 47/21 ms. These are finite functional observations under a one-second
test bound, not a latency SLA or general performance comparison. Busy close retains
the live owner, cancellation releases the socket, and reopening reconciles the
same committed command with a fresh challenge instead of another logical advance.

Each profile retains 274 witness exchanges, two subjects, 44 logical advances,
48 command logs, ten public readbacks, complete revoked-session loss accounting
and 59 sync-interruption cases / 771 command records, including eight actual
Reserved sends. All prior C client/server/recovery and original Rust public traces
pass. The canonical collector completes in 2,017.048 seconds and the minimum C
graph in 1,279.171 seconds. The native Debug/Release suites each pass 284 tests;
the three new transport tests also pass on Rust 1.90. Strict Clippy, installed
formatting, a build without TLS features and 134 final source/package/inventory
checks pass. The initial source test failure was a stale 244-file guide count;
the corrected guide and gate now require all 245 Rust sources.

The candidate archive is
`30990b4971c8de9f3f14069c7e3c2de39b8ba2dc2d2d667535706b458d58ac31`.
Only four native source files and two candidate guides differ from the preceding
archive; manifests, dependency lock and consumed SDK archives are unchanged.
Final validation snapshot `afe52f15` preserves all 174 package-qualification input
hashes; its artifact guide separately corrects the source census and distinguishes
the implemented candidate from the abstract lifecycle model. This ledger is added
after execution. Public outputs are retained as
`20260930-continuity-c-witness-cancel`; a collector summary initially used an old
record filename, then resumed with independent copied-file hash verification.
That metadata repair did not rerun or alter SDK execution.

Predecessor `e97ea9f8` completes native Linux installed Debug/Release witness and
59-case sync matrices. Downloaded evidence independently rechecks 56 witness-file
hashes and a 274-exchange transcript per profile, 771 command records per profile
and all 192 raw sync receipts. Its CodeQL run `36761687553` passes six jobs and the
244-file Rust gate at synthetic PR merge `e06480e1706ef89b38fca7b5356fada18a84cd82`.
The push workflow was 42/43 at the captured checkpoint, with one native job still
running. These results exclude the cancellation patch and its new 245-file census.
Witness metadata remains plaintext on the signed TCP carrier. Witness TLS/service
deployment, connect cancellation, global invocation bounds, independent cross-host
and current-device qualification, remaining product/language/lifecycle integration
and controlled performance/security/release requirements remain open.

The unpublished C surface now adds explicit operational and cleanup witness
constructors, for 29 isolated exports. They retain the original independently
configured witness identity/public key and device signer and reuse native witness
admission; missing, wrong, unavailable or invalidly signed evidence cannot trigger
enrollment, reset or a local-profile fallback. SDK-revoked cleanup can still use
the original witness signer. Cancellation shares the owner signal across native
exchanges; fresh status queries still require witness admission after cancellation.

Clean snapshot `bfcb81d4` passes actual installed C-to-C TLS bootstrap, message
delivery, target-1 rekey and cleanup against a separate native witness socket/store.
Rust 1.98.1 and Rust 1.90 each execute Debug and Release. Two
committed advance responses are deliberately lost; fresh attempts recover the
same commands as AlreadyAppliedExact. The independent public transcript readback
checks 274 exchanges, two subjects, 44 logical advances, fresh challenges and
both lost-command recoveries, plus 48 C command logs and eight public readbacks.
It checks complete loss accounting and an actual application record; native
endpoints verify signatures. This is not a second signature implementation.
The canonical original Rust+C collector completes in 1,205.706 seconds; the minimum
toolchain's C graph completes in 1,146.070 seconds. Both retain all prior client,
server, two-epoch recovery and 59-case sync-interruption traces per profile.
Strict Clippy, installed formatting and 132 source/package/inventory tests pass.
The candidate archive is
`808c7a660b93a8231d0d86a6a19ba88f466f69e514205da95d252926ea8158ce`;
its changed members are fixture/documentation inputs, with native protocol
implementation and lock unchanged. These elapsed times are run durations, not
performance claims. Evidence is retained as `20260930-continuity-c-witness`.

After execution, the collector adds a post-verification public-file export and
CI upload glob. The prior verification AST and all native/C workload inputs remain
unchanged. The new exporter is separately replayed against all four actual results:
56 verifier-selected files per profile preserve their original hashes and refuse
an existing destination. Raw witness transcript and public readbacks are retained
without private keys or journals. This export-only replay is not relabeled as a
second SDK execution. The new carrier
is signed TCP and does not encrypt witness metadata; witness TLS/service deployment,
held-socket cancellation, and independent cross-host qualification remain open.
The new source inventory requires 244 Rust files in hosted extraction.

Predecessor `2c584a8b` additionally completes native Linux installed Debug/Release
sync matrices: 59 cases and 771 command records per profile, including eight actual
Reserved outcomes. All 192 uploaded raw `.events` files and recorded command hashes
are independently checked again after download. CodeQL `36754770998` completes all
six jobs; its 242-file Rust gate analyzes PR synthetic merge
`f5219567c2291c450dfa558038b11fad045c1b53`. Those results do not include the new C
witness source. The full workflow's longer native/proof jobs were still running
at this checkpoint; the Linux component result is not a whole-run completion claim.

At `25db790c`, push CI `36746031054` completes all 43 jobs and CodeQL
`36746042255` completes all six. Hosted Linux x86_64/GCC 13.3 executes the
installed C client, server and SDK-revoked cleanup in Debug and Release; each
cleanup trace independently checks 26 commands and four public readbacks.
Rust's 241-file quality gate is bound to PR synthetic merge
`2f4f0bd9b6f7af94a27ba2d9dcbc039197cab6e3`. This closes that checkpoint's Linux
C cleanup/extraction gates, not the newly added syscall-interruption matrix,
cross-host connection or current-device qualification.

The installed C collector now includes a separately hashed, test-only syscall
probe and public Rust fixture to interrupt real journal syncs in owned C processes.
It requires complete before/after matrices for owner-open/send/close, cleanup
begin and exact-report acknowledgement, with a real retained reservation before
every cleanup cut. SDK revocation precedes full C loss accounting and subsequent
native closed-state verification. Clean snapshot `fe3688b7` qualifies fresh
macOS arm64 installed packages with Rust 1.98.1 and Rust 1.90, both Debug and
Release. Every combination completes 59 independent cases: 27 send cases (13 sync
points; eight positive Reserved outcomes), 13 cleanup-begin cases (six sync points)
and 19 acknowledgement cases (nine sync points). Each profile checks 771 command
records and original complete loss-report readbacks. The canonical original
Rust+C collector completes in 1,146.549 seconds; the minimum-toolchain C graph
completes in 1,085.640 seconds. These durations are functional qualification
records, not performance comparisons. Strict Clippy, installed formatting and
129 source/package/inventory/verifier tests pass. The unchanged candidate archive
remains `ef58a03d80f5b7e2f8ea0083e04ce57f17288feacf555f886799bb774cf671a2`.
Evidence is retained as `20260930-continuity-c-sync-fault`. The matrix retains
failed development attempts, including dyld self-resolution diagnosed by comparing
the resolved function address with the wrapper, and an incorrect auxiliary numeric
status mapping corrected to compare the public C constants with native named states.
Fresh native Linux execution of this matrix, power loss, injected EIO and all C
archive-index commit faults remain
separate gaps. Normal installation/connection tests still run without loader
overrides; only fault children receive the explicitly identified probe. The
current helper adds a 242nd tracked Rust file for the hosted extraction gate.
After execution, the workflow upload list adds only `*.events` to retain the raw
cut receipts; no workload, library, verifier or compiler input changes. The complete
actionlint invocation retains the predecessor's identical unknown `ubuntu-26.04`
runner-label diagnostic, with no additional current diagnostic.

The unpublished C consumer now implements a separate cleanup owner with sixteen
`qpc_recovery_v1_*` exports, for 27 isolated exports in total. It opens original
installation/archive state after SDK operational revocation, reports every native
loss-accounting field, and requires the host's durable complete report before
exact-ID acknowledgement and catalogue retirement. Handles cannot cross owner
kinds. Original archive restoration restores metadata only; it does not revive
session keys or operational authority. Required-witness admission still refuses
without its missing C adapter. This preceding checkpoint did not execute a
nonzero uncommitted-reservation C case or installed cleanup commit fault injection;
the later process-interruption qualification above adds those bounded cases.

Clean snapshot `e6af1399` executes fresh installed archives on macOS arm64:
Rust 1.98.1's original Rust plus C client/server/cleanup Debug and Release collector
completes in 474.806 seconds; Rust 1.90 independently compiles the same graph and
completes all three C traces in both profiles in 400.225 seconds. The unchanged
native candidate archive remains
`ef58a03d80f5b7e2f8ea0083e04ce57f17288feacf555f886799bb774cf671a2`.
Each C cleanup trace checks 26 command logs and four public readbacks, including
every loss-report row, an independently recomputed ciphertext commitment and
the original native/C archive byte equality. Its state includes two epochs,
three unconsumed deliveries, one unknown committed send, one skipped position,
a pending old-epoch resolution and target-2 rekey. Two real C process exits after
report fsync and acknowledgement force original-state reconciliation. Wrong IDs,
tampered archives, kind confusion, pre-freeze cancellation, repeat retirement and
metadata-only restoration are exercised without editing journal images.
Strict Clippy, installed `cargo fmt --all -- --check` and 124 source/package/
inventory verification tests pass. A source-template rustfmt attempt cannot
resolve the intentionally installed archive fixture; its failed record is retained
and the complete installed-tree check passes without omitting modules. These
elapsed times measure qualification duration, not C performance. Source and public
execution evidence is retained as `20260930-continuity-c-recovery`; no private
runtime key/journal directories are exported.

The preceding [C server checkpoint](../bindings/c/ContinuityPackageConsumer/README.md)
adds listener ownership and receives bootstrap, application and rekey exchanges
through the shared native engine. Its eleven isolated exports include a synchronous
application callback: failure and unknown external commit leave the inbox
unconsumed; success requires durable effect plus deduplication. The callback
retains no borrowed pointers beyond its invocation. Reentrant close returns Busy,
listener cancellation and release are checked, and acknowledged ciphertext remains
retired. That checkpoint leaves required-witness C admission, C cleanup/recovery
and product integration open; these functions are still outside product ABI 2.

Snapshot `6221d0c1` produces candidate archive SHA-256
`ef58a03d80f5b7e2f8ea0083e04ce57f17288feacf555f886799bb774cf671a2`.
The actual Rust 1.98.1 installed Rust+C collector completes in 464.277 seconds.
Rust 1.90 independently builds the same installed C/Rust graph and completes
both C directions in Debug and Release in 387.569 seconds, including Clippy.
Every server trace checks five independently read application records and 24 C
command logs, covering failure before output, unknown commit after fsync,
process exit after fsync, original-ID retry and target-1 rekey. One duplicate
case uses the actual public native receiver API to consume a verified durable
C application record before the sender receives an ACK; the C server then skips
its callback on replay. This is explicitly a native recovery transition, not a
C recovery API. The sender's refusal to regenerate acknowledged ciphertext is
also asserted. No journal image is edited or rewound. The two original Rust tests
and prior C client trace remain in the collector.

At predecessor `bf2f569a`, Linux C qualification exposes a harness size-bound bug:
the shared-library copy inherited the 32-MiB source/archive limit, although all
binary identity reads already allowed 256 MiB. It failed before C execution.
The copy now takes that explicit binary limit, compares the installed hash with
the selected build output, and retains the default source limit. A real
124,676,976-byte compiler binary reproduces the old refusal and copies exactly
under the binary bound; oversized/default-limit and existing-target negative
checks remain required. The protocol, Rust/C binding and archive bytes executed
above are unchanged by this collector fix.

At `9662ecea`, hosted Linux job `109969255312` executes the actual installed
Rust/C client and server in Debug and Release using GCC 13.3 on x86_64. The
candidate archive has the same `ef58a03d...671a2` SHA-256 above. Each profile
independently verifies two client and five server application records, plus 28
client and 24 server command logs. This closes the earlier copy-limit failure
for that executed Linux scope. It is a same-host qualification, not a macOS-to-Linux
connection or evidence for the new C cleanup module. The push CI run
`36736935717` completes all 43 jobs successfully. Its associated CodeQL run
`36736940942` completes all six jobs and passes Rust's 240-file quality gate on
synthetic PR merge `b8b903516e3ffd3d8d251d37739107de6567ea86`. The new cleanup
module requires its own 241-file hosted extraction.

The predecessor's CodeQL run `36730212717` completes all six jobs. Its Rust gate
extracts all 239 files with checkout `fdf72f535bfcf4d4999fa8f92c76833def5d386c`,
the PR's synthetic merge rather than a relabeled branch head. The predecessor's
Android 16-KiB failure remains retained despite the later successful run. Its
structured capture shows transport loss during minimal-consumer cleanup; attempt
19 expires during owned ADB listener validation and returns exit 2, classified
by the shell observer as structural failure. It does not show a malformed package
reply. Later observations remain device-unavailable and app absence remains
unresolved. The failed runtime receipt is retired with primary status 2. The
capture does not establish why the emulator transport disappeared; no OOM or SDK
workload cause is inferred, and no ownership check or retry budget is weakened.

At `bf2f569a`, the initial unpublished Continuity C owner client executed
against the same installed engine and nine SDK archives. Its
`qpc-owner/1` client surface keeps original protected installation/policy/signing
owners, typed errors, 64 owner/call bounds and concurrent cancellation. It adds
no raw private-key getter, parallel protocol implementation or product ABI 2
exports. Required-witness C admission, receive callbacks, cleanup/recovery APIs,
the remaining language adapters and product integration remain open.

The clean macOS arm64 qualification snapshot `368a4295` completes in 503.246
seconds. Both Debug and Release execute the original two Rust tests, the actual
C client trace and the call-admission unit. C covers TLS bootstrap, original-ID
delivery recovery after receiver fsync/exit, target-1 rekey, cancellation before
reservation and after TLS dispatch, Busy close, original-installation reopen,
exact resend and durable SDK revocation. Separate file readback checks application
bytes across the rekey; the collector checks all 28 C command logs per profile,
exact exports, installed sibling-library loading, archive origins and unchanged
source/lock/binary identities. These durations are functional execution records,
not controlled performance measurements.

Strict consumer Clippy and formatting pass. Rust 1.90 also passes all-target
Clippy and the real call-admission unit; this does not substitute for an MSRV
network/package run. The 106 related source/package/inventory tests pass, and the
source gate retains `release_claim_eligible=false`. Development failures remain
recorded: build-tree dylib lookup, an inherited nonblocking test socket, an SDK
policy denial collapsed into configuration error, and direct Clang missing its
SDK root. The fixes select installed sibling lookup, bounded blocking observation,
typed denial and an explicit macOS SDK; no failure assertion is relaxed.

For the preceding `e00281e` head, the installed Linux x86_64 Debug/Release reports
also complete with the same macOS archive SHA-256
`5e41e4ffe057ddc9521aef8f77b5cea6c8755a433e09bdbc9c493d01d9de10a0`.
Its push CI ends with 41 of 43 jobs successful, PR CI with 40 of 43; CodeQL passes
all six jobs. Three candidate jobs hit the explicit 40-minute deadline, with one
canonical Debug suite taking 2,059.56 seconds. The job budget is now 90 minutes
with all tests unchanged; new-head completion remains required. The PR Swift
consumer and packaging checks pass before artifact upload fails with ENOTFOUND.
The push Android 16-KiB run fails its initial cleanup observation after a system
service restart; the final trap observes three absent states and retires the
failed receipt. That later cleanup does not erase the failed runtime result.
Default actionlint still reports the identical pre-existing ubuntu-26.04 label
diagnostic. No current-head full-CI, cross-host, independent-implementation,
device, controlled-performance or release-completion claim follows from this
local C checkpoint.

The Continuity [wire grammar](continuity/WIRE_V1.md) and
[resource descriptor](continuity/BUDGETS_V1.json) now describe the implemented
candidate profile. The codecs, journal and native carriers consume shared Rust
constants; CI executes a compiled descriptor and compares every limit and the
independently recomputed rekey-profile commitment with the reviewed JSON. These
documents explicitly retain an unfrozen product contract and do not authorize
foreign bindings to bypass the existing verifiers or durable owners.

That inventory exposed an actual quota defect: image validation counted account
rosters against the prekey limit, although generation and sealing use separate
quotas. The public-API regression fails on the old predicate and passes after
counting records by kind. It generates/retires 1,023 actual keys, admits a peer
roster and the 1,024th prekey, rejects the 1,025th, then commits local revocation
and verifies it after reopening. Quotas, tombstones and journal formats remain
unchanged. Both full Debug and Release suites pass 281 unit tests and two public
integration tests without failures or ignored tests. The capacity regression
also passes on Rust 1.90; strict all-target Clippy passes on 1.90 and 1.98.1.
Independent OpenSSL checks cover 20 identity/control envelopes and 12 witness
envelopes from fresh public vectors, retaining their finite oracle scope.

The updated installed macOS candidate archive has SHA-256
`5e41e4ffe057ddc9521aef8f77b5cea6c8755a433e09bdbc9c493d01d9de10a0`.
Outside-checkout Debug/Release consumers both execute a network rekey, reconcile
unknown delivery, verify application readback and clean up after durable
revocation. Input sources remain unchanged throughout execution. This qualifies
the installed same-host Rust path; it does not execute a foreign Continuity API
or close protocol freeze, lifecycle, security or performance obligations.

At `41da8962`, push CI run `36706327650` passes all 43 jobs and CodeQL run
`36706338664` passes all six jobs. Both push and PR installed Linux consumers
complete Debug/Release on x86_64 with the earlier byte-identical candidate archive
`7681ac4b8adc0040705ad1cfbfa444e98589bb06a2668901513f76355f0b76ad`.
The PR source is synthetic merge `9f40d4a1dc9515d3e504ef56acb55922841a0833`.
These receipts precede the quota correction and do not qualify that later source.
The PR's Android 16-KiB job fails during APK installation, before SDK execution;
its retained system-service restart and kernel/user page-unit observations are
recorded in [Android runtime evidence](SDK_ANDROID_RUNTIME.md). A passing push
does not close that failure.

The earlier installed Continuity Rust candidate consumes a Cargo-produced 0.0.0 archive
and nine 0.2.0 SDK archives outside the checkout. The macOS arm64 qualification
completes both Debug and Release public connection traces, independent application
and cleanup readback, strict Clippy, and post-execution source/lock/binary identity
checks. The archive SHA-256 is
`7681ac4b8adc0040705ad1cfbfa444e98589bb06a2668901513f76355f0b76ad`.
Its SDK cohort is the byte-matched twelve-crate artifact from `91554a16`; all nine
consumed source trees are rechecked against the current SDK. The record retains
the initial missing-version packaging failure, the mixed-path staging failure and
a rejected Release run whose compiler helper could not find `libLLVM.dylib`.
Explicit compiler-private library lookup fixes that launch environment; application
test processes run without loader overrides. No warning is suppressed.

At that earlier checkpoint the candidate engine, public workload and lock bytes are unchanged from
`91554a16`; this is an installed Rust boundary, not another protocol implementation.
The candidate remains `publish = false`, and the twelve-crate SDK publication
topology and ABI 2 remain unchanged. The `continuity-installed-rust` CI lane
executes the same run's SDK packages on Linux. Foreign Continuity adapters,
independent/cross-host interoperability, protocol freeze, lifecycle/security and
performance obligations remain open within 0.2.0. Local actionlint 1.7.12 retains
the identical pre-existing unknown `ubuntu-26.04` label diagnostic; the added job
uses `ubuntu-24.04`, and no linter rule or existing runner is changed to hide it.

Android emulator state format v2 adds raw `/proc/vmstat` and `/proc/zoneinfo` to
the existing before-install, failure and one-shot-recovery captures. The retained
16-KiB failures have `MemAvailable` snapshots and watermark-kill messages but lack
the kernel free/reserve/watermark and reclaim counters needed to assess that
relationship. All 13 native probe statuses remain visible and the first failed
read remains the completion status. Timeouts, 64-KiB output bounds, RAM, routing,
retry allowances and package/cleanup acceptance are unchanged. The precise old
producer fails the new-field assertion; the corrected producer passes all 184
command tests and 198 related runtime-state/device-proof/SDK-runtime tests with
warnings treated as errors. These are local collector contracts. Actual runtime
snapshots and package execution retain their own source/host scope; this addition
does not establish an OOM or ADB repair.

At `e9b38945`, push run `36701922227` completes the API 23 runtime job. Its actual
full-SDK and version-only packages pass; both v2 baseline captures contain all 13
successful probes, including vmstat and zoneinfo, at 16,784 and 16,607 bytes within
the unchanged 64-KiB bound. This confirms that profile's baseline reads. API 35
and error-path collection retain separate qualification; the earlier intermittent
transport failures have not been declared repaired.

The native [installation recovery entry](../research/continuity-identity-candidate/INSTALLATION.md#recovery-after-operational-authority-expires)
now reaches existing session cleanup after live policy/credential admission is
unavailable. `InstallationRecovery` admits original Active configuration, exact
paths/key and its existing index. Its bounded IDs remain discovery hints. Session
selection authenticates the original archive and journal/device/protection, with
the original policy/witness binding and signer still required for witness-backed
storage. `InstalledSessionRecovery` retains all three database owners while
exposing only closure and catalogue operations. No runtime/context is recreated,
no missing Active storage is reprovisioned, and separately retained archive input
cannot silently replace an index row.

The public consumer performs three fresh processes after signed durable SDK
revocation: freeze and persist the complete loss report, exit before acknowledgement;
reopen, match and acknowledge the exact report, retire the catalogue row; then
authenticate retained archive bytes and independently confirm the terminal journal
state. A fourth, bounded contender checks all three recovery leases. Native cases
include a real unconfirmed outbox, expired/closed authority, exact catalogue
restoration, invalid/missing configuration and request/reply loss at the original
witness. Initial noncanonical temporary-path fixtures failed with `PrivateFile`
and were corrected without changing admission. Frozen source contains 1,019 files
/ 234 Rust files, archive SHA-256
`f8681b0cca762fcb99eb95aa091a09016e0290eab9dffe2c94d7deda7cc4c860`.
This remains an unpublished native API; installed Continuity adapters, authority
renewal, physical power-loss and cross-host qualification remain separate work.

The frozen recovery source passes **280 native unit tests plus two public
integration tests** in each of Debug and Release, zero failed or ignored; runner
times are 797.230/792.877 seconds under overlapping load. The two-test integration
count includes its child-process helper. Rust 1.90 executes both all-feature and
connection-only paths, reporting one and zero network rekeys respectively. Four
retained configurations independently verify eight application files and their
complete host loss reports, with report IDs agreeing across freeze, completion
and a fresh terminal-state verification process. Both compiler versions pass
strict all-feature Clippy; all six feature variants, warning-strict docs/format
and 95 clean source/isolation/release contracts pass. The
`20260930-sdk-installed-recovery` cohort retains exact source, binaries, failed
fixture and passing logs. Wall times are not a controlled performance result;
synthetic private keys and journals are excluded from its evidence mirror.

Predecessor **4c4436d1** push CI's Android 16 KiB job fails before the full consumer's
instrumentation starts: installation reports success, package ownership matches
twice without convergence, and ADB loses transport. Before/recovery guest boot IDs
agree. The retained log includes 77 system lowmemorykiller actions, while the two
memory snapshots are not peak measurements or a causal explanation of transport
loss. This pre-workload failure is distinct from the older application `LOW_MEMORY`
exit and the later cleanup failure. No SDK workload, OOM or transport repair is
claimed from these diagnostics; the gate remains failed.

The [public native service consumer](../research/continuity-identity-candidate/INSTALLATION.md#public-consumer-and-original-service-recovery)
now verifies signed bootstrap material, borrows the original verified local device
and policy, and opens both original `DeviceInstallation` owners through public
APIs. A separate integration crate executes actual TLS bootstrap, bidirectional
delivery, service restart and network rekey with persistent SDK policy stores and
local private signers. An actual receiver process exits after application fsync
and before consumption ACK; the sender retains `Committed`, reopens its original
service and reconciles the same ID/input to `Acknowledged`. Eight lease checks,
wrong-role refusal, cancellation without outbox publication and persistent signed
SDK revocation are included. These are same-host native processes, not installed
Continuity bindings or independent implementations.

The external consumer first failed compilation solely because verified-device
projection was absent and the original policy projection was private. The added
borrowed projections preserve current admission and shared-owner closure. The
shared `PrivateFileError` now implements the standard error traits without
changing file admission. A later feature-specific run exposed a real reference
startup race: an empty ready file was observable before its address write. The
reference now atomically publishes a fully written, synced file without replacing
an existing marker. The initial failure and empty-file evidence remain retained.
An invalid empty-KEM revocation fixture and one formatting failure are also kept;
the fixture now uses the existing valid policy that disables the current suite.
No policy validation or error assertion was weakened.

Rust 1.90 executes both all-feature and connection-only public consumers. After
the readiness repair, each feature profile additionally passes eight consecutive
full connection/recovery runs while the native suites run concurrently. Independent
post-run verification checks all 36 final application files from these 18 runs
against the exact public session/message IDs and expected plaintext. All-feature
receipts report one network rekey; connection-only receipts report zero. The
qualified source contains 1,017 files / 232 Rust files, archive SHA-256
`b989b629f6b81e124bf1b81000c04d43bbea2c938a14e9de75566f82bcafe417`.
The only later Rust edit collapses the ready-publication call to rustfmt's required
line layout. All raw state containing synthetic private keys is retained privately.

The production bytes pass all 277 native unit tests in each of Debug and Release
(837.49/720.01 harness seconds under overlapping load). The already-running Debug
command subsequently reproduces the old ready-file race in its pre-repair
integration binary, so its overall exit remains 101. Release's pre-repair
integration happens to pass; that does not invalidate the race. Fresh final-source
Debug and Release public consumers each pass both integration tests in
6.414/16.120 runner seconds. Two more independent application-file pairs are
verified from these final runs, bringing the retained qualified total to 20 runs
and 40 final files. This is execution evidence, not a performance baseline.

Both compiler versions pass all-feature strict Clippy; all six independent feature
variants and warning-strict docs pass. The feature script's final formatting step
initially fails, then the exact rustfmt-only correction passes. All 95 clean
source/isolation/release contracts and 18 affected host-store tests pass, with
host-store strict Clippy. The `20260930-sdk-service-reference` evidence cohort
retains failed and passing commands, source manifests, exact executables and
sanitized application hashes; raw keys and journals are excluded from its mirror.

At predecessor **ec47451b**, push CI passes all 42 jobs and CodeQL passes all six
languages. PR CI completes 41/42 jobs: Android API 35 / 16 KiB fails during minimal
consumer cleanup. Its instrumentation records `runtimeVersionOnly` success and
normal instrumentation completion; subsequent ADB transport loss prevents cleanup
confirmation. The added lowmemorykiller capture observes system memory-watermark
kills before that app starts. Those observations do not establish why transport
failed, measure peak memory, or resolve the older application `LOW_MEMORY` exit.
The failed job and its raw diagnostic evidence remain part of release assessment.

The native [installation owner](../research/continuity-identity-candidate/INSTALLATION.md)
now durably retains an independent journal identity and its exact key/device/
policy/witness/path bindings before creating children. Creating permits only
initial genesis preparation; Active permanently removes permission to recreate
missing children. Activation commits and reads back Active before releasing the
service, rechecks the original witness/policy and retains all three owner leases.
Unknown activation outcomes return no service and reconcile the same record.
Required-witness enrollment remains explicit. This supplies a native service
initialization boundary, not published Continuity bindings or a global device
registry/configuration rollback witness.

The frozen installation Debug/Release suites each pass 277 tests, zero failed or
ignored, in 832.271/826.724 runner seconds (827.07/746.33 harness seconds) under
overlapping load. These are not performance measurements. Focused execution
covers six actual process cuts, bounded competing owners, two measured activation
sync barriers with four before/after faults, and sixteen signed witness request/
reply losses across first activation and active restart. Tests commit a real
bootstrap outbox before removing active child files, refuse regeneration, and
recover identical bytes only after restoring the originals. Malformed/partial
configuration, changed bindings, closed policy and stale Creating state against
an advanced journal are refused.

Rust 1.90/1.98.1 strict Clippy, six independent feature variants, warning-strict
docs/formatting and 95 clean source/isolation/release checks pass. The retained
`20260930-sdk-installation` cohort includes the initial incorrect phase assertion,
the corrected sync measurement (excluding database-close barriers), the initial
strict test-code lint errors, and all final source/binary/log evidence. Frozen
source has 1,016 files / 231 Rust files; archive SHA-256:
`6812fe42a9498e417c5d02009c17d509a9ea93257b0d4f93d4ceaf4e0a1326d1`.
Published SDK ABI, journal v21 and network/archive wire formats are unchanged.

Clean source `f89e0632` completes the official `sdk-020` physical matrix on both
wired devices: iPad Pro 11-inch (M4), iPadOS 27.0.1 (24A446), and iPhone 16 Pro,
iOS 27.0 (24A437). All four SDK groups pass on each device. Independent console/
app-container readbacks agree, all eight per-device proof checks pass, and each
nonce-owned app has three consecutive cleanup absence observations. Exact app
and static-library hashes are rechecked and retained privately. Both embedded
profiles match the pre-existing profile bytes; provisioning updates and device
registration were disabled. Matrix proof SHA-256:
`1b5107b67ed1845fd716478724281b194036b4af47053d703ea20ac1449db21a`.
This closes that commit's source-built two-device SDK matrix. Installed XCFramework,
minimum-OS, durable policy and Continuity device qualification remain separate;
the harness explicitly uses test-only in-memory policy updates. It does not
qualify the new native initialization API or transfer its receipt to a later head.

An observed aggregate-recovery counterexample is repaired: an authenticated
member backup could open its cleanup owner after whole-batch freezing or
acknowledgement, but catalogue restoration returned `Suspended`, leaving the
whole batch blocked by `ArchiveRequired`. Exact restoration now checks original
scope and fresh witness admission/release without asking for an independent
closure disposition. Individual member freeze, acknowledgement and retirement
remain refused; original whole-batch accounting and journal tombstones are
unchanged. Both phases and sixteen additional witness request/reply losses are
covered by real journal/index tests.

The frozen aggregate-recovery Debug/Release suites each pass 266 tests, zero
failed or ignored, in 742.588/739.136 runner seconds under overlapping load.
These are qualification times, not performance results. Rust 1.90/1.98.1 strict
Clippy, six feature variants, warning-strict docs and formatting pass. The
`20260930-sdk-aggregate-catalogue` cohort retains the old implementation's failure,
an initially incorrect test error classification and its correction, original
logs, exact executables and all 229 Rust sources. Frozen source archive SHA-256:
`e55dbf51096a2e44f59ae2959d4157c96f0bd1f591f720f2d01c11bd11d61b69`.

The first combined source/script check failed when a native-command fixture
exceeded five seconds and a nested shell outlived its direct parent during
temporary-directory cleanup. A controlled blocked probe reproduces a write after
the old timeout. Guest fixtures now use the existing bounded process-group
runner, retaining the five-second deadline and native exit/argument assertions;
the same blocked probe leaves no surviving reader or late write. All 225 affected
Android/process-boundary tests pass with warnings treated as errors. This repairs
test subprocess ownership, without attributing the original five-second stall to
an unmeasured cause. The repaired clean snapshot passes all 279 combined
source/isolation/release/Android checks in 54.539 runner seconds; the original
278-test failed run remains retained separately.

Predecessor `5d81c340` completes all 42 PR CI jobs and six CodeQL jobs. Its Android
minimum and 16 KiB package/runtime jobs pass, but that does not resolve the
earlier `8067cd97` exact-process `LOW_MEMORY` termination. The collector now also
captures AOSP's actual `lowmemorykiller` tag; RAM, workloads and acceptance are
unchanged. See the [runtime diagnostic scope](SDK_ANDROID_RUNTIME.md).

The same clean `5d81c340` source passes all four SDK workload groups on one wired
iPad Pro 11-inch (M4), iPadOS 27.0.1 (24A446). Console and app-container readback
agree on the run nonce; cleanup confirms three absent observations. Proof SHA-256:
`28ccf1b9368bc952adedfb021ee214e1286bf4064655a9eb3d5ce19a16f8c97d`.
The first manual-signing build failed before installation; automatic selection of
the existing unchanged profile succeeded without account/profile provisioning.
Raw device/signing evidence remains private. This is source-built Swift/C/Rust
execution with test-only in-memory policy updates, not installed XCFramework,
minimum-OS, persistent-policy, full device-matrix or Continuity device evidence.

The native session archive catalogue now supports bounded discovery, exact
restoration through an existing cleanup-only owner, and explicit retirement after
the original journal confirms the host's complete closure report. Restoration
does not recreate operational context; deletion changes only the public index,
never journal tombstones, claims, budgets or capacity. Present and absent outcomes
retain fresh original-witness admission. Unknown index commits close the owner
and require exact reopen/readback; conflicts are never overwritten. See the
[catalogue contract](../research/continuity-identity-candidate/SESSION_ARCHIVE_STORE.md#discovery-exact-restoration-and-terminal-retirement).
This is a native recovery API prerequisite, not installed Continuity binding or
device/root lifecycle completion.

Frozen Debug and Release catalogue suites each pass 264 tests, zero failed or
ignored, in 727.584/722.472 runner seconds under overlapping load (not performance
measurements). Focused execution covers eight before/after storage faults and
sixteen witness request/reply losses across present and absent dispositions,
both local roles and separate-process restore/retire/repeat recovery. Strict
Clippy on Rust 1.90/1.98.1, six independent feature variants, warning-strict docs
and formatting pass; the clean snapshot passes 95 source/isolation/release checks
(corrected from the earlier prose count of 45 against the retained raw log).
The `20260930-sdk-archive-catalogue` cohort retains source identities, exact
executables and outputs. Its frozen archive SHA-256 is
`9fc06163712fe46406732efe90019269232fa3b01f599651ebeb7a2934ea68b1`.
The changes are confined to the unpublished candidate and its documentation;
the earlier actual SDK package results retain their own source/report identity.

The native [archived whole-batch cleanup](../research/continuity-identity-candidate/FANOUT_ABANDONMENT.md#archived-whole-batch-cleanup)
now loads the original complete fanout membership from the authenticated journal,
then reads and authenticates every member's QPCSCA01 record from its existing
SessionArchiveStore. Its restricted owner exposes status, whole-batch freeze,
acknowledgement after complete host accounting, abandoned-batch metadata retirement
and close. It never reconstructs an operational policy/context, accepts a recipient
subset or grants new data/control authority. The public-context and archived entry
points share the same freeze, erasure and retirement transaction engines.

Every archive must match before an already sealed reservation/freeze/terminal intent
can be reconciled. A missing member archive is ArchiveRequired, not a claim that
the batch is absent. Invalid MACs and valid-MAC context substitutions fail without
changing the original image or pending intent. Absent/Retired dispositions in
required-witness storage also require fresh original witness evidence; a local
counter alone cannot supply them. Retired session/source/one-time records and the
monotonic batch ID remain after batch metadata retirement. This API does not retire
ordinary committed fanout history or turn an unconfirmed outcome into consumption.
Candidate v21 storage and existing wire/SDK contracts are unchanged.

Focused qualification passes nine archival lifecycle tests plus the exact pending-
reservation admission test. It covers three actual cleanup-commit process kills,
three contenders checking both journal/index leases, mixed handshake roles,
committed peer revocation and complete unknown/unconsumed accounting. Each of the
three transitions exposes four sync barriers (24 before/after storage faults);
open plus each transition exposes five witness exchanges (30 before/after losses).
Expiry permits only confirmation of an already applied intent. The corrected full
Debug/Release suites each pass **246 tests**, zero failed or ignored, in
**716.265/710.917 runner seconds** under overlapping load. Both retained disclosure
witnesses still recover six messages each. Strict Clippy passes on Rust 1.90 and
1.98.1 for all features, each carrier and no defaults; warning-strict docs and fmt
pass. The clean 1,011-file snapshot passes **95** source/isolation/release-contract
checks with warnings as errors and no skips, including all **227 Rust files**.

The independent feature checks initially caught a test helper unnecessarily gated
on connection-tls. It now serves the unconditional archival lifecycle tests without
skipping them. A real schema counterexample also showed that the index accepted an
extra multimap table: the old opener fails the new rejection assertion. The shared
schema validator now refuses every unsupported table namespace, and open/live-lookup
regressions pass. The corrected source was rerun through both complete native suites;
earlier 245-test runs and all initial diagnostics remain separately retained.

At predecessor 54eef232, the three native candidate CI matrix jobs pass (Linux Rust
1.90/1.98.1 and macOS 1.98.1), and check job 109700266455 passes 2,354 artifact tests
with three existing platform skips. Its compiler-install contract now passes there.
The PR runner checks out merge 4bfc536afd76af1ce18525d42183afdcc298319b; GitHub confirms
its tree is exactly a2cfc608e9948e7cc6ad33d8157bb2c0c73b1f93, identical to 54eef232.
These observations do not qualify the newer archived-fanout patch's hosted execution.
Installed SDK adapters, committed-history/catalogue restoration UX, witness renewal,
device/root lifecycle, independent endpoints, current devices and construction-
specific recovery/security/performance remain separate requirements.

The immutable-file follow-up closes two related initialization gaps. Wrapping-key
reopening synchronizes the exact admitted single-link file and pinned directory
before returning its owner. The shared `provision_private_file` no longer unlinks
an admitted file when its callback returns an error: a real concurrent opener had
already used a complete key to persist a signing owner when the old creator cleanup
removed the wrapping file. The original counterexample fails before this correction
and passes afterward. SDK policy stores, policy-agent authority/repository/witness
stores, and candidate signing/journal/witness/archive owners share this root fix.
Errors still propagate, existing paths are never overwritten, and partial state is
refused. The observable error contract now preserves a reserved path for explicit
reconciliation instead of automatically making it retryable.

Targeted validation covers seven key creation/open process cuts, six before/after
sync failures, linked/partial/public-file refusal and the actual signed-policy SDK
runtime recovered after a committed-but-unknown creation result. The latter generates
a real controlled key and verifies alias revocation on close. Frozen candidate
Debug and Release suites each pass 258 tests (zero failed/ignored); the shared
SDK checks pass 41 FFI, 18 host-store and 259 policy-agent tests, plus the existing
process-global umask test run separately. Strict Clippy passes on Rust 1.90 and
1.98.1; feature splits, documentation and formatting pass. The clean qualification
snapshot passes 108 source, isolation, release and package-profile contracts.

The twelve real Rust archives are produced at clean snapshot
`de5e6cd78ba8e1a84a5587f6a459552d1d4f3154`. An external consumer of nine archives
passes all four public API groups on Rust 1.98.1 and 1.90, including a real child
process file-size-limit failure that preserves partial storage and refuses both
replacement and runtime admission. Package report SHA-256 is
`dad33b81aa2b4340c6d0ebf8a9029365d127bc4fb341d96c26fca1181890f704`.
The first producer run is retained as **unqualified**: cargo-audit returned zero
while stderr reported missing registry entries and incomplete yank checks. The
producer now fetches the separate fuzz lock and rejects any JSON-mode audit
diagnostic. The corrected workspace, fuzz and consumer audits have empty stderr,
zero reported vulnerabilities/warnings and a pinned advisory database. These are
dependency audit results, not a cryptographic security proof.

The source/evidence cohort is `20260930-sdk-key-owner`; frozen native suites and
qualified packages use identical Rust source. Final documentation records results
without changing package inputs. This does not promote the unpublished Continuity
candidate into installed bindings or prove hardware power-loss durability.

For predecessor `7d0bdfcc`, PR CI run `36666337606` terminates with 41 successful
jobs and one Android 16K instrumentation crash; CodeQL `36666337627` passes all
six jobs. Native candidate macOS and both Linux compiler jobs pass. The Android
workload emits three SDK pass markers, but its instrumentation process dies before
a complete result and is correctly rejected. Cleanup confirms removal. No matching
process backtrace establishes the crash cause; this differs from the older cleanup
transport failure below. It remains a release blocker, not a tolerated flaky pass.

The [journal creation follow-up](../research/continuity-identity-candidate/DURABILITY.md#creation-with-an-unknown-result)
requires a caller-retained public identity before provisioning. A real process cut
after durable genesis but before owner return failed against the old internally
generated ID and passes after explicit identity binding. Required-witness creation
also needs a restricted genesis-metadata reader: local-only reopening correctly
refuses it, and ordinary anchored reopening requires enrollment that may not yet
exist. `recover_anchor_genesis` returns only exact authenticated revision-1 enrollment
metadata, refuses pending intents and advanced state, and leaves explicit enrollment
and fresh original-witness admission mandatory. Storage v21 and network/SDK ABI 2
are unchanged; the unpublished creation signature changes only the isolated candidate.

The final frozen source passes **252 tests each in Debug and Release**, zero failed
or ignored, in **715.854/711.675 runner seconds** (harness 711.39/628.78), under
overlapping load; these are not performance comparisons. Three real creation-process
cuts and nine bounded lock contenders cover local before/after commit and required-
witness after commit. Recovery completes a real local bootstrap and an original-
witness-backed prekey generation and reopen. An authenticated pending-intent fixture is refused
without changing either stored row. The first complete runs each had 250 passes and
two failures: the test's marker filename became visible before its contents. The
marker is now written/synced privately and atomically published; assertions and
cases are unchanged. Both entire suites were rebuilt/rerun on the frozen correction.

Strict all-target/all-feature Clippy passes on Rust 1.90 and 1.98.1; independent
control/connection/no-default checks, warning-strict docs and fmt pass. The clean
1,012-file snapshot passes **95** source/isolation/release-contract tests with no
skips; the final marker-only correction also passes the **45** source/isolation
checks and focused process tests. The inventory is **228 Rust files**. Updated
public-vector examples execute, and independent OpenSSL 3.6.4 verifies 20 public
and 12 witness envelopes, 30 proofs, nine selections, 160 signature negative
controls and six witness transitions. This is public-byte/signature interoperability,
not independent endpoint/session interoperability. Frozen archive SHA-256:
`cda5cb89dd0b32362ef66623e32d0d661c183602e466dbf0a9c6de377828c46b`.
Full logs, initial failures, executables and public artifacts are retained in the
recovery archive, with its evidence index mirrored as `20260930-sdk-journal-creation`.
Only evidence/contract documentation changes after the frozen verification.

Predecessor 8b40942a's PR CI 36660620002 ends with 39 successes, one Android 16K
failure and two Linux cancellations; its CodeQL run 36660620007 succeeds. Checkout
merge `3fd212c22f52aa8693654bfdaf2e151239fd9ad1` has the exact 8b40942a tree
`d5d3c9149fff5df187047e13be3444ea88c11fbd`. Both Linux Debug suites pass 246 tests;
Rust 1.98.1 also completes Release, but the 25-minute job cap interrupts later checks.
MSRV Debug alone takes 1,251.15 seconds before Release compilation is cancelled.
The job now has a bounded 40-minute budget with all checks retained; new-head hosted
qualification remains required. Android's three instrumented SDK cases report pass,
but a second observed ADB transport loss prevents confirming app removal. Its job
remains failed; the underlying second-disconnect cause is unproven. The same-head
push's 16K job succeeds, which does not erase this retained failure. No cleanup
acceptance or transport retry budget is relaxed.

Installed SDK owners/adapters, independent endpoints,
current physical devices and the broader release obligations remain open. The user
handles external human review separately.

At **54eef232**, the native [bootstrap cancellation contract](../research/continuity-identity-candidate/BOOTSTRAP_CANCELLATION.md)
adds permanent cancellation before application activation. It atomically removes
private plans/checkpoints, retains exact operation/context/authority/one-time claims,
and persists a stable public receipt. Early one-time inventory becomes permanently
abandoned; already consumed keys remain consumed; reusable inventory stays usable.
Existing application sessions require session closure. A restricted cleanup owner
reopens using only the wrapping key and independently retained journal ID, with the
original witness/pin/enrolled signer still mandatory where required.

Candidate disk v21 preallocates a 170-byte cancellation slot per bootstrap record,
so terminalization never needs an extra record or a larger image. Earlier candidate
images fail closed without implicit migration. Public wire protocols, primitive
contracts, SDK ABI and bindings are unchanged. Local logical erasure does not erase
old pages, backups or external owners and cannot recall already released messages.

The focused run passes 14 tests in 32.781 runner seconds, including
20 observed handshake process cuts, 20 cancellation-commit cuts, 20 Busy contenders,
all four prekey modes, exact receipt replay and prevention of one-time key reuse.
Four measured sync barriers cover eight before/after storage faults; six witness
losses cover query/advance/readback. Wrong key/ID/context/pin/signer, canonical
encoding, local policy closure and enrollment expiry are covered. The full local
Debug/Release suites each pass **235 tests**, zero failed or ignored, in
**647.944/637.999 runner seconds** under overlapping load. Both disclosure witnesses
still recover six messages each. Strict Clippy passes on Rust 1.90 and 1.98.1 for
all features, each independent carrier and no defaults; warning-strict docs and fmt
also pass. The clean 1,009-file source snapshot passes **95** source/isolation/release
contract tests with warnings as errors and no skips, including all 225 Rust sources.
An initial run from the managed worktree is retained as a failure because release
provenance requires a real .git directory; the same files pass from an independent
clean Git snapshot without weakening that requirement. Native cancellation does
not close installed language integration, cross-host
and current-device qualification, witness renewal, aggregate archival cleanup,
device/root lifecycle or construction-specific recovery/performance requirements.

At predecessor 1cb996af, the hosted check job runs 2,354 artifact tests and reports
one failure (three existing platform skips): its compiler-pinning test still expects
the candidate job to install cargo-audit after that install moved to the shared
audit job. The exact test fails locally before the repair and passes afterward.
Its candidate install expectation is now explicitly empty; total install accounting,
per-job compiler selectors and independent warning-denied candidate-lock audit
checks remain enforced. Shared audit job 109689571991 actually completes the
warning-denied candidate-lock scan of 170 dependencies. Predecessor CodeQL completes
six analyses; that is not a claim of an empty finding set. New-head hosted execution
remains required. This repairs the stale test contract, not an audit bypass.

At **1cb996af**, the native [connection archive index](../research/continuity-identity-candidate/SESSION_ARCHIVE_STORE.md)
now makes cleanup persistence mandatory in the actual QPCNET01 Actor. Its immutable,
128-entry protected index is committed and read back before either message-state
activation; the initiator retains its archive before sending the final bootstrap
flight. Both sides recheck cancellation/deadline/authority afterward. Data submission
and delivery require the original indexed MAC/scope before local mutation. The data
path performs an indexed read rather than scanning/copying all archived sessions.
Missing/corrupt state never provisions a replacement, and exact retries do not
consume another archive slot. Error::Archive preserves this local failure boundary.

Focused validation passes two archive-index tests and 13 actual connection tests.
Both endpoints independently expose two archive sync barriers: all eight before/
after connection faults prevent activation and recover under the original session.
Four index-only sync faults preserve exact-or-absent outcomes. Actual client/server
archive-commit kills precede activation; server-cut contenders check both journal
and index leases, and the client-cut observer also checks the index lease. Cancellation and an elapsed deadline after archive commit
prevent activation. Missing and MAC-modified archives block client reservation and
server inbox/application effects; restoring the original metadata recovers the same
committed outbox without false consumption.

The complete native reference connection now performs three network rekeys, verifies
both application directions with independent disk readback, closes original policy
owners and runs cleanup in new processes on both endpoints without constructing
verified contexts. This closes the native archive/index persistence prerequisite;
installed language adapters, catalogue retirement/restore UX, aggregate archival
cleanup, initial bootstrap cancellation, witness renewal and device/root lifecycle
remain open. The full local Debug/Release suites each pass **225 tests**, zero
failed/ignored, in **618.479/608.068 runner seconds** under overlapping load.
The two existing disclosure witnesses still recover six messages each. Both compiler
floors, independent carrier/no-default Clippy, warning-strict docs, fmt and 45 clean
source checks pass. This is not a performance comparison or a release verdict.

At predecessor 2e8a3445, Linux job 109674393232 completes candidate tests, sealed-SDK
tests and documentation, then hits its 25-minute limit while recompiling cargo-audit.
The GitHub annotation confirms that time limit. The separate candidate lock audit
now reuses the fixed 0.22.2 tool already installed by the unconditional audit job;
the original warning-denied command, matrix tests and 25-minute candidate bound
remain. Three warning-strict wiring checks pass. Actionlint 1.7.12 reports the same
pre-existing ubuntu-26.04 runner-catalogue diagnostic for both baseline and current
workflow, with no new diagnostic or suppression. New-head hosted execution and
actual candidate lock-audit completion remain to be observed.

At **2e8a3445**, the native [archived session cleanup](../research/continuity-identity-candidate/SESSION_CLOSURE.md#archived-admission-and-restart)
adds QPCSCA01, a 362-byte cleanup-only archive authenticated under a dedicated
journal-wrapping subkey. The host can fsync it before message activation, closing
the gap where a crash could lose the only reconstructible cleanup context.
Its restricted owner verifies the original journal/owner/context/session/role and
storage protection, then reconciles only existing sealed intents. It cannot create
an operational BootstrapContext, extend a policy lifetime, create a missing session
or expose message/rekey APIs. v20 storage and existing wire/public SDK contracts
are unchanged. Required witnesses retain exact signer/pin, head and enrollment checks.

The focused 11-test lifecycle run passes in 85.191 runner seconds. New cases include
four observed process kills and four Busy contenders without constructing any verified
context in the child; every archive truncation and a bit mutation in each of its
362 bytes; wrong key/store/pin/signer; and witness enrollment expiry. Eight activation
sync-fault cases yield six authenticated saved-transaction recoveries and two genuine
Absent outcomes, determined from the actual stored image/intent. Sixteen closure
sync-fault cases now also reopen through the archival API; 20 additional before/after
witness losses cover archive open plus freeze/terminal transitions. Reserved fanout
remains indivisible through the same restricted path. Strict Clippy on Rust 1.90 and
1.98.1 and 45 clean source/isolation checks pass, with 220 Rust source files.
The complete Debug/Release suites each pass **218 tests**, zero failed/ignored,
in **619.889/612.144 runner seconds** under overlapping load. Both retained
reservation-disclosure experiments still recover six future messages each. Separate
carrier-only Clippy on both compilers, no-default Clippy, warning-strict docs and fmt
also pass. Final exact-source hosted qualification remains pending for this patch.

At predecessor **552a95a7**, both previously failing native Windows packaging trust-
boundary steps now pass. Both Windows 2022 job 109664744957 and Windows job
109664745017 complete successfully in the saved observation. Those are actual
Windows results for the output-parent repair, not a claim that this archive patch's
current CI or all package/device gates are complete. Host archive/index persistence,
aggregate archival abandonment, witness enrollment renewal, initial bootstrap
cancellation, device/root replacement, installed integration, cross-host/current-device
qualification and construction-specific recovery/performance remain open.

At **552a95a7**, the native [independent-session closure](../research/continuity-identity-candidate/SESSION_CLOSURE.md)
adds permanent freeze, complete metadata-only host loss accounting and keyless
terminal records for ordinary sessions and incomplete rekeys. It preserves
authenticated ACK prefixes and unknown outcomes, cannot split a reserved fanout,
and lets committed fanout members close separately. Source-linked bootstrap
fences prevent old flights from reactivating a closed session. Journal v20 uses
QPMST011's preallocated closure tail and the shared QPABND02 terminal grammar;
older candidate images fail closed without implicit migration. Wire controls,
messages, SDK primitives and published bindings retain their existing contracts.

The final local debug/release suites pass **213 tests each**, zero failures or
ignored tests, in **591.800/582.903 runner seconds**. These overlapping runs are
not a performance comparison. Seven new tests cover retained-context cleanup
after revocation/policy close, both roles, actual pending input, incomplete rekey
flights before/after cutover, partial fanout ACKs, aggregate reservation fencing,
**16 measured before/after sync faults**, **16 signed witness response losses**,
and two observed closure-commit process kills with bounded competing writers.
A separate real reservation cut also verifies Busy ownership and exact input
accounting. The two existing reservation-disclosure controls still recover six
messages each, retaining their finite counterexample scope.

Initial full runs pass 210 tests and fail three tests that incorrectly treat the
end of State as the end of Control. The repair verifies the actual serialized
Control range before extracting reservations or mutating a pending root/epoch;
it also corrects two negative tests which had accidentally mutated the new tail.
All original decapsulation, signature, key agreement and attack assertions remain.
Rust 1.90/1.98.1 strict all-target/all-feature Clippy and 45 clean source checks
pass; the carrier-only feature checks, no-default build, docs and fmt pass with
the same library code. Only test extraction changed after those feature checks.
That checkpoint has 218 Rust files. Its hosted qualification is tracked separately
from the later archive change above.

The prior `f151c136` completes all six CodeQL analyses, with its finding scope
separate from job completion, but both Windows jobs fail output-parent admission.
The shared helper now requires positive ordinary-directory metadata after a
missing-child result, preserving reparse/non-directory errors across platforms.
The old helper fails both portable error-mapping controls; the current three
affected Python modules pass **48 tests**, with warnings as errors and no skips.
The native Windows rerun is still required. No alert, assertion or platform check
is suppressed. At that earlier checkpoint, archived-context reconstruction after
policy expiry was still missing; the new restricted archive path is qualified
separately above. Installed bindings, initial-bootstrap cancellation, device replacement,
native cross-host/device execution and construction-specific recovery/performance
remain open.

The [Python input-flow assessment](SDK_INTERNAL_REVIEW.md#python-input-flow-assessment-and-output-admission-2026-09-29)
matches all 36 prior CodeQL annotations to their actual CLI/environment sources;
all thirteen flow files at `a9fcf139` match the analyzed merge blobs. These are
source-specific internal dispositions under the local-operator model, not a
claim that the complete scan is clean or that every possible caller is safe.
An adjacent Android output-confinement defect is reproduced with actual writes
outside a disposable target via `..` and a symlinked parent. The shared fixed
admission returns the resolved in-target destination and preserves filesystem
errors, including link loops and non-directory parents. The old code fails three
regression subcases; the fixed affected modules pass **47 tests**, no skips, with
warnings as errors, plus the retained old/new filesystem and three real CLI
admission checks. No SDK runtime/ABI or Continuity source changes in this patch;
current hosted security analysis and complete package/device qualification remain
separate requirements. No alert is suppressed or dismissed.

The [public bootstrap material importer](../research/continuity-identity-candidate/BOOTSTRAP_BUNDLE.md)
now reconstructs the original verified context from a bounded QPBNDL01 input.
Its existing policy/runtime owner, account pins, exact intended device IDs and
generations, required prekey quality, directory expectation and trusted clock
are independent caller inputs. Incoming public materials cannot enroll their own
trust or reopen a closed owner. All four prekey modes retain the original context
commitment; a fully signed same-account package for reversed device roles fails
the intended-peer check. Native endpoint processes reverify saved public inputs
before running the existing connection and recovery cases.

The current local debug/release suites pass **206 tests each**, zero failures or
ignored tests, in 365.363/369.495 runner seconds. These overlapping runs are not
performance comparisons. An independent Python constructor passes one valid and
25 negative packages through the actual compiled Rust importer, with separate
fixture trust and unchanged pre/post executable hash. This is cross-language
input verification, not installed-language SDK connection qualification. The
public-only OpenSSL oracles separately pass 20 envelopes/100 signature negatives
and 12 witness envelopes/60 negatives. Strict Rust 1.90/1.98.1 Clippy, independent
transport features, no-default compilation, fmt, warning-strict docs and 45 clean
isolation/inventory checks pass for 216 Rust files. The new importer and corpus
are wired into the public-vector CI job; hosted execution of this source is pending.

The preceding head `fb98db1c` has an explicitly unresolved hosted CodeQL result:
check [109631309472](https://github.com/billlza/q-periapt/runs/109631309472)
reports **36 Python path/command-input annotations** (five critical and 31 high)
and missing Rust/Swift configurations at that observation. Workflow analysis-job
completion and a clean security finding set are separate requirements. The
annotations and their source identity are retained for input-to-sink analysis;
no suppression, dismissal or confirmed-exploit claim is made. Earlier successful
analysis jobs do not close these findings or qualify the newer source.

The preceding [native reference connection](../research/continuity-identity-candidate/CONNECTION_TLS.md)
starts with an empty sender journal and a real encrypted responder prekey inventory.
Original bootstrap flights cross actual standard TLS sockets; both sides activate
message state, perform three network rekeys, and deliver application bytes in both
directions. Independent file readback checks the session/message IDs and plaintext.
A durable Consumer transaction precedes the peer's consumption MAC; network receipt,
inbox commit, and a prefix blocked by earlier missing input never masquerade as
confirmed consumption. Unknown external commits are reconciled by the same ID.

The QPCNET01 connection carrier shares one bounded TLS/socket/cancellation engine
with the unchanged QPCCTL01 control carrier. Journal v19, v6 rekey controls,
application/ACK bytes and published contracts are unchanged. Eight added tests
include five observed process kills with bounded competing writers, application
failure/unknown commit/post-commit cancellation, a genuine old-epoch ACK, out-of-order
prefix blocking and pre-dispatch bounds/cancellation/clock failures. The final
full debug/release suites pass **200 tests each**, zero failures/ignored, in
501.18/331.11 runner seconds; overlapping runs are not performance comparisons.
Strict Rust 1.90/1.98.1 Clippy, three separate feature configurations, fmt,
warning-strict docs and 45 clean source/inventory checks pass. These are same-host
native process results, not installed-language, independent-implementation,
cross-host/device or completed recovery-analysis qualification.


The [reserved-fanout abandonment contract](../research/continuity-identity-candidate/FANOUT_ABANDONMENT.md)
adds an explicit two-stage terminal lifecycle. A reserved batch can freeze all
member sessions, return only metadata for durable host loss accounting, then
erase logical private state while preserving source/session/ID tombstones. Old
bootstrap, data, ACK and rekey output cannot reactivate those sessions. Peer
revocation does not prevent cleanup, and required witnesses cannot be bypassed.
A killed producer's actual precommit ciphertext supplies a keystream-reuse
counterexample to simply replacing the pending input. v19 storage uses QPFANO02
and QPABND01; pairwise v6 and published contracts remain unchanged.

The v19 local debug/release runs pass **192 tests each**, zero failures/ignored,
in 503.38/350.78 runner seconds. They overlap and are not performance
comparisons. Six added tests cover the keystream counterexample, two process cuts
with bounded competing writers, 18 measured before/after sync faults and 16 signed
witness response losses, revoked-peer cleanup, exact host accounting, fresh-session
delivery and full batch capacity. Strict Clippy on Rust 1.90/1.98.1, no-default
compilation, fmt, warning-strict docs and 45 clean source/inventory checks pass.
These are native candidate checks; exact-head hosted qualification, installed
cross-language/device paths and broader lifecycle/recovery requirements remain open.

The preceding `1210788c` now passes all **42 CI jobs** and **six CodeQL analyses**.
Both Linux toolchains and macOS pass 186 debug/release tests. Tested merge
`e0c64352b84832a7bc0a451e726b3582a521f578` has tree
`04a65c1f94390ec7b5e3f1c2c38dd30a71d3e223`, identical to that head. These hosted
results apply to v18 fanout, not the new v19 abandonment changes.


At `1210788c`, the isolated [account-send candidate](../research/continuity-identity-candidate/FANOUT.md)
now binds every required device in the installed signed roster. It reserves all
pairwise input slots together, then commits all chain/outbox advances before
releasing any member. A real unary-loop counterexample discloses the first
recipient's plaintext before the second recipient exhausts its budget; the batch
API rejects that case before any reservation. v18 journal metadata and reverse
member links prevent unary release of a reserved prefix. The global batch counter
does not reset on retirement. Existing pairwise control and data wire bytes remain
unchanged; acknowledgement, unresolved delivery and retired history are explicit
per-member outcomes.

That checkpoint's eleven focused tests cover peer and own-account rosters, mixed bootstrap roles,
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


## Installed OpenSSL witness interoperability (2026-10-01)

The separate native `anchor-tls` carrier now has a C reference peer using
OpenSSL 3.6.4 in both endpoint roles. It requires TLS 1.3, the standard
X25519MLKEM768 group, dedicated `q-periapt-anchor/1` ALPN, fresh mutual
certificate authentication, exact certificate/subject admission and both
authenticated stream endings. The original signed witness encodings and
native durable state engine are unchanged. OpenSSL is used only by the
qualification peer; it is not added to the product C library's dependencies.
The [C consumer guide](../bindings/c/ContinuityPackageConsumer/README.md)
documents invocation, resource bounds and the isolated peer's failure behavior.

The earlier native-TLS cohort at `1c1d7c80` completed installed C Debug/Release
execution with native Rust peers on Rust 1.98.1 and 1.90. Its sealed local evidence retains
17,917 hashed files. The new runtime snapshot `4286be0c` and source-gate snapshot
`aef1e19e` have the same 183 qualification input hashes; the latter corrects
only the artifact guide's Rust source census. Product/candidate engines and
the C owner library sources remain identical to `e6ef8fc6`. The candidate
archive remains `be7b33dd86eefafd093939fb5478b27f3b78d4a759585d2b1e3785e91c402936`,
and the consumed SDK report remains
`117d1de9be16ccf45846129262237349735635e9dceda69e03bd222f6a521309`.

The complete Rust 1.98.1 installed Rust/C collector passes in 1,081.905 seconds;
the Rust 1.90 installed C collector, including its native Rust peers, passes in
1,033.470 seconds. Both Debug and Release execute all original C client,
server, revoked-cleanup, 59 sync-interruption cases / 771 command records,
274 signed-TCP witness exchanges and 142 native-TLS witness exchanges. Each
of these four configurations additionally passes 142 OpenSSL-server witness
exchanges, two real signed OpenSSL-client query/advance exchanges, and four
pre-store refusals: wrong-subject credentials, trailing data, absent authenticated
close and wrong ALPN. Actual receiver bytes, original loss accounting and
crash/reopen cleanup are independently checked. These timings include build
and qualification work; they are not SDK latency or performance comparisons.

Each OpenSSL configuration exports 29 server, seven client and five rejection
public files. The collector matches header/CLI/runtime versions, retains the
actual `libssl`/`libcrypto` and peer identities, and rechecks all selected inputs
after execution. Public exports are independently replayed and rehashed.
Strict Clippy passes on both compilers. The committed source passes 142
source/package/inventory/verifier tests and the source gate, requiring all 250
tracked Rust files for CodeQL extraction. Five receipt-verifier regressions
use explicitly synthetic metadata, not fabricated TLS/signature evidence.

The original failed experiments are retained. OpenSSL's normal half-shutdown
return of zero was initially misclassified as an I/O error. Two same-name
self-signed trust anchors also made the selected successful client depend on
trust-store order; each leaf passed alone, and reversing the combined store
reversed which client failed. Distinct issuer names in the fixture remove
that ambiguity while retaining certificate verification and exact leaf pins.
The first collector rejected the CLI's explicit library-version suffix, and
one development run collided with an existing command-record filename. These
were harness failures, not successful qualifications. The first source check
also retained a stale source-count failure and an incomplete global-toolchain
launch; the complete rerun selected the owned compiler explicitly.

The local `20261001-continuity-witness-openssl` evidence cohort retains 18,432
hashed files / 263,242,147 bytes: exact sources, binaries/dependencies, archives,
public runtime readbacks, command receipts and original failures. No private
runtime keys or journals are exported. Predecessor `e6ef8fc6` finishes both
43-job CI runs and six CodeQL jobs. Its downloaded Linux x86_64 artifact matches
the hosted archive digest and all 5,084 decompressed files; both profiles also
recheck 58 signed-TCP public-file hashes and a 274-exchange semantic transcript.
Historical TLS reports record 142 exchanges per profile but omitted public TLS
exports. The current workflow adds those exports and requires the independent
OpenSSL peer on Ubuntu 26.04. Current-source hosted qualification remains separate.

The independent implementation here is TLS. Witness signatures and transactions
still execute in the native `AnchorStore` host over bounded IPC. A full independent
witness engine, deployed service, cross-host/current-device execution, certificate
and authority renewal, the remaining fault/concurrency boundaries, product and
language integration, construction-specific recovery analysis, controlled
performance and final release coordination remain open. The candidate remains
`0.0.0 / publish=false`, outside product ABI 2. No merge, publication, external
audit, full TLS fault coverage or formal security proof is claimed.

### Immutable first-key publication (native source candidate, 2026-10-03)

Wrapping and all four signing-owner files now use complete private staging images,
file sync, descriptor-relative NOREPLACE rename, published-inode checks and pinned
parent sync before returning an owner. A killed initial header write no longer
leaves a partial formal key. Existing partial destinations remain refused. A
concurrent opener may reconcile a published image before its creator receives a
result; later creator errors never delete the published identity.

Failed attempts retain staging names instead of using check-then-unlink cleanup.
The original error and attempted staging name remain observable; the name is not
deletion authority. Private unpublished orphans, bounded first-use retry/maintenance,
initial redb configuration recovery, and physical erasure remain open. The original
Preparing enrollment can resume signer creation with its retained SigningKeyId and
must reuse an already-published key. Requested/active identities cannot be reset.

This changes the shared host-store SDK source inputs. The earlier packaged SDK and
Continuity archive receipts do **not** qualify this new source. The retained local
verification is native macOS source testing, not a new archive, Linux/device run,
physical power-loss claim, independent implementation or full lifecycle release.

### Initial database publication (native source candidate, 2026-10-03)

The host policy store and Continuity enrollment, installation, journal, archive and
witness genesis now initialize in private staging, commit their complete schema,
and publish with file sync, NOREPLACE rename, inode verification and pinned-parent
sync. One original Database and exclusive lock span publication and probe drops.
The unreleased low-level Rust initializer now borrows `&Database` and returns `()`;
all workspace callers are updated. This does not alter product C export signatures,
wire/schema encodings, established mutable-transaction semantics or crypto KAT inputs.

Pre-publication interruption leaves no formal database and releases no owner. Only
an original never-active first-use intent can authorize a bounded retry. After
publication, unknown results reopen the original state. Existing partial formal
schemas remain refused; redb may update its own allocator/recovery metadata while
opening before application-schema refusal. No failure removes names or chooses
staging orphans. Exclusive orphan maintenance and legacy-partial recovery remain
unclosed. Anchored journal creation also rechecks the live policy after publication;
a concurrently closed policy withholds the owner without resetting its genesis.

This is local native implementation and validation. Fresh SDK/Continuity archive
consumers, current Linux/device runs, final-source full qualification and the wider
lifecycle/recovery/performance/security requirements remain independent gates.

### Foreign credential Commit result loss (source candidates, 2026-10-04)

The current source exercises the original registered C, Swift and Kotlin owners
through two distinct failure boundaries. At `dc1c2fd1`, the actual foreign Commit
reaches durable witness Applied, its TCP/TLS result is withheld, and SIGKILL is
reaped before an unchanged local Pending state and fresh signed Applied Status
are checked. The reopened foreign owner completes historical recovery after the
original signed policy really expires. The component cohort contains 12 cases,
including the retained Closed controls, and 936 public-file readbacks.

At `2a1d5ada`, the live foreign call instead receives transport error 218. The
same handle must return Closed, C output remains untouched, and explicit close
must complete before a normal process exit. Fresh reopening preserves the
original operation, signer, journal and Pending bytes. Independent original-signer
Status verifies Applied before actual foreign recovery under live or really
expired policy. Exactly one Commit and ACK are recorded; retry is read-only.
C/Swift/Kotlin cover 12 cases and 780 public files. The original killed-Commit and
target-free cancellation regressions add 12 cases and 856 checked public files.
The native engine, product ABI 2 and candidate 73-export library are unchanged.

[Commit-error evidence](../research/sdk-alpha1/evidence/20261004-foreign-commit-error-2a1d5ada/QUALIFICATION.json)
and [killed-Commit evidence](../research/sdk-alpha1/evidence/20261004-foreign-commit-loss-dc1c2fd1/QUALIFICATION.json)
retain source/binary identities, bounded public transcripts and actual commands.
These are Apple Silicon development-consumer results with the same native engine;
they are not exact-source installed archives, physical-platform qualification or
an independent protocol implementation. Current hosted package/CodeQL checks,
remaining lifecycle/concurrency boundaries, authority renewal, device/root
replacement, upgrades, recovery analysis, controlled performance and external
review remain open. The full 0.2.0 release objective is not complete.


At `a55a8c76`, the Apple Silicon cancellation fixture retains typed native TLS
errors and verifies the exact killed-owner admission before classifying them.
Candidate `44c9ff79` CI run `37232506398` ended with 45 successful jobs and one
failed installed Swift job: its C Debug live/expired TLS ACK cancellation cuts
rejected `ConnectionAborted` with preserved OS error 22. CodeQL run
`37232506434` passed. The original failure remains retained.
An isolated actual-C experiment reproduced a positive 25 ms write-timeout setter
failure in `close_notify`, after SIGKILL/reap and native ACK handling, by adding a
bounded 10 ms reply/close scheduling interval. With identical native
instrumentation, the old fixture failed three times and the typed fixture passed
three times while retaining the same errno; all three no-kill controls passed.
The original hosted failure has no syscall-stage trace, so its precise
interleaving is not asserted. Generic `ConnectionAborted`, raw `InvalidInput`,
text impersonation, a different OS cause, wrong/missing admission and multiple
failures still fail; the native engine, library, timeouts and product ABI remain
unchanged. The delay and instrumentation exist only in isolated diagnostic
copies. Current C/Swift/Kotlin consumers passed all 24 ordinary TCP/TLS,
live/expired Status/ACK cancellation cases; 1,632 public files were freshly
verified, alongside strict all-target Clippy, nine C unit tests, four shared TLS
regressions and 31 collector/source-cohort tests. Evidence is sealed under
`research/sdk-alpha1/evidence/20261004-tls-cancellation-cut-a55a8c76/`.
This closes a diagnosed fixture gap, not current-head hosted archive, platform,
full lifecycle, security-analysis, performance, external-review or 0.2.0 release
gates. macOS scope remains Apple Silicon only.


At `864cc594`, installed-APK observation records a known byte mismatch before a
later package-path query can mask it as package unavailability. The current
private-file snapshot and final path/byte recheck remain mandatory; a copy
modified during the final query still refuses. No ADB protocol, observation
budget, retry policy, native SDK or ABI changes. The original implementation
failed empty, short and same-width-corrupt copy precedence controls; the changed
implementation passed all194 bounded-command tests and two real shell ownership
loop regressions. This is error preservation, not an Android transport fix.
The motivating owned API35/16KiB comparison at diagnostic `5ab0698d` completed
73 exact copies in75 attempts: raw exec-out returned zero for an empty copy,
whereas shell-v2 returned255 for a4096-byte truncated copy. Both had a failing
trial, so shell-v2 completion did not repair disconnection. All four preflights
verified actual routes, separated streams/exit7 and independent guest log
capture. Source and original artifacts are sealed in
`research/sdk-alpha1/evidence/20261004-installed-apk-copy-observation-864cc594/`.
Separately, product `4126bb5b` runtime16KiB failed in the second configuration's
installation. Its matching crash-dumper was already present in the installation
baseline: the captured system_server SIGSEGV preceded SDK installation. This
framework failure and earlier copy/offline observations are not asserted to
share a cause. Exact new-head hosted qualification and the full0.2.0 lifecycle,
platform, security, performance and external-review gates remain open.


At `2d7d05b1`, a real-journal/witness regression preserves exact renewal-receipt
admission against an opaque-target counterexample. A and B have different
operations/statements but the same current C1/R1. Independent preparation of A
can name B's real sealed target; fresh account admission then reports Current
with that exact head. Full honest B recovery nevertheless stays Suspended and
preserves pending bytes before and after A's ACK. Neither head equality nor
account authority is treated as B's receipt. The 22 related witness regressions
passed; after correcting four new test-style Clippy diagnostics, the exact final
test passed again and strict all-target Clippy and the source gate passed.

An isolated joint-authorization construction also authenticated two targets
after both C0 and P0 expired and rejected 27 invalid cases using actual candidate
signatures. This is not a durable policy-renewal operation. A new policy
checkpoint still cannot replace P0 directly. The construction must bind current
account and policy approval together and retain a witness continuation binding
after ACK, without resetting the original session or operation state.
[Construction boundary](../research/continuity-identity-candidate/LIFECYCLE_RENEWAL.md)
and [sealed observations](../research/sdk-alpha1/evidence/20261004-joint-lifecycle-authorization-2d7d05b1/QUALIFICATION.json)
record the threat-model distinctions, original failed exploratory attempts and
remaining persistent-state, crash, concurrency and foreign-consumer obligations.
Device/root replacement, witness handoff and the full 0.2.0 objective remain open.

An isolated follow-on from `af55fbf7` persists exact Applied authorization across
ACK, later Closed/ACK, ordinary writes/fences and roster updates. Its experimental
single-observation admission checks current account, exact statement, validity
and head together. A second variant connects this to real native owner release
and denies old account-only admission once adopted; the real A/B encrypted-target
case distinguishes A from B at the same head before and after ACK. The same
modified-source hashes passed 46 witness tests, 22 enrollment/witness tests and
strict all-target Clippy. The patches remain isolated: they use credential
renewal to validate the mechanism, do not implement joint policy continuation,
and do not complete legacy-format migration or installed-consumer qualification.
The [persistent-authority experiment](../research/sdk-alpha1/evidence/20261004-witness-authorization-prototype-af55fbf7/QUALIFICATION.json)
records those limits. A future policy authorization must keep its own exact
scope and validity across credential-only updates; whichever transaction last
ran cannot silently replace that policy authorization.

The exact-authority prototype was then checked against actual legacy state from
an independently compiled old-runtime binary at source `7368c34a`. The old
binary writes `QPANC003` after completed/ACKed C1 renewal and real SDK prekey
generation; the new binary opens the same original files. Three profiles pass:
live C1 refuses specifically on missing witness authorization before new C2
approval; expired C1 recovers through current independent C2 approval; and a
lost C2 Commit reply followed by C2 expiry reconciles original history without
releasing the expired owner, then requires independent C3 approval. Original
keys, journal/storage identity, grant/proposal bytes and inventory remain bound;
new SDK work succeeds under current authority. Each operation has one Commit
and ACK. Strict all-target Clippy passes on the exact consumer source.
[Upgrade evidence](../research/sdk-alpha1/evidence/20261005-witness-legacy-upgrade-7368c34a/QUALIFICATION.json)
records both binary identities and the three synthetic-clock fixture profiles.
P0 remains current; this does not qualify joint policy renewal, installed foreign
archives, independent-host transport or the full 0.2.0 upgrade/release contract.

Hosted source `4126bb5b`, run `37236532231`, completed 42 jobs successfully but
retains the Android 16 KiB framework failure and a separate installed-foreign
job cancellation. GitHub reports that the latter exceeded its two-hour limit.
Its completed collector outputs cover C at 22:25 UTC and Swift at 22:51;
Kotlin Release/G1 policy expiry completes at 23:40:58, 118m32s after the first
Rust command record. All 303 retained command results are either successful or
explicit negative controls. Kotlin's remaining cancellation, commit-loss and
later Release workloads lack completion evidence. The Kotlin and whole-package
summaries and final source/tool/archive recheck are absent, so this run does not
qualify the complete installed package.

The installed foreign job now runs separate Swift and Kotlin matrix legs. Each
retains the complete Rust/C archive prerequisite, all language profiles, original
command/runtime deadlines, the 120-minute job bound and full artifact whitelist.
One leg cannot cancel the other. Local validation passes 47 collector/workflow
checks and Bash syntax; actionlint reports the same two existing `ubuntu-26.04`
label diagnostics as the baseline and no new diagnostics. The
[CI split evidence](../research/sdk-alpha1/evidence/20261005-installed-foreign-ci-split-33a795cf/QUALIFICATION.json)
retains the timeout, incomplete coverage and original failed local invocations.
The new matrix still requires hosted execution; runtime and protocol behavior
are unchanged by this CI split.

### 2026-10-05: local continued-owner and peer-renewal recovery

The native local-only continuation now releases the original enrollment owner
before expired peers have supplied their renewal grants. Peer G retains its P0
scope while current T/P1 authorizes admission and exact retry. Unacknowledged
local completion, superseded policies and observed revocation still refuse.
Same-account peer updates preserve local T and durably record an authenticated
local revocation before refusing success; that refusal is not NoCommit.

A second actual regression exposed a restart gap: journal R2 retained C1, but
the configuration's expired R1 incorrectly caused `Protocol(Validity)`. The
corrected public owner path authenticates that configuration as history, then
uses current journal G/T/roster and actual P1 for admission. The returned device
has R2's checkpoint and authority binding; the original signer, configuration
receipt and journal identity remain intact. Expired or revoked current R2 still
refuses without replacing state. Ordinary renewal retains current-time checks.

The exact promoted source passed **527 native library tests**, **3 compile-fail
documentation tests**, strict native/C all-target Clippy, **9 C source-consumer
tests**, **41 native/package contract tests** and formatting for the twelve
changed Rust files. Peer-journal faults cover twelve before/after cuts at six
measured barriers: four recover the predecessor and eight the committed target,
all retaining the original operation and local T. The
[local qualification](../research/sdk-alpha1/evidence/20261005-peer-policy-recovery-e5b271cf/QUALIFICATION.json)
retains the two real red regressions, current successful runs and source hashes.
C validation here is source compatibility, not installed-archive qualification.

Separately, source `242876ff` CI run `37254954329` passed its Rust/C installed job
on Linux x86_64. Artifact `11323391738` matches its published digest; all 445 input
files match that Git head and independent before/after inventories agree. This
predates the above delta and does not exercise installed foreign T/P1 APIs.
Swift/Kotlin installed jobs were still running at this update. That run's exact
Rust inventory failed at 317 versus 325 after eight legitimate new files; the
inventory and path sentinels are corrected with 43 passing tests. Android 16 KiB
remains failed: runtime instrumentation passed, then cleanup APK ownership
copies were truncated twice and ADB disconnected. Uninstall is unconfirmed and
the transport root cause remains open.

Exact-T required-witness admission, policy-only renewal, expired-uncommitted
joint cancellation, device/root replacement, foreign T APIs, installed current
archives and the remaining 0.2.0 platform/security/performance/review gates remain
required. macOS remains Apple Silicon only. No merge or release is implied.
