# Continuity product admission boundary

Status: unpublished product integration. The initial adapter review used
`7997282c00342325c79d3c3d2b9d086e718df1e7`; subsequent native account-member
carrier work is noted below.
This records implemented boundaries and work still required for 0.2.0. The
candidate interface and protocol are not frozen or admitted for publication.
Product ABI major 2 and the existing KEM/KAT contracts remain unchanged.
The complete [release scope](RELEASE_0_2_SCOPE.md) still governs.

The agreed Android physical-device acceptance scope is the single selected phone,
now running API 37 after its system upgrade. That device gate is satisfied by the
retained successful acceptance runs. An API 36 phone, a second device or a stable
emulator is not required, and their absence does not make those results
insufficient or untrustworthy. Subsequent software changes use the same phone for
relevant regression checks; those checks do not reopen a hardware-count gate.

## What the installed consumers currently establish

The unpublished [Android JNI adapter](../../bindings/android/ContinuityPackageConsumer/README.md)
now covers first-use configuration, independently pinned registration, explicit
peers, bidirectional transport, original-ID retry, rekey and cancellation. Its
actual AAR is consumed by a minified release app on the selected API 37 phone;
[two trust profiles and 24 ART processes](../../research/sdk-alpha1/evidence/20261011-android-continuity/CHECKS.json)
pass the implemented lifecycle. One phone satisfies the agreed device scope.
The [signed-TCP and mutual-TLS required-witness registration routes](../../research/sdk-alpha1/evidence/20261011-android-witness/CHECKS.json)
additionally pass in 30 ART processes on that same phone; missing/wrong trust and a corrupted
signed reply are refused, and independent genesis enrollment enables activation
and original-request reopen. Android now also provisions its own independent
account registry, verifies and replays the approved association, selects its live
authority for first activation, and reopens the original managed enrollment.
The [four registry routes](../../research/sdk-alpha1/evidence/20261011-android-authority/CHECKS.json)
pass in fifty ART processes: forged revisions are refused,
cancel does not revoke an already selected child, and close does, even after the
same registry is reopened. The [same-key credential renewal route](../../research/sdk-alpha1/evidence/20261011-android-credential/CHECKS.json)
passes in 110 ART processes on that phone: independently approved target,
original operation after process restart, lost Commit/Applied reply, historical
reconciliation without a new commit, and current-authority activation with the
same signing identity and journal. The [extended original-traffic route](../../research/sdk-alpha1/evidence/20261011-android-renewal-traffic/CHECKS.json)
passes in 130 ART processes: an unassociated peer is refused, explicit independent
peer registration enables communication, and the installed native C receiver
persists one business effect before exiting with 77. After local renewal, Android
reopens the original session and retries the original message; its acknowledgment
returns without replacing or duplicating that effect. These routes run before
original credential expiry. Android's public device interface also now admits
an independently approved remote credential grant. The
[150-process ART route](../../research/sdk-alpha1/evidence/20261011-android-remote-credential/CHECKS.json)
renews the installed C counterparty, rejects wrong pins/operations and local-identity
misuse, refuses the superseded peer object, then reopens the original session.
A fresh process retains the pending message and next slot; exact retry preserves
the two distinct application effects. The
[222-process cancellation route](../../research/sdk-alpha1/evidence/20261012-android-credential-terminal/CHECKS.json)
now also passes on that phone. A target roster expires under real clocks while
its credential and the original policy remain live. Cancellation stays Pending
until independently authorized Closed; a lost cleanup acknowledgment preserves
that decision across restart. Recovery dispatches no new Commit or Close and
restores the preceding authority, original identity, journal and session; a new
third message produces exactly one additional business effect. Already committed
renewals remain Committed under close and expiry reconciliation.

The [local-only expiry route](../../research/sdk-alpha1/evidence/20261012-local-roster-expiry/CHECKS.json)
passes 60 ART processes on the same phone. It exposed and fixed a shared native
recovery gap: an expired target roster blocked activation, but cleanup previously
waited for credential expiry. Exact predecessor history now permits
ExpiredUncommitted when either signed target expires. This terminal still refuses
activation until a separate independently approved grant is staged and committed.
After explicit peer admission and original-session restoration, the same identity,
journal and next message slot deliver one new effect without duplicating the old
one. The old implementation's failure and the stale-context rejection are retained.
The corrected native engine passes 909 library tests and strict Clippy; the full
Debug/Release host JNI run passes 726 Java processes, including the existing
required-witness routes.

The [original-policy expiry route](../../research/sdk-alpha1/evidence/20261012-android-policy-expiry/CHECKS.json)
adds 144 ART processes on that same accepted phone. Real P0 expiry leaves the SDK
policy and target credential/roster live. Fixed and recoverable trust each cover
signed TCP and mutual TLS, with both an uncommitted prepared target and an actual
pre-expiry Commit whose reply was lost. Historical proposal replay and explicit
Close preserve the original identity, journal and terminal history; a competing
Applied result remains Committed. Expired P0 refuses staging, a new Commit and
activation, and captured post-expiry recovery sends no Commit. The complete
Debug/Release host regression passes 1,014 Java processes; 28 reader tests,
59 package/source-inventory tests and strict Clippy also pass. Production AAR and
native engine bytes are unchanged from the preceding qualification; its 909 native
tests were not rerun for this test-only addition. That checkpoint did not cover
SDK-runtime expiry/revocation, independent policy/roster renewal, device retirement
or root replacement. No additional Android device is required.


The [independent protocol-policy renewal route](../../research/sdk-alpha1/evidence/20261012-android-policy-renewal/CHECKS.json)
now adds the Android public adapter at `b8c8226c`: 234 ART calls on the same
accepted phone, with fixed/recoverable SDK trust and local, signed-TCP and mutual-TLS
storage coordination. After real P0 expiry, independently retained target inputs
and both account-root and policy-root approvals authorize P2. The original signer,
journal, session and uncertain message survive, with exactly one observed business
effect. The outer SDK policy and device credential remain live in this scenario.
Required-witness Commit really applies before its reply is lost; exact history
recovers Applied and completes retirement without another policy Commit or Close.
Missing current-target selection and missing required registry remain explicit
failures. Local resolution is not substituted for required-witness recovery.

Complete Debug/Release qualification passes 1,482 host Java processes, 35 reader
checks, 27 package/first-configuration checks, 81 source-inventory checks and strict
Clippy. The existing C first-configuration regression also passes after sharing
receiver-policy setup. Native engine bytes and runtime sources are unchanged from
the preceding 909-test native qualification. Captures retain the JNI field-count
failure, checked test-slice repairs and an export-list error. Exact successful
commands preceding that export error were reverified against source/tool/package
identities before the remaining workload continued. SDK-authority expiry/revocation,
roster renewal, retirement and root replacement remain separate Android software
work; the agreed physical-device gate remains complete.

The [peer-roster continuation route](../../research/sdk-alpha1/evidence/20261012-android-peer-roster/CHECKS.json)
passes 46 host Java calls and 46 ART calls on that same accepted phone. An
independently approved R2 that retains the same member preserves the original
session, pending message and next message slot. Exact retry after the receiver
commits and exits before acknowledgment leaves one business effect. A subsequent
empty R3 revokes the member: both sending through the retained peer object and
reopening the peer fail with Scope 103. Malformed input, a wrong checkpoint and
cancellation are rejected before admission. The initial test incorrectly expected
every roster advance to invalidate old children; the retained failure and current
membership checks explain the correction. No runtime authorization was relaxed.
[Archive-only readback](../../research/sdk-alpha1/evidence/20261012-android-peer-roster/ARCHIVE_READBACK.json)
verifies all 463 captured member hashes and both execution records. This completes
that route's physical acceptance; API 36 hardware and a second phone are not
required. The [complete Debug/Release integrated regression](../../research/sdk-alpha1/evidence/20261012-android-roster-integrated/README.md)
now passes 3,442 Java processes: 1,720 lifecycle calls plus one JNI boundary process
per profile. All 44 new roster export routes are independently reread from the
capture, and source/package inputs remained unchanged throughout execution.

The [Android original-device retirement adapter](../../research/sdk-alpha1/evidence/20261012-android-retirement/README.md)
passes 84 host Java calls and 42 ART calls on that accepted phone, including twelve
host and six ART process cuts. Android creates and retains its original keys and
journal locally. After independently authorized native generation replacement,
the cleanup-only owner preserves the complete original report across host
acknowledgement, journal erasure, signer erasure and reopening. The native runtime
rejects a modified report, a receipt with the wrong purpose and ordinary enrollment
resumption after retirement. The original peer business effect remains unchanged.
Source/package-bound captures and archive-only public readback are retained.
The original capture uses native successor activation; that alone does not
establish fresh Android successor traffic.
This is additional software coverage on the already sufficient physical device.

The subsequent [Android-created replacement route](../../research/sdk-alpha1/evidence/20261012-android-replacement/README.md)
closes that fresh-successor traffic gap. Both generations
create their own keys and journals through Android APIs; the independent issuer
receives only public enrollment material. The original C counterparty explicitly
admits the signed new roster before accepting a new session. A lost acknowledgement
and exact successor retry preserve one new effect and the previous device's original
effect. Debug/Release host runs pass 128 Java calls; the accepted phone passes
64 ART calls with six real process cuts and complete resource cleanup. The initial
Checkpoint 105 refusal is retained and explained by the omitted peer-roster admission.
The existing AAR/native engine is unchanged. The public adapter and complete
replacement test are now integrated into the main sources. All 60 library/JNI
source inputs match the accepted AAR; its physical acceptance remains valid.
The normal installed-package qualifier now requires the replacement/retirement
case and rereads its bounded public export. The
[complete integrated Debug/Release run](../../research/sdk-alpha1/evidence/20261012-android-retirement-integrated/README.md)
passes 3,570 Java processes with unchanged compiled inputs and archive-only
readback. The following root checkpoint extends this integration; independent
protocol implementations remain separate work.

The isolated [Android account-root replacement checkpoint](../../research/sdk-alpha1/evidence/20261012-android-root/README.md)
now passes the original target, transition to another approved target, transition
after binding, and adoption of an already committed competing replacement. Both
original and successor identities are generated through Android APIs. Debug/Release
host runs cover 560 Java calls and 96 process cuts; the same accepted phone covers
280 ART calls and 48 cuts. Original reports and message identities survive restart,
unknown activation reconciles, invalid receipts are rejected, successor traffic
preserves distinct application effects, and controller close revokes its successor.
All library class members are identical between the qualified host JAR and AAR.
Public archive readback covers sixteen host and eight ART routes, and the phone's
test installations and owned port mappings are removed. The subsequent
[direct noncommit and cancellation checkpoint](../../research/sdk-alpha1/evidence/20261012-android-root-controls/README.md)
adds 164 host calls and 82 ART calls with the unchanged AAR. A signed noncommit
remains Closed across restart and refuses the old freeze; idle cancellation stops
controller calls while its active successor remains usable until controller close.
The adapter and all five routes are now in the main sources. The normal package
qualifier requires the complete 30-test catalog and rereads each bounded export.
The [combined current-source Debug/Release integration](../../research/sdk-alpha1/evidence/20261012-android-root-integrated/README.md)
now completes 4,294 Java calls, including 724 root calls and 124 root cuts. All
15,965 captured member hashes and root/retirement/roster exports were reread.
This does not reopen the already satisfied physical-device gate.

The [integrated iOS store checkpoint](../../research/sdk-alpha1/evidence/20261012-ios-main-integrated/README.md)
adds physical execution on the offered USB-connected iPhone 16 Pro with iOS 27.0.
It creates two fresh identities under fixed/recoverable SDK trust, verifies the
registration signatures at the host, activates the independently issued grants,
and reopens exact original state. Eight private-path probes refuse symlinks and
0755 directories with code 203; all 57 host-store unit tests and Clippy also pass.
The [subsequent USB connection route](../../research/sdk-alpha1/evidence/20261012-ios-network/README.md)
uses 20 application launches and six actual TLS exchanges. For each trust profile,
the C receiver exits with 77 after its business effect and the iPhone reopens and
retries the same session/message; one unchanged effect is retained. The transport
relay copies opaque TLS bytes only. This is Swift/iOS to C/macOS execution with
the shared engine. The subsequent [managed iOS witness checkpoint](../../research/sdk-alpha1/evidence/20261012-ios-managed-witness/README.md)
adds four on-device registries and four independently verified device identities
across fixed/recoverable trust and signed TCP/mTLS witness runtime. All 66 app
launches pass, including missing witness (216), wrong witness (103), preparation
cancellation (302), malformed signed receipt (218), absent registry (211), and
closed/finally released registry (202). Twelve peer TLS and 486 phone-witness
exchanges preserve the original session/message and one effect through four
receiver exit-77 cuts. Twenty-eight actual refused reconnections are retained as
failures. TLS runtime does not fall back to signed TCP. The app is removed.
The [iOS credential renewal checkpoint](../../research/sdk-alpha1/evidence/20261012-ios-credential/README.md)
adds 130 successful launches across the same four trust/carrier combinations.
Each waits for actual credential expiry and observes 104 for old activation and
a fresh request. An independently approved same-key renewal is staged exactly,
committed once at the witness, and reported as unknown 218 after reply truncation.
Historical reconciliation/replay works without new account authority and dispatches
no fresh commit; new activation without the registry still returns 211. The
original signer, journal, session/message and one peer effect remain unchanged.
Twelve peer TLS and 542 witness streams are retained with 28 refused retries;
twelve altered public/execution captures are rejected. This is credential renewal,
not signer replacement or post-compromise recovery. The test app is removed.
The [iOS policy checkpoint](../../research/sdk-alpha1/evidence/20261012-ios-policy/README.md)
completes another 122 app launches in four scenarios. The receiver adopts P1
before real P0 expiry; the phone then refuses old activation with 104. Independent
account and policy approvals authorize continuation. A modified approval returns
102; repeated staging and recovery preserve the exact witness proposal. Applied
reconciliation and retry retain the original session/message and one effect.
Twelve public-record mutations are rejected; all 3,168 archived members are
hash-checked and the public records reread. The
[iOS replacement/retirement checkpoint](../../research/sdk-alpha1/evidence/20261012-ios-replacement/README.md)
adds 64 Swift calls and six actual app exit-77 cuts across fixed/recoverable
trust. Both generations create identities and journals on the phone; the
independent issuer sees public requests only. Exact retirement reports survive
report retention, journal and signer erasure; old operational reopening returns
215. The original C peer explicitly admits the successor roster, and new-session
retry preserves the original effect plus one successor effect. Twelve altered
captures are refused and all 2,201 archive members are hash-checked and reread.
The [iPad root checkpoint](../../research/sdk-alpha1/evidence/20261012-ipad-root/README.md)
then completes all five root routes under both trust profiles: 362 Swift calls,
62 actual app process cuts and 20 receiver cuts. Original proposals/reports and
old/new business effects survive restart. Noncommit remains Closed; cancellation
preserves the live successor until controller close, which revokes it with 202.
All ten route exports and 16,334 archive hashes are reread. The Scene-based
harness requires an exact host startup acknowledgement before SDK work; failed
prior attempts are retained separately. The
[installed iOS binary-package checkpoint](../../research/sdk-alpha1/evidence/20261012-ios-binary-package/README.md)
then qualifies an extracted Swift product and arm64 device/simulator XCFramework.
Both consumers build without warnings or custom SDK search paths. Its installed
iPad app completes the original root route with 68 calls and twelve app cuts;
all startup/result/exit records and public exports are checked. The source
comparison covers 503 current compilable inputs, and both slices expose exactly
152 owner functions. The [iPad Complete-protection checkpoint](../../research/sdk-alpha1/evidence/20261012-ios-data-protection/README.md)
adds five installed-package launches with two independently verified on-device
identities: actual protected-data unavailability, sentinel EPERM and exact 702
refusals, unchanged original file inventory, and successful original-identity /
journal / publication recovery and activation after unlock. Its scope is
successfully closed local-profile owners with host-applied Complete protection.
Live-owner/background transaction handling, simulator execution and canonical
release-pipeline integration remain open. The existing one-phone Android gate
stays passed.

The [canonical Apple producer checkpoint](../../research/sdk-alpha1/evidence/20261012-apple-package-producer/README.md)
adds a reproducible three-slice arm64 Swift package to the existing installed
qualification and Swift CI job. Sixty relevant checks, all 686 package members,
three exact native export sets and the final consumer link maps pass locally.
The macOS and iOS 27 simulator cancellation/close probes execute the packaged
native owner. Xcode's varying slice order is canonicalized; a fresh producer run
matches the expected archive hash from two earlier native builds. The subsequent
[physical iPad checkpoint](../../research/sdk-alpha1/evidence/20261012-canonical-apple-device/README.md)
executes this exact canonical archive through all five account-root routes under
fixed/recoverable trust: 362 app calls, 62 app exit cuts and 20 receiver exit cuts.
The package, selected native slice and executable identities are rechecked; all
startup admissions and public records pass, and the run-owned app is removed.
Hosted CI remains separate. Earlier Data Protection evidence keeps its original
artifact scope; neither cohort asserts live-owner background recovery or PCS.

New C, Swift and Kotlin/JVM integrations use explicit first-use configuration:
[C](../../bindings/c/ContinuityPackageConsumer/README.md#explicit-first-use-configuration),
[Swift](../../bindings/swift/ContinuityPackageConsumer/README.md), and
[Kotlin/JVM](../../bindings/kotlin/ContinuityPackageConsumer/README.md#first-use-configuration-unpublished-candidate).
Preparation copies the host's SDK trust/policy, independently pinned protocol
policy and local TLS inputs. Finishing validates them and publishes the original
configuration, SDK store and generated wrapping key. Creating enrollment then
owns a generated device signer and original public request. The host independently
authenticates the account, approves the intent, obtains the signed grant and
enrolls any required witness. Unknown creation results reconcile the same inputs;
opening committed configuration never chooses a new lineage after an error.

The [first-use expiry checkpoint](../../research/sdk-alpha1/evidence/20261010-first-configuration-expiry-integration/CHECKS.json)
records C/Swift/Kotlin flows that refuse activation after actual protocol-policy
expiry, obtain independent renewal and recover the original session/message with
one receiver effect. Those same-host, shared-engine checks do not qualify SDK
policy replacement, independent protocol implementations or every supported
platform. Complete current-source installed cohorts retain their own gates.

The C adapter's legacy [`Owner`](../../bindings/c/ContinuityPackageConsumer/src/owner.rs)
contains one `DeviceService`, one device signer, one verified `BootstrapContext`,
one SDK policy store and one pair of exact application TLS credentials. Its
constructor reads the fixed private fixture layout, verifies the independently
retained pins and bundle, opens the existing installation and activates it. It
does not generate local enrollment material or provision an installation.
[`Request`](../../bindings/c/ContinuityPackageConsumer/src/opening.rs) copies the
bounded path, prekey mode and witness selection before activation; it does not
change this trust or storage boundary.

The separate C [`registration owner`](../../bindings/c/ContinuityPackageConsumer/src/enrollment.rs)
now generates the original signing identity under a committed native enrollment
intent. Its public request is admitted by an independently authorized authority;
credential/roster acceptance takes a separately obtained trust pin. Activation
moves the whole `EnrolledDevice` into the existing device parent, retaining its
enrollment lease during peer communication. Explicit resume never falls back to
the legacy installation constructor. Same-credential roster refresh and original
session restoration preserve the original request, signer and journal. Required
witness activation checks current signed authority; local Active alone cannot
release an owner after denial or an unavailable reply. The C interface now has
152 unpublished exports, separate from product ABI 2. SDK policy/store, TLS setup,
authority transport and final provisioning remain independently supplied inputs;
see [the C integration path](../../bindings/c/ContinuityPackageConsumer/README.md#registering-an-original-device).

Swift and Kotlin now expose this registration route through `ContinuityEnrollment`,
typed approved intents/checkpoints and independent account pins. Their shared
setup/registration transfer cell moves one owning reference into `ContinuityDevice`;
it never creates another owner from an integer handle. Old aliases cannot operate
after transfer, and closing them cannot close the successor. The installed-package
gate requires local connection/restoration and signed-TCP/mutual-TLS authority
traces plus observed old-wrapper ARC/GC release. Kotlin runs both Serial and G1
and rejects direct Java construction of the enrollment owner. These are scoped
same-host checks, not the complete device/platform or authority lifecycle.

The additive C [`device owner`](../../bindings/c/ContinuityPackageConsumer/src/device.rs)
now opens an Active installation from independently retained local identity,
policy and private-owner configuration. It checks the controlled signer against
the verified local credential without deriving local trust from a peer bundle.
Fresh/restored peer children reuse that same service and witness owner. Parents
and children share the existing bounded registry; idle child disposal does not
take the service's network lock. Parent cancellation signals the active child and
fences later calls; successful parent close releases storage even with retained
idle children. Native errors keep their original reconciliation requirements.
Current C workloads exercise both roles, multiple handles for one context at each
endpoint, lifetime/capacity/identity refusal, real delivery recovery and required
witness profiles. The C account adapter now retains the exact parent and every
selected peer through one native `send_account_member` invocation. A separate
three-installation workload covers two distinct recipient devices, complete-set
refusal, original-message crash/retry, unary replay refusal, reordered targets and
aggregate cancellation/close behavior. Swift and Kotlin retain the same parent
and complete peer set through their typed owners. A separate native mutual-TLS
witness workload now completes both member deliveries after the first receiver
exits following application persistence, preserving the original batch/message
and idempotent readback. The same foreign endpoints now execute this trace and
four committed-witness-reply losses with three distinct devices in one original
signed roster. Both own-account and peer-account delivery refuse an incomplete
recipient set before reservation or application-network access. Broader delivery
faults, authority lifecycle and final product admission retain separate gates.

The [`C header`](../../bindings/c/ContinuityPackageConsumer/qpc_owner.h) exposes
pairwise operations, device/peer preparation, complete-account member delivery and restricted original-session
recovery. Swift and Kotlin now add `ContinuityDevice`, native parent retention,
typed account targets/status/results and complete-account member calls. Their
current installed-package and lifecycle evidence must bind the changed source.
Whole-account abandonment/report traversal, exact acknowledgement and retirement
now reuse the native transaction through all three bindings. Installed cohorts
exercise complete reports after SDK revocation and original-ID recovery under
local, signed-TCP and mutual-TLS witness profiles. The
[qualification ledger](../SDK_0_2_RELEASE_READINESS.md#latest-qualification-checkpoints)
binds each result to its source and carrier. Current-source registration package
qualification, browser permanent-retirement and renewed-authorization composition, remaining root/witness-key
replacement and the broader failure matrix remain required. These finite
own-account traces do not qualify the complete multi-device lifecycle.

The restricted C retirement owner now delegates to native `RetiredDeviceEnrollment`.
It requires the original enrollment intent, independently pinned witness authority,
exact generation-replacement proposal and permanent old-subject proof. Eight C
processes exercise the complete original report, durable host accounting,
independent purpose-21 acknowledgement, logical journal/signer erasure and exact
reopening after three lost completions. Native Rust reconstructs and compares the
complete report, checks session/message accounting and fences ordinary enrollment
after erasure. The complete `ce70bf83` native/C installed producer now passes
both profiles, with the current reader independently checking retirement outputs.
Swift now has the separate `ContinuityRetiredEnrollment` owner, bounded immutable
inputs/report outputs and eight actual cleanup processes in both source profiles;
56 tests per profile and original registration regression pass. Fresh archive
qualification remains separate. Kotlin now delegates the same restricted flow,
with immutable public inputs/outputs, private owner construction and existing
Cleaner/call lifetime protection. Private Maven consumers run all eight cleanup
processes under Serial/G1 with both qualified C engine profiles; 54 JVM tests per
native profile and original registration regressions pass. Complete Kotlin
distribution and platform qualification remain open.
The subsequent [foreign successor checkpoint](../../research/sdk-alpha1/evidence/20261008-foreign-successor-traffic/README.md)
also exercises original generation-2 creation, resume, activation and fresh TLS
through C/Swift/Kotlin owners. Replacement authorization and witness decisions
still use the native authority controller. Complete current-source distributions,
physical erasure and independent implementations remain separate requirements.
The later Android retirement/replacement runs above satisfy the agreed physical
acceptance for those Android routes on the selected phone.

| Required boundary | Existing implementation to reuse | Foreign integration still missing |
| --- | --- | --- |
| Explicit new lineage and exact restart | C/Swift/Kotlin/Android configuration owners and the browser IndexedDB owner admit explicit first-use inputs; enrollment commits the original signer/request, accepts independent trust inputs and retains the enrollment lease; reconcile/open preserve original identity | Complete current-source archive/device qualification, deployed authority transport, broader creation faults and final product provisioning |
| Device-scoped protocol service | Native shared service, foreign device-parent/peer owners and the browser device retain one journal and archive index under one installation lease; account calls pin the complete peer set | Complete lifecycle and source-bound qualification on every supported target |
| Account-wide local transaction | Shared journal transaction with complete-set admission and per-member outcomes; native and foreign carriers, including Android, retain original operations; the browser adds original-account/session recovery, complete loss reports and whole-reservation abandonment | Broader interruption/concurrency and authority lifecycle; browser permanent retirement and composed renewal-to-cleanup recovery |
| Authority lifecycle | Native/C/Swift/Kotlin original enrollment, credential renewal, joint or independent protocol-policy continuation, peer-roster refresh and original-session recovery; native witness account-root retirement fences previously unseen old-root devices; the native managed owner orders registry/enrollment/journal commits, retains non-commit, transitions to approved targets and adopts an independently approved committed winner | Complete deployed authority lifecycle, managed retirement accounting in [account-root cutover and witness-key handoff](../../research/continuity-identity-candidate/AUTHORITY_REPLACEMENT.md), foreign distribution qualification, remaining Android whole-account services, WASM authority/persistence integration and current-source qualification on every supported platform |
| Permanently retired enrolled device | Native atomic generation replacement and restricted retired enrollment; C/Swift/Kotlin delegate complete report/host acknowledgement and original journal/signer erasure without operational authority; Android-created original and successor devices, cleanup and fresh traffic pass on the accepted phone; installed browser permanent retirement preserves full reports and original object identity across expiry, interruption and cancellation | Complete current foreign distribution qualification, remaining foreign replacement authorization, browser managed account-root cutover and wider lifecycle qualification |
| Platform persistence | Native protected-file/redb engines, Android installation storage and the browser IndexedDB backend retain original write intents and reconcile uncertain commits | Remaining platform lifecycle/failure qualification and release admission under each backend's actual durability contract |

The native fanout methods are in
[`durable/messages/fanout.rs`](../../research/continuity-identity-candidate/src/durable/messages/fanout.rs).
They take all required pairwise contexts and existing session IDs, derive the
recipient set from the installed roster, reserve every input together and commit
all chain/outbox changes before releasing any ciphertext. A binding must delegate
to this transaction. Looping over the pairwise `send` API would permit a partial
local commit and does not implement this contract. Opening a separate current C
owner for each peer also conflicts with the exclusive installation/journal leases.
Neither approach is an acceptable multi-device implementation.

The native TLS carrier now adds `send_account_member`, which takes the original
complete `FanoutInput` and an explicitly selected member session. It checks all
archive/recipient inputs, commits the whole local aggregate, and re-admits that
aggregate on every network retry. Unary replay of a live committed aggregate
member is fenced at the journal boundary. Foreign multi-peer owners must use this
shared carrier and preserve its distinct consumption, pending-resolution, unknown
delivery and retired-history outcomes. This native addition does not supply the
foreign context-registration or provisioning APIs described below.

The native `DeviceService::reopen_peer` entry now restores an established peer
under the already retained installation/journal/archive leases. Its opaque
`SessionReopenRequest` must match the original local owner, policy and witness
scope, session, role and archive, with current native identity/roster/budget/witness
checks. The returned `ReopenedPeer` retains public context ownership and its exact
session/role; it holds no additional storage lease. Closing the service still
closes protocol authority. Both same-account and peer-account tests restore two
contexts, refuse an omitted recipient without partial mutation, execute the
existing complete-roster transaction and replay its exact ciphertext after
original-installation restart. This is the native existing-session prerequisite;
the separate native fresh-admission entry is described next. C parent/child
handles and Swift/Kotlin parent/child owners reuse both entries. Android and browser
owners now expose fresh admission and original-session reopen; their complete
platform lifecycle still needs the separate qualifications described above.

`DeviceService::admit_peer` now admits a freshly and independently verified peer
context against the same active installation. It rechecks current advertisements,
credentials/runtime, local and known-peer rosters and the original witness. An
unknown account's initial verified roster is checked without installation or
advancement; the first actual bootstrap must repeat admission and persist that
roster with its operation reservation. `BootstrapPeer` owns public context and
role, without a session or durable grant. Both roles, later revocation, full roster
capacity, unchanged stores and policy/runtime closure during authenticated witness
queries are tested on current and minimum Rust. This supplies the native fresh
boundary. C registration and Swift/Kotlin owners now delegate to it; enrollment
and the remaining platform lifetimes retain separate obligations.

## Required owner and input separation

The adapter integration requires a device-scoped service owner, bounded
verified peer-context owners and separate setup/recovery authorities. These are
contract roles, not frozen class names or permission to expose raw native handles.

One service must retain the original installation, journal, archive index, local
signer and SDK policy runtime across all its peer contexts. Registering a peer
must verify its public bundle against independently supplied account/root/roster,
device-generation, protocol-policy, directory and requested-mode expectations.
The incoming bundle cannot supply those expectations. Registration must also
match the service's original local storage owner and policy binding; merely
matching a display name, account ID or certificate is insufficient. Reopening
reconstructs the same verified inputs and does not manufacture missing sessions.

Restart also needs separate existing-session and fresh-bootstrap admission.
The current C constructor re-verifies its fixture bootstrap bundle at the wall
clock; that path includes prekey-advertisement validity. The native message
engine deliberately distinguishes this from current session-identity checks.
The native `BootstrapBundle::request_reopen` and
`DeviceInstallation::reopen_session` path now reconstructs the original session
after public snapshot expiry, requiring its Active installation, exact message
state/role and cleanup archive, current installed rosters, credential/policy/runtime
authority, signed budget and fresh required witness. Native and public TLS
qualification is recorded in `research/continuity-identity-candidate/INSTALLATION.md`.
The C candidate now adds `qpc_owner_v1_prepare_reopen`; Swift/Kotlin expose
`prepareReopen` and `reopen` through their existing lifetime owners. The prepared
request copies an explicit session ID and preserves the original activation,
cancellation and deadline boundary. Local-profile development runs exercise all
three public foreign methods with genuinely expired advertisements at the current
foreign clock and real TLS/application readbacks. Separate C/Swift/Kotlin
development runs restore the responder's original session under required signed
TCP and mutual-TLS witnesses, refuse missing/wrong pins and bad signatures, cancel
partial replies and stalled handshakes, and reopen the same session. Public
readback verifies the selected session, command results and original witness/socket
records; the existing constructor workload also passes in all three languages.
The complete `a897ba54` Rust/C/Swift/Kotlin archive producer and independent
package/public-record readback now pass in both profiles. The later `caf5ab1e`
shared-service restoration and `469ccf31` fresh-admission additions have separate
targeted native evidence; their installed foreign packages have not been
requalified. These finite workloads do not cover
all witness-store rollback or credential/root lifecycle transitions. The existing
fresh constructor does not auto-fallback.
Historical material verification must not turn an old timestamp into renewed
operational authority or permit an expired selection to start a new bootstrap.

Operations must select an admitted context explicitly, preserve its current
policy/roster/witness checks, and keep both context and parent service alive until
the operation returns. Closing a peer context cannot acknowledge messages, erase
pending journal work or close an unrelated peer. Device-service close/cancellation
must have defined effects across all its active calls; call and owner capacity
must leave close/reconciliation available. This extension must reuse the native
state machine and its transaction boundaries rather than introducing a second
ratchet in any language binding.

Peer disposal needs its own lifetime boundary. An idle peer's destructor or
Cleaner must be able to retire that peer while an unrelated peer uses the device
service. Requiring the parent's long-running network lock for that cleanup could
return BUSY after the foreign object becomes unreachable and strand capacity.
Active account calls must retain every selected peer and the parent through the
native return, not merely copy their integer IDs. Parent close must invalidate
child operations while preserving already borrowed objects until their calls
drain. The adapter must test these races and budget reclamation explicitly; the
existing single-owner reachability-fence tests do not establish child ownership.

Witness I/O also needs the selected invocation's cancellation owner. The C
adapter now retains the independently configured witness endpoint and credentials,
but snapshots the active call's token and absolute deadline together for each
fresh native exchange. Sequential cancelled calls under one retained endpoint are
tested with distinct tokens and real stalled TCP/TLS sockets. Existing public
owners still reuse their original one-way token. A device parent must fence
new child calls after parent cancellation and signal its active child invocation;
single-peer cancellation must not poison another peer's future calls. This
transport separation is now used by the C parent/child registry. It does not
claim parallel journal operations or supply language-level lifetime owners.

An aggregate result must preserve every member's original session/message IDs and
the distinction between committed ciphertext, peer acknowledgement, pending
resolution, unknown delivery, retired history and abandoned reservation. Local
aggregate commit is not remote atomic application execution. A cancelled or failed
dispatch cannot authorize a replacement aggregate ID or exclude a required device.

## Provisioning is an explicit authority

The native [`DeviceEnrollment`](../../research/continuity-identity-candidate/ENROLLMENT.md)
now owns the pre-credential transaction: independently approved intent, durable
signing-owner identity, exact dual-signed request, current credential/roster/policy
admission and one future journal identity. It delegates child creation and service
activation to the existing installation engine. A committed Activating phase makes
an unknown cross-record activation result resumable without choosing a new lineage.
A final live-policy check follows the enrollment commit before releasing owners.
The ordinary archive-shipped native TLS connection now retains this enrollment
owner through activation, original-state restart, traffic and rekey, with mandatory
public identity/readback checks in the package gate. The older setup loaders below
still use their existing protected configuration; new integrations enter through
the configuration and enrollment route above. The signed-TCP roster recovery
profile remains a preconfigured installation.
The registered session-restoration profile now continues the original enrollment
through an explicit same-credential roster update and reopens its original session
without releasing the enrollment lease. Credential/root/policy replacement remains
outside those traces.
The older preconfigured route takes an independently provisioned wrapping key;
the first-use configuration route above generates it. Trusted account
authorization/transport and current response checkpoint acquisition remain host
inputs in both routes. Partial initial files are retained or explicitly reconciled
against their original creation intent; an error never authorizes replacement.

The native [initialization contract](../../research/continuity-identity-candidate/INSTALLATION.md)
already distinguishes Creating from Active. A foreign setup owner must expose
that same distinction and retain the original public identities before any
dependent durable creation. Generating a key, accepting enrollment material,
preparing empty children, enrolling a required witness and activating a service
are distinct steps with distinct persisted outcomes.

The C candidate now has that separate setup owner: explicit create/resume,
original status/identity, initial storage preparation and activation into the same
device-parent handle. It reuses the original device authority loader and native
installation transactions. Local and required-witness traces exercise actual C
processes, cancellation while a signed reply is held, error cleanup and original
TCP/TLS activation. Its public subject/genesis outputs authorize no witness
enrollment by themselves. This setup route takes the independently prepared
protected configuration described above; it is separate from the public enrollment
route and does not issue credentials.

Swift/Kotlin now expose the same explicit setup operations and typed original
journal/phase/genesis values. Successful activation moves the existing native
owning reference into a device wrapper; it creates no second native destructor or
Cleaner. Closing the old setup is harmless after transfer, including Kotlin `use`;
other old-setup methods refuse Closed. Reference cells refuse concurrent transfer
or close while activation runs and permit cancellation without holding a monitor
across native work. A cancellation already admitted may race completion and affect
the successor, so it must be joined. Failed activation retains only the original
setup reference for cleanup and cannot justify new provisioning.

Actual extracted Swift and Maven consumers exercise local and required-witness
setup. They release/collect the old setup, use the successor, retain original
creation identity across restart, and check held-reply cancellation and TCP/TLS
activation. The local activation/close process-cut matrix now calibrates actual
installation syncs in installed C/Swift/Kotlin consumers and interrupts before and
after every observed sync. It distinguishes complete replies already observed
from unknown results, and requires unknown results to cover both Creating and
Active. Independent native readback preserves original journal identity, the next
account position, absent account state and empty archives. Creating rejects ordinary
device access; original resume reconciles either phase and Active cannot recreate
children. The additional returned-EIO workload binds each real sync error to
opening, activation or close using consumer phase receipts. Opening failure (204)
and uncertain activation commit (207) consume operational eligibility; only original
resume resolves the persisted phase. Close-phase metadata sync errors follow a
successful activation commit and cannot be used to relabel an activation error.
The required-witness workload keeps the original authenticated witness alive
across those same process cuts and returned errors. A native controller enrolls
the original prepared genesis and observes the original anchored journal before
the call, after the fault and after reconciliation. The foreign call and recovery
explicitly select signed TCP or mutual TLS; missing witness configuration still
refuses 216. TLS phase counters must show encrypted admissions and no plaintext
fallback during foreign operations. Independent public replay binds the original
subject, genesis image, complete signed-query transcript, native observations,
phase receipts and exact client/controller exits. Native endpoints authenticate
the exchanges; replay is not a second signature implementation. Only selected
public pins, certificates and logs are exported, never TLS private keys.

Complete source-bound archives, initial intent/child preparation faults, witness
process crashes and each supported device remain separate qualifications.
Process interruption and returned EIO are not physical power loss.

An open error must never select provisioning. Existing, partial or conflicting
key/configuration/child files remain errors. Creating may resume only the original
creation intent; Active may only reopen original children. Unknown activation
results must be reconciled against the original configuration even when the call
returned no owner. Required-witness enrollment uses the original committed genesis
and independently selected witness; a timeout cannot select local-only protection.

Secret inputs must remain controlled owners or explicitly reviewed transfer APIs.
The test directory's raw TLS-key file and externally prepared signing/prekey files
are not by themselves a complete public enrollment contract. Account-root issuance,
device credential issuance and local device operation remain different authorities.
Renewal/replacement must preserve retained-session and loss-accounting contracts
before a new credential or policy can authorize operations in an Active lineage.

In particular, extending a device credential's validity changes its signed body
and credential digest even when its account, device ID, generation and public
keys are unchanged. `bootstrap::storage_owner` includes that digest. Both
`DeviceInstallation::open_bound` and the sealed journal header require the
original owner, so accepting the new credential at the installation layer alone
cannot implement renewal. The implemented
[same-key credential-renewal transaction](../../research/continuity-identity-candidate/CREDENTIAL_RENEWAL.md)
retains that binding and verifies an independent root grant for the exact original,
predecessor and successor identities. Restricted installation recovery still only
permits accounting and closure; successful cleanup is not renewed operational
authority. Installing a newer roster for unchanged credentials is a separate
operation; roster-only tests do not qualify replacement credentials.
The native witness now has an explicit
[`update_roster_authority`](../../research/continuity-identity-candidate/ANCHOR_WITNESS.md#explicit-refresh-under-a-newer-roster)
for that unchanged-credential case. It takes the retained subject and predecessor
checkpoint, validates the current successor and preserves all journal-head and
last-command state. It enables reconciliation of an original client roster write
after witness admission expiry; it neither changes an installation's credential
binding nor supplies the complete operator enrollment/renewal service.
The archive-shipped Rust consumer makes same-credential refresh and original
installation recovery a mandatory stage. Its public evidence reader checks exact
request/commit identities and original bootstrap outbox readback across separate
device processes. Signed TCP, injected protocol time and a parent-process witness
are explicit limits of that roster-only profile. Separate
[installed C/Swift/Kotlin credential-renewal evidence](../../research/sdk-alpha1/evidence/20261004-foreign-credential-renewal-4a9f8c46/)
is source-bound and does not turn roster-only recovery into credential replacement.

A renewal transaction therefore needs independently authorized old/new bindings,
the original journal/session/message identities and explicit treatment of retained
operations, archive ownership and required witnesses. Configuration and journal
updates must reconcile the same renewal after every interrupted or unknown commit;
stale or conflicting credentials must not regain send authority. Removing the
credential digest from the owner or accepting a mismatched header would change the
existing security contract. The implemented public enrollment and renewal paths
must continue to meet these requirements in current-source package and platform
qualification. Their finite failure traces do not complete deployed authority
lifecycle, root/witness-key replacement or the broader failure matrix.

## Platform and release admission

JDK 25 FFM qualification does not exercise Android ART/JNI. The Android adapter
has separate public owner APIs and actual AAR/native-library execution on the
accepted phone, as recorded above. Its reference, callback, exception,
cancellation and unloading/lifetime contracts still require their own evidence;
desktop FFM and in-memory policy tests cannot substitute for those boundaries.

The product WASM entry point includes a persistent browser device over IndexedDB,
bounded browser transport, original-session recovery and authority-maintenance
APIs. The [installed complete-account delivery qualification](../../research/sdk-alpha1/evidence/20261014-browser-account-fanout/README.md)
adds two-recipient atomic local submission and original-operation retry. The
browser recovery owner now retains original enrollment, installation, archive and
journal leases without constructing a current runtime. Local protection permits
explicit loss accounting after credential/policy expiry; required protection
retains the independent witness's authorization boundary. Fresh freezes,
acknowledgements and metadata retirement require current witness authorization.
Expiry permits historical reads and exact already-applied confirmation, not new
advances or discarded pending intents. The installed browser
[permanent retirement qualification](../../research/sdk-alpha1/evidence/20261014-browser-permanent-retirement/README.md)
now covers independent generation replacement, full two-view loss accounting,
host acknowledgement and original journal/signer retirement after actual expiry.
It also exercises cancellation, Worker termination and missing/replaced signer
refusal. This separate exit does not provide composed in-place renewal. The native
[cleanup/renewal boundary](../../research/sdk-alpha1/evidence/20261014-recovery-renewal-boundary/README.md)
confirms that an unapplied ordinary intent can block both the renewal request and
preparation of an independently approved G/T after witness expiry. An already-applied
target with a lost reply reconciles. Independent replacement and permanent retired
accounting are a separate exit path, now exposed by the browser owner; they do not
provide in-place renewal or managed account-root cutover. Atomic persistence,
revision exclusion, uncertain commits, restart, quota
failure, cancellation and original witness reconciliation must retain their
explicit contracts across the complete lifecycle. Browser capabilities must be
reported, and unavailable required capabilities must fail without changing the
signed security profile. Compilation or an in-memory replacement cannot supply
this evidence.

Before admitting the candidate into the release graph, each supported package
must exercise fresh setup from its public entry point, exact restart, at least two
peer contexts in one device service, complete-roster fanout, required-recipient
failure, roster/update races and aggregate unknown outcomes. The same packages must
exercise revoked/expired operational authority with original restricted recovery.
Current-device, cross-host and independent-endpoint evidence remain separate.

Protocol/domain and durable-format freeze, explicit candidate-state disposition,
package/version/export tables, installer failure behavior and maintenance policy
must move together. Renaming a candidate package or retaining a successful pairwise
test report cannot supply the missing product contracts above.


Native first-key publication now stages complete wrapping/signing images and uses
non-replacing rename plus file/parent sync before owner release. This closes the
newly-created partial *formal key* path; old partial files are still refused.
Enrollment signer interruptions now resume the retained original intent and reuse
any published original signer. Shared-host source changes invalidate reuse of the
older SDK archive cohort for this candidate. Atomic initial database creation,
unpublished-staging maintenance, foreign adapters and new archive/device evidence
remain required; this increment is not full lifecycle or release admission.


The next native source increment also stages initial policy, enrollment,
installation, journal, archive and witness databases. The same exclusive Database
owner survives initial commit and publication; callers borrow it during genesis
initialization. Successful old-image reopen and before-publication explicit retry
remain distinct. Formal partial files are not replaced, and no staging cleanup is
inferred from names. Post-publication live-policy closure is checked before an
anchored journal owner escapes. This does not close orphan maintenance, legacy
migration, actual archive/foreign/platform consumers, full recovery analysis or
release admission.
