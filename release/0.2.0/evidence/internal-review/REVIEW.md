# Final 0.2.0 source reconciliation

Selected source: `af4618c8065d7133adfb86e1d116577089161ff0`, tree
`4ee8fb082744d6f0fc9297fa31200f145df477c7`. Full workflow `44036831452`
completed all 11 jobs successfully. `INVENTORY.json` pins the nine actual raw
analysis archives and all 5,012 results at this exact source. All result
(rule, primary path, partial-fingerprint) multisets match the original 8abbf8d2
review. All 526 primary/related source paths still exist; 519 have identical
bytes. `SOURCE_DELTA.json` identifies the seven changed files.

## Final source differences and reviewed boundaries

The changed analysis-bearing files retain their original input authority:

- `apple_sdk_profile.py` adds the explicit signed SDK profile. Its native ZIP,
  signed-resource inventory, complete source snapshot and installed package are
  hash-bound before and after use. The credentialed wrapper selects the signed
  mode; codesign runs on the fresh extracted package, with the independently
  pinned certificate SHA-256. The original selected compiler/input/output
  capabilities remain explicit local operator choices.
- `continuity_c_abi.py` validates a closed candidate/release selector and the
  actual corresponding freeze flag. `continuity_c_consumer.py`,
  `continuity_native_package.py`, `continuity_android_distribution.py` and
  `continuity_windows_consume.py` select release mode at their existing
  qualification calls. Headers, 158 declarations, input file readers and
  command builders retain their previous authority. No failing ABI comparison
  is replaced by a default or an alternate header.
- `test_apple_distribution.py` extends synthetic profile and signature-seal
  substitution controls. Its file-mode results remain test fixtures, and are
  separate from the actual signed-package execution/readback.

Additional release-tool changes outside the reported finding locations were
reviewed with their affected tests and retained real readbacks. The distinct
SDK GitHub plan uses the original private account lock, staged file-descriptor
transport and durable intent/outcome journal. It requires an evidence-only
child of the qualified source, exact annotated tags, both drafts before any
upload, both complete inventories before publication, and Apple-then-platform
publication. Unknown effects remain unresolved until exact reconciliation.
Final verification checks immutable release signatures and every freshly
downloaded asset. The explicit CLI profile pins the actual installed 2.103.3
binary to its official release bytes; historical profile identities are intact.

The private reference Cargo source version correction is constrained to the
existing exact name, `0.0.0`, canonical Cargo path, no ABI-interface claim, and
an actual `publish = false` definition. The service distribution remains
`0.2.0`. The real frozen 21-row graph has a retained red/green test, and altered
publication settings, names, versions, paths and distribution versions are
rejected. Normative graph/lock bytes were not changed by this repair.

Current-source hosted artifact tooling executed 4,015 tests with no failures
or errors and the three pre-existing platform-conditional skips. The retained
70-control manifest/service/publication pass and earlier source-pinned signing,
transaction and failure-recovery controls provide their stated scopes. These
checks do not replace full installed-platform qualification or publication.

## Runtime observation retained separately

The preceding 723c1fe5 Windows 2025 Release first-registration execution
returned OS error 997 and failed; its missing completion record also caused
the expected downstream refusal. This is retained, not labeled as fixed or
proved external. The transport source did not change in the manifest repair.
Two isolated Windows experiments completed 24,000 actual Mio connections and
bidirectional transfers and 8,000 bounded idle-read comparisons without
reproducing it. The selected af4618c8 Windows workflow `44036376236` subsequently
passed all four native OS/build profiles and both original public readbacks
(eight jobs including the two producers). An additional instrumented original
workflow retains the same failure outcomes and is diagnostic evidence only.
No new retry, swallowed error, deadline relaxation or network-security change
was introduced. These finite observations make no universal reliability claim.

## Retained baseline reasoning

The narrative below is retained with its original source and execution wording.
It supplies the unchanged trust-boundary, cryptographic-use and proof-scope
reasoning. The current inventory, source delta and disposition index above bind
its application to the final source; its historical pending sentence does not
replace this final reconciliation. Independent external review remains the
user's separate track. No alert is automatically dismissed, no query is disabled,
and this internal source review does not itself authorize or claim publication.

---

# Source-bound current analysis review

Reviewed source: `8abbf8d2e73a27af7794528fd92d13fe3be2942d`, tree
`733e2e6e17be2241d85264ea5e15e07a35f04527`. The nine actual archives are
identified in `INVENTORY.json`. Its 5,012 records include repeated target
observations; they are not 5,012 established vulnerabilities. Java/Kotlin,
Swift and Actions have no reported results in these archives. That absence is
an observation about these analyses, not proof of absence of defects.

This review records the reported input boundaries and the critical operations
below. It does not dismiss alerts, change query suites or relax a check. The
selected final release's source deltas and final analysis still need their own
reconciliation. A review of this source is not a publication receipt.

## Python execution records

The earlier [52-record review](../20261109-codeql-input-boundary-review/README.md)
and [additional matched-runner record](../20261109-codeql-critical-delta/README.md)
cover the same execution interfaces. Of the earlier review's 70 Python source
pins, 64 still match exactly. The six deltas were inspected:

| Source | Relevant change and disposition |
| --- | --- |
| `android_runtime_control.py` | Command text now comes from a bounded regular-file snapshot and must match the captured size and digest. It does not change the explicit SDK/tool selection or the command verbs. |
| `continuity_package.py` | Formal companion name/version/channel validation, selected native-package production and source inventory additions. The native path requires full installed C qualification on supported Linux. Existing explicit tool inputs and fixed argument builders retain their meaning. |
| `continuity_kotlin_consumer.py` | Formal Maven/package identity and a local Kotlin version constant used consistently for the runtime closure. No newly selected command program. |
| `continuity_swift_consumer.py` | Archive filename uses the selected companion version. No command-construction change. |
| `continuity_windows_consume.py` | Metadata lookup uses the formal companion name. No command-construction change. |
| `third_party_licenses.py` | Explicit supplemental license inputs and target-union collection. The target set is bounded, plain triple syntax is checked, source and package output roots are explicit, and selected license paths/bytes are compared. Cargo remains an explicitly selected, absolute tool with fixed metadata arguments. |

The [current shared-sink review](../20261116-release020-admission/CODEQL_SINK_REVIEW.md)
traces all 24 named origins at `bounded_process.py`, including the origins not
covered by the older representative code flows. Those are deliberate compiler,
interpreter, provider and test-binary execution capabilities. Neither separate
argv nor version checking authenticates a malicious tool selected by the local
operator. `python_bootstrap.py:44` similarly implements the explicit `-c`
interface; it is not a business-input evaluator.

The matched-runner cleanup defect remains fixed: cleanup begins only after this
invocation successfully owns its preparation. The execution target is derived
from the new output's explicitly overwritten `CARGO_TARGET_DIR` and fixed
binary names. Historical experiment selectors retain their documented trusted
local CLI boundary, including the earlier review's unsanitized selector caveat.

## Python file paths and permissions

All 184 distinct named origins of the 1,307 path records are explicit CLI
arguments or process-environment selections. This was checked against the
analyzed Git source, including each historical driver, rather than inferred
from its filename. There are 78 active/nonhistorical origin locations and 106
historical locations. An operator-selected file capability is the relevant
authority; these interfaces do not claim to sandbox a hostile invoker.

The origin families have different contracts:

| Family | Actual authority and limits |
| --- | --- |
| Package producers/readers and ABI/license inspectors | The caller selects input archives, source roots, tools and output destinations. Archive/member names retain their separate closed-inventory, regular-file, digest and extraction checks. Permission to read an input path does not authenticate its bytes. |
| Android tools and runtime controllers | SDK/NDK/JDK installations and the intended emulator/device are explicit inputs. The existing registered-root, runtime-profile, package/serial and owned-output checks remain required. A process environment is not a device response. |
| CodeQL/proof/performance qualification | The invoker selects tools, retained databases/results and evidence destinations. Fresh-output and source/query/model identities remain separate admission checks. Trusted tool selection is not arbitrary-code isolation. |
| Publication and source-results assemblers | Caller-selected source/evidence paths enter existing fixed private-root, source/head, receipt and archive admission. Public package assets and private transaction state retain distinct permissions. No remote artifact supplies permission to replace a ledger or select a publication command. |
| Independent-peer workers and host tests | CLI parameters deliberately select implementation/provider code and private fixture/configuration paths. The harness owns child markers, interruptions and local peers. These are not remotely exposed path-selection APIs. |
| Matched-trace auditor | The documented `compact_results` path is selected by its operator. Its four findings retain the separately executed traversal, symlink, inventory, replacement and parsed-byte/hash controls in the [auditor revalidation](../20261111-matched-auditor-findings/README.md). |
| Retained experiment drivers | Each reported source statement selects a local label, mode, checkout, binary or prior receipt. Several labels can select paths outside a nominal evidence subdirectory; no confinement claim is made for those trusted historical CLIs. They are not installed product endpoints or a service accepting untrusted job requests. |

These dispositions address the reported source-to-file capability. They do not
transfer trust to network content, manifest members or an arbitrary selected
compiler, and do not assert that every unrelated I/O operation is correct.

Of the 53 permission records, six are intentional public distribution output:
`platform_distribution.py:773/779/790/799` creates a fresh public directory,
copies the closed asset set and writes the public manifest/checksums with
0755/0644 modes; `third_party_licenses.py:460/463` writes public license text
and its inventory with 0644. These paths do not contain the private publication
journal or a registry credential. The other 47 are temporary test fixtures:
unsafe-mode/hardlink/identity mutation controls, mock public package trees,
executable fixtures, or wrappers preserving the actual tested `os.open` mode.
Their enclosing test/function names and exact locations are retained in the
disposition index. They do not modify production private-file defaults.

The synthetic credential and synthetic-certificate SHA-1 records retain the
[two explicit fixture dispositions](../20261109-codeql-singleton-followup/README.md).
The current Apple signing path also requires its independent SHA-256 certificate
pin; SHA-1 is the compatibility identity, not the sole certificate authenticator.

## Rust file, command and diagnostic records

The four target archives name 383 distinct origins for path/command records.
364 are process environment, CLI, current-executable or temporary-directory
selections. The remaining 19 are fixture directory entries, private fixture
files or the captured output of a selected test peer. The latter were inspected
at their actual use: single-component directory entries are copied into an
owned fixture, witness addresses remain separate command arguments, and child
state/enrollment paths are checked against the fixture root before reopening.
The installed Rust consumer additionally checks directory/file type, private
modes, link count and bounded control-record lengths.

Most origins belong to integration tests, examples or test modules. The
non-obvious production-file locations have explicit test boundaries:

| Source | Actual inclusion boundary |
| --- | --- |
| `bindings/rust/SDKPackageConsumer/src/lib.rs` | `#[cfg(test)] mod tests` at lines 4–5. |
| FFI `src/lib.rs:1565` | The test module starts at 1549–1550. |
| Host-store `filesystem.rs:585/610` | `redb_header_tests`, `cfg(all(test, any(unix, windows)))`. |
| Handoff import `testing.rs` | `import.rs:15` selects the Unix test module. |
| `connection_transport.rs:178/199/229` and `control_transport.rs:361/392` | Explicit Unix-only `test_support` modules. |
| Signer retirement `faults.rs` | Parent `retirement.rs:24` selects the test-only fault module. |
| `messages/rekey.rs:305`, retired cleanup `erasure.rs:237` | The injection functions themselves are `cfg(all(test, unix))`. |
| Enrollment `account_root/process.rs` | `account_root.rs:428` selects tests; `tests.rs:18` includes this process module. |
| `windows_key_reopen.rs` | `lib.rs:125` selects `cfg(all(test, windows))`. SystemRoot selects the fixed PowerShell executable; fixture paths are environment values, not script interpolation. |
| Reference-app `enrollment.rs:187` | The marker function is explicitly `cfg(test)`. |
| Whole-KEM reference `main.rs:1199` | The optional local diagnostic report is inside the test module beginning at 1062. |

The actual non-test command sources are the native build script: Cargo's
`RUSTC`, explicit absolute `CC_wasm32_unknown_unknown`, and validated Cargo
target metadata. It invokes selected compiler programs with fixed argument
arrays. Building with an adversarial compiler is outside this trust boundary.

Four reference-service CLIs select operator files: native device, Witness,
policy publisher and SDK policy authority. Their argument dispatch, absolute
database selection, `operator_io` bounded private reads, independent trust
inputs and exclusive private exports were inspected. In particular, the
Witness server closes over its already selected path and identity; network
frames do not replace them. Its local enrollment operation is separate from
network serving. No claim that an arbitrary local operator is untrusted is
introduced into these command interfaces.

The log-injection records are test failure diagnostics, predominantly captured
child logs. They intentionally retain text from the selected child when a test
fails; they are not sanitized production audit records. The five native
cleartext-logging records are likewise scoped: fanout output reports counts,
lengths and timings; the Witness assertion formats a unit/error result; the
expired-renewal assertion formats a public checkpoint/error result; and the C
receiver failure reports the selected fixture peer's stdout/stderr. This does
not promise that arbitrary replacement child programs can never emit secrets.

## Rust cryptographic values, allocations and pointers

The `ZeroizingBytes::zeroed` record names 28 distinct cryptographic sinks in the
native archive. Other target sink sets are subsets. All 28 were traced beyond
the initializer. The production groups are:

- Journal encryption and signer persistence: complete 32-byte entropy fill
  with propagated failure, or exact 40-byte `QPVKEY01` decoding before use;
  domain-separated derived keys fill the complete output before returning.
- Traffic keys: `step` expands 64 bytes and splits exact 32-byte next/message
  keys before the AEAD call; receiver retention and index checks remain in force.
- Bootstrap confirmation: the SDK export/direct HKDF producer fills the whole
  key; confirmation does not use the allocation's initial zeros.
- Durable cancellation, rekey completion/response, closure archive, retired-report and
  transferred-control keys: complete HKDF expansion precedes HMAC construction,
  with failure propagated.
- Closure, fanout-abandonment and resolution report keys: fresh entropy is
  filled before storage/use; decoding copies the complete retained key. Absent
  resolution keys return a state error, and the absent closure-key sentinel
  stays `None` rather than becoming a zero authentication key.
- Account-root fences, witness handoff and write-intent authentication: the
  original journal key's separate derivation methods expand all 32 bytes before
  returning. This includes the five sink additions relative to the older
  23-sink review.

The remaining named sinks in that record are explicit adversarial/positive
tests using the same completed derivations, including disclosed-chain packet
forgery, key-only replacement, authenticated marker tampering, rekey
confirmation and the witness/account-root witness controls. Their current
regions were checked; the old 23-sink receipt was not treated as coverage of
all 28 current sinks. This is a use-before-fill review, not a new proof of the
KDF, RNG, physical erasure or compromise theorem.

Other hard-coded-value records are distinguished explicitly:

- SDK `purpose.rs:14` and its retained paper copy are public HKDF salt/domain
  constants, applied to secret input material; they are not claimed secret keys.
- The four retained bootstrap `nonce` functions fill all bytes with
  `getrandom` and return only after success. Their known-answer derivation
  vectors and the current bootstrap vectors are in test modules.
- Policy-agent authority/IPC constants are request/replay/adversarial test
  vectors under the actual test modules, including the separately included
  Unix IPC tests.
- SPQR and whole-KEM comparison programs use their declared public salt and
  deterministic comparison initialization. These are experimental reference
  constructions; their fixture seed is not a product key-generation path.

Both allocation reports are the two vectors in `sdk_path_perf::paired`.
`main` rejects sample counts outside 100–5000 before calling it. This bounds
the selected capacities; the benchmark does not allocate from network length.

The two Windows ACL pointer records retain one owned OS security-descriptor
allocation throughout validation. Successful `GetSecurityInfo`, non-null
descriptor/owner/DACL, descriptor validity/control/revision, owner SID and
`IsValidAcl` precede the ACL header read. Each `GetAce` result is checked, its
header must fit within the ACL, the header is read unaligned, and the complete
ACE/SID bounds are checked before use. The allocation is released by `LocalFree`
afterwards. The OS contracts are the [descriptor allocation contract](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo),
[ACL validation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-isvalidacl)
and [ACE accessor](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getace).

The launchd pointer record follows a successful `launch_activate_socket`,
non-null array and count exactly one. The descriptor value is copied before
freeing the array and validated before constructing `OwnedFd`. The mismatch
path closes each returned descriptor and frees the array. The installed Xcode
27.2 SDK's `launch.h:164–198` explicitly specifies the returned array/count and
the caller's `free` duty. This source review does not claim a new Windows or
launchd execution.

## C qualification paths and overall boundary

All three C path records retain the separately hashed qualification probe and
setup-client scope. The harness removes inherited loader and `QPC_TEST_`
variables, then supplies its exact target and receipt. The target is opened
read-only with leaf `O_NOFOLLOW`, regular/euid/0600/single-link checks and exact
device/inode selection. The receipt is fresh `O_EXCL`; setup appends fixed phase
records to the harness-selected private receipt. The direct local invoker can
select another same-user qualifying file: neither leaf `O_NOFOLLOW` nor this
probe claims hostile-host or ancestor-directory authentication. The probe is
not linked into the product library.

No new source fix is required by the reported operations reviewed above. The
prior C overwrite and matched-runner cleanup fixes remain actual fixes, not
reclassified successes. This conclusion does not establish final CI, a frozen
contract, a final artifact cohort or publication. Those remain independent
release requirements with their own execution and provenance.
