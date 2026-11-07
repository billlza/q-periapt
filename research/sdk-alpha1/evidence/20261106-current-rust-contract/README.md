# Installed Rust candidate with the retained-fanout contract

Source `4c595a2a382a052979f6ea7c174a19c5e7935315` passes the original installed
Rust qualifier in both Debug and Release on macOS arm64. A newly produced
Continuity crate is consumed outside its checkout with the nine exact SDK
archives. The archive-shipped contract example also compiles and executes there,
matching descriptor schema 3 and its 16 retained-fanout-record limit.

This closes the local installed Rust and descriptor check for these inputs.
It does not qualify other languages/platforms, freeze the Continuity product
ABI or security contract, accept resource budgets, or complete the release.

## Source identity and justified reuse

The existing SDK producer remains at
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. Its workspace-input digest is still
exactly `c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d`.
The unchanged producer validator accepts that report against the new source's
same digest. All twelve producer archive hashes are checked; the candidate
consumer uses nine of them. The [original SDK producer capsule](../20261105-current-sdk-producer/README.md)
retains their actual bytes and original build/audit evidence. No new SDK audit
or new build of those unchanged SDK archives is claimed here.

The candidate's 1,401 qualification inputs differ in six files: the Kotlin
refusal-report inventory, compiled contract example, shared contract constant,
fanout constant reference, and two native test files. Its new 769-member crate
differs from the prior installed crate in only the latter five files. The
fanout runtime source is byte-identical after removing exactly the original
16-valued constant line and its new shared-constant import line. The constant's
value, admission logic and decoder logic remain unchanged. The descriptor now
exposes a quota that was previously omitted; the separate source regression
and old/new descriptor evidence are in the
[capacity-contract checkpoint](../20261106-fanout-capacity-contract/README.md).

This source is a clean detached local clone with a real `.git` directory, as
required by the existing package provenance gate. The main checkout's untracked
witness census and the ongoing `5678d101` Kotlin/Swift qualifications remain
untouched. Their future results retain their own source identity.

## Executed validation

The unmodified `artifact/continuity_package.py` runs from 07:27:56 through
07:36:19 UTC on 2026-11-06. It packages the candidate against the recorded SDK
archives, reconstructs actual installed package trees outside the checkout,
and executes all three complete consumer tests in each profile:

- `service_peer_process`;
- `owned_services_connect_restart_rekey_and_reconcile_unknown_delivery`;
- `reopen::public_session_reopen_after_expiry_reconciles_unknown_commit_over_real_tls`.

Both profile reports state three passed, zero failed, zero ignored and zero
filtered tests. These are six executions of three named tests, not six distinct
test definitions. They cover the original owned connection, exact unknown-result
recovery, enrollment and roster renewal, revocation/cleanup, device replacement
and retirement paths. Native signature verification and the existing public
readers retain their separate roles. Strict all-target consumer Clippy passes;
original 900-second component limits and assertions are unchanged.

A subsequent readback checks all nine actual SDK trees, the entire candidate
tree, archive bytes, command receipts, both source inventories and both full
public outcome groups. The original qualifier retires completed build
directories after verifying them: the two test-binary hashes remain receipts,
and those binary bytes are not claimed to be available or replayed later.

The installed candidate's own `examples/contract_report.rs` then builds in a
separate Release target directory using the same installed consumer graph and
unchanged lock. The strict contract gate executes that binary, compares every
field with the reviewed schema-3 budget file and observes 16 retained fanout
records. The example's actual archive-derived source path is checked. Its
449,376-byte executable is retained, SHA-256
`1ece058fd255612e733a20ba6a805653423ab3b23737308dd326ab30c12e8fd5`.

The first auxiliary readback failed because its line normalizer left removed
statements' newlines at different positions. The corrected normalizer removes
each exact complete line once and compares every other byte. That original
failure, the premature dependent descriptor invocation's missing-prerequisite
refusal, and the successful corrected executions are all retained. Neither
failure was in the native qualifier; no product check was weakened or rerun to
hide a failed native test.

## Public reproduction and retained artifacts

The readback copies only 558 explicit public files: application effects, original
ciphertexts, report IDs, enrollment/authorization objects and the public
lifecycle traces. Re-running the original readers on those copies reproduces
both full outcome groups. A fresh extraction subsequently runs only captured
reader sources and those public bytes, again reproducing both groups. It does
not access live private journals, invoke a native workload, or implement another
signature verifier. [PUBLIC_REPLAY.json](PUBLIC_REPLAY.json) and its command/
stream receipts record this execution; no new negative-control suite is claimed.

The new candidate crate is 1,963,238 bytes, SHA-256
`98ee41cb4047e69db79e9f235695bfef2508fbe42fa423fee96851bf7c2bf8cc`.
[CONTINUITY_PACKAGE.json](CONTINUITY_PACKAGE.json), [READBACK.json](READBACK.json)
and [DESCRIPTOR.json](DESCRIPTOR.json) bind the actual commands, input identities,
installed source trees, results and remaining scope.

[CAPTURE.zip](CAPTURE.zip) has 2,592 members, 9,224,166 bytes, SHA-256
`a2ee3911dee6e5c128d1217f03c6789f89611e70a7a32e96c0940a04449ef6cc`.
Every member was reread against [FILES.json](FILES.json), including during the
standalone extraction. It retains the new crate, public traces, source readers,
drivers and failed diagnostic records, original command outputs and the compiled
descriptor. SDK archives remain in the separately linked exact producer capsule;
private runtime stores are not exported.

These are same-host, shared-engine observations with the existing clock/Witness
fixture boundaries. Physical devices, foreign bindings, cross-host deployment,
the computational proof, final CI, external review and release authorization
remain separate obligations. Timing during concurrent qualifications is not a
performance or energy result.
