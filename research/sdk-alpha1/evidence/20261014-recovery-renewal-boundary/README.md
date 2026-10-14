# Cleanup intent and renewal after witness expiry

The current coordinator has an in-place renewal availability gap when an ordinary
cleanup write was retained locally but never applied by the required witness before
its authorization expired. This checkpoint records the gap and a separate native
permanent-retirement path. It does not implement an authorization bypass or claim
that the renewal gap is fixed.

Two native regression tests execute six fresh cohorts through actual enrollment,
journal, session, archive and signed witness implementations. Protocol time is
controlled by the fixture (150 before expiry, 170 afterward); this is same-host
native evidence, not physical-device, browser or independent-implementation proof.
The terminal source is in `source-05.rs` and the current source overlay in the
capture. Earlier accepted and failed cohorts were not reopened.

| Original cleanup Advance | Original policy at 170 | Observed renewal result |
| --- | --- | --- |
| Not delivered to witness | Current | Request fails; exact image and pending bytes remain |
| Applied, reply lost | Current | Exact target reconciles; original renewal request is available |
| Not delivered to witness | Expired | Request fails; exact image and pending bytes remain |
| Applied, reply lost | Expired | Exact target reconciles; original renewal request is available |

All four original credentials expire at 160. The original pending record is an
authenticated `QPWINT01`, produced by the actual session closure operation. In
both unapplied cases, a separately issued current G/T can be staged in enrollment,
but `prepare_witnessed_policy_continuation` returns `Conflict` before dispatch and
preserves the original journal image and pending bytes. The tests retry the public
request with the same original operation identity and compare retained bytes.

The cause is the existing ordering: public renewal requests reconcile the original
installation and pending journal write first. A generic unapplied Advance needs
current witness authorization. Preparing a G/T target instead inspects the pending
slot and refuses an unrelated ordinary write. Neither path may treat transport
failure as authenticated NoCommit or overwrite that write. The old authority-only
credential transition additionally requires the same current original policy and
is barred after joint/independent authority transactions; it is not a coordinator
repair. A future in-place solution needs an explicit independently authorized
transition, exact original head/intent binding, stale/replay exclusion and unknown
commit reconciliation. Relaxing ordinary expiry or deleting pending is not that
solution.

Two further fresh cohorts use independent native control-plane approval to replace
the device generation and permanently retire its old witness subject after actual
fixture credential/policy expiry. One retained cleanup was unapplied; the other
was applied with its reply lost. Their complete retired reports retain two views:
`Authoritative + UncommittedTarget`, or `SupersededSource + Authoritative`.
Both views retain the same original session and one identical unconfirmed message;
only the sealed target contains the pending closure. Reporting and host accounting
leave the original journal image/intent unchanged. The test writes the full report,
syncs file and parent, verifies readback, records host accounting, then obtains the
independent purpose-21 acknowledgement before explicit journal and separate signer
erasure. Ordinary enrollment reopening remains refused. This is an authorized exit
through a new device, not continuation of the old one. Logical erasure and file sync
do not prove removal from backups/pages or physical power-loss durability. Browser
permanent retirement and deployed approval transport remain unqualified.

Validation records include two passing Rust tests/six cohorts, strict native
Clippy with all features/targets and warnings denied, and 60 inventory/package
controls. The new test module raises the exact Rust inventory from 658 to 659;
both presence and missing-file controls include it. Product runtime code is
unchanged. The separate module keeps this boundary out of the already large
witness coordinator test file; no product performance claim follows from line count.

Preserved unsuccessful attempts are part of the capture: the first G/T fixture did
not strictly extend the current policy interval and was correctly rejected; the
initial collector looked for `eprintln!` outcomes in stdout instead of stderr; one
test used the wrong report field name; strict Clippy rejected a newly added test
`panic!`, now expressed as an explicit failing `Result::expect` assertion. The
release-provenance control rejected the linked main worktree's `.git` file; the
same staged source overlay passed in the owned real clone without changing the
guard. These are not product fixes or red/green security-fix claims.

The independent CI observation concerns source `978e405f64b92999677e34be6ea3a36bd3471956`:
[installed Rust/C job](https://github.com/billlza/q-periapt/actions/runs/38537722025/job/115767948387)
was cancelled by its 105-minute job limit. GitHub's annotation explicitly confirms
that cause. The retained 71,770,606-byte artifact has SHA-256
`d017cfee812a5350389d4e5fb96e18e0f5780c0eddddd6ba07d64bef834cf1c7`.
The 165 inspected terminal command receipts are successful; the last completed
Release policy-continuation command precedes cancellation by 52 seconds. No final
package aggregate exists and the interrupted child has no success receipt. The
completed Debug C profile took about 48 minutes after its C build, in addition to
packaging and native Rust qualification. The workflow now allows 150 minutes for
both complete profiles and runner variance; 15-minute individual command bounds,
network deadlines and every scenario remain unchanged. The revised budget needs
a new actual CI result before being called sufficient.

Local actionlint 1.7.12 reports the same two unknown `ubuntu-26.04` labels on the
baseline and modified workflow. Exact differential diagnostics are retained; no
ignore flag/config or runner downgrade is used. Therefore full local workflow lint
is not reported as passed. GitHub ran the affected job on the existing runner.

`CHECKS.json` binds the archive and source overlay. Exact-commit source-gate evidence
is produced after committing this checkpoint. Full 0.2.0 release, lifecycle,
independent endpoints, protocol/security freeze and performance admission stay open.
