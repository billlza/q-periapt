# Installed program replacement over the original Continuity state

This checkpoint qualifies one finite **same-format program replacement edge** on
Apple Silicon. It does not establish a general schema migration, a published
product-version upgrade, arbitrary downgrade support or release admission. Product
code, format tags, limits, cryptographic checks and existing recovery assertions
are unchanged. The new source changes select an explicitly bound executable at
existing test-process cuts and record the program identity used for each restart.

## Installed inputs and observed scope

Both native executables are existing genuinely installed crate/SDK consumers,
compiled outside their independent source checkouts. Their complete build reports,
candidate archives, binary bytes, hashes and relocation receipts are retained.
They share the SDK producer at `6084f3bf`, report SHA-256
`d9cd990bf3dc6a731ec09b659fdc38f3f3cbc17b2f035b09e5e61094cbc11885`.

| Input | Source commit | Executable SHA-256 |
| --- | --- | --- |
| Before | `6ce866b31088b3215bcc24bcfef84b4075ff5907` | `f7fe7507bdd539b4404709b45df207869b5d06ecfc1f62f979c866e01f8437a8` |
| After | `21e00e9c3cfd193b9f51491888347f583620dfe0` | `c6af99c69f87f15f7c741ed97161b41c6b1673bae6ecc12f4ef4ea5a51e12b22` |

Each candidate archive has 767 files. Their only changed members are
`examples/contract_report.rs`, `src/contract.rs` and `src/crypto.rs`, from the
[signature-purpose contract correction](../20261104-signature-purpose-contract/README.md).
All storage encoders/decoders are byte-identical. The original build reports remain
build-only reports; their `runtime_qualified: false` fields are not rewritten to
claim this later execution or a full release qualification.

Each successful attempt installs wheel SHA-256
`596bba62781296558a64d768a12ed618043b8cf3e14070cdf81c2ed423d3a094`
into a fresh outside-checkout directory using offline, hash-required, no-dependency,
no-bytecode installation. The existing isolated probe imports and hashes all
**105** product modules before and after the experiment, with `-I -S -B` and an
explicit private empty cache. Source test controllers are copied separately;
there is no source-tree protocol import. CPython 3.14.10, cryptography 48.0.1 and
OpenSSL 4.0.1 run on Apple M4 Max, macOS 26.7.2 / Darwin 25.6.0.

The native fixture combines the actual persistent peer and test Witness in one
process, reached through a loopback byte bridge and test-control pipe. Original
account-root replacement, enrollment, predecessor retirement and successor
selection run before the measured cuts. Existing synthetic fixture clocks and
trusted test authorization remain explicit. This is neither an independently
operated remote Witness nor physical power-loss evidence.

## Executed scenarios

| Scenario | Controller source | Real SIGKILL/re-exec cuts | Program switches | Native commands | Witness attempts |
| --- | --- | ---: | ---: | ---: | ---: |
| One-program baseline | `b22f627a` | 10 | 0 | 328 | 219 |
| Two-program ordinary lifecycle | `b22f627a` | 10 | 9 | 328 | 219 |
| Witness mutation interrupted before dispatch | `f1740265` | 11 | 10 | 345 | 230 |
| Witness mutation committed, signed reply withheld | `f1740265` | 11 | 10 | 346 | 230 |

The replacement scenarios perform **32 process cuts and 29 actual version
switches**, including 15 forward and 14 backward selections over the same current
state. The baseline adds 10 cuts. No backup is restored. Every cut reaps the old
PID with return code `-9`, starts a distinct PID, retains the same original journal
path and hashes the same **58** original key/identity/public-input files. The
selected process must refuse the retired, unselected and wrong-target controls
before explicitly reopening the original approved successor.

Cuts cover approval, original bootstrap reply, final/session, activation,
received message, committed outbox, acknowledgement, rekey response, rekey receipt
and new-epoch traffic. The two unknown-outcome cases add a cut while the original
send reservation is unresolved. Exact original bootstrap responses, session
identity, outbox ciphertext, plaintext, acknowledgement state and rekey responses/
receipts survive. Both directions communicate and reach epoch one.

The unknown-outcome transcripts distinguish `not_dispatched_by_fixture` from
`signed_reply_withheld_by_fixture`, then show the same mutation command reaching
the replacement process. The pending target digest is the exact retained digest.
Witness retries preserve the command ID, subject, operation and target; the
protocol deliberately generates a fresh challenge and signature for the new
attempt. Thus its complete transport frame is **not** byte-identical. That is
separate from the byte-identical original business/bootstrap/rekey results.

`review.py` independently rereads all 1,347 native command inputs/outputs and 898
Witness attempts, the actual PID chain, program identities and exact replay
pairs. All four results pass; **24** modifications of the captured reports or raw
transcripts are rejected. The related independent-tooling suite passes **67 tests**,
including nine plan-admission tests. These counts do not substitute for the real
installed executions above.

## Failure retained and reproducibility

The first preparation attempt installed the wheel but failed the existing probe:
the observation driver omitted its required explicit private cache directory.
`ATTEMPT_01_FAILURE.json`, the unchanged strict probe, its original stderr, command
and driver remain. No lifecycle scenario ran in that attempt. Fresh attempts
`run-02` and `run-03` include the required cache and complete; the probe is neither
weakened nor skipped. Duplicate immutable inputs omitted from the archive are
listed with identical retained copies in `CAPTURE_INPUTS.json`.

The public controller accepts `--native-restart-program-plan /absolute/PLAN.json`
only with `--root-successor-process-restart peer`, `peer-before` or `peer-after`.
The plan has schema version 1, exactly two `programs` named `before` and `after`,
and an ordered `restarts` list of `{ "case": "...", "program": "before|after" }`.
Each program specifies canonical `executable`, `installation_report` and
`installation_report_sha256`. The report binds the executable to its actual
installed build. An exact cut census and both switch directions are required.
A changed/partial input, unsupported scenario or failed reopen aborts; there is
no fallback executable. Archived command records contain every actual argument,
working directory and exit status. The source-bound controller copies and the
original drivers are included for replay against retained input artifacts.

`CAPTURE.zip`, `SHA256.json`, `SUMMARY.json` and `CHECKS.json` preserve and verify
the public evidence. No external private fixture directory, signing key, wrapping
key or private database is copied into this checkpoint. Public path and digest
receipts remain. Archive members are reread and the four scenario readers rerun
directly over the archive before completion is recorded.

The [upgrade/maintenance contract](../../../../docs/continuity/UPGRADE_MAINTENANCE_V1.md)
now separates existing Witness compatibility, same-format program replacement and
physical database migration. Final format/package/ABI admission, explicit preview
state disposition, promised legacy writer/reader edges and staging-orphan
maintenance remain open, alongside the existing proof/platform/resource/external
review/release gates. Nothing here removes a recognized old Witness format or
weakens an original-operation recovery obligation.

At **2026-11-04 14:24:09 UTC**, the twelve current-head CI runs contain 266 successful,
53 queued, four running, seven failed and two skipped jobs. The older independent
run `41791763191` at `adaaeb49` is now 4/4 successful: Python source and installed
wheel on Linux x86_64 and Apple Silicon, with source-built Rust counterparts.
That older run is not genuinely installed-Rust evidence. PR #117/#118 heads remain
`475cd239`/`6084f3bf`. No push, rerun or new CI wave was initiated.
