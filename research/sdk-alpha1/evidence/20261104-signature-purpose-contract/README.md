# Complete signature-purpose contract readback

Commit `21e00e9c3cfd193b9f51491888347f583620dfe0` closes a concrete specification
and acceptance-coverage gap. The signer already used purposes 1–39, while the
wire document's summary ended at 22 and the compiled descriptor did not expose
the purpose inventory. This was missing contract coverage, not an observed
signature forgery or a change to the protocol's existing purpose numbers.

One declaration now generates the internal byte-valued enum and its read-only
name/byte inventory. `contract::SIGNATURE_PURPOSES` exposes that metadata to the
existing example. The descriptor and its strict reader move explicitly to schema
2; all prior names, numbers, domains, profile commitments and numeric limits are
unchanged. Signing/verification code after the enum is byte-identical. The wire
document lists all purposes and links their distinct transaction contracts.
The descriptor continues to state `frozen_product_contract: false`.

## Actual old and new observations

The old `contract_report` executable was built from the previously qualified
installed candidate at `6ce866b3`, with its original SDK archives. Its real schema
1 output contains no purposes. The old reader at `fccc3d2f` accepts that output
against its old document. The expanded reader rejects the **same executable's
output** with `contract fields differ`; the failed report and streams are retained.

The new candidate is independently packaged from clean `21e00e9c` source and
consumed outside the checkout using the original exact SDK archives. The SDK
producer remains `6084f3bf`, with report SHA-256
`d9cd990bf3dc6a731ec09b659fdc38f3f3cbc17b2f035b09e5e61094cbc11885`.
The installed builder completes its original graph, source, build and strict
Clippy checks. The new `contract_report` is separately built and linted from that
installed dependency graph. Its SHA-256 is
`cf4bdccd3372bbabffc0d219c0d3db64b4e84baff71f1bec1d98bbbbc9ec4490`.
The actual compiled descriptor exactly matches the reviewed schema 2 document,
including all 39 purposes.

Seven Python contract tests pass. They reject every purpose's changed number,
omission or rename, an extra purpose, invalid/duplicate byte values and old
descriptors, while retaining the existing domain, limit and unfrozen-state
controls. Formatting and strict example Clippy pass. Seventeen source-workspace
crypto/signing-persistence tests pass, with zero failed or ignored tests;
1,383 other library tests are outside that selected run.

The new installed native counterpart has SHA-256
`c6af99c69f87f15f7c741ed97161b41c6b1673bae6ecc12f4ef4ea5a51e12b22`.
The previously installed Python wheel is reused only after all 105 module hashes
match its installation receipt, and they remain unchanged afterward. Its wheel
SHA-256 is `596bba62781296558a64d768a12ed618043b8cf3e14070cdf81c2ed423d3a094`.
The actual independent runs pass 35 publication checks and 44 historical-directory
checks, including three Rust-signed receipts, canonical conflict equality and
wrong-purpose/signature refusal controls. These are focused installed
interoperability checks, not a repeat of the full
[25-command lifecycle cohort](../20261104-installed-independent-lifecycle/README.md).

## Preserved failed attempts and scope

The combined diagnostic driver passed build, Clippy and contract readback, then
its private unit-test command failed because the candidate is an excluded
dependency, not a workspace test member with admitted dev-dependencies. That
driver remains failed. The original source-workspace crypto suite was executed
separately; the installed dependency exclusions and resolver contract were not
changed to make it a test member. Its separate pass does not rewrite the failed
driver as an aggregate success.

Updating the earlier local clone also failed on a historical promisor object
that the local Git upload process could not fetch. Direct source admission then
refused bytecode caches and untracked source inputs in the primary checkout.
Those observations are retained. A fresh depth-one independent clone of the exact
commit passed the existing provenance checks, preserving the user's untracked
work. An initial shell redirection before creation of its fresh `target` directory
did not start the builder; that launcher error is separately recorded.

`CAPTURE.zip` retains 132 files: exact command receipts/streams, old/new descriptors,
the old reader/document, fresh installed-build report, focused source and independent
results, public receipt/vector bytes and bounded diagnostic drivers. Private
signer files and stores are excluded. Every member is re-read and pinned by
`SHA256.json`; `CHECKS.json` records each successful and failed scope separately.

At 11:16:55–11:17:01 UTC the GitHub connector returned inventories identical to
all thirteen retained 10:37 inventories. The twelve current-head runs remain at
260 successes, 63 queued, seven failed and two skipped jobs; the separate older
independent run has two successes and two queued jobs. `driver/CI_RECHECK.json`
references the unchanged [CI capture](../20261104-ci-runtime-failures/README.md).
No upload or rerun was requested while that wave remains open.

This qualifies the complete purpose-table comparison and its selected regressions.
It does not freeze the product protocol, admit Continuity into product ABI 2,
qualify the full current platform/lifecycle matrix or close the computational
recovery and external-review obligations.
