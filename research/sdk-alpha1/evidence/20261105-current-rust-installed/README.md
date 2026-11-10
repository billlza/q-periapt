# Current candidate: installed Rust Debug and Release

The original installed-candidate gate passes both Debug and Release on macOS
arm64 at source `5678d1019861fa1b04f3a219ba3fde7e0ddaaba8`. Each profile runs all
three public consumer tests, with zero failed, ignored or filtered tests. This
qualifies the current unpublished Rust archive and its nine installed SDK
dependencies on this host. It does not close foreign bindings, physical-device,
independent-engine, product-ABI, proof, external-review or release acceptance.

The command was:

```sh
sh artifact/python-run.sh artifact/continuity_package.py \
  --report target/sdk-020/RUST_SDK_PACKAGE.json \
  --report-sha256 1e40fc2ae0c7c113509ae2a5c5a858cbd73a8a6fd7f63e66203316c4c61e228d \
  --toolchain-root /Users/bhmq03@durham.ac.uk/.rustup/toolchains/1.98.1-aarch64-apple-darwin \
  --output target/continuity-installed-rust-current
```

It ran from the clean full clone, through that clone's isolated Python
dispatcher, with Rust/Cargo 1.98.1. The original 900-second component limits
were unchanged; no shorter outer deadline was added. The command returned zero
and its outer stderr was empty. Strict all-target consumer Clippy also passed.

## Actual installed execution

Both profiles execute the complete owned-service connection test and the
original-session reopen test, including their child service process. Cargo's
test summaries report 29.87 seconds for Debug and 27.60 seconds for Release.
These observations are not a benchmark or product resource budget.

The original readers check unknown-delivery reconciliation, exact retained
outbox bytes, fresh-bootstrap refusal during restoration, forward and reverse
application readbacks, one network rekey, durable SDK revocation and retained
cleanup identity. They also check enrollment, roster renewal, generation
replacement and retirement exports against the same original executions.

Each roster-renewal trace has 19 records, one logical advance and two rejected
attempts. Its required signed-TCP witness runs in the parent process, and its
protocol clock is injected. The retirement scenario includes eight recovery
processes, original-owner publication and fresh-generation TLS traffic. These
are same-host, shared-implementation observations. They do not establish an
independent Witness implementation, cross-host recovery, physical erasure or
power-loss behavior.

## Source and archive readback

The [final package report](CONTINUITY_PACKAGE.json) has SHA-256
`8698d7fbd298343693aab1618126128132d8a8bc48c205f910170db0e1250bd1`.
It records both profiles, `completed=true`, `partition_completed=true`,
`sources_unchanged=true`, `publication_performed=false` and
`release_claim_eligible=false`.

The actual candidate archive is 1,962,485 bytes with 769 members and SHA-256
`0730aa20794527b3947dc4734bf82d48516294c42018dc8dfd23ebc5f42fc2a6`.
The SDK input root is
`c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d`.
The [matching SDK producer](../20261105-current-sdk-producer/README.md) retains
the actual SDK archives; this capsule records that producer's exact report and
capture digest rather than duplicating its archive cohort.

An independent reread through the same isolated dispatcher verifies all 1,401
source inputs, the candidate archive, the actual extracted candidate tree and
all nine SDK package trees outside the checkout. It reruns the original public
readers against both retained runtime traces and obtains exactly the report's
results, without rerunning native workloads. See [READBACK.json](READBACK.json).
The initial driver invocation was refused because its file was outside the
clone. That refusal is retained; the successful driver is inside the clone's
`target` directory and uses the unchanged dispatcher.

The gate intentionally retires completed package and Rust build directories.
Their retirement receipts are retained. Native executable hashes are original
execution receipts; their retired bytes were not available for the later
reread and are not claimed to be exported.

## Retained evidence

`CAPTURE.zip` contains 1,991 individually verified members: the actual candidate
archive, original command receipts and streams, public lifecycle exports,
source inputs, readback drivers and results. Its 7,822,827 bytes have SHA-256
`bd0b031a28f8e1e6da0bd943574217e0316113ea30a7cb81e1ebf9d755a41d42`.
Every member was reread against `FILES.json`, and all captured source inputs
were also compared with their exact Git commit. Caller-owned private runtime
trees remain local and are not exported.
