# Browser policy persistence checkpoint

The installed `q-periapt-sdk-wasm/web/storage` candidate provides an exclusive
policy owner backed by IndexedDB and Web Locks. Create and open are distinct;
neither missing nor malformed storage is silently replaced. The private runtime
is exposed only through controlled operations. A complete signed policy image
and its exact trusted state commit before activation, and close revokes retained
key/secret owners before releasing the cross-realm lease.

The actual npm archive is
`d7472fff22e0d8cdf0028c7b04e6c38045027692e458e126ddf4d826f861f4c8`, with manifest
`d7fcc389423d060863852128a90de8de16d4cdb3287c958606b64bf4122fd928`.
It was built with Rust 1.98.1, wasm-bindgen 0.2.129 and wasm-pack 0.15.0,
installed outside the checkout, and exercised with Node 26.3.0, npm 12.1.0,
strict TypeScript 7.0.2 and Chrome 154.0.8037.99 on macOS arm64.

Real window and dedicated Worker execution covers exclusive ownership, actual
KEM/derived-key agreement, invalid signatures and stale callers, signed
revocation, old-key rejection, signed reenablement and realm restart. An actual
aborted IndexedDB transaction retains the preceding state and closes its owner.
Concurrent close prevents returning the updated runtime even when the signed
policy committed. Corrupted signatures are rejected and create cannot erase the
original image.

Two actual Worker terminations distinguish an IndexedDB request's success from
transaction completion. The former retained the old policy; the latter retained
the committed revocation even though the SDK never returned it. The controller
observes release of the exact cross-realm lease before reopening. An observed
termination delay is retained; calling `terminate()` alone was not counted as
completed cleanup.

Quota faults use two independent empty browser storage partitions and the real
Chromium quota override. Each has 8 MiB available; a 64 MiB WebCrypto-generated
test write shares the SDK's strict transaction. No error or successful storage
result is mocked. Three actual `QuotaExceededError` paths exercise creation's
strict barrier, reopening that uncertain creation and policy replacement. With
quota restored, the original signed image reopens; failed replacement preserves
the old policy and closes its runtime. Test data remains inside the owned browser
contexts, which are closed after each scenario.

This found a real defect in the draft: creation can commit its schema/image
upgrade transaction before its strict barrier fails. A read-only reopen could
then return an active runtime. `failures/quota-reopen-red2.log` in the capture
records that counterexample. Opening now verifies the original image and
reasserts it in a strict transaction before exposing the runtime; the same quota
condition rejects both creation and reopening. Browser transaction errors also
retain their original abort/quota causes.

The capture preserves earlier failed experiments: invalid test KDF labels,
overly generic abort classification, asynchronous lease observation, and quota
workloads whose zero-filled data or shared quota state did not establish the
intended failure. These are not counted as successful quota tests. Assertions
were retained; the final fault cases have independent storage state.

`artifact/wasm_browser_storage.py` verifies the installed manifest and every
consumer against current source, records the selected tools, runs both suites,
rechecks inputs and confirms browser/server cleanup before setting `completed`.
The `bindings-wasm` CI job invokes it before consuming the same archive on the
minimum Node runtime. Hosted execution remains a separate result.

[CHECKS.json](CHECKS.json) pins the 160-member [CAPTURE.zip](CAPTURE.zip), SHA-256
`2f134fa26bb9a58495be5ec37132cfa1c1c89fe3e67053abf55c409989a454ce`.
All hashes and extracted browser records were reread. [READERS.log](READERS.log)
records 14 package/browser reader tests, including removal or substitution of
Worker cuts, lease release, quota failures, original states and diagnostics.

This is browser SDK policy persistence, not a Continuity session journal,
root-authority recovery, witness transport or independent protocol implementation.
Web Locks protect cooperating owners, not malicious same-origin code. Browser
data deletion/eviction and restoration of a complete old profile require separate
application recovery and rollback protection. IndexedDB strict durability is a
browser contract, not evidence of native filesystem or power-loss equivalence.
Firefox, Safari, mobile and minimum browser storage qualification remain open;
the earlier Android physical gate remains accepted and unchanged.
