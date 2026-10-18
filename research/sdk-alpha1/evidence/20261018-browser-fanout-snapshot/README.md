# Installed browser fanout snapshot validation

The account-send snapshot lifetime change at
`ca7e13fac927218e20b231804c1e93054117edfa` now runs through the actual installed
WASM package in Google Chrome 155.0.8059.80 on macOS arm64. The package was built
with Rust 1.98.1, installed outside the checkout and consumed with Node 26.3.0 and
TypeScript 7.0.2 strict NodeNext. Its source manifest binds the changed fanout
module and the browser owner. Native issuer, witness and both receivers were
rebuilt against the same source and current pinned dependency graph.

The original four complete-account scenarios pass all 212 browser invocations:
local storage protection, required witness with a lost reply, receiver business
effect followed by application failure, and actual Worker termination after the
native peer result but before its reply is delivered. Each retains the original
aggregate, recipient sessions, per-member message IDs and ciphertext across
reopening and retry. Eight receiver effects are checked against their exact
session/message/payload bytes. The first effect's file identity remains unchanged
on retry; an already confirmed member returns with zero further exchanges.
Retirement remains refused until every original member has a final disposition.

The same unchanged assertions exercise omitted/duplicate/empty target sets,
out-of-range selection, closed input/policy, ten invalid JavaScript indices,
altered-input retry and the unary-send bypass refusal. Invalid pre-submission
input leaves the aggregate absent, member positions unchanged and peer dispatch
count unchanged. Original per-operation deadlines remain in place.

Independent readback matches every CLI response to the retained case records,
checks all 28 native peer records and 2,211 witness request/reply records against
their raw bytes, verifies all eight effects, and rechecks the served package,
fixture binaries, source identities and owned browser close receipt. The browser
executable/version is tied to the live process ancestry of this specific CLI
session. The producer's `browser_runtime: not-run` receipt is retained unchanged;
this separate checkpoint records the subsequent actual Chrome execution.

Three preparation failures remain in the capture. The archived fixture lock was
refused by `--locked`; unseeded offline resolution then selected eight newer
external entries and was rejected before building. Seeding from the current root
lock retains all 120 required external entries without new versions or checksum
changes. The initial package consumer lacked its pinned TypeScript offline cache.
After preparing that exact compiler, the unchanged consumer successfully checked
the same already-built archive; no package build or assertion was bypassed.

`CHECKS.json` binds `CAPTURE.zip`; its internal inventory binds every original
public file. The capture includes the installed package, source/build/consumer
receipts, original and adapted drivers, public wire records and CLI responses.
Generated signing/wrapping keys, databases and browser profiles are excluded.

This is one-host, same-implementation interoperability over the explicit loopback
HTTP test carrier. The harness reopens original state through fresh Workers to
exercise persistence. Its timings and witness traffic are not a normal-workload
performance benchmark. Browser allocation/latency/energy, the complete browser
reservation/commit interruption matrix, independent implementations, other
platforms and full release admission remain separate. The Windows CI cohort at
`b47eb541` still predates the snapshot change.
