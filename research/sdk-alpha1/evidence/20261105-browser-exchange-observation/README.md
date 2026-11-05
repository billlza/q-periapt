# Browser ordinary-exchange observer failure

[Bindings-WASM job 127182901124](https://github.com/billlza/q-periapt/actions/runs/42008993679/job/127182901124)
failed on source `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`. The downloaded
artifact distinguishes two execution boundaries: the local-policy browser/native
session report is complete with eight exchanges; the **required-witness** report
is incomplete after its `activate` phase, with six exchanges. This is not a
failure of the already completed local-policy report.

The required-witness phase used HeadlessChrome 156 on Linux x86_64. Its client
result reached the intended lost-reply `PeerTransport` failure with both owner
and returned error closed. The outer verifier nevertheless rejected three
remaining DevTools failure events instead of its required single lost response.
The phase recorded no HTTP errors, console/page diagnostics or relay failures.

| Observer event | HTTP status | Exact relay request match | Request bytes | Relay disposition |
| --- | ---: | ---: | ---: | --- |
| `/exchange`, `ERR_ABORTED` | 200 | 3 | 172 | Response retained, not withheld |
| `/exchange`, `ERR_ABORTED` | 200 | 5 | 3,643 | Response retained, not withheld |
| `/exchange/drop-once`, `ERR_EMPTY_RESPONSE` | No status | 6 | 183 | Response deliberately withheld |

The first two associations use the complete `request_diagnostics.body_hex`,
SHA-256 and byte-for-byte equality with the recorded request files. Response
files match their recorded hashes and QPCXCH01 response kinds. These checks
establish server-side identities and the observed HTTP statuses. **They do not
establish that the browser consumed each complete response.**

The existing fixture's `transport-receipts.js` instruments only profile 1
(Witness). The failing phase retains 89 fulfilled Witness receipts, and no
ordinary-exchange client receipts. The corresponding verifier admits only exact,
fulfilled, signature-checked Witness replies when explaining an `ERR_ABORTED`
event. Ordinary `/exchange` events remain unexplained by design, then fail the
strict outer inventory check.

The source's bounded Fetch success path waits for stream EOF, validates the
length and cancellation state, and returns bytes. It does **not** call
`controller.abort()` on success. Abort occurs in cancellation/error handling;
removing that behavior would not be an evidence-backed fix. A fulfilled ordinary
exchange followed by a DevTools cancellation observation remains a hypothesis,
not a confirmed cause in this capture.

The next distinguishing observation is bounded fixture-only instrumentation of
profile-2 Promise fulfillment/rejection and exact request/response hashes,
preserving the original Promise and SDK behavior. Any future event classification
must match the actual client result to its original relay bytes and retain real
failures, duplicate/mismatched receipts and the deliberate lost response. Merely
dropping `ERR_ABORTED` events or accepting HTTP 200 would weaken the gate.

Artifact **13407418993** contains 548 members, all CRC-checked: 3,659,134 bytes,
SHA-256 `456935ecff7887382134de44e52b9f20e5097a6a4102d8f73b502fc46a50782e`.
The full artifact, complete job log and eight source-pinned collector/fixture/
transport files are preserved in `CAPTURE.zip`. All 14 capsule members were
reread: **3,514,615 bytes**, SHA-256
`1553dfbd2818aef12cd65b48eda7df2340755c46c30096ba4f994f3be1363abb`.
`READBACK.json` contains exact event hashes/timings and the unresolved distinction;
`FILES.json` binds retained bytes. No product or verifier change, new browser
execution, rerun or release acceptance is claimed by this readback.
