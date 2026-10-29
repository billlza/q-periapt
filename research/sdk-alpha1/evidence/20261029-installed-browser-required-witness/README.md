# Installed browser with a separately enrolled Witness

The captured browser uses installed SDK archive
`06b13752dd172c6629e62c2251b99ff6174043713a2d8966014686d5f1169ed3`.
The native reference peer and persistent Witness were built from the recorded
repository inputs in Debug and Release. Each report binds 277 source files,
the installed browser files, native binary hashes and the independent issuer
provider. These are shared-engine interoperability runs, not an independent
session implementation or a newly published SDK.

Both required-Witness profiles completed eight forward and four reverse
HTTP/TCP session exchanges and 185 browser Witness exchanges. They retain
separate genesis approval, missing-carrier refusal, no receipt before enrollment,
wrong-head rejection, fresh signed Witness requests, actual native and Witness
SIGKILL/restart, offline refusal, original journal/session/key identity, one rekey,
exact lost-ACK retry, and a durable browser business-effect cut before the
consumer returns. The same operation IDs and ciphertext survive recovery.
The ordinary local-policy profile also completed the full bidirectional workload.

The first concurrent reverse attempt failed because the reference Witness used
the service's zero-length queue. The native sender received Witness EOF while
the browser was recovering; the incoming relay then timed out. The Witness now
has a bounded eight-frame queue, at most two queued frames per IP, and one
executing storage owner. Original acceptance deadlines are retained. Real socket
regressions cover overflow, expiry without owner invocation, and shutdown that
drops queued input while joining the active callback. Other services retain the
default immediate-busy rejection. The final Debug and Release Witness restarts
observed 38 and 32 queued requests respectively, with no busy rejection.

Earlier failures remain in the diagnostics: the fixture initially tried to
prepare an already Activating installation, then assumed Fetch cleanup always
produced one specific browser diagnostic. Those fixture corrections preserve
the durable activation selection and require the actual HTTP failure event.
A separate initial Debug handshake exhausted its unchanged 10-second budget.
Component timing on private copies of that closed synthetic Witness separates
host/configuration open, protected-key loading, store handling and close costs.
It does not establish stable tail latency or justify removing persistence or
authentication checks. Subsequent full runs passed with the same operation
budget; the earlier timeout is not relabelled a fix or a success.

`CAPTURE.json` binds every member of `CAPTURE.zip`. The archive contains public
synthetic transcripts only. The readback replays public framing, commitments,
state transitions, process identities and failure dispositions. The runtime
fixture independently verifies each browser Witness request and reply with
the separate reference implementation; the pure reader does not rerun signature
verification. Eleven readback tests, including ten mutations, bind required policy, original activation,
genesis, keys, process replacement and actual browser failure records.

Reference library tests (124), strict all-target/all-feature Clippy, and Rust
1.90 checks passed. Hosted validation of this change, device/power-loss tests,
Passkey authorization, full lifecycle acceptance, tail-latency characterization,
multi-epoch secrecy and final 0.2.0 release remain separate gates.
