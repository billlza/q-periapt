# Apple Silicon native candidate completion

[Job 117680781073](https://github.com/billlza/q-periapt/actions/runs/39129232908/job/117680781073)
finishes successfully at `23280124efd2f0f3003d4ce85e3db665f6ec8a25` using Rust
1.98.1 on Apple Silicon. Terminal-only log retrieval records the exact test
sequence. Debug and Release each pass 1,037 candidate main tests, integration
groups of 4, 2, 4 and 3, and 17 documentation tests. Sealed SDK operations pass
27 tests and four documentation tests in each profile. All-target feature
checks, strict Clippy, formatting and documentation steps also finish successfully.
This closes that native job, while the complete workflow still has installed
consumer jobs pending.

The downloaded public-vector artifact is 1,936,823 bytes with 1,939 members,
SHA-256 `38026deb113e5bf5410d76463a7c77149a444d5670ad97a7721a5ec5493b1479`.
Both original public verification scripts are rerun locally against these new
downloaded bytes with OpenSSL 3.6.4. Their semantic results and fixture hashes
match the hosted reports. The bootstrap/identity oracle checks 20 signed
envelopes, 30 membership proofs, nine authenticated selections and rekey
transcripts. The witness oracle checks 57 signed envelopes and 285 signature
negative controls, including the actual joint Applied/Closed proposal outcomes.

The compiled wire-contract output matches the committed budgets and remains
explicitly unfrozen. Local review checks the actual public bundle bytes and
retained outputs for one accepted input and 25 refused variants. Those native
bundle executions remain producer observations: this artifact does not contain
the compiled native executables, so their reported hashes are not locally
recomputed. Eleven workflow, budget, runner and reader sources match the exact
tested Git commit; no uploaded executable is run locally.

`CAPTURE.zip` retains the original artifact, terminal job/log metadata, complete
public replays, executed reader sources and checked manifest. It is 2,069,017
bytes with 1,659 members, SHA-256
`92bdeedc24fab3e4528432e471c970066253ffc4232397958af63a4086cf9e14`.
An initial ancillary log request failed because `gh` refused terminal escape
sequences; the validated artifact was already downloaded. The subsequent
terminal-only reader records raw log bytes directly to a file and strips escapes
from displayed summaries. Both diagnostics remain in the capture.

These receipts do not substitute for installed consumers, physical-device
lifecycle, hardware power loss, full construction security or final release
admission. Product/candidate/binding/toolchain inputs remain unchanged through
the independent-reference implementation at `061ff030`.
