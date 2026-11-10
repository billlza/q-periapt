# Independent persisted control requests and explicit-target progress

This local ARM64 checkpoint adds the unchanged purpose-13 `QPRKRQ01` request and
a bounded one-step driver to the independent Python/OpenSSL endpoint. It is based
on `582d4283a613c181cfc90476eedd93d737538d29` plus the 40 exact source files in
`CHECKS.json`. Product SDK, candidate, language bindings and toolchain inputs are
unchanged. The isolated actual Rust counterpart now exposes the existing native
control APIs to the experiment; no protocol logic is substituted in that adapter.

The final run passes seven targets, 111 fresh-process operations, 80 native
commands, 13 real SIGKILL cuts and 13 codec refusal checks. Separate public
readback verifies 101 control results and all 33 distinct signed controls,
including both signature components, context/session/epoch/predecessor fields and
the complete four-flight transcript chain. The actual ARM64 counterpart SHA-256
is `2eac9edaafbc7ba0d83bef73601718d27a82a6ed3dedb0d8210b46787a272417`.
Secret KEM/MAC/AEAD verification occurs in the actual interoperating runtimes;
the public reader does not load private state or keys.

The complete archived version-two peer package creates the initial image. A real
pending plaintext send and exact signed offer survive an explicitly interrupted
upgrade to `QPREFS03`. The old writer reads the pre-upgrade pending state, its old
reader refuses version three, and the original ciphertext decrypts in Rust after
recovery. Ordinary open does not upgrade: version one and two retain their prior
operations, while the new control driver requires explicit upgrade.

The non-proposer's durable request contains a prepared public body or exact
committed signature. `BodyPrepared` is deliberately distinct from Rust's sealed
signature-randomness reservation: an uncommitted signature may be recomputed.
Once committed, all retries use its original bytes. Completion clears the request
atomically with its target. Missing/wrong signing owners, signed invalid fields,
both corrupted signature components, wrong purpose, expiry, retired/future targets
and malformed envelopes are refused. Cached committed outputs need no private
signer but still require current authority.

Four real sends exhaust a signed budget of four even after all are acknowledged.
A control request remains possible and does not refund any application credit.
A separate old unacknowledged ciphertext allows a request at target four but
blocks offer admission until its original ACK arrives. Requests therefore do not
pretend to attest settled history. Repeated requests during final preparation and
after completion return the original offer without starting another target.

Local completion returns no extra flight. Explicit delivery can still replay a
committed receipt that was never dispatched, allowing the other endpoint to
finish. The four deterministic retry schedules cover both initiating roles and
proposer/non-proposer starts. Each distinct flight is dropped once and duplicated
once, with at most 32 attempts, eight deliveries per attempt and 32 queued messages.
They finish both peers without dummy application traffic. This is a control-pipe
fault schedule, not an implemented network carrier, timer policy or energy result.

All six original lanes pass on this source closure: eight durable rekeys/150
workers/11 kills/75 native commands; 122 full-size outboxes with exact-fit capacity
admission; 19 storage kills/46 controls; six epoch-zero kills/27 workers/nine native
commands; eight volatile rekeys/132 commands/108 refusals; and 41 bootstrap/traffic
commands/51 refusals. Strict release build/all-target Clippy, rustfmt, actionlint,
Python parsing and both public readers pass. Rust source count remains 722.

`CAPTURE.zip` includes all seven final public lanes, the original two failed
harness attempts, exact sources/executable, review/sealing scripts and lint/build
records. Its manifest verifies every included file. The failed attempts concern
a helper/directory name collision and incorrect expected budget-error wording;
an initial reused reader also expected upgrade version two rather than three.
Their traces remain, and no product assertion was weakened. Intermediate runs and
all private fixtures remain local. No private images or signing/wrapping keys are
uploaded; captured private-path references are not followed by the public reader.

Hosted qualification is still pending. Required witnesses, authority renewal and
revocation, application epoch resolution, installed/cross-host consumers and the
complete identity/install lifecycle remain open. The internal reservation cuts
need disclosure/refinement analysis; these runtime results do not establish
hardware power-loss durability, erasure or post-compromise security.
