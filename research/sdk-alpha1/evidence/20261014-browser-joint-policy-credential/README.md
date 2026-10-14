# Browser joint policy and credential maintenance

The installed WASM package now exposes the shared native G/T lifecycle:
verified two-root policy continuation, stage, local reconciliation, historical
local recovery and separate local or witnessed activation. The public credential
request supplies the original journal, original credential, current credential
and roster, actual prior policy, and prior T. These values are not reconstructed
from caller-selected version numbers. Existing witness preparation, commit,
historical query and explicit Close APIs carry the exact joint T transaction.

Ten fresh Chrome scenarios passed on macOS arm64, with 164 recorded Worker
invocations, including intentional failures and Worker termination:

| Scenario | Observed result |
| --- | --- |
| Local G1/T1 then G2/T2 | Same installation journal; next request retains T2, C2/R2 and original C0/R0 |
| Required-witness G1/T1 then G2/T2 | Exact retained proposals, independent preparation, commit and activation |
| Lost Commit reply, both generations | Fault occurs after native Commit/Applied; reopened history returns Committed; Close cannot undo it |
| Worker terminated after Applied, both generations | Actual termination before response delivery; original operation recovers as Committed |
| Independently closed target | Historical Closed; target activation refused |
| Required-witness local activation attempt | AnchorRequired and closed owner; subsequent explicit witnessed admission succeeds |
| Local committed target after real expiry | Repeated historical Committed recovery without a current runtime; activation rejected |
| Local uncommitted target after real expiry | Repeated Suspended errors; Pending remains Pending, without an invented NoCommit |
| Lost witnessed commit reply followed by real expiry | Repeated historical Committed recovery without a current runtime; activation rejected |
| Witness cancellation after real expiry | Independently approved Closed, repeated historical recovery, activation rejected |

Every staged joint proof also rejects a modified signature. The separate issuer
checks each request against its retained original registration and preceding
issuance, and rejects reuse of one root approval for both authorization roles.
Normal generation-two issuance and the subsequent public request verify the
actual T predecessor. Historical queries are checked not to submit Commit or
Close. An ambient cookie control confirms normal witness requests omit cookies
and Authorization. The expiry cases use actual host and browser clocks and
short-lived policies signed before testing; no clock override or post-signature
validity edit is used.

The package archive SHA-256 is
`44ee7451655618f284e152cd76008447d281abda22c659ee81e7790b2705d4f1`.
Each fresh browser copy matches the installed package bytes. Producer scripts,
executables and static web files are hashed before and after accepted runs.
Rust 1.98.1 WASM Clippy with warnings denied, Rust 1.90 WASM compilation,
installed Node tests, TypeScript 7.0.2 strict NodeNext, 53 artifact controls,
scoped Rust formatting and whitespace checks passed. CodeQL source inventory
includes both new Rust modules, increasing the expected count from 646 to 648.
The package builder now gives Cargo an explicit output-specific target directory
so independent package builds do not share the wrapper's default target path.

Two initial package attempts failed to load the existing pinned LLVM library:
the hardened shell boundary cleared its loader search environment. The accepted
build sets that path inside its owned Python driver, without replacing compiler
or library bytes. The first native fixture build also exposed an Arc/Runtime
reference type error; the corrected fixture then compiled. These failures and
the original failed fixture source remain in CAPTURE.zip. The package producer's
`browser_runtime: not-run` receipt is preserved: the later browser runs are
separate evidence, not a rewritten producer result.

The new browser and WASM continuation code lives in dedicated modules and uses
the existing operation owner and native transaction implementation. No parallel
state machine, policy downgrade or relaxed verifier is introduced. No runtime
performance improvement is claimed.

This is owner-lifecycle qualification using the same shared protocol engine in
separate browser, issuer and witness processes on one host. It does not establish
an independent implementation. Original business-message and rekey recovery
through two browser joint updates, a browser interruption between local journal
commit and completion receipt, other engine/platform coverage, PCS, current CI
and full release admission remain separate. The accepted device and protected
historical cohorts were not reopened. Private authority keys, browser profiles
and storage databases are excluded from CAPTURE.zip.
