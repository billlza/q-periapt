# Independent closed-epoch application accounting

This local ARM64 checkpoint implements the candidate's existing explicit outcome
resolution contract in the independent Python/OpenSSL endpoint. It uses the exact
48-source closure recorded in `CHECKS.json`, based on
`4b901bfb3d1d5bbb36ee6c5bafe689255b80bc46`. The actual native counterpart has SHA-256
`373fcc74dee63dd7a5d1731e1e7478cd11bc7dfdfb0b214e24f773653607248a`.
Product SDK, candidate, bindings and dependency/toolchain sources are unchanged;
the native test adapter calls the already existing Rust resolution APIs.

Resolution is two committed steps. First, an explicit call freezes a fully closed
epoch and commits an immutable report with a separate private random HMAC key.
The report retains unknown outgoing IDs/ciphertext digests, unconsumed plaintext,
skipped indices and original counters/floors. Old traffic operations are fenced;
new traffic remains available. After its own durable accounting, the application
acknowledges the exact ID. The SDK removes old data/key references but preserves
the original floors: unconfirmed sends become `DeliveryUnknown`, never delivered.
Only an acknowledged resolution permits later history collection.

`QPREFS04` stores bounded resolution metadata in the existing control headroom.
It reconstructs reports from frozen traffic rather than serializing a second
plaintext copy. Versions one through three remain readable without implicit
migration. The complete archived version-three writer supplies real outstanding
traffic for an interrupted explicit upgrade; the old reader rejects version four.
Acknowledgement accepts immutable `bytes` IDs, with bytearray/memoryview refusals
checked before state mutation.

The main scenario passes six epochs, 99 fresh-process operations, 59 actual native
commands, six SIGKILL cuts and ten malformed-state/downgrade controls. Cuts include
pre-intent freeze/acknowledgement, head publication, post-acknowledgement release,
upgrade and a current-epoch send that remains resumable while old traffic freezes.
Both implementations retain the original floors and distinguish pending, unknown,
previously acknowledged and later retired messages. Separate application files
retain every report outcome before acknowledgement, with file synchronization
(including macOS `F_FULLFSYNC`) and parent-directory synchronization. This is not
a transaction spanning arbitrary external application effects.

Two capacity boundaries pass. With 122 full-size outboxes filling the business
allowance, the original 113-byte reservation correction still holds: 13,700 bytes
is refused before commit and 13,587 bytes fits exactly. The same full image can
freeze and account for 64 old outboxes using control headroom. Observers closing
the owner after freeze/acknowledgement commit cause failure without result release;
reopening recovers the original state and leaves the current outbox unchanged.
A separate direct-host run receives all 64 maximum-size plaintexts (1 MiB),
reopens the exact complete report and persists the host's quarantine decisions.
The real Rust peer accounts for its corresponding 64 unknown outgoing messages.
That run uses 138 native commands; no report-count or message-size limit was lowered.

The isolated disclosure experiment gives its forge function only the old send
chain after the first genuine message. It receives no identity, root, KEM, journal
or ACK key. A real Rust peer consumes forged indices one and two and emits a valid
ACK floor of three; the honest sender sent only one and correctly refuses it.
The original admissible ACK is deliberately not delivered to the sender (though
the experiment transcript preserves it). If the host retained that ACK, ordinary
recovery would remain possible. After three actual rekeys, the genuine outbox
blocks target four. Explicit unknown-outcome accounting then allows the **same
original offer** to complete and traffic continues through epoch six. The run
has 51 independent worker operations and 42 native commands. This shows a specific
accounting/progress boundary, not post-compromise confidentiality or reversal of
effects from forged old traffic.

All seven prior lanes pass on the final source closure. Three separate public
readers verify command/result hashes, worker PIDs/cuts, original report and message
identities, application-record equality, maximum plaintext bytes and signed rekey
transcripts. The resolution/disclosure reader checks 53 signed controls. Secret
report MAC/AEAD checks and direct-host cleanup/input-refusal assertions run inside
the actual implementations; public replay loads no private keys or images.

Strict release build/all-target Clippy, rustfmt, actionlint and Python parsing
pass. The added native adapter is a separate module; the Rust inventory is now
723. All 46 source-contract tests pass in a real-Git snapshot of 1,123 matching
files, including the exact source count and missing/added-source refusals. This
does **not** constitute a new CodeQL database extraction or analysis.

`CAPTURE.zip` contains all ten final public lanes, the native executable, exact
sources, public readers, quality-input manifest and build/lint records. Every
included file is hashed in its manifest. Intermediate successful runs and all
original/interrupted private fixtures remain local. Private-path references are
not followed by the public reader. No private report/wrapping/signing keys or
journal images are uploaded.

Hosted verification remains pending. Required witnesses, current-authority renewal
and revocation, full identity/install lifecycle, network carriers/scheduling and
installed cross-host consumers remain open. Logical removal is not physical
erasure of Python memory, old images or backups. These results do not establish
hardware power-loss behavior, global application atomicity, PCS proof or release
readiness.
