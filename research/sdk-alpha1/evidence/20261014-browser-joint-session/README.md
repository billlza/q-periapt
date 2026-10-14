# Original browser sessions through two joint updates

The installed browser package now has direct session evidence for G1/T1 followed
by G2/T2. Four protocol scenarios passed, plus a fresh local repeat after repairing
the test page's startup diagnostics: 193 Worker invocations in total, including
expected refusals, transport failures and intentional Worker termination.

Each scenario establishes an original session with a separately running native
peer, sends an application message, loses its result, prepares an unacknowledged
reverse message, and interrupts an epoch-one rekey exchange. Both joint updates
then complete while those original operations remain outstanding. After each
generation, the browser retains the same journal and pending rekey state; the
native peer independently verifies and admits the exact browser G, including an
exact retry. The peer remains under its still-live P0. It does not adopt a newer
policy and then fall back to P0.

The four scenarios cover local protection, required witness, required-witness
Commit response loss in both generations, and Worker termination after actual
Commit/Applied in both generations. In the first two, the receiver commits the
message receipt but the transport drops its ACK. In the latter two, the receiver
first durably publishes the business effect, then returns an explicit Application
error before reporting success to the SDK. Those errors and nonzero native exits
are expected fault receipts, not successful SDK commits.

After G2/T2, the legacy policy-bound reopen is refused. Correct continued-session
reopening completes the originally interrupted rekey to epoch one and resends the
original application wire byte for byte. The receiver's effect file retains its
device, inode, size and modification time; the retry does not create another
effect. The browser observes authenticated consumption and Acknowledged status.
The outstanding native-to-browser message also completes using its original wire.
Repeating it returns the same ACK without another plaintext callback. A fresh
post-update message succeeds as well.

This demonstrates the application contract with a durable, idempotent host
consumer. It does not promise global exactly-once execution for arbitrary external
side effects. Likewise, completing the rekey is a protocol-progress observation,
not a post-compromise secrecy conclusion.

The package is the installed archive
`44ee7451655618f284e152cd76008447d281abda22c659ee81e7790b2705d4f1`
from the preceding browser joint-maintenance qualification. The native peer was
rebuilt against clean source commit `e8949e78e531528736fb5731c4f41143773c82df`
in its own Cargo target directory. Public authority fixtures use the unchanged
source and binaries already recorded with that package qualification. Every
accepted run checks its scripts, native executables, CLI/runtime and static web
payload before and after execution. No product code or policy guard changes in
this evidence-only increment.

The first two runs inherited a test-page favicon 404, captured in their raw console
logs. A real SVG favicon was added to a fresh page. Run03 then correctly observed
zero console messages but failed a fixture assertion that incorrectly required an
empty log file to exist. The repaired check requires the pinned CLI's exact
zero-error/zero-warning result and rejects any nonempty console log. Run04 passed
that startup check and the full local two-generation protocol scenario. Original
page errors, the failed assertion and its source remain in CAPTURE.zip; they were
not suppressed or rewritten as passes.

These are separate processes on one macOS arm64 host using the same underlying
protocol implementation. The native endpoint's P0 remains live during these runs.
Both-endpoint policy expiry/continuation, a browser cut between local joint journal
commit and completion receipt, other engines/platforms, independent implementation,
broader lifecycle, PCS, performance and release gates remain separate. No accepted
or protected historical cohort was reopened. Private keys, browser profiles and
storage databases are excluded from the archive.
