# Original send inputs and AEAD query normalization

This note isolates the original-input obligation behind the fixed-zero-nonce
traffic path. It gives a source argument and a conditional normalization of
repeated encryption calls, supported by existing Debug/Release regressions at
`39d35880b7f5bff012f9a1b09588adebb3bd22dd`. It does not prove distinct message
keys, AEAD confidentiality, the shared key schedule or the multi-epoch theorem.
The [execution and source capture](../../research/sdk-alpha1/evidence/20261105-aead-send-origin/README.md)
retains eight actual test executions and a separate failed outer readback.
No product source, test assertion, protocol byte or recovery predicate changes.

## The relevant encryption input

Let a **send origin** identify one authoritative history's sending direction,
original traffic epoch and chain index. This is a provenance identity, not a
claim that two public message IDs or derived 256-bit keys cannot collide.
The history follows the existing [storage contract](STORAGE_RECOVERY_V1.md):
exact pending-write recovery and one authoritative device lineage, without a
hostile host rewriting private state or restoring a competing fork. Read-only
acquisition and disclosure remain separate security-game events.

For a retained send seed `s` and index `j`, the actual
[`step`](../../research/continuity-identity-candidate/src/durable/messages.rs)
computes

```text
next || K = HKDF-Expand(HMAC-SHA256(0, s), DM || "chain" || be64(j), 64)
DM        = "Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/"
N         = 0^96
A         = DM || "aead" || header || be16(len(ad)) || ad
```

The 93-byte header contains tag `QPCMSG03`, session, role, epoch, index, the
retained message ID and plaintext length. `K` is the last 32 output bytes;
`next` is the first 32. The sole application-message encryption site in
[`Traffic::send_input`](../../research/continuity-identity-candidate/src/durable/messages/traffic.rs)
uses ChaCha20-Poly1305 with `(K,N,A,plaintext)` and appends the 16-byte tag.
The candidate lock pins `chacha20poly1305 = 0.11.0` and `hkdf = 0.13.0`.
The nonce requirement is per key; merely using different message IDs does not
satisfy it. [RFC 8439, section 4](https://www.rfc-editor.org/rfc/rfc8439.html#section-4)
describes the keystream and authentication-key reuse caused by repeating a
key/nonce pair for different messages.

## Why retries preserve the tuple

For one admitted original send history, every execution of the encryption site
for the same send origin has the same `K`, plaintext, `A` and nonce. The argument
uses these ordered boundaries:

1. **Individual reservation.** `DeviceJournal::send_message` persists the exact
   ID, plaintext and application AD in `SendPlan` before calling `Traffic::send`.
   An existing plan is compared byte-for-byte with the supplied plaintext and
   AD. A changed input fails before the encryption call. A failure of that first
   persistence closes the owner and returns without reaching encryption.
2. **Aggregate reservation.** `send_account_message` persists every member plan
   and its batch binding in one aggregate intent before `resume_account_message`
   computes any member ciphertext. Resume reloads the retained recipient set
   and invokes the same `send_input` through `send_reserved`; it does not accept
   replacement member plaintext. An ordinary per-session send cannot bypass a
   member's active batch reservation.
3. **Private computation.** Encryption operates on transaction-private state.
   It clears the candidate plan, advances the candidate seed/count and inserts
   the exact outbox together. Until that next image commits, an interrupted
   computation can leave the already durable original reservation. Retrying it
   recomputes from the same old seed, index, header and exact input.
4. **Commit and unknown outcome.** The complete chain/outbox image is persisted
   before dispatchable bytes are returned. `persist` closes the owner on error;
   reopening reconciles the original pending intent. This is not permission to
   treat an uncertain encrypted operation as a fresh slot. The recovered state
   retains either its original reservation or its original committed outbox.
   Current authority is checked again before release.
5. **Committed replay.** The occupied-outbox branch returns the saved ciphertext
   or an error before `step` or encryption. Its intent-digest comparison is not
   a fresh encryption path: even an input-digest collision would return the old
   bytes rather than encrypt the colliding new input under the old key. The
   separate exact-input API contract still needs its stated digest assumptions.
6. **Consumption and closure.** ACK retirement advances `send_floor` without
   resetting `sent` or the send seed. Rekey closing refuses a pending plan,
   marks the old sender closed and erases its live send seed. A closed/resolved
   epoch cannot encrypt with that erased value. Individual session closure and
   aggregate abandonment freeze the record, then replace it with a terminal
   encoding; they do not refund the uncertain slot. Bootstrap cancellation
   refuses an already activated message record.

The induction is over accepted state transitions in that authoritative history.
Before the first encryption, persistence has fixed the input. A failed candidate
transition preserves the prior durable reservation or its exact pending intent;
a successful transition makes subsequent same-origin calls cached replays.
Advancement changes the origin, while terminal transitions remove the right to
send. Byte copies of the same reservation and process restarts are still the
same origin. This is a source-level invariant argument, not a machine proof of
the operating system, every storage failure or arbitrary private-state mutation.

## Normalizing deterministic encryption calls

In a simulation which already supplies the correct original application inputs,
their permitted equality decisions and the surrounding private-state interface,
retain a private table indexed by send origin. On the first actual encryption
computation, query the corresponding encryption interface with the real tuple
and cache its result. On later computations for that origin, return the cached
result after the unchanged input/state checks. The table survives simulated
process restarts; it is simulation state, not a proposed product cache.

Determinism and the invariant above give an exact coupling of all successful
ciphertext bytes. The simulation performs at most one encryption query per
origin, even if the real implementation recomputes an interrupted private
ciphertext. It retains the real persistence failures and release checks. It must
not produce success, suppress an error or dispatch the cached bytes merely
because it already obtained them from its encryption interface.

The first query is charged at **private computation**, not first network release.
This also handles a later public ciphertext digest: resolution and historical
metadata can expose `H(ciphertext)` before a caller retrieves the wire. Both
that digest and any eventual wire must use the same cached bytes. Delaying the
query until network dispatch would omit this observable dependency.

The normalization alone is not a nonce-respecting security reduction for all
message keys. It becomes one encryption query per key only outside a separately
bounded event in which distinct send origins share a derived key. Establishing
that event's bound requires the still-open shared key-schedule argument; no
independence or birthday probability is asserted for the concrete keys here.
The surrounding confidentiality game must also simulate application-input
comparison, permitted disclosures and receiver/decryption behavior. This note
does not silently provide a hidden challenge plaintext to a reduction or supply
the missing challenge-ciphertext decryption exclusions. Those are composition
obligations, not defects established by this execution record.

## Executed support and unsafe-reset control

Four existing tests were run in each of Debug and Release:

| Case | Actual observation |
| --- | --- |
| Individual message sync failures | Activation/send/receive failures before and after their configured sync cuts return no early result; reopening preserves the original input, wire and one chain advancement. |
| Aggregate sync failures | Nine measured barriers, 18 faults per profile; all members reconcile together as absent, reserved or committed, with exact recovered wires. |
| Aggregate process cuts | Two recipients; real child termination after reservation, after first private ciphertext computation and after aggregate commit; competing writers refuse ownership, replacement input is refused, and the precommit wire equals the recovered wire. |
| Deliberately unsafe reservation reset | The shipping API refuses replacement. A test-only, unpersisted mutation then deletes/replaces a retained plan and shows that old/new ciphertext XOR equals old/new plaintext XOR. The real abandonment path instead freezes and closes the sessions. |

The last case demonstrates why retaining the original input is necessary. Its
unsafe mutation is explicitly outside the public API and is not an attack on an
admitted production transition. The actual precommit wire is compared inside
the test; this capsule retains source, command results and markers, not the
temporary private test directories. Real process termination is not power loss.

The first outer reader incorrectly interpreted the fixture's send budget `4` as
the recipient count. All three Debug test commands had passed; its failed
assertion and streams are preserved. A corrected reader checks the actual
two-recipient fixture and reuses those three completed executions. It then runs
the Debug unsafe-reset case and all four Release cases. No product test was
weakened or rerun to hide a failure. Both parent attempts stay below the same
1,800-second limit, with 900-second component limits and bounded streams.

This supports the original-input and retry part of the
[computational recovery obligations](COMPUTATIONAL_RECOVERY_V1.md). Distinct
key derivation, AEAD/ACK security, accepted-prefix simulation, full composition,
platform qualification and external review remain separate.
