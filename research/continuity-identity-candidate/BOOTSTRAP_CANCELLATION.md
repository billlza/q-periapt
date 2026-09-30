# Permanent local bootstrap cancellation

`DeviceJournal::cancel_initiation` and `cancel_response` terminate an existing
bootstrap before application message activation. A host explicitly chooses this
permanent operation; a socket disconnect, deadline or transport cancellation
does not implicitly invoke it. Network retries keep their existing semantics.

The existing operation ID, context, account authorities and one-time claims
remain allocated. A single aggregate transaction replaces the private plan or
checkpoint with public input and an immutable cancellation receipt. The initiator
retains its 32-byte request; the responder retains its original 5,817-byte initial
flight so its operation ID still authenticates the exact original input. No
public-flight release, fresh bootstrap under the same ID or message activation
is permitted afterward. Existing application sessions return `Suspended` and
require the separate session-closure procedure. Definitively rejected bootstraps
remain `Rejected`; cancellation does not fabricate another outcome for them.

This is a logical erasure boundary. Redb history, snapshots and caller-owned
external keys may still contain older material. Local-only journals do not
detect whole-store rollback. Already returned flights cannot be recalled and a
peer may still complete independently. A cancellation receipt never asserts
remote receipt, remote cancellation, application consumption or cryptographic
post-compromise recovery.

## One-time inventory

Before response commit, selected one-time inventory entries become
`PrekeyAbandoned`; their recovery commands are replaced by the original claiming
operation ID. They cannot be regenerated, republished, reassigned or refunded.
After response commit they stay `PrekeyConsumed`. Both directions of each
inventory/claim link remain validated in every authenticated aggregate image.
Reusable entries remain available and can subsequently be explicitly retired.
The receipt records their historical cancellation disposition, so later retirement
does not change that receipt. Claims for external owners also remain reserved;
the journal cannot erase those owners.

## Receipt and storage

Candidate journal v21 uses table `continuity_device_candidate_v21`, outer tag
`QPVLT021` and plaintext tag `QPVIMG21`. It reserves 170 bytes in every initiator
and responder record from the first reservation. Cancellation replaces those
bytes and shrinks private payloads; it requires neither a new record slot nor
an enlarged aggregate. Other record kinds have no cancellation slot. Older
candidate formats fail closed without implicit migration or replacement.
Bootstrap/control/application wire protocols, SDK ABI and primitive KAT behavior
are unchanged.

An unused slot is exactly 170 zero bytes. A receipt slot is:

```
QPBCTR01[8] | previous_phase[1] | report_id[32] | presence_mask[1]
| initial_hash[32] | reply_hash[32] | final_hash[32] | session_id[32]
```

Absent values must be zero, present values nonzero, and the role/previous-phase
pair determines the exact mask. The known public flights use the existing
bootstrap hash framing and `initial-wire`, `reply-wire`, `final-wire` labels.
The session identity uses the existing `session-id` hash of the 104-byte final
prefix. `ProcessingReply` records a signed selected reply, not completed KEM
confirmation. Prepared or committed public flights establish local persistence,
not transport delivery.

The stable report ID is HMAC-SHA-256 under the HKDF-SHA-256 wrapping-key subkey
`Q-PERIAPT-CONTINUITY-BOOTSTRAP-CANCELLATION-KEY/v1`. Its length-framed input binds
the journal, owner, operation, context, role, previous phase, authorities, claims,
inventory references and original private record. No private record is exported.
After erasure, the receipt's authority comes from the authenticated aggregate;
it is not a publicly verifiable signature, and the original-record MAC cannot
be recomputed from public terminal metadata alone. Unrelated subsequent writes
do not change the receipt.

## Reopen without operational policy objects

`BootstrapCancellationJournal` accepts an existing private database, its wrapping
key and an independently retained `JournalIdentity`. It exposes only a bounded
public bootstrap inventory, exact cancellation and owner shutdown. It cannot
provision storage, create a `VerifiedDevice` or `BootstrapContext`, release
handshake messages, activate sessions or generate keys.

An owner hint from the bounded database header selects a decryption candidate
only. The complete image and independent ID authenticate before any recovery
write. Missing state, wrong key, wrong ID or corrupt relationships fail. An
existing authenticated write intent may be reconciled exactly, including a
prior message activation; an activated session then requires session closure.
This reconciles an already sealed command, not a newly admitted operation.

Required-witness journals still require the original pinned witness and its
original journal/owner/policy subject. The witness verifies the actual enrolled
device signer on signed queries and advances. The cleanup owner does not
manufacture a fresh device credential or relax witness enrollment validity.
An expired enrollment can confirm an exact already-applied cancellation intent;
it cannot authorize a previously unperformed advance. There is no local fallback.

Unknown storage or witness outcomes close the owner. Reopen and query/retry the
same operation. An exact terminal retry returns the original receipt without
another revision or key transition. The database lifetime lock serializes
cancellation and activation; a separate contender receives `Busy`.

## Validation scope

Focused tests cover real process cuts at eight initiator and six responder
phases, with all four prekey selections before and after response commit:
20 observed bootstrap cuts, 20 cancellation-commit cuts, and 20 bounded competing
cleanup owners. The cancellation child creates no verified policy, identity or
bootstrap objects. Readback checks the original receipt, canonical terminal
payload, non-growing image, retained one-time claims, forbidden key reuse and
continued reusable-key operation.

Four measured local sync barriers yield eight before/after failures. Six signed
witness losses cover the read, advance and post-commit query; two expiry cases
distinguish already-applied from unperformed advances. Additional tests cover
wrong key/ID/context/pin/signer, local policy close, duplicate cancellation,
active-session refusal, operational entry-point fences, truncated/noncanonical
metadata and authenticated inconsistent relationships. The full local Debug and
Release suites each pass 235 tests (zero failures/ignored), with runner times
647.944 and 637.999 seconds under overlapping qualification load. Those timings
are not performance comparisons. Both compiler floors pass strict all-feature,
individual-carrier and no-default Clippy; warning-strict docs and fmt pass. The
clean source/isolation/release-contract suite passes 95 tests without skips. The
release ledger retains initial failures, exact source scope and hosted limitations.

These native candidate results do not qualify installed foreign bindings,
cross-host endpoints, current physical devices, witness renewal, migration UX or
an independent security proof. SDK integration remains a separate release gate.
