# Focused review of the native profile and unknown application input

Date: 2026-11-07. Reviewer: theory agent. Scope: native/source_profile.md Sections 3–4 and their alignment with the frozen joint-continuation v0.3, plus the targeted Send intent-prefix audit.

## Conclusion

The live profile provides concrete state recipes and call interfaces for the new continuation. The unknown message and send-intent digest can remain opaque during the one-use AEAD reduction; the allowed Resume and receive paths do not require their public disclosure. The focused prefix check closes a potential extra plaintext-comparison channel in the surrounding journal format.

This conclusion applies to the declared authoritative-history and honest-application profile. It preserves active network validation and the original acquisition eligibility. The record error is the existing renderer comparison with its actual nonce/query/confinement conditions; it is not inferred from the mere presence of encryption.

## Fixed inputs reviewed

- native/source_profile.md v0.2, including the finite \(M\) traffic-information revision and the marked-allocation trace.
- native/send_intent_prefix_audit.md, a focused reading of the already captured source.
- native/source_map.json and the reported source identity construction, used for call/phase correspondence.
- Frozen theory joint_continuation.md, joint-continuation.tex and joint-primitive-bounds.tex v0.3.

The exact source identities are owned by native/source_identity_manifest.json. The source profile reports that its 24 files match both current checkout 1c68aa666db22d36ee136be1ec712545a9e74f03 and manuscript pin 228c944fc476e3e57d6c08063cacb19bca5b360e. This review does not reinterpret that inventory as branch or test coverage.

## Concrete adapter reasoning

A materialized record experiment holds real private values and invokes the listed actual reservation, KEM, root/confirmation/traffic, AEAD and ACK functions. Its corresponding table experiment holds immutable handles and recipes. The subsequent cryptographic reductions replace those concrete operations, not a newly assumed all-protocol oracle.

For HMAC schedule reductions, outputs of the designated row/column primitive are known to the reduction, so confirmation bodies, signatures, traffic metadata and ACK checks are computed honestly. For the later AEAD reduction, the selected message key and application challenge bit are hidden; the challenge payload and send-intent digest therefore also become private handles.

A pending Resume restores the original plan and compares against that same immutable application input. The result of this equality is known from provenance. A committed Resume returns the exact cached outbox wire. A crash before persistence can cause native encryption to run again, but the reduction's cache is attached to the original private computation and has the same input tuple.

Incoming exact challenge bytes can be recognized from the cached ciphertext. The authenticated marker suffices for the declared public transition and private delivery of the opaque payload. Altered ciphertexts retain the actual AEAD authentication/failure interface. No step assumes every receive is merely an equality test.

## Outer journal prefix: the resolved question

It was necessary to check that the unknown send-intent digest did not reappear as a clear journal-operation binding. The source chain in the focused audit is:

| Source call | Consequence |
| --- | --- |
| durable/messages.rs:424–435 | State encoding becomes the session payload, then is persisted. |
| durable.rs:906–911 | The full target image is sealed before journal intent creation. |
| durable/write_intent.rs:637–646 | Ordinary commit calls PendingWrite::new. |
| durable/write_intent.rs:129–130 | new calls new_bound with binding=None. |
| durable/write_intent.rs:132–186 | The QPWINT01 prefix contains journal identities, revisions, old/new image digests and target length, followed by encrypted target and its HMAC. |

The ordinary Send path does not use BoundTransaction's Credential/Policy/Roster variants. Thus its clear prefix contains neither the challenge plaintext nor its send-intent digest. The Outgoing digest remains within the encrypted session payload.

The target-image hash in the prefix is still handled by the existing joint image/intent commitment comparison. It is not declared harmless without that comparison. This matches the renderer's need for known prefixes or already supplied commitment outputs, and preserves equality of repeated registered images.

## Two source distinctions retained

1. A target's full matching post-reservation state capture triggers the existing all-continuations eligibility certificate. A key-only or plaintext-only fragment is a different operation, assessed by its actual return. Neither successor-root-only nor next-seed-only disclosure is relabelled a full Snapshot.
2. A successor root's owner follows the installed source field: FinalReady already places the new root in State.rekey. The next seed refers to the committed post-first-send field with sent=1, not an old durable seed while an uncommitted private candidate already has a computed successor.

The revised \(M\)-information profile also avoids an unproved wire-uniqueness inference. Existing source locks show local immutable response/final behavior, but the continuation theorem simply admits different complete information strings. It marks a fresh material/direction before its values and keeps identical strings as the same protected entry.

## Record comparison placement

The source profile's score comparison
\[
\rho_j^{\rm live}\le2\min\{1,\epsilon_{{\rm com},j}+
\delta_{{\rm nonce},j}\}
\]
is used with the concrete primitive interface held fixed and with the existing commitment hypotheses. The hidden-root and hidden-message adapters then supply their own proved comparisons. The live core does not invoke cleanup reports, so no report-row term is added to this particular comparison. Enabling those reports uses their previously proved dependency order and actual residual.

The private outer image nonce remains confined. A partial projection exposing it is not silently covered by a head-only record argument, even when the simulator happens to know its value. The ordinary metadata paths in this profile do not return it.

No additional source change, remote action or benchmark was needed for this review.
