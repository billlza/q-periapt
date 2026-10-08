# Prekey inventory and manifest publication boundary

Two native regressions passed in Debug and Release with all candidate features.
They use actual SDK-generated prekeys in an encrypted journal, a real inventory
close/reopen, and hybrid device signatures. Trusted protocol time is the fixed
test value 150; this is not a cross-process crash or remote-directory experiment.

The first run reconstructed identical manifest bodies, body digests and every
membership proof after inventory reopen. Its two complete signed envelopes
differed in both build profiles, and signing did not change the journal revision.
The second signed different real prekey sets at the same caller-selected epoch;
both signatures and all proofs verified, while the manifest body digests differed.

These observations match the lower-level APIs' documented contracts. Different
signature bytes need not mean a different logical manifest. They do not justify
changing the body digest or forcing deterministic signatures, and are not a
vulnerability finding. The proposed owned publisher must separately reserve the
complete intent/epoch and recover a committed artifact. Retaining exact envelope
bytes is the selected SDK retry contract, not a cryptographic requirement inferred
solely from randomized signatures.

All raw public envelopes and member proofs are captured. A separate byte readback
checks the body equality/difference, unchanged context/count and proof comparisons;
the native tests perform signature verification. Strict Clippy passed for the
candidate library and tests with all features and warnings denied. No private
keys, sealed generation tokens or private journal images are included.

The proposed operation and its storage, capacity, retirement, authority and
distribution obligations are in
[`PREKEY_PUBLICATION_CONTRACT.md`](../../../../docs/continuity/PREKEY_PUBLICATION_CONTRACT.md).
No publication owner or foreign publication API has been implemented by this
change. The separately captured 2662-test preflight belongs to `61577327`, before
these new regressions and this contract document.
