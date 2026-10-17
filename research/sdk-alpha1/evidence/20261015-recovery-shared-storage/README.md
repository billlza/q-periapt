# Shared wrapping-key disclosure projection

Status: **cross-session disclosure and normal shared-key execution are checked;
the positive recovery theorem for this extended model remains open.** This is a
symbolic research result, not an actual SDK attack or release qualification.

The [editable model](../../../continuity-recovery-symbolic/shared-storage.spthy)
extends the key-scoped model with independently allocated wrapping keys that
sessions can reuse in either role. Captured records are explicit symmetric
ciphertexts. Signer-file encryption uses a purpose-separated hash abstraction of
the wrapping key. The earlier per-session unsealing flag and its two unsealing
rules are replaced by ordinary symbolic decryption. The original complete query
declarations, including the positive recovery formula, remain unchanged. No new
restriction prohibits disclosure.

The source motivation is concrete: `DeviceJournal::Active` owns one `JournalKey`,
and [`seal`](../../../continuity-identity-candidate/src/durable.rs) serializes all
records into one encrypted image. The same wrapping key derives the
[`signer-file encryption key`](../../../continuity-identity-candidate/src/crypto/persistence.rs).
A session label therefore does not identify an independent storage-secret owner.

| Checked statement | Search / independent replay steps | Result |
| --- | ---: | --- |
| `sibling_wrapping_key_unseals_target_record` | 36 / 85 | One sibling Cut exposes a wrapping key also used by the target. One target phase-8 capture permits knowledge of the exact target message, without target Cut or identity/entropy disclosure. |
| Same attack query with independent per-session wrapping allocation | 1 / 1 | No trace found; only Setup allocation changes. Ciphertext rules and the full attack query are unchanged. |
| `recovery_with_shared_storage_is_executable` | 50 / 171 | The target initiator and sibling responder actually store state under the same key. Target reservations follow Cut, both peers confirm before the message, and no identity/entropy/snapshot disclosure occurs. |

The two sessions have distinct IDs and three distinct wrapping keys with exactly
one cross-role overlap. Trace checks bind the record, leaked key and attacker
knowledge to the exact target payload, and inspect causal paths. The normal
witness checks the sibling's actual `!Wrap` premise and phase-4 `!Stored`
conclusion. Both witness certificates replay without `--prove`; neither imports
a reusable helper. The normal trace establishes satisfiable recovery premises,
not universal message secrecy.

The attack is outside the main theorem's premises: it has no target Cut and does
acquire a target post-reservation record. It shows why a session-local disclosure
flag cannot represent shared-key ownership. It does not contradict the earlier
positive theorem under independent wrapping keys, or establish a defect in the
SDK's documented device-level trust boundary.

The earlier 20-property proof scripts do not transfer automatically: replay
returns zero and displays the main theorem as verified, but ten required
properties remain incomplete. The complete group is rejected. A fresh search
keeps every rule and complete query declaration unchanged, but reaches its
900-second deadline without a terminal proof inventory. It is interrupted and,
after the bounded grace period, terminated (exit `-9`); no result is admitted.
This timeout is neither a counterexample nor a security proof. A focused search
and independent replay verify `traffic_key_derivation_requires_prior_root` in
169 steps each, with no prior reusable premise and all complete query declarations
preserved. Thus the first obligation closes on its own; this does not identify
which later obligation or cumulative cost exhausted the whole-group budget.
The remaining 19 universal properties are incomplete in this helper certificate.

The first normal witness exercised only the sibling initiator's distinct storage
key (44 / 140 steps). It remains in the archive; the final witness adds the
sibling responder reservation under the shared key. The initial trace verifier
looked for `Wrap`/`Stored` in graph metadata; persistent facts are named
`!Wrap`/`!Stored`. The corrected verifier preserves all substantive checks and
uses the same proof and trace bytes. The earlier verifier is retained.

This projection still has one exchange per session, freshly sampled publicly
revealed initial roots, perfect primitives and honest signing randomness. It
captures individual retained record ciphertexts, whereas the SDK encrypts a
whole journal image. A whole-image trace/knowledge correspondence, arbitrary
root ancestry, multiple epochs, concrete HKDF/AEAD/hybrid security and SDK
refinement remain unproved. Identity-file capture is still conservatively
counted as identity exposure even before decryption. A runtime cannot infer the
absence of these disclosures from local protocol progress.

`CAPTURE.json` records member digests; `READBACK.json` records a complete archive
readback. All recorded values are symbolic terms and public process evidence;
no private device or SDK test cohort is included or reopened. Existing CI replay
profiles remain the independent-identity and key-scoped models.
