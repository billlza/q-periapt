# Bootstrap manuscript modules — final independent review

## Disposition

**The corrected modules are accepted for their declared bootstrap and epoch-zero ACK experiment.** The joint-entry and source-to-schedule arguments retain the required premises, original source slots, complete descriptors, capture accounting, and late-registration order. The terminal theorem now contains a constructive, one-sided MAC comparison with the necessary record terms.

Reviewed final identities:

| Module | SHA-256 | Bytes |
| --- | --- | ---: |
| `bootstrap-authentication.tex` | `72c4f982bdf7229623ca790d83d3a2dc55ef0f6cb0f32cc832a61700f28e766d` | 24,890 |
| `bootstrap-entry.tex` | `cbd221f1b5f9ae268a4694e2256d49811106755f85991d7bfcb8fa2ee4951aaa` | 6,171 |

The exact source assessment uses commit `471900bfe8070d1021a1feb67481437d599d80ba`. The JSON retains pins for the 19 non-test message source files and the supporting mathematical modules.

## Terminal MAC correction

The initial bare sum of HMAC-row terms omitted the representation of fresh ACK keys in serialized records. Source inspection also found extra raw uses of those bytes in application reports. The revised construction resolves both points at the experiment and comparison interfaces.

Starting in the actual-record endpoint `H_R` with all registered ACKs independently randomized, mark every immutable record version containing a registered random ACK atom. Exact copies, containing images and pending intents remain marked after local deletion; public ACK tags remain ordinary row outputs. With `C_ACK` the successful acquisition of a marked object, zeroing the local terminal bit before that return costs at most `eta_mac = Pr_H_R[C_ACK]`. This local modification is separately charged even if a terminal event was already latched.

While the sampled random ACKs are still known, construct the actual records. Apply the existing real-to-opaque comparison in its required order: private-wire equality, commitments, then the opaque renderer. Its cost `rho_mac` uses the displayed 192-bit commitment and nonce-collision terms and counts every fresh seal, including failed persistence. Only after this step are the selected unknown HMAC keys installed in registration order.

On the declared operation surface, their remaining raw computation is the ACK row. The resulting bound is

```text
E_bs-mac = min(1,
  eta_mac + rho_mac + sum_r epsilon_Hrow(T_r, q_r, 107)).
```

This is a one-sided cost from `H_R` to an opaque-record, independent-row terminal experiment. The terminal guessing bound is applied there, so a second actual-record endpoint comparison is unnecessary. The global recipe stop still preserves the event already observed; the final paragraph now explicitly distinguishes that global stop from the charged local capture-zero modification.

The exact ACK input is 43 domain bytes, 15 label bytes, and a 49-byte transmitted prefix: 107 HMAC input bytes. The 32-byte tag makes the wire 81 bytes. Role 2 emits direction 1 using its receiving ACK key, which is the initiator-bound activation block 4. Role 1 uses the separately designated other-direction key and string. Counts include a keyed verification whose later floor check rejects. The continuation retains the public compression oracle, other keys, all their actual uses, and numerical coincidences; no distinct-key conditioning is introduced.

## Source cross-use census and experiment scope

Two concrete report interfaces consume the serialized ACK bytes:

| Source function | Authenticated bytes |
| --- | --- |
| `messages/closure.rs::report_mac` | `record.payload[..len-64]` followed by 64 zero bytes; the original private state remains present |
| `messages/fanout/abandonment.rs::report_mac` | Entire `record.payload` for each batch member |

These are additional private-input computations under report keys. The corrected online experiment positively lists admission, original bootstrap/resumption, Final, activation, epoch-zero ACK, restoration, named disclosures and sibling observations once. A larger application interface can add the corresponding report comparison. The image/intent commitment term has its stated record-observation meaning throughout.

## Joint-entry and source-schedule checks

The joint-entry module keeps the exact SHA-256 HMAC pad encodings and 32-byte versus 64-byte IKM formulas. Its raw cache admits the short/long alias when the known half and inner pad state coincide. Later stages use complete effective descriptors, separate padding and outer-message classes by their length encodings, and retain complete shared-oracle budgets.

The reply-source adapter fixes the original generation and encapsulation reservations before private computation, retains failed original draws, and distinguishes original fresh ML-KEM input slots from later selected ciphertexts. The expanded-owner restoration validation remains a real operation; relevant fresh honest ciphertexts use the existing collision monitor. The source-pair lemma now explicitly states the correctness event charged in its existing correctness term.

The source acquisition residual uses both actual adjacent endpoints and cumulative immutable provenance. Its real-record construction precedes opaque records and unknown challenge embedding. The complete parent/root table is formed before a hidden root is deferred to online registration. Registration is immediately before the first private ACK computation or use. Full effective root aliases use the global compression-collision bound, while all sibling values and the internal block-4 feedback into block 5 remain real before the exported ACK override.

The final readback resolved every substantive finding recorded in `REVIEW_INITIAL.json`. The derivation and source details are retained in `RECOMMENDED_REPAIR.md`; the independent initial-source adapter review is recorded separately at its final proof hash. No parent manuscript was edited by this review.
