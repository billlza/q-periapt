# Independent review of the bootstrap manuscript connection

## Assessment

The compressed joint-entry argument retains the required hidden-input encodings,
adaptive descriptor allocation, shared-oracle accounting and exact short/long
alias. The source-adapter and deferred-tail sections retain the original pair
slots, fresh-encapsulation monitor, two-endpoint acquisition residual, late
registration and common five-block-table comparison. The principal correction
is the new MAC instantiation: a bare sum of HMAC row advantages does not cover
the serialized ACK keys and their public record commitments.

The explicit bootstrap operation surface proposed in the review resolves the
additional application-level cross-uses without changing an execution midway.
Define it once, at the start of the online experiment: admission, original
bootstrap/reservation/resumption, Final, the two activations, epoch-zero ACK
generation and verification, checkpoint restoration, and the specified key and
record disclosures. The admitted later application interface consists of ACK
operations and the specified observations of the four sibling values.

This operation surface supplies the opaque-record interface needed by both the
source schedule and the terminal MAC argument. Full SDK session-closure and
fanout-abandonment reports have separate keyed uses of serialized state; they
are extensions of this experiment, rather than operations whose behavior can be
silently dropped in its reduction.

## Recommended terminal MAC comparison

Let H_R be the ACK-only ideal endpoint of the proved schedule comparison. Its
registered keys Z_r are independently sampled before their first use, and exact
class repeats retain the same key. Let Y be the latched Bad bit, including the
experiment's global recipe stop and hash-collision stop.

Mark every immutable record version containing a registered Z_r atom, together
with containing images, pending intents and exact copies. Marks follow typed
provenance, not numerical equality with an unrelated locally known value. They
remain attached to old versions after deletion or erasure. Public ACK tags are
ordinary row outputs, not raw key atoms. C_ACK is a successful raw acquisition
of any marked object in H_R.

Set eta_MAC = Pr_H_R[C_ACK]. A sharper valid cost is Pr_H_R[Bad and C_ACK].
The local comparison returns zero immediately before such a raw return, giving
the score Y_cap = Y * 1[not C_ACK] in the coupled complete execution. Therefore

    E_H_R[Y] <= eta_MAC + E_H_R[Y_cap].

This is a charged comparison stop. The original global recipe stop still
preserves the latched event; capture after Bad is covered by eta_MAC rather
than being reinterpreted as a harmless global stop.

Start with known sampled Z_r and construct the real records. Apply the existing
real-record-to-opaque corollary in its stated order: structural complete-wire
equality, then commitment replacement, then the opaque table renderer. A valid
one-endpoint cost is

    rho_MAC = min(1, sum_i Phi_192(d_i,Q_i) + binom(M,2)/2^192),
    d_i <= 1 + 5 K_i^hdr.

All fresh sealing attempts enter M; exact retries reuse their original seal.
Atom-free rows contribute d_i=0. The nonce equality term can be omitted for an
interface with no private-wire equality query. All public commitment replies
are consumed by that comparison world's subsequent prefixes and checks. Every
Q_i includes the full reduction and final event test.

Only after this record comparison, replace the registered ACK rows in fixed
registration order. Presample the selected uniform challenge and leave it unused
until that registration. All earlier preparation and all other locally known
keys retain their actual shared-oracle computations. The restricted source
interface uses the selected key only for its HMAC row and opaque retention;
there is no raw key return before the declared global stop. Exact repeated
messages use their cached value. Numerical equality with other sampled keys is
handled by the ordinary shared-oracle calls and the primitive advantage, with
no distinctness conditioning.

The authenticated epoch-zero string has 107 bytes, so the row cost is

    sum_(r=1)^R epsilon_Hrow(T_r,q_r,107).

T_r includes all honest generation and verification evaluations, including
verification attempts later rejected by the floor check. Each q_r bounds the
entire derived experiment uniformly over the intermediate hybrids. The last
game has opaque records and independent ACK functions on complete strings; it
retains the local capture-zero rule. Its Bad probability is bounded by
q_v/(2^256-q_v+1), since stopping with zero cannot introduce a successful guess.

Consequently the terminal contribution can be denoted

    E_MAC = min(1, eta_MAC + rho_MAC
                   + sum_(r=1)^R epsilon_Hrow(T_r,q_r,107)).

Use E_MAC in the terminal inequality. This is a one-sided cost from H_R to the
opaque-record, ideal-row terminal experiment. It is not the full distinguishing
gap from actual-record HMAC to actual-record ideal MAC. The latter would require
an additional endpoint comparison. No second acquisition probability is needed
for the stated one-sided terminal inequality: the final ideal-game bound holds
with its own capture-zero stopping behavior.

## Source census and boundaries checked

The complete non-test messages subtree at integration commit
471900bfe8070d1021a1feb67481437d599d80ba was inspected, together with messages.rs.

- Traffic::from_material makes block 4 initiator send_ack and responder
  receive_ack. Responder generation emits direction 1; initiator generation
  emits direction 2 under the separately designated block-5 key.
- The epoch-zero prefix is 8+32+1+8=49 bytes; the message domain has 43 bytes
  and the acknowledgement label has 15. The HMAC input is 43+15+49=107 bytes.
  The wire includes only the 49-byte prefix and 32-byte tag, hence 81 bytes.
- Epoch, session and direction checks precede the verification HMAC. The
  consumption-floor ceiling follows it and does not remove that keyed call
  from T_r.
- Traffic::encode_into serializes both ACK keys. For the admitted call surface,
  those bytes flow into the image/intent interface covered by rho_MAC.
- Restored live epoch-zero state has resolution Unrequested and closure None.
  Its parser does not compare the active ACK values to constants. The zero-key
  checks in acknowledged resolution apply to a state created by the separate
  application-resolution interface, which is outside the defined experiment.
- Session closure report_mac authenticates record.payload[..len-64] plus a
  canonical zero tail. Fanout abandonment report_mac authenticates each entire
  member payload. Both are real cross-uses of ACK bytes under another key;
  neither is an epoch-zero ACK row nor an image/intent commitment. This is why
  the operation surface must be explicit rather than claiming every SDK API.

## Other necessary wording adjustments

1. State registration as "Immediately before the first private ACK computation
   or use"; "at" that computation leaves the source ordering ambiguous.
2. Add the source-correctness event to the original-pair/effective-family lemma.
   Its proof uses equality of the two S0 values. The theorem already pays the
   corresponding delta_j; the lemma should expose that premise locally.
3. Say the initiator uses its separately designated A_R key, not that its key
   bytes must differ. The analysis deliberately allows numerical coincidences.

No finite execution is used as a substitute for these analytical comparisons.
