# Record-aware terminal comparison for bootstrap authentication

This note records the added composition argument used by the manuscript's
historical responder-activation theorem. The complete original-source and
schedule reductions are retained in `reply/proof.md` and `terminal/proof.md`;
the exact short/long entry is retained in `entry/proof.md`. The final theorem
and all definitions are in `bootstrap-authentication.tex`.

## Experiment and terminal event

Fix the manuscript's bootstrap/ACK operation surface: original reservation and
resumption, context admission, Final, both message activations, epoch-zero ACKs,
checkpoint restoration, the specified disclosures and sibling observations.
The global recipe guard stops before returning a reconstruction of any already
registered ACK key. Its terminal event is latched at the first registered
initiator connection that succeeds without a preceding durable responder
activation of the exact signed transcript. Global recipe stops preserve this
latched event.

The original-source schedule comparison yields an endpoint H_R in which each
registered initiator-bound ACK value is a cached independent 32-byte key.
Registration occurs immediately before the first private computation or use
at either endpoint. Both endpoints and exact retries share that value. The
actual five-block activation Expand is evaluated first: its internal block 4
still feeds block 5, and only the exported ACK value is replaced. Siblings and
numerical key coincidences retain their actual distribution.

## Immutable ACK record marking

For each registered replacement key, mark every immutable serialized version
that contains that key, including containing image/intent versions and their
copies. Carry marks through every intermediate reduction and through deletion
of local records. The acquisition event C_ACK occurs at any successful
raw-byte acquisition of a marked object, including a containing image, intent
or copy, irrespective of whether its key material is readable. Let
eta_MAC = Pr_{H_R}[C_ACK]. The tighter event-intersection probability may be
used when available.

Modify the output bit to zero on C_ACK. This is a local output modification,
and can erase a terminal event observed earlier. Its one-sided probability
cost is at most eta_MAC, because the two experiments otherwise have identical
execution and output. It is distinct from the global recipe stop above.

## From real records to opaque records

All registered replacement keys are sampled values known to this reduction.
Apply the existing real-record to structural-equality comparison, then the
complete commitment replacement and opaque renderer, to all marked versions
and their immutable containment closure. Use the complete experiment's framed
query budget and original nonce allocation count. The resulting rho_MAC is the
same record-cost interface used in the preceding source comparison, including
the Phi_192 term and original-nonce collision term.

The renderer preserves equality, version identity, guard checks, copy lineage,
failure behavior and all unmarked observations. Acquisition of the selected
marked material is already assigned output zero, so the simulation never
needs to reveal an unknown target row key on a scored execution. Hiding the
record commitments precedes all changes to the ACK HMAC rows.

## Registered ACK rows

Replace the ACK rows in registration order. At a selected rank the key is
uniform and no earlier admitted operation has computed with it as an ACK key;
the record interface is now opaque. The reduction delegates the selected
key's ACK computations and verifications to its row oracle and evaluates
other keys locally under the same compression oracle. It retains all
numerical coincidences rather than conditioning on their absence.

The admitted surface's raw post-registration use of that selected value is
the epoch-zero ACK HMAC. Its authenticated input is the 43-byte message domain,
the 15-byte acknowledgement label and the 49-byte wire prefix: 107 bytes in
total. Both real generation and every keyed verification are counted in T_r
and q_r, including verification before a later consumption-floor rejection.
These are complete continuation budgets, so work outside the selected row
remains in the reduction. The row replacement costs
epsilon_Hrow(T_r, q_r, 107).

Summing the local output modification, real-to-opaque record comparison and
registered-row comparisons gives the one-sided terminal-event cost

    E_bs-mac = min(1, eta_MAC + rho_MAC
                       + sum_r epsilon_Hrow(T_r, q_r, 107)).

Its endpoint has opaque records and independent ACK rows. A fresh accepted
ACK prefix/tag at a registered row then has the ordinary independent-tag
guessing bound. If the prefix/tag was previously produced by the honest
responder on the same registered class, source ordering already supplies its
earlier durable activation. Exact repeats preserve that history. The
collision monitor binds the complete Initial and Reply wires, the session
identifier and activation class. Adding the source/schedule comparison and
the monitored collision event yields the manuscript theorem.

This is a one-sided event comparison ending at opaque records, which is the
interface required by the terminal theorem. It does not require a second
real-record PRF endpoint. The full message-source census and independent
review bind the exact admitted operation surface and the final manuscript
equations.
