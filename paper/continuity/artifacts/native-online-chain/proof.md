# Original native experiment and online chain composition

The complete formal statement and proof are in `../../native-chain-composition.tex`. This record fixes the interfaces and costs used in their integration. Statement labels identify the canonical results independently of numbering.

## 1. The experiment

Start with the original established-session native live core: one authoritative history per endpoint, passive retained copies, public control and plaintext-free Resume interfaces, and one private left-or-right application operation. Fix the chain lifetime `1 <= L <= 2^64 - 1` and every comparison's whole-execution resource budgets before interaction.

For each candidate `(g,a)`, the original generation and encapsulation slots remain those of the executed-slot selector. Preserve three distinct online designations:

1. Designate the original effective ContextBound tuple `m*` immediately before its first private hash computation through any protected alias. The complete ten-field tuple includes the other component secret. The original source slot and the hash-table equality class remain distinct identities.
2. Designate the complete traffic information entry `I*` and direction before its first traffic-block allocation. Root-schedule aliases with equal information share their material handle. Independently allocated materials retain different handles even if epoch, index or numeric values coincide.
3. Immediately before a previously unseen private chain call in that selected material and direction, choose Continue or Mark using the available transcript and the public step descriptor. Mark occurs at most once, at an index below `L`. The ledger is indexed by original material, direction and index. A sender call, a receiver's skipped-step computation, or a failed receive attempt can be the first call. Rolling back native transaction state does not roll back this original-computation ledger.

Only pre-Mark Continue steps permit the additional earlier-message-key projection. Their seeds and Extract values keep private handles. After the marked pair is derived, its individual successor seed may be disclosed. Suffix work then evaluates the actual chain from that successor. The complete declared successor-root, opposite-direction and other-entry observations remain available.

These are named individual projections, with identity fixed at the corresponding allocation. Acquiring an entire image retains its entire session-version scope. The fact that an image contains an available successor seed does not change the acquisition predicate for its other contents. Its immutable version save time is retained when it is copied or resealed.

The one left-or-right operation stays attached to the marked original send. A rejection, uncertain outcome, failure or retry does not move it to another index or material. The terminal selector must identify the same accepted logical send and its original reservation handles; if no such send is reached, the original valid-target condition is false. The predicate `E` is the original native eligibility predicate evaluated on this controller's execution.

A receiver can reach the marked step before the challenged sender. The one-key AEAD games therefore permit classical decryption calls before their at-most-one encryption call, preserving actual pre-encryption replies. After challenge encryption an exact challenge decryption returns the established authenticated marker. The confidentiality and integrity costs refer to these explicit operational games.

## 2. Native correspondence

The traffic constructor assigns each peer's send seed to the matching peer's receive direction. The complete installed schedule and traffic information determine its material identity. Equal-input resumptions preserve that identity; separate original allocations do not merge on a truncated epoch/index identifier.

Induction over actual private calls gives one deterministic Extract/Expand pair per material, direction and index. At zero the seed is the selected traffic block; thereafter the predecessor successor and fixed native domain/index determine the inputs. A failed receive can compute several steps and discard its candidate state. Those calls nevertheless occurred, so they remain in the proof ledger and deny a later retroactive mark. Reusing a retained skipped message key introduces no fresh call.

The sender first retains a pending plan binding message identifier, plaintext and associated data. Its first persist precedes the chain step and encryption. A failed first persist performs no encryption. A later failure recovers either that retained plan or its already committed outbox. The plan checks reject a changed intent, while an exact retry reuses the original tuple. Thus the marked step invokes the one-use encryption interface at most once, even if its first chain computation was at the receiver.

The private-image representation carries the same handles. The original candidate-local free stop is certified by an acquired intact version of the selected session saved after at least one candidate reservation. Since eligibility places the selected cut before both reservations, every continuation after that certificate has a false candidate eligibility conjunction. This reasoning depends on reservation and version times, not on the later marked index. Whole post-cut captures remain subject to it; old and unrelated versions keep the established correspondence. The newly named individual observations are already supplied by the prefix interface, so the live-core charged projection event stays empty.

## 3. Native score and event bounds

Let `eta_attr = Pr_native[E AND NOT A]`. Let `epsilon_rec,j` be the existing whole-execution live-core record event cost, `a_j^+` and `a_j^-` the two operational component-event advantages, and `delta_j` the existing component correctness term. Write

```text
B_chain,j = min(1,
    2 Phi_256(d_j,Q_H,j)
  + 2 Delta_init,j
  + 2 Delta_prefix,j(L)
  + 2 epsilon_AEAD,j).

Adv_msg_chain <= min(1/2,
    (eta_attr + sum_j [2 epsilon_rec,j
                      + a_j^+ + a_j^- + 2 delta_j + B_chain,j]) / 2).
```

The original score is first partitioned in its native game. Each candidate's own comparisons then recompute the same available terminal event. Record simulation costs `2 epsilon_rec,j`, component comparison costs `a_j^+ + a_j^- + 2 delta_j`, and the complete-tuple and single native root-entry comparisons cost `2 Phi_256 + 2 Delta_init`. The resulting uniform-root continuation is exactly the completed online prefix interface. Its qualified signed-score cost is `2 Delta_prefix(L) + 2 epsilon_AEAD`. No comparison assumes that a selector or eligibility outcome stays the same in another hybrid.

For integrity, latch `Bad_msg_chain` at a successful fresh authenticated receive/inbox installation under the marked step. At that time its complete associated-data/ciphertext pair must be absent from the earlier honest private encryption ledger for this material, direction and index. A later encryption does not erase the event. Accepted-send provenance selects that historical event at the end.

For the operational component adapter whose Boolean output is `E AND A AND I=j AND Bad_msg_chain`, denote its advantage by `a_j^msg`. Then

```text
Omega_chain,j = min(1,
    Phi_256(d_j,Q_H,j) + Delta_init,j
  + Delta_prefix,j(L) + epsilon_INT,j).

Pr_native[E AND Bad_msg_chain] <= min(1,
    eta_attr + sum_j min(1, epsilon_rec,j
                          + a_j^msg + delta_j + Omega_chain,j)).
```

Each Boolean comparison is charged once. The free-stop certificate also applies if the recorded inbox event predates the accepted challenge send, because the final conjunction still includes original eligibility. In the ideal selected-key experiment an early successful fresh decryption already supplies a valid integrity witness; the reduction may return it immediately. This proves the upper bound even when the target's first computation is receive-side work.

In both inequalities the executed-slot selector bounds the corresponding original-game attribution residual by the established fresh-signature/framed-collision term `Delta_attr`. Its retained-plan induction associates each installed traffic entry with its original KEM calls before message selection. Chain progress and exact aliases preserve that association. The expanded signature adversary includes the full later controller, so its ordinary ML-DSA bridge and all associated budgets include this work.

## 4. Cost and evidence boundaries

`Delta_prefix(L)` contains the original three joint root/traffic comparisons and the two chain comparisons for each potentially protected prefix index. It excludes root initialization, which is explicitly added above. At `L=1` it is the established first-message schedule cost. There is no additional combinatorial message-index guessing factor; other whole-execution budgets may grow with the longer run, including source-attribution, record, component, ContextBound and suffix work.

The new theorem establishes selected-message integrity. The retained selected-root theorem separately establishes confirmation and first-message integrity, with its own confirmation-row and guessing terms. Both formal statements remain available with their stated event definitions.

The finite controls exercise the concrete bookkeeping risks: wrong material/direction marks, retrospective marking after failed receive work, record-version/candidate scope, private origin timing and historical forgery events. The stored source copies authenticate the exact operational order. The mathematical reduction and its independent review supply the security argument; prior native executions and formal-verifier evidence keep their original identities.
