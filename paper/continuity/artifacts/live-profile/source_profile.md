# A concrete native profile for candidate-local simulation

Version 0.3 — final source mapping and hand refinement construction, 2026-11-07. Aligned with the independently reviewed, frozen joint-continuation proof v0.3, including finite multi-info challenge creation.

## Result established by this source pass

There is a concrete **live-session recovery profile** that can carry the existing record simulator into the native first-message continuation. It includes a real old-state compromise, new durable KEM reservations, crash/reopen, all three confirmation flights, asynchronous FinalReady sending, active packet/ACK validation, persistent application state and exact retries. Its selected first-message continuation can additionally permit a named successor-root projection and the selected next-chain-seed projection when supplied by the new joint branch theorem. These two projections refer to actual source fields; they are not claimed to be new public SDK APIs.

The source result is an explicit interface and representation construction. The cryptographic differences remain the existing commitment/renderer bound and the new primitive continuation bounds, with each used at its actual comparison. No recovery condition is strengthened. In particular, an allowed partial projection is never relabelled a whole-session acquisition merely to obtain a free stop.

## Fixed source identity

The inspected checkout is `1c68aa666db22d36ee136be1ec712545a9e74f03`. All 24 captured source/note files are byte-identical to the manuscript pin `228c944fc476e3e57d6c08063cacb19bca5b360e` and to the current worktree. Thus the paper's immutable-source references for these files continue to apply. `source_identity_manifest.json` records Git blob and SHA-256 identities; `source_map.json` contains 20 inspected function mappings with exact ranges. The original sources remain available at the immutable GitHub commit URLs recorded in those files. The audit execution also retained 24 byte-identical local copies under `/workspace/scratch/646fb6c54bf4/work/joc_round4/native/source_snapshot/`; the manifest's `snapshot` fields describe that audit location. Those copies are not duplicated beside the repository manuscript artifacts, and no adjacent `source_snapshot/` directory is required to use the committed map. File inventory size is not being used as a line-coverage claim.

## 1. The actual profile

Start from one valid established native session, with admitted context, identity owners, journal ownership and finite execution budgets. The storage environment is the already stated authoritative-history contract: native-generated immutable images/intents, exact pending-write reconciliation, process crashes and failed/uncertain commits, with read-only capture of retained objects. It does not restore a competing private-state fork or replace a registered object with adversarially forged disk bytes. This is a restriction on the experiment's storage interface, not an addition to message eligibility.

The application is an honest private principal. Under the selected recovered root, allow up to the declared finite budget M of distinct complete traffic information strings. At the first allocation of a fresh complete info string, the controller may mark that material and a global direction as the challenge origin, before any block of that material is generated. It cannot mark an already allocated info as fresh. The application submits one equal-length challenge pair for that marked material's selected direction and first logical send (`index=0`). Exact repeated info strings, including matching endpoint calls, inherit the same material and protected-seed identity. Application retries of the challenge use `resume_message(id)`; authorized received/resolution plaintext is delivered to the private application. The network adversary can delay, replay and replace public control, ciphertext and ACK wires, observe ordinary public errors/status, capture declared old/other/full objects, and request declared key/entropy disclosures. All predicates are evaluated in the actual comparison world's trace. The fresh marking is the challenge-creation profile, not a new condition added to E or a claim about unrestricted adaptive choice among already observed message keys.

The live core executes bootstrap completion already present in the initial state; ordinary rekey offer/response/final/receipt; `next_message_id`, one challenge `send_message`, `resume_message`, `receive_message`, consumption and ACK calls; public status and head/intent metadata; further rekey and ordinary known-input traffic. The core need not invoke closure, fanout-abandonment or closed-epoch resolution. This makes the first native bridge usable with no cleanup-report term. The existing report theorem remains an explicit extension when those calls are included, with its genuine key/secret-output residuals.

A challenge delivery does not make plaintext public. An exact challenge frame can be recognized by its actual cached bytes and passed to the private application as the original opaque input handle. Altered frames keep the real authentication/error interface; an application-message privacy theorem must provide its AEAD verification/integrity comparison, not merely an encryption-only game.

## 2. Exact root and traffic program

Let `DR` be the 40-byte string `Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/` and `DM` the 43-byte string `Q-PERIAPT-CONTINUITY-MESSAGES-CANDIDATE/v2/`. Let `H_L(x)` denote the source's actual SHA3 domain-hash with domain `DR || L`, including the length framing implemented by `crypto::digest`.

| Native operation | Actual computation | Source map |
|---|---|---|
| Pending root | `R = HKDF-Expand(HMAC(previous, S), DR || pending-root/HKDF-SHA256/ || H_response-core(core), 32)` | N04 |
| Responder confirmation | `C_r = Expand(HMAC(0,R), DR || responder-confirmation, 32)`; tag is `HMAC(C_r, H_response-core(core))` | N04 |
| Final / receipt confirmation | `C_f,C_a = Expand(HMAC(0,R), DR || final-confirmation / receipt-confirmation, 32)`; HMAC uses the corresponding actual core digest | N05 |
| Traffic material | `W = HMAC(session,R)`; `Expand(W, DR || epoch-traffic/HKDF-SHA256/ChaCha20Poly1305/ || context[32] || be64(epoch) || H_traffic-transcript(offer||reply),128)` | N06 |
| Four leaves | Direction-1 seed, direction-2 seed, ACK-1 key, ACK-2 key, each 32 bytes; role 2 swaps local send/receive ownership | N06 |
| Chain step 0 | `next || K = Expand(HMAC(0,seed), DM || chain || be64(0),64)` | N07 |
| Message | ChaCha20-Poly1305 under `K`, nonce `0^96`, `AAD=DM||aead||header[93]||be16(len(ad))||ad` | N07–N09 |
| ACK | HMAC under the direction's ACK key over `DM||acknowledgement||wire_prefix`; target-epoch prefix has tag, session, role, epoch and receive floor | N10 |

The traffic info contains the **whole produced signed response**, so it is computed after the responder confirmation tag and signature. It must be recomputed in each hybrid's own execution. This is an adaptive but fully available info string; freezing the original world's reply would change the source program.

The source locks the complete response during completion (`accept_rekey_response`, lines 783–792) and checks the final against the responder's own saved offer/response (`finish_rekey`, lines 983–994). We do not turn those local checks into an unproved assertion that one root can only feed one complete traffic info across every active history. Instead every actually encountered complete info is registered; distinct infos use distinct material identities, while exact repeats reuse their existing identity. The finite API execution budget bounds M. This preserves active control-wire processing without requiring a separate global wire-uniqueness premise.

The measured source lengths are in `native_kdf_encodings.json`: confirmation Expand inputs have lengths 63, 59 and 61; traffic Expand inputs have lengths 156, 188, 188 and 188; step-0 inputs have lengths 57 and 89. Therefore even if `session=0` and the two Extract salts alias, the confirmation and traffic inputs are distinct by length. Later traffic blocks are distinguished by their final counter byte. Equal salt bytes must share the same row; the session constructor does not exclude all zero (N19).

The current/pending root is never tested for nonzero in the checked live paths. `key()` checks width and copies. Active seeds also accept every 32-byte value. The zero checks in `Traffic::decode` are erasure invariants for already closed/exhausted fields; the corresponding transition first explicitly overwrites that field with zero. Acknowledged resolution does the same for all four leaves (N14). Thus there is no additional source-level rejection event for an otherwise valid fresh root/active seed equal to zero. Primitive collision/alias bounds retain their own treatment.

## 3. Source transitions and representation invariant

Use a ghost source ledger, not an invented Rust field: an actual `RecoveryKey::reserve` draw gets an original invocation slot; a successfully retained session payload gets its immutable semantic version; each fresh outer seal gets a distinct sealing invocation. This separates original KEM entropy from its token nonce and the later image nonce.

| Step | Source action | Invariant used by the simulator |
|---|---|---|
| Reserve generation/encapsulation | Draw original tape, construct the bound token, install `Plan::Key` or `Stage::Encapsulation`, persist before replay | Original token/source handle and binding fixed; `res(o)≤save(v)` (N02–N03) |
| Execute / exact restart | Reopen and consume the same token with its original recorded inputs | F returns that origin's public key or ciphertext/shared value; no fresh KEM slot is created (N02–N03) |
| Pending root / signatures | Persist source phase with root, public body and a locally known signing reservation | Public body and signatures use the actual returned confirmation output; private root may be an opaque handle (N04–N05,N12–N13) |
| Proposer FinalReady | Install traffic, close old send, set `state.rekey=root`, persist FinalReady | New send epoch is active before receipt; receive epoch remains old (N11) |
| Responder receipt commit | Install traffic, close old send and receive, replace root, complete control, persist | Both directions advance at the actual durable transition (N11) |
| Proposer accepts receipt | Check signed receipt/MAC, close receive and complete history | No second traffic allocation and no second root replacement (N11) |
| Reserve application input | Persist exact `SendPlan(id,mb,ad)` before encryption | `mb` can be an opaque private-input handle of known length (N08) |
| First private encryption | Derive step output, form exact header/AAD, encrypt, advance transaction-private seed and insert outbox | Cache the encryption reply by send origin at this point, even before network release (N07–N08) |
| Failed/uncertain persistence | Reopen original retained reservation or exact committed target | Recompute the same tuple or replay the original ciphertext; never grant dispatch merely because the simulator has cached it (N08,N15) |
| Receive / ACK | Authenticate on a transaction-private candidate, commit success, privately deliver/consume, verify ACK and advance floor | Real error outcomes remain; ACK retirement never resets the sending counter (N09–N10) |
| Reopen / validation | Decode only native-generated registered handles; check phase, widths, known metadata, public signatures and listed confirmation results | Unknown values are used only by the declared primitive calls or by persistence, not an unmodelled live zero test (N12–N14) |

For the KEM-stage native-to-record comparison, F is the **specified list of real native operations**: bound reservation replay, public-key extraction, encapsulation, decapsulation, the above root/confirmation/traffic schedule, application AEAD and ACK operations. It holds the original state in the materialized experiment. A component or hidden-root reduction replaces those concrete calls using its own established adapter, rather than receiving an unexplained all-protocol oracle.

The outer journal-intent prefix also remains available to this simulator. Ordinary message persistence goes from `store_message_state` (messages.rs:424–435) through `persist_attempt` (durable.rs:906–911) to `write_intent::commit` (write_intent.rs:637–646), which calls `PendingWrite::new` and `new_bound(...,None)` (129–132). Thus it selects QPWINT01 and carries only journal ID/owner, old/new revisions, old/target image digests and target length before the complete encrypted target (174–182). It contains no clear `send-intent(mb,ad)` field. These ciphertext commitments retain their existing joint image/intent rendering comparison; they are not treated as plaintext-independent without that comparison.

For the later hidden-message step, retain opaque handles not only for hidden root/seed/key values, but also for the selected `mb` and its `send-intent` digest. `SendPlan` contains plaintext; `Outgoing` contains its digest. Neither value is returned by `message_status` or the checked historical metadata, which expose an enum or lengths (N16). A pending `resume_message` recovers the original plan and compares it to the same immutable input; a committed resume returns its cached wire. Those branches do not need the simulator to learn the AEAD challenge bit.

## 4. The concrete record bridge

Fix one candidate pair and a declared opaque family. Include every private field unavailable at the relevant proof stage: selected reservation/token values for the KEM adapter; the hidden root/seed and application input/intent for the joint/message adapter. Keep all nonopaque values materialized and all corresponding public hashes real. Only records with a designated private atom enter the private commitment replacement.

The source correspondence to a materialized typed record machine is exact on the profile above. Prove it by induction on accepted native calls and storage outcomes:

1. Initially, the pre-cut state and registered directory have the same actual bytes, state and metadata.
2. The actual reserve and persist order registers one original slot/token and one original saved version. Encode/decode preserve fixed widths, phases and recorded bindings. Actual core calls do not rebind the token to a different input.
3. A protocol transition obtains the concrete outputs listed in §2, then builds the same payload recipe and known metadata. Reopen checks use those same outputs and phase guards. Signatures and public transcript hashes are computed from that world's actual bodies.
4. A fresh image or intent uses the exact constructors in N15. A pending target is retained before apply; apply copies its original bytes. Existing registered-handle equality and ordinary error outcomes are preserved. A crash changes the active owner but does not invent or erase a retained target.
5. Known-output metadata/captures return the same values. A certified whole-session capture stops at zero before unknown bytes are needed. A separately charged projection stops before its actual exposed result. These monitors use source handles and declared operations, not an unknown secret's raw value.

Now apply the existing real-record-to-table theorem to this instantiated typed machine, with the same concrete F and stopped score. For the live core,

\[
 \rho_j^{\rm live}\;\le\;
 2\min\{1,\epsilon_{{\rm com},j}+\delta_{{\rm nonce},j}\},\qquad
 \delta_{{\rm nonce},j}=\min\{1,{M_j\choose2}2^{-192}\}.
\]

The nonces/intent prefixes and `M_j` count actual fresh invocations, including seals whose later commit fails; copies and exact pending-target application retain their existing handles. The commitment theorem's full oracle-query accounting and admitted known-input/nonce-confinement conditions are used with the actual source domains. Where private-wire equality is absent, the renderer's additional nonce-collision term disappears as in the existing theorem.

This bound is for the record connection with its concrete primitive interface held fixed. The actual component and joint-root adapters then pay their respective cryptographic terms. The source construction is not a substitute for those primitive comparisons. If cleanup reports are enabled, use the actual stopped report interface and add its score comparison `2 epsilon_rep` once in the local comparison chain; a key-only fragment must still retain its genuine original-game residual.

## 5. Permitted captures and projections, without changing E

| Actual observation | Treatment in this profile | Reason |
|---|---|---|
| Old pre-cut target-session version, and its journal key | Return actual known bytes/key | The version retains its original save time and no selected later reservation. It supplies the intended compromise. |
| Other-session or atom-free records, header/metadata with no private-wire nonce exposure | Real computation and actual return | Inputs are available; these rows are not replaced. |
| Full image, full pending target or complete selected-session version saved at/after a member reservation | Free `U_j` | Matching subject plus `res(o)≤save(v)` implies every attributed eligible cut is before the acquired version. No decryption test is needed. |
| Actual target signing-file/key or designated target-epoch entropy disclosure | Original predicate's free stop, when its exact identity/slot matches | Use the already existing identity/entropy event, not a guessed source label. |
| Public head, pending intent digest, native status/length/ciphertext-digest metadata | Retain the commitment/table reply or real known-input output | These do not contain a full private version or an unhashed plaintext commitment. |
| Successor-root-only field with verified epoch/phase ownership | Return the computed successor value through the joint continuation | This is an explicitly stronger projection over the actual root field, not a Snapshot; it must expose neither selected R nor a full post-cut session version. |
| Selected next-chain-seed-only field after the first send's durable advancement | Return the independent next leaf provided by the joint continuation | The original current seed and message key remain separate; a precommit old seed is not mislabelled as next. |
| Opaque token ciphertext, selected current root/seed/message key, unknown private payload slice | Actual charged `B_j` unless another already defined rule independently supplies U | A partial object does not automatically acquire an intact session version. |
| Outer private-image nonce or a private-wire partial projection | Preserve the original view by a charged stop for the existing record hop | Even a locally known nonce cannot simply be revealed in a comparison whose commitment bound uses its hidden fresh entropy. Normal public head/metadata APIs do not expose it. |
| Guessing `Send(challenge_id,m)` or public target plaintext/send-intent | `B_app` if this extended caller capability is admitted | It can reveal the private input without changing the existing E; the live profile instead uses private application ownership and Resume-only challenge retries. |
| Batch-only protected report-key fragment | Actual protected-report-key residual in the optional report extension | Its own record does not contain the member's intact session version (N18). |

The charged events remain events in the **one original native run**. Candidate-local accounting charges only the final attributed candidate's actual projection event. An event that affects another candidate is not a global halt.

The source has an important exact distinction for the last application row: on an occupied outgoing ID, `send_input` returns its cached wire iff the submitted input digest matches, otherwise `Conflict` (N17). For two chosen equal-length messages with distinct such digests, an adversarial retry of `m0` reveals the challenge choice. This is why an all-client-API privacy claim would be false. It is not a defect in the product's intended idempotent caller API. The declared network/capture experiment keeps that caller private and still retains active network authentication and ACK checks.

## 6. Exact ownership of stronger projections

`State::encode` places the current `rekey` bytes at session-payload offsets `[73,105)`. Their epoch is the installed root epoch: during proposer FinalReady this is the new send epoch although `control.confirmed_epoch` is still old. `Control::validate_epochs` enforces the corresponding `(new_send,old_receive)` phase. Thus a source mapping must use the actual phase/field owner, not only a confirmed-epoch counter.

A root in `response::Stage::Signing/Ready` or `completion::FinalSigning/ReceiptSigning` belongs to `control.target()`. At FinalReady the plan no longer carries that root; it is already in `State.rekey`. A successor-only projection first checks that this actual owner is the intended successor, then returns those 32 bytes. If the only available field is still the selected current R, it is not the permitted successor projection.

The selected next seed is the `Traffic.send` field after committing the selected first send, with `sent=1`. Before that commit, the durable field can still be the selected old seed even though a transaction-private candidate has computed the next one. This distinction is preserved across uncertain commits. Later retained copies keep their source step, so a later seed is not relabelled as the original next leaf.

## 7. A nontrivial source-realizable compromise/recovery witness

This is a construction from the native calls, not a new executed benchmark receipt.

1. Activate an established session at epoch 0, retain version `v0`, and place cut c after its save. Capture `v0` plus its actual journal wrapping key, exposing the old `State.rekey` and old traffic state. Keep the identity signing owners with the honest peers; the source's existing disclosure fixtures already make this separation explicit (N20).
2. After c, call `prepare_rekey_offer`; its key reservation g is durably saved before execution. A process crash at this point is allowed. Reopen the original directory and resume the same offer without creating another g.
3. Call `respond_rekey_offer`; its encapsulation reservation a is also after c and saved before execution. Obtain the actual response and responder confirmation.
4. When the proposer first allocates the response's complete traffic info, mark this fresh material and the proposer's outgoing direction before generating its four blocks. Accept the response and commit FinalReady and the new send state. The public final can be delayed; a new-epoch application send is locally permitted at this boundary. For the marked direction's first send, reserve the private challenge input, permit an uncertain persistence/reopen, and recover the same original ciphertext through `resume_message(id)`. The matching peer later reuses the same complete info; this witness uses M=1.
5. Deliver final/receipt as needed for the receiving direction, deliver the challenge frame privately to the honest application, consume it and exchange ordinary ACKs. Public status, head commitments and metadata remain visible throughout.
6. Complete the next honest rekey using subsequent contributions, which may be disclosed as allowed later-epoch data. Permit a named successor-root-only projection and a retained post-first-send next-seed-only projection; the joint continuation must simulate these exact fields together with the public confirmation/ACK view.
7. Select the original accepted first send. Its reservations are both after c; its original pair is unique by the honest matched offer/response execution; no selected-session version saved after c was acquired in full. The old captured version still has `save(v0)≤c`. The original E and A therefore have a nonempty honest branch even though old private state, the journal wrapping key, later contribution data, successor root and next seed are available to the attacker.

The branch exercises an actual compromise and durable recovery, not a no-disclosure warm-up. Full later record capture remains an allowed request and simply invokes the original score's free-stop certificate; the proof has not removed that request or redefined its eligibility effect.

## 8. Frozen alignment and review

Completed: original-operation/storage source map; actual root/confirmation/traffic/ACK program and lengths; salt aliases; zero-value admission behavior; FinalReady ownership; actual private-input/retry behavior; typed capture rules; constructive nontrivial trace; instantiated record-interface argument.

The joint h-oracle treatment, Gamma aliases, finite M allocation identity, exact Expand-table rewrite, selected-seed freshness, active receive adapter and challenge-bit-independent gate have completed independent review against `joint_continuation.md` v0.3 and both frozen TeX modules. The repository manuscript layout places this source map in `artifacts/live-profile/` and the proof/review records in the adjacent `artifacts/joint-continuation/`; `independent_review.json` binds the reviewed source hashes. The local working review is retained at `/workspace/scratch/646fb6c54bf4/work/joc_round4/theory/independent_review.md`. No native code, manuscript, remote branch or CI run has been changed by this source pass.
