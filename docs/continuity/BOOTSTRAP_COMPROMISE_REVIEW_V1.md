# Bootstrap construction and compromise review v1

Prepared on 2026-11-07 against source commit
`cc3d414b0731bd820ab5a0d847fcfcbe18546c36`. The bootstrap implementation paths
reviewed here are unchanged from the release plan's protocol checkpoint
`228c944fc476e3e57d6c08063cacb19bca5b360e`.

This document completes the source and evidence assembly for the
**stage-specific bootstrap construction/compromise matrix** requested by the
[0.2.0 admission plan](RELEASE_0_2_ADMISSION_PLAN.md). It records the implemented
construction, the exact authority granted at each stage, and the implications
of specific secret disclosures. It supplies material for the existing
[external review](EXTERNAL_REVIEW_BRIEF.md); it records no external approval
and makes no change to the release's acceptance criteria.

## Review result and evidence convention

The implemented construction has a non-circular derivation graph, distinct
initiator/responder signatures and confirmation keys, durable one-time-prekey
consumption coupled to the response outbox, and an epoch-zero ACK check before
the connection client reports establishment. A retained classical-component
disclosure experiment demonstrates why signed-body acceptance and agreement on
the complete signed-wire root are different stages. The corrected native
carrier and the portable carrier enforce the additional root-bound proof.

The existing [protocol permissions](PROTOCOL_V1.md#bootstrap-and-confirmation-permissions),
[bootstrap specification][bootstrap-doc], [wire contract](WIRE_V1.md#session-policy-and-bootstrap),
and [state contract](STATE_MACHINE_V1.md) already describe these mechanisms.
This review joins them with the source and compromise cases; it does not
replace their operation, storage, or encoding contracts.

Evidence labels used below are:

| Label | Meaning |
| --- | --- |
| **R** | An identified retained record documents an executed test or interoperability outcome. Its original revision, scope and run identity remain attached. |
| **S** | A conclusion derived from inspected source, or an assertion present in an identified test's source. This review did not execute that test. |
| **U** | A specifically identified cryptographic proposition whose general proof remains unresolved in the existing construction review. |

An R result can also have an S explanation. A test source is not silently
promoted to an execution receipt, and a successful concrete execution is not
promoted to a general KCI or AKE theorem. No tests, CI jobs, providers, wire
formats or admission rules were changed or rerun for this document.

## Terminal-agreement assessment — 9 November 2026

The [terminal-agreement assessment](BOOTSTRAP_TERMINAL_AGREEMENT_V1.md)
proves exact full-wire correspondence at responder Final acceptance and derives
historical responder activation from initiator READY acceptance under an explicit
online protected-family ACK-key schedule and multi-key MAC experiment. The conversion preserves
exact retries, same-body signature aliases and the distinction between the
bootstrap root and its initial rekey-root output. Its source correspondence and
executed public-input controls are retained in a separate
[evidence packet](../../research/sdk-alpha1/evidence/20261109-bootstrap-terminal-agreement/README.md).
The cryptographic dependency is the specified joint schedule under the selected
disclosures; the terminal conversion is now a completed input to that assessment.

## 1. Secret names and the actual derivation graph

Let **I** be the bootstrap initiator and **R** the responder. The context `ctx`
binds the fixed suite; exact protocol policy and SDK policy binding;
role-ordered accounts, devices, generations, credential digests and roster
authority; the complete authenticated prekey selection; and the independently
supplied directory checkpoint. `BootstrapContext::new`,
`from_historical_inputs`, and `check` implement this correspondence
([source][bootstrap-source]).

| Symbol | Actual source value |
| --- | --- |
| `S0` | ContextBound hybrid secret from I's encapsulation `C0` to the authenticated responder prekeys. |
| `sk_reply` | I's fresh hybrid reply private key, retained by its original initiation. R encapsulates `C1` to its signed public key. |
| `S1` | ContextBound hybrid secret from that responder encapsulation. |
| `K0` | SDK purpose-derived initial-confirmation key from `S0`, bound to `t0`, policy and the `InitiatorConfirmation` purpose. |
| `seed`, `KR`, `KI` | Separately labelled HKDF outputs from `S0 \|\| S1` and reply-core digest `t1`. They produce the bootstrap root, responder confirmation and initiator confirmation respectively. |
| `K_B` | `PendingSession.root`, derived from `seed`, the session ID and `ctx`. |
| `R_0`, `T_0` | Separate outputs of message activation: a 32-byte initial rekey root and 128 bytes of epoch-zero directional traffic/ACK material. |

The public transcript and KDF order are, using the exact domain-separated
hash operation documented in [BOOTSTRAP.md][bootstrap-doc]:

```text
C0, S0 = Encapsulate(selected responder public keys, initial KEM context)
t0     = H("initial-core", initial prefix || C0)
MAC0   = HMAC(K0, t0)
Initial = initiator-signed(initial prefix || C0 || MAC0)
H0      = H("initial-wire", complete signed Initial)

C1, S1 = Encapsulate(reply public key, reply KEM context containing H0)
t1     = H("reply-core", reply prefix || C1)
seed   = HKDF(salt=t1, IKM=S0||S1, label="handshake-seed", 32)
KR     = HKDF(salt=t1, IKM=S0||S1, label="confirmation-responder", 32)
KI     = HKDF(salt=t1, IKM=S0||S1, label="confirmation-initiator", 32)
MACR   = HMAC(KR, t1)
Reply  = responder-signed(reply prefix || C1 || MACR)
H1     = H("reply-wire", complete signed Reply)

F      = Final tag || ctx || H0 || H1
MACI   = HMAC(KI, H("final-core", F))
sid    = H("session-id", F)
K_B    = HKDF(salt=sid, IKM=seed, label="session-root/"||ctx, 32)

R_0 || T_0 = HKDF(salt=sid, IKM=K_B,
                  info=message initial-domain||ctx, 160)
```

Here the three bootstrap labels and the session-root label include the full
`Q-PERIAPT-CONTINUITY-BOOTSTRAP-KDF-CANDIDATE/v1/` prefix.
`bootstrap::{initial_key,schedule,derive,final_prefix,pending}` and
`durable::messages::State::new` implement the graph. `Traffic::from_material`
splits `T_0` into two 32-byte chains and two 32-byte ACK keys
([bootstrap][bootstrap-source], [activation][messages-source],
[traffic][traffic-source]). **S; R4 corroborates an independent live bootstrap
and confirmation, while T1 below identifies the independent synthetic vectors.**

This notation matters for compromise analysis. `K_B` is the bootstrap root;
the subsequently stored `State.rekey = R_0` is a different value. The epoch-zero
ACK is derived through `T_0`, not by expanding `R_0`. Exposing `K_B` reconstructs
both outputs; exposing only `R_0` is not the same source-level disclosure. For
positive rekey epochs, the separate equations in
[RECOVERY_DEPENDENCIES_V1.md](RECOVERY_DEPENDENCIES_V1.md) apply.

Both complete signed flights enter `sid` and `K_B` after their signatures have
been produced. Their signatures and confirmation inputs therefore do not depend
on the final root they help identify. The initial flight contains bootstrap
material, with no 0-RTT application payload field. **S.**

## 2. Stage and output-permission matrix

The phase names below are the actual `DurableStatus` variants, rather than new
protocol states. The volatile bootstrap objects perform cryptography; the
journal grants durable output permission; the connection layer additionally
checks peer establishment evidence.

The staging implementations are [InitiationPlan][initial-plan] and
[ResponsePlan][response-plan], with [initiator journal operations][initiator-source],
[responder journal operations][responder-source], and the
[shared journal commit/release methods][journal-source]. The inventory's
[consume/validation code][prekey-source] supplies the one-time boundary.
Connection enforcement is in the native [client][native-client] and
[server][native-server], portable [client][portable-client] and
[server][portable-server], and shared [ACK verifier][ack-source]. Current
authority is resolved by the [journal roster layer][roster-source] and
[retained-session identity layer][retained-source].

| Stage | Checks and retained state | Permitted result at this layer | Source and evidence |
| --- | --- | --- | --- |
| **B0: admit the public context** | Independently pinned account/roster and policy inputs; both device identities; allowed prekey quality, membership/selection, time and directory expectation; exact local SDK runtime. Historical reconstruction does not recreate a current runtime owner. | Public verified metadata and an admitted context. The context digest is a commitment, not a session or commit capability. | `BootstrapContext::{new,from_historical_inputs,check,current_policy}`; `bootstrap_bundle` verification. **S; T1/T6; R4**. |
| **B1: commit Initial** | `InitialKeyReserved` → `InitialKemReserved` → `InitialSignatureReserved` → `AwaitingReply`. The journal retains the original reply-key/encapsulation/signing reservations, then the exact signed Initial and private reply state. Initiator signature purpose is 5. | Dispatch/replay the committed Initial. `S0` and the reply private owner remain private. No application payload is delivered by this flight. | `InitiationPlan::{reserve,advance,complete}`; `DeviceJournal::{initiate,resume_initial}`. **S; T1/T2**. |
| **B2: authenticate and prepare Reply** | `admission/query_id` checks the initial signature and context before an operation is recorded. `Executing` reserves the original request and selected one-time fingerprints before decapsulation/MAC0 verification. Successful `ResponsePlan::reserve` retains authenticated `S0`, nonce and a sealed responder encapsulation; phases continue through `ResponseKemReserved`, `ResponseSignatureReserved`, `Prepared`. Invalid MAC0 becomes `Rejected` and clears the claims. | A prepared private result; the fresh response is not released from `Executing` or a reservation-only phase. Exact recovery continues the original operation. | `durable::responder`, `ResponsePlan`, `DeviceJournal::release_prepared`. **S; T1/T3/T4; R4**. |
| **B3: commit and release Reply** | From `Prepared`, `release_prepared` calls `prekeys::consume`, sets `AwaitingFinal` and persists them together. It rechecks context and durable release authority. Responder signature purpose is 6; MACR confirms the joint contribution against `t1`. | Dispatch/replay the exact committed Reply. Selected one-time inventory tokens become consumption tombstones in the same transaction; reusable prekeys remain reusable under their declared mode. | `release_prepared`; `prekeys::{consume,validate_image}`. **S; T3/T4**. |
| **B4: accept Reply and commit Final** | I checks the responder's two signatures, `ctx`, exact `H0`, decapsulates `C1`, and verifies MACR. `ProcessingReply`/`FinalPrepared` retain the accepted exact result before `FinalCommitted`. | Dispatch the exact Final and retain provisional `sid`/`K_B`. A successful reply check is not a receipt proving that R retained this same full signed-wire transcript. | `finish_initiator`; `DeviceJournal::{accept_reply,resume_reply}`. **S; R1/R2; T1/T2**. |
| **B5: R accepts Final** | R compares the entire expected Final prefix, including its saved `H0/H1`, then verifies MACI. `DeviceJournal::finish` commits `Complete` before returning the public session ID. `activate_responder_messages` requires `Complete` and atomically transfers the root to `Messages`. | R's local confirmed bootstrap result; after the separate activation, its ordinary message-state operations. The service/connection path retains and requires the closure archive before returning READY. | `ResponderOperation::finish`; journal `finish`; activation; native/portable server branches. **S; R1/R2/R3/R4**. |
| **B6: I verifies READY** | Native `QPCNET02` and portable `QPCXCH01` check exact `sid` and epoch 0, activate I's local state, require the archive, verify the epoch-zero ACK MAC and recheck current authority before returning. The ACK also binds direction and its committed consumed prefix. | Client `Established` or portable `Session`. A public ID, TLS reply or syntactically valid zero-tag ACK does not satisfy the MAC check. An already valid proof is replayable for this original session while its epoch-zero state and authority remain available. | Native `ConnectionEndpoint::establish`; portable `EnrolledDevice::establish_session`; `Traffic::accept_acknowledgement`. **S; R1/R2/R3**. |
| **B7: use or reopen Messages** | Original journal/session identity, current permitted identity/policy, retained epoch and message/ACK rules govern each operation. Renewed historical-session authority is resolved through the dedicated retained-session path. | Committed traffic, authenticated consumption and exact retries under the selected session; a reopened session is an original local fact. | `message_state`, `check_session_context_release`, retained identity resolution. **S; R3; T5/T6**. |

**Local activation and peer-confirmed connection success have different APIs.**
The public low-level `activate_initiator_messages` accepts `FinalCommitted` and
requires dispatch of the committed Final before application frames in its
documented contract. It does not itself verify the peer's READY proof. The
connection APIs perform that additional verification. In their forged-ACK path,
activation can already be durable when establishment fails; the original request,
Final and session remain the objects to reconcile. R2 and R3 exercise this
distinction. There is no inferred rollback or permission to generate a replacement
transcript after that error.

## 3. Compromise matrix

Each row identifies the disclosed asset and the target stage. A disclosure of
one key is not a disclosure of every key stored by the same device. Conversely,
an acquired encrypted image plus its actual wrapping key exposes all relevant
retained contents in that image. The distinction is by asset and history, not
by a convenient session label.

### 3.1 Identity and authority

| Disclosure or intervention | Where it enters and what the source establishes | Stage-specific interpretation and evidence |
| --- | --- | --- |
| **R's P-256 signing component only; genuine Reply body and ML-DSA signature retained** | A fresh canonical low-S P-256 signature on the same body passes both signature checks. MACR is unchanged. The complete Reply wire, `H1`, `sid` and `K_B` change at I; the original R rejects the resulting Final prefix. | **Executed R1**, all four prekey modes: four controls and four aliases. B4 is successful local reply acceptance; it is not B5/B6 agreement. The native false-READY and forged-ACK checks then reject connection success (**R2**). |
| **I's full signing identity disclosed; attacker aims to impersonate R to that I** | I's signing owner is distinct from `S0` and `sk_reply`. The fixed target-context path still checks R's purpose-6 signature, exact Initial hash, MACR and the final epoch-zero proof. Possession of I's identity naturally enables signing as I in other operations. | This is the **initiator-side KCI question**. The remaining checks and key separation are **S**, with T1 substitution controls. Their general resistance under all allowed signing/session queries is **U1**, rather than a theorem inferred from those controls. |
| **R's full signing identity disclosed; attacker aims to impersonate I to that R** | The fixed context still requires I's purpose-5 signature and MAC0 before R reserves its fresh response. R's identity and prekey owners are separate inputs. Compromise of R's signing authority also affects new manifests or replies it can sign; fresh-context admission and a previously fixed context must be analyzed separately. | This is the **responder-side KCI question**, with the input checks established at **S** and initial-confirmation refusals exercised by **R4**. The adversarial multi-session claim is **U1**. |
| **Only one required identity-signature component is unavailable or its signature is altered** | `PublicKey::verify` checks canonical P-256 and ML-DSA over the same purpose-bound message. Both are mandatory. Purpose 5 and 6 cannot be substituted by a credential, roster or manifest purpose. | Rejection assertions are in T1/T6; independent dual-signature corruption refusals are in **R4**. This source rule is distinct from a proof of the surviving component under an arbitrary component-key disclosure. R1 supplies the concrete same-body alias case. |
| **Independent account, protocol-policy or directory approval inputs are replaced** | Context construction binds the caller's accepted roots/checkpoints and selected policy; a network manifest does not choose the `DirectoryExpectation`. Retained historical metadata supplies no fresh operational policy. | **S; T1/T6; R4** for altered trust pins. Compromise of the independent approval mechanism changes a trust premise, rather than being repaired by session MACs. Directory consistency and approved authority replacement retain their existing separate contracts. |
| **Current roster/policy closes or revokes authority after preparation** | `authorize_context`, `check_context_release`, `check_session_context_release` and `image_attempt/check_release` use the current authenticated state. Native retries re-release from the journal; portable calls sample trusted time around engine/carrier boundaries. Retained-session grants explicitly reject fresh bootstrap use. | **S; T6**; closed-policy/wrong-owner release is exercised in **R3**. A cached valid wire does not by itself grant current dispatch authority. READY is not a freshly signed remote-authority statement. |

### 3.2 Prekeys, pending contributions and storage

| Disclosed asset and timing | Constructive effect on this bootstrap | Controls and evidence |
| --- | --- | --- |
| **Both selected responder prekey private components, before or after public `C0`** | The declared decapsulation path reconstructs `S0` and hence `K0`. R's fresh contribution `S1` is a separate schedule input; possession of the prekeys is not itself possession of `sk_reply` or the responder's fresh encapsulation tape. | **S**, `authenticate_initial` and `schedule`. One-time/reusable status controls use and retention, not a different KDF. Confidentiality with this partial compromise belongs to **U2**. |
| **Only the selected classical or PQ prekey component** | The attacker receives one component's private input. ContextBound still processes the actual two-leg result and binding; the source does not equate a one-component disclosure to the full `S0`. | **S** source mapping; the component-security/combiner premise is part of **U2**. All four admitted selection modes are exercised by T1, and inventory selection/consumption by T4. |
| **I's `sk_reply` or its recoverable original generation reservation** | The captured owner/tape can decapsulate the later public `C1`, giving `S1`. At `AwaitingReply`, the complete I checkpoint also retains `S0`; obtaining that complete private state therefore supplies both inputs, not merely `S1`. | **S**, `WaitingInitiator`, checkpoint/restore and `InitiationPlan`. The conclusion follows from the actual fields and replay algorithm; no new bootstrap-disclosure execution is claimed here. |
| **I's complete initiation plan after both KEM reservations, plus the matching wrapping key** | The same original key and encapsulation can be replayed to recover `sk_reply` and `S0`; the later public Reply supplies the ciphertext needed for `S1`. Later execution or exact retry does not create a replacement secret. | **S**, `InitiationPlan::{compute,complete,encode}`. T2 covers exact reservation/retry behavior. A generation-only plan from B1 is a narrower capture and must not be silently upgraded to the later complete plan. |
| **R's readable `ResponseKemReserved` or later private plan/checkpoint** | The phase-13 plan already retains authenticated `S0` and the sealed original encapsulation for `S1`; its exact bound public input permits replay. A prepared checkpoint directly retains `K_B` and the remaining confirmation state. | **S**, `ResponsePlan::{reserve,compute,encode}` and responder checkpoint. T3/T4 cover preservation and commit ordering. These field dependencies identify the exposed branch even when the public Reply is emitted later. |
| **Encrypted journal or token without the matching wrapping key; key learned later** | Captured bytes remain a retained object. Later key disclosure can make their original reservations or roots readable; deletion or a newer outer write does not invalidate the adversary's copy. The actual captured phases determine the resulting secrets. | **S** storage/replay mapping. Confidentiality of the protected bytes uses the existing record/AEAD assumptions. Signer files are separately typed assets; including them with their matching wrapping key also exposes identity authority. |
| **Signing-reservation `rnd` without the signing key** | The reservation contains an input binding and explicit ML-DSA signing randomness. The P-256 path uses its own signing operation; these stored bytes are not an exposed P-256 nonce. | **S**, `SigningReservation` and the pinned ML-DSA backend; the existing [body-origin analysis](AUTHENTICATED_BODY_LEMMA_V1.md) identifies the nonce-aware primitive premise (**U2**). |
| **Consumed one-time prekey is replayed or relabelled by a new manifest** | Durable records use actual key fingerprints as claims, and consumption remains linked to the original response. An exact committed Initial reuses its response; a different Initial competing for that one-time key fails. Re-labelling a public key does not create a new one-time key. | **S; T3/T4/T6**. Both selected one-time entries are consumed only where the selected quality requires them. The volatile `ResponderOperation` alone has no global one-time inventory; the journal is the enforcing layer. |

### 3.3 Session-root and carrier compromise

| Disclosure or intervention | Consequence and retained boundary | Evidence |
| --- | --- | --- |
| **An old session's root/state, while establishing a fresh independent bootstrap** | No old session-root parameter enters `schedule` or `pending`; the fresh exchange uses `S0`, `S1` and its role-ordered transcript. A proof or ACK for another session fails exact session/direction/epoch checks. Any shared identity, prekey, RNG or storage disclosure must additionally be included in the case. | **S** graph and ACK parser; T5 covers the ACK/epoch checks. General fresh-session independence with correlated compromise histories remains part of **U1/U2**. |
| **This bootstrap's `K_B`, or both `S0` and `S1` with the complete public transcript** | The graph reconstructs `R_0`, both epoch-zero chains and both ACK keys. An attacker holding the applicable ACK key can compute the root-possession proof. That proof consequently certifies key possession under its secrecy premise; it is not an additional independent identity signature. | **S**, `pending`, `State::new`, `Traffic::from_material`, `acknowledgement`. The stage contract explicitly distinguishes this disclosure from the next row. |
| **Only the initial stored rekey root `R_0`** | `R_0` and `T_0` are sibling outputs of the 160-byte expansion from `K_B`. The implemented graph contains no `R_0 → T_0` derivation. A whole message-state capture includes additional fields, whereas this row names only `R_0`. | **S** exact source distinction. Turning separation of fields into an indistinguishability theorem requires the KDF argument in **U2**. |
| **A later old-epoch rekey root or ACK key** | Later-epoch material follows the rekey equations and may expose that epoch's chains/ACKs. ACKs bind the actual session, direction and epoch; an authenticated old prefix retains authority over its old outboxes. It does not by itself authenticate another epoch's acknowledgement. | **S; T5**, including an old-key-generated modified new-epoch ACK rejection. The full rekey recovery analysis remains in its existing recovery notes, not a bootstrap KCI result. |
| **Configured TLS peer key or arbitrary portable carrier control, with public READY fields** | The carrier may drop, replay or alter public frames. Native and portable establishment still require the matching epoch-zero ACK MAC. R2 gives the adversarial carrier its actual configured TLS key and only R's classical device-signing component; both public-only READY and a well-formed forged proof are rejected. | **R2; R3** for portable tamper/loss and exact retry. A valid retained ACK does not establish current peer availability, fresh remote authorization, physical erasure or a host application effect. |

## 4. Concrete tests and retained executions

### Source/test index

These are precise existing test names and implementation locations. An S entry
identifies inspected test logic; only the R ledger below supplies an execution
claim for this review.

| ID | Source and named checks | What is directly covered |
| --- | --- | --- |
| **T1** | [bootstrap.rs][bootstrap-source]: `both_real_peers_agree_for_every_permitted_mode_and_pin_all_flights`; `valid_signatures_cannot_replace_kem_confirmation_or_transcript_binding`; `repeated_initial_requires_fresh_responder_contribution_and_conflicts_at_initiator`; `admission_requires_exact_roles_runtime_selection_directory_and_live_policy`; `key_schedule_matches_independent_python_hmac_sha256_and_sha3_vectors`. | Four mode agreement, exact flights and conflicting replies; separately signed bad ciphertext/MAC/context; independent KDF vectors; live policy/runtime, role and selection requirements. |
| **T2** | [durable/initiator/tests.rs][initiator-tests]: `both_journals_reopen_and_agree_for_every_mode_with_no_signing_owner`; `signature_and_confirmation_failures_preserve_pending_initiation`; `pinned_reply_survives_local_quota_failure_and_cannot_be_substituted`; `each_reply_sync_failure_recovers_the_exact_reply_final_and_session`; `process_kill_at_eleven_initiator_cuts_recovers_exact_reserved_work`; `signing_reservation_replays_both_signatures_and_binds_the_complete_command`. | Initiator input pinning, deterministic recovery, signing reservations and committed result boundaries. |
| **T3** | [durable/tests.rs][durable-tests]: `invalid_inputs_never_consume_prekeys_and_second_valid_initial_conflicts`; `a_new_signed_manifest_cannot_relabel_a_consumed_public_key`; `eight_responder_process_cuts_preserve_exact_response_and_live_peer_confirmation`; `final_confirmation_commit_errors_recover_the_same_session_identity`. | Initial rejection/claims, cross-manifest one-time identity, responder process cuts and final commit recovery. |
| **T4** | [durable/prekeys/tests.rs][prekey-tests]: `inventory_roundtrips_every_quality_and_atomically_retires_only_selected_one_time_keys`; `response_sync_failures_keep_inventory_and_outbox_consumption_indivisible`; `process_loss_recovers_original_inventory_before_authentication_and_commits_consumption`; `invalid_or_substituted_inventory_tokens_fail_closed_without_consumption`; `installed_revocation_fences_prekey_generation_and_cached_leaf_but_allows_retirement`. | Actual prekey inventory, atomic consumption/outbox, restored owners, token substitution and current revocation. |
| **T5** | [durable/messages/tests.rs][message-tests]: `confirmed_roots_transfer_atomically_and_both_directions_survive_reopen`; `initial_and_chain_keys_match_independent_hmac_sha256_vectors`; `rekey_epoch_cutover_preserves_old_outboxes_and_separates_new_ids_and_acks`; `closed_or_expired_authority_cannot_release_cached_messages`. | Activation/root transfer, initial traffic and ACK vectors, epoch separation, old-key forgery rejection and release authority. |
| **T6** | [identity/policy tests][identity-tests]: `each_signature_component_is_required_and_purposes_are_separate`; `roster_fork_revocation_and_generation_changes_require_the_exact_pin`; `protocol_authority_components_cannot_be_reused_as_active_device_identity`; `malicious_signer_cannot_relabel_a_reusable_public_key_as_one_time_in_selection`. [roster tests][roster-tests]: `process_loss_at_roster_intent_or_commit_recovers_revocation_before_output`. [portable tests][portable-tests]: `wrong_owner_and_closed_policy_do_not_release_new_frames`. | Required signature components, identity/authority separation, authenticated one-time classification, durable revocation and current output permission. |
| **T7** | [classical alias regression][alias-tests]: `classical_signature_alias_preserves_reply_authentication_but_final_rejects_root_split`. [native confirmation regressions][native-tests]: `native_establish_rejects_public_ready_after_classical_reply_alias`; `native_establish_authenticates_ready_after_classical_reply_alias`. | Same-body wire substitution, staged root split, public-only and forged-MAC READY rejection. **R1/R2**. |
| **T8** | [portable tests][portable-tests]: `confirmed_bootstrap_reopens_and_delivers_in_both_directions_without_duplicate_effects`; `tampered_ready_proof_closes_owner_and_exact_retry_recovers_committed_original`; `cancelled_admission_dispatches_nothing_and_closes_owner`. | Actual owned engine/journal establishment, forged/lost READY, exact original retry, and cancellation. **R3**. |

### Retained execution ledger

| ID | Retained record | Executed result and precise scope |
| --- | --- | --- |
| **R1** | [20261105-authenticated-body][e-body], `CAPTURE.zip`, `original-run/EXTRACTS.json`, `original-run/FORMAL_RELEASE_RESULT.json`, `FILES.json`. | Extracts from the completed Release run at source `4effa8b2b25e7403ab912b65894a7d1e73695542`, implementation `f560d803c43a24fff222daa5e5bd623bfdf874`. Four honest controls and four classical aliases; all three T7 tests report `ok`. This review reread the ZIP and the exact extracted records. |
| **R2** | [20261031-native-ready-confirmation][e-native], `VERIFICATION.json` and retained red/green review archive. | The historical QPCNET01 undesired success was reproduced; QPCNET02 introduces the epoch-zero proof. The checkpoint records 49 selected passing tests, including helper entries, on macOS arm64. The regression distinguishes public-only READY, forged ACK and local activation before failure. |
| **R3** | [20261013-owned-session-exchange][e-portable], `native-tests-04.log` and retained driver. | Seven portable core tests with actual signatures/KEMs and encrypted native journals; carrier/effect implementations are in-process. The checkpoint also records 11 existing native TLS regression entries, including process helpers. This is the original component execution, not a new all-platform claim. |
| **R4** | [20261018-independent-bootstrap][e-independent], `CHECKS.json`, `CAPTURE.zip`. | Independent Python/OpenSSL initiator and actual Rust responder complete all three flights and retain the same `sid`; ten native commands and 35 Python refusal controls. The final recorded provider is cryptography 48.0.1/OpenSSL 4.0.1. Correctly signed altered initial ciphertext fails native confirmation; independent signature/pin/encoding checks also reject. A synthetic seam separately exercises valid dual signatures with invalid MACR. |

R1's archive is **163,090 bytes**, SHA-256
`e1b96c96e075986b04f83b077eeea3e5cf9685e649a7e7d6f37175e6b38232e0`.
The current bytes of seven of its eight captured implementation/regression
files match `FILES.json`, including `crypto.rs`, the ML-DSA backend, both T7
test files and the three rekey files. The remaining `contract.rs` difference
is the addition of `MAX_RETAINED_FANOUT_RECORDS = 16` and its two comments;
the captured signature domains and bootstrap suite are unchanged. This
comparison preserves the scope of the historical receipt and does not label
the complete present checkout as having been rerun.

The former native public-ID READY defect is therefore an identified historical
failure with an implemented correction and retained regression outcomes. It is
not an unresolved claim that the current carrier still returns the old false
success. The live independent bootstrap proves its recorded interoperability
and confirmation outcomes; no private-root export hook was added to make that
test possible.

## 5. Remaining construction propositions and review handoff

The following are the existing proof/review questions localized by this matrix,
not additional package or platform gates:

| ID | Proposition to settle | Exact interface supplied by this review |
| --- | --- | --- |
| **U1: staged agreement and KCI** | Proposition 1 and Theorem 2 of the [terminal assessment](BOOTSTRAP_TERMINAL_AGREEMENT_V1.md) establish the full-wire Final invariant and the joint-schedule-to-terminal-agreement conversion. The KCI assessment now instantiates that schedule with the chosen local-identity and prekey disclosures, alongside its context-admission assumptions. | B0–B7 permissions, exact transcript classes, prior durable responder activation and the explicit multi-key verification bound. The source-linked theorem permits exact READY replay; R1/R2 retain the live B4/B6 separation. |
| **U2: computational key schedule and hybrid authentication** | Connect the two ContextBound contributions and allowed component/entropy disclosures to the joint HKDF, confirmation, root and ACK experiment. Cover the actual shared inputs and signature-randomness interface under the declared classical/PQ assumptions. | The explicit `S0/S1 → seed/KR/KI → K_B → R_0/T_0` graph, source-defined contexts and the specific disclosure rows. The existing conditional body-origin and recovery component notes remain inputs to this analysis. |
| **U3: disclosure and retention correspondence** | Match any claimed erasure or post-compromise history to the actual retained journal, one-time inventory, replay tokens, wrapping keys and signer files. Preserve original operation identities across retry and pending writes. | Actual staged plans and checkpoint fields; atomic consumption and exact outbox behavior; temporary claims versus consumption; named storage/test paths. A fresh execution time is not substituted for the retained reservation's origin. |

The completed source review supports carrying forward the current derivation
graph and stage-specific output contracts as the concrete construction under
review. The stage/asset matrix identifies where each broader cryptographic
claim must attach and gives the reviewer the existing successful executions,
the corrected failure case, and the actual implementation entry points. The
designated reviewer's assessed scope and findings remain a separate record in
the established external-review process.

[bootstrap-doc]: ../../research/continuity-identity-candidate/BOOTSTRAP.md
[bootstrap-source]: ../../research/continuity-identity-candidate/src/bootstrap.rs
[messages-source]: ../../research/continuity-identity-candidate/src/durable/messages.rs
[traffic-source]: ../../research/continuity-identity-candidate/src/durable/messages/traffic.rs
[initial-plan]: ../../research/continuity-identity-candidate/src/bootstrap/staged.rs
[response-plan]: ../../research/continuity-identity-candidate/src/bootstrap/response_staged.rs
[initiator-source]: ../../research/continuity-identity-candidate/src/durable/initiator.rs
[responder-source]: ../../research/continuity-identity-candidate/src/durable/responder.rs
[journal-source]: ../../research/continuity-identity-candidate/src/durable.rs
[prekey-source]: ../../research/continuity-identity-candidate/src/durable/prekeys.rs
[native-client]: ../../research/continuity-identity-candidate/src/connection_transport/client.rs
[native-server]: ../../research/continuity-identity-candidate/src/connection_transport/server.rs
[portable-client]: ../../research/continuity-identity-candidate/src/session_exchange/client.rs
[portable-server]: ../../research/continuity-identity-candidate/src/session_exchange/server.rs
[ack-source]: ../../research/continuity-identity-candidate/src/durable/messages/acknowledgement.rs
[roster-source]: ../../research/continuity-identity-candidate/src/durable/rosters.rs
[retained-source]: ../../research/continuity-identity-candidate/src/bootstrap/retained.rs
[initiator-tests]: ../../research/continuity-identity-candidate/src/durable/initiator/tests.rs
[durable-tests]: ../../research/continuity-identity-candidate/src/durable/tests.rs
[prekey-tests]: ../../research/continuity-identity-candidate/src/durable/prekeys/tests.rs
[message-tests]: ../../research/continuity-identity-candidate/src/durable/messages/tests.rs
[identity-tests]: ../../research/continuity-identity-candidate/src/tests.rs
[roster-tests]: ../../research/continuity-identity-candidate/src/durable/rosters/tests.rs
[portable-tests]: ../../research/continuity-identity-candidate/src/session_exchange/tests.rs
[alias-tests]: ../../research/continuity-identity-candidate/src/bootstrap/classical_alias_tests.rs
[native-tests]: ../../research/continuity-identity-candidate/src/connection_transport/confirmation_tests.rs
[e-body]: ../../research/sdk-alpha1/evidence/20261105-authenticated-body/README.md
[e-native]: ../../research/sdk-alpha1/evidence/20261031-native-ready-confirmation/README.md
[e-portable]: ../../research/sdk-alpha1/evidence/20261013-owned-session-exchange/README.md
[e-independent]: ../../research/sdk-alpha1/evidence/20261018-independent-bootstrap/README.md
