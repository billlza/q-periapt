(* Migration Contract V2: accepted-session-key binding at the hash-input
 * abstraction boundary.
 *
 * BindingViaCR supplies the proved injective LP8 byte encoding.  One abstract
 * H_sha3 models the implementation's single SHA3-256/Xof256 primitive; the
 * H_context/H_post/H_finished/H_accept/H_state names below are domain/input
 * views of that same operation, not independent random oracles.  This file does
 * not prove the Rust encoder correspondence, SHA3 collision resistance,
 * signatures, persistence, crash behavior, or temporal protocol refinement.
 *)
require import AllCore List BindingViaCR.

type state_identity = bytes * bytes.

type state_revision = {
  revision_global_generation : bytes;
  revision_chain_id : bytes;
  revision_epoch : bytes;
  revision_digest : bytes;
}.

type migration_record = {
  protocol_id : bytes;
  encapsulator_role : bytes;
  committed_epoch : bytes;
  initiator_policy : bytes;
  responder_policy : bytes;
  authenticated_negotiation_digest : bytes;
  selected_suite : bytes;
  effective_floor : bytes;
  committed_state_digest : bytes;
  typed_pre_kem_digest : bytes;
  component_mode : bytes;
}.

(* Exact canonical MigrationStateV1 body committed by V2 M10.  V2 does not
 * replace this signed-state wire format; it commits its SHA3 digest. *)
type canonical_full_state = {
  state_global_generation : bytes;
  state_chain_id : bytes;
  state_protocol_id : bytes;
  state_epoch : bytes;
  state_previous_digest : bytes;
  state_authority_key_id : bytes;
  state_execution_policy : bytes;
  state_floor : bytes;
  state_component_mode : bytes;
  state_allowed_suites : bytes;
}.

type migration_execution = {
  kdf_label : bytes;
  kdf_suite : bytes;
  kdf_policy_version : bytes;
  migration_ss_pq : bytes;
  migration_ss_traditional : bytes;
  migration_ct_pq : bytes;
  migration_pk_pq : bytes;
  migration_ct_traditional : bytes;
  migration_pk_traditional : bytes;
  execution_policy_digest : bytes;
  migration : migration_record;
  full_state : canonical_full_state;
}.

(* Exact byte-contract constants.  This V2 domain is distinct from the existing
 * 315-byte phase-1 V1 context domain. *)
op migration_v2_domain : bytes =
  [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
   73;79;78;45;67;79;78;84;69;88;84;47;118;50].
(* schema=2 is encoded as an unsigned 16-bit big-endian field. *)
op migration_v2_schema : bytes = [0;2].
op migration_v2_policy_context_domain : bytes =
  [81;45;80;69;82;73;65;80;84;45;80;79;76;73;67;89;
   45;67;79;78;84;69;88;84;47;118;49].
op migration_contextbound_domain : bytes =
  [81;45;80;69;82;73;65;80;84;45;72;89;66;82;73;68;
   45;75;69;77;47;118;49].
op migration_state_v1_domain : bytes =
  [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
   73;79;78;45;83;84;65;84;69;47;118;49].
op migration_state_v1_schema : bytes = [0;1].
op migration_post_kem_domain : bytes =
  [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
   73;79;78;45;80;79;83;84;45;75;69;77;45;84;82;65;
   78;83;67;82;73;80;84;47;118;49].
op migration_post_kem_schema : bytes = [0;1].
op migration_finished_domain : bytes =
  [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
   73;79;78;45;70;73;78;73;83;72;69;68;47;118;49].
op migration_accepted_key_domain : bytes =
  [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
   73;79;78;45;65;67;67;69;80;84;69;68;45;75;69;89;
   47;118;49].
op migration_initiator_role : bytes = [1].
op migration_responder_role : bytes = [2].
op migration_initiator_encapsulator : bytes = [1].
op migration_responder_encapsulator : bytes = [2].

lemma migration_v2_contract_constants_exact :
  migration_v2_domain =
    [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
     73;79;78;45;67;79;78;84;69;88;84;47;118;50] /\
  migration_v2_schema = [0;2].
proof. by rewrite /migration_v2_domain /migration_v2_schema. qed.

lemma migration_confirmation_constants_exact :
  migration_v2_policy_context_domain =
    [81;45;80;69;82;73;65;80;84;45;80;79;76;73;67;89;
     45;67;79;78;84;69;88;84;47;118;49] /\
  migration_state_v1_domain =
    [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
     73;79;78;45;83;84;65;84;69;47;118;49] /\
  migration_state_v1_schema = [0;1] /\
  migration_contextbound_domain =
    [81;45;80;69;82;73;65;80;84;45;72;89;66;82;73;68;
     45;75;69;77;47;118;49] /\
  migration_post_kem_domain =
    [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
     73;79;78;45;80;79;83;84;45;75;69;77;45;84;82;65;
     78;83;67;82;73;80;84;47;118;49] /\
  migration_post_kem_schema = [0;1] /\
  migration_finished_domain =
    [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
     73;79;78;45;70;73;78;73;83;72;69;68;47;118;49] /\
  migration_accepted_key_domain =
    [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
     73;79;78;45;65;67;67;69;80;84;69;68;45;75;69;89;
     47;118;49] /\
  migration_initiator_role = [1] /\ migration_responder_role = [2] /\
  migration_initiator_encapsulator = [1] /\
  migration_responder_encapsulator = [2].
proof.
  by rewrite /migration_v2_policy_context_domain
             /migration_state_v1_domain /migration_state_v1_schema
             /migration_contextbound_domain
             /migration_post_kem_domain /migration_post_kem_schema
             /migration_finished_domain /migration_accepted_key_domain
             /migration_initiator_role /migration_responder_role
             /migration_initiator_encapsulator
             /migration_responder_encapsulator.
qed.

op state_of (m : migration_record) : state_identity =
  (m.`committed_epoch, m.`committed_state_digest).

(* Exact V2 M0..M12 projection.  M4 is committed_epoch, M10 is
 * committed_state_digest, and M12 is component_mode. *)
op migration_fields (m : migration_record) : transcript =
  [ migration_v2_domain;
    migration_v2_schema;
    m.`protocol_id;
    m.`encapsulator_role;
    m.`committed_epoch;
    m.`initiator_policy;
    m.`responder_policy;
    m.`authenticated_negotiation_digest;
    m.`selected_suite;
    m.`effective_floor;
    m.`committed_state_digest;
    m.`typed_pre_kem_digest;
    m.`component_mode ].

op migration_body (m : migration_record) : bytes =
  encode (migration_fields m).

op migration_policy_context (execution_digest : bytes)
                            (m : migration_record) : bytes =
  encode [migration_v2_policy_context_domain;
          execution_digest;
          migration_body m].

op migration_contextbound_fields (e : migration_execution) : transcript =
  [ e.`kdf_label;
    e.`kdf_suite;
    e.`kdf_policy_version;
    e.`migration_ss_pq;
    e.`migration_ss_traditional;
    e.`migration_ct_pq;
    e.`migration_pk_pq;
    e.`migration_ct_traditional;
    e.`migration_pk_traditional;
    migration_policy_context e.`execution_policy_digest e.`migration ].

lemma migration_body_state_inj m0 m1 :
  migration_body m0 = migration_body m1 => state_of m0 = state_of m1.
proof.
  move=> hbody.
  have hf := encode_inj (migration_fields m0) (migration_fields m1) _.
  - by move: hbody; rewrite /migration_body.
  have hepoch : m0.`committed_epoch = m1.`committed_epoch.
  - by move: hf; rewrite /migration_fields; smt().
  have hdigest : m0.`committed_state_digest = m1.`committed_state_digest.
  - by move: hf; rewrite /migration_fields; smt().
  by rewrite /state_of hepoch hdigest.
qed.

op canonical_full_state_fields (s : canonical_full_state) : transcript =
  [ migration_state_v1_domain;
    migration_state_v1_schema;
    s.`state_global_generation;
    s.`state_chain_id;
    s.`state_protocol_id;
    s.`state_epoch;
    s.`state_previous_digest;
    s.`state_authority_key_id;
    s.`state_execution_policy;
    s.`state_floor;
    s.`state_component_mode;
    s.`state_allowed_suites ].

op canonical_full_state_body (s : canonical_full_state) : bytes =
  encode (canonical_full_state_fields s).

(* All named views share the same primitive.  Their LP8 preimages contain the
 * concrete implementation domains, so bad events can be attributed by stage
 * without assuming independent hashes. *)
op H_sha3 : bytes -> bytes.
op H_context (x : bytes) : bytes = H_sha3 x.
op H_post (x : bytes) : bytes = H_sha3 x.
op H_finished (x : bytes) : bytes = H_sha3 x.
op H_accept (x : bytes) : bytes = H_sha3 x.
op H_state (x : bytes) : bytes = H_sha3 x.

op migration_kem_direction_valid (direction : bytes) : bool =
  direction = migration_initiator_encapsulator \/
  direction = migration_responder_encapsulator.

lemma migration_exact_kem_directions_valid :
  migration_kem_direction_valid migration_initiator_encapsulator /\
  migration_kem_direction_valid migration_responder_encapsulator.
proof. by rewrite /migration_kem_direction_valid. qed.

op migration_execution_well_formed (e : migration_execution) : bool =
  e.`kdf_label = migration_contextbound_domain /\
  migration_kem_direction_valid e.`migration.`encapsulator_role /\
  e.`migration.`committed_epoch = e.`full_state.`state_epoch /\
  e.`migration.`committed_state_digest =
    H_state (canonical_full_state_body e.`full_state).

lemma migration_policy_context_state_inj d0 d1 m0 m1 :
  migration_policy_context d0 m0 = migration_policy_context d1 m1 =>
  state_of m0 = state_of m1.
proof.
  move=> hcontext.
  have hf := encode_inj
    [migration_v2_policy_context_domain; d0; migration_body m0]
    [migration_v2_policy_context_domain; d1; migration_body m1] _.
  - by move: hcontext; rewrite /migration_policy_context.
  have hbody : migration_body m0 = migration_body m1 by smt().
  exact (migration_body_state_inj m0 m1 hbody).
qed.

lemma state_neq_migration_contextbound_fields_neq e0 e1 :
  state_of e0.`migration <> state_of e1.`migration =>
  migration_contextbound_fields e0 <> migration_contextbound_fields e1.
proof.
  move=> hstate.
  rewrite /migration_contextbound_fields.
  smt(migration_policy_context_state_inj).
qed.

op migration_context_hash_input (e : migration_execution) : bytes =
  encode (migration_contextbound_fields e).

op migration_abi2_key (e : migration_execution) : bytes =
  H_context (migration_context_hash_input e).

op migration_post_kem_fields (e : migration_execution) : transcript =
  [ migration_post_kem_domain;
    migration_post_kem_schema;
    migration_body e.`migration;
    e.`migration_ct_pq;
    e.`migration_ct_traditional ].

op migration_post_hash_input (e : migration_execution) : bytes =
  encode (migration_post_kem_fields e).

op migration_post_kem_digest (e : migration_execution) : bytes =
  H_post (migration_post_hash_input e).

op migration_finished_fields (e : migration_execution)
                             (sender_role : bytes) : transcript =
  [ migration_finished_domain;
    migration_abi2_key e;
    sender_role;
    migration_post_kem_digest e ].

op migration_finished_hash_input (e : migration_execution)
                                 (sender_role : bytes) : bytes =
  encode (migration_finished_fields e sender_role).

op migration_finished (e : migration_execution) (sender_role : bytes) : bytes =
  H_finished (migration_finished_hash_input e sender_role).

op migration_initiator_finished (e : migration_execution) : bytes =
  migration_finished e migration_initiator_role.

op migration_responder_finished (e : migration_execution) : bytes =
  migration_finished e migration_responder_role.

op migration_accepted_key_fields (e : migration_execution) : transcript =
  [ migration_accepted_key_domain;
    migration_abi2_key e;
    migration_post_kem_digest e;
    migration_initiator_finished e;
    migration_responder_finished e ].

op migration_accepted_hash_input (e : migration_execution) : bytes =
  encode (migration_accepted_key_fields e).

op migration_final_key (e : migration_execution) : bytes =
  H_accept (migration_accepted_hash_input e).

op revision_of (e : migration_execution) : state_revision = {|
  revision_global_generation = e.`full_state.`state_global_generation;
  revision_chain_id = e.`full_state.`state_chain_id;
  revision_epoch = e.`migration.`committed_epoch;
  revision_digest = e.`migration.`committed_state_digest;
|}.

type migration_acceptance = {
  acceptance_execution : migration_execution;
  acceptance_role : bytes;
  acceptance_current_revision : state_revision;
  acceptance_initiator_finished : bytes;
  acceptance_responder_finished : bytes;
}.

type accepted_session_key = {
  accepted_session_secret : bytes;
  accepted_session_revision : state_revision;
}.

op migration_role_peer_check (a : migration_acceptance) : bool =
  (a.`acceptance_role = migration_responder_role /\
   a.`acceptance_initiator_finished =
     migration_initiator_finished a.`acceptance_execution) \/
  (a.`acceptance_role = migration_initiator_role /\
   a.`acceptance_initiator_finished =
     migration_initiator_finished a.`acceptance_execution /\
   a.`acceptance_responder_finished =
     migration_responder_finished a.`acceptance_execution).

(* This is a bounded acceptance predicate, not a temporal trace model.  The
 * responder branch checks peer I before locally deriving R; the initiator
 * branch records its issued I and verifies peer R.  KEM encapsulator_role stays
 * inside the execution and is intentionally independent of acceptance_role. *)
op migration_accepted (a : migration_acceptance) : bool =
  migration_execution_well_formed a.`acceptance_execution /\
  a.`acceptance_current_revision = revision_of a.`acceptance_execution /\
  migration_role_peer_check a.

op migration_accepted_record (a : migration_acceptance)
    : accepted_session_key option =
  if migration_accepted a then
    Some {| accepted_session_secret =
              migration_final_key a.`acceptance_execution;
            accepted_session_revision = revision_of a.`acceptance_execution |}
  else None.

(* The binding game compares the secret projection.  Comparing whole accepted
 * records would make state binding trivial because the revision is a field. *)
op migration_accepted_key (a : migration_acceptance) : bytes option =
  if migration_accepted a then
    Some (migration_final_key a.`acceptance_execution)
  else None.

op migration_context_collision (e0 e1 : migration_execution) : bool =
  migration_context_hash_input e0 <> migration_context_hash_input e1 /\
  H_context (migration_context_hash_input e0) =
    H_context (migration_context_hash_input e1).

op migration_accept_collision (e0 e1 : migration_execution) : bool =
  migration_accepted_hash_input e0 <> migration_accepted_hash_input e1 /\
  H_accept (migration_accepted_hash_input e0) =
    H_accept (migration_accepted_hash_input e1).

op migration_post_collision (e0 e1 : migration_execution) : bool =
  migration_post_hash_input e0 <> migration_post_hash_input e1 /\
  H_post (migration_post_hash_input e0) =
    H_post (migration_post_hash_input e1).

op migration_finished_collision (e0 : migration_execution) (r0 : bytes)
                                (e1 : migration_execution) (r1 : bytes) : bool =
  migration_finished_hash_input e0 r0 <>
    migration_finished_hash_input e1 r1 /\
  H_finished (migration_finished_hash_input e0 r0) =
    H_finished (migration_finished_hash_input e1 r1).

op migration_state_collision (e0 e1 : migration_execution) : bool =
  canonical_full_state_body e0.`full_state <>
    canonical_full_state_body e1.`full_state /\
  H_state (canonical_full_state_body e0.`full_state) =
    H_state (canonical_full_state_body e1.`full_state).

lemma state_neq_migration_context_hash_input_neq e0 e1 :
  state_of e0.`migration <> state_of e1.`migration =>
  migration_context_hash_input e0 <> migration_context_hash_input e1.
proof.
  rewrite /migration_context_hash_input.
  smt(encode_inj state_neq_migration_contextbound_fields_neq).
qed.

lemma migration_roles_distinct :
  migration_initiator_role <> migration_responder_role.
proof.
  by rewrite /migration_initiator_role /migration_responder_role.
qed.

lemma migration_kem_directions_distinct :
  migration_initiator_encapsulator <> migration_responder_encapsulator.
proof.
  by rewrite /migration_initiator_encapsulator
             /migration_responder_encapsulator.
qed.

(* Independent post-KEM input binding.  This is a collision decomposition, not
 * a Finished forgery or authentication theorem. *)
lemma migration_post_input_binding e0 e1 :
  (migration_body e0.`migration <> migration_body e1.`migration \/
   e0.`migration_ct_pq <> e1.`migration_ct_pq \/
   e0.`migration_ct_traditional <> e1.`migration_ct_traditional) =>
  migration_post_kem_digest e0 = migration_post_kem_digest e1 =>
  migration_post_collision e0 e1.
proof.
  move=> hcomponent hdigest.
  rewrite /migration_post_collision /migration_post_hash_input
          /migration_post_kem_fields.
  rewrite /migration_post_kem_digest /migration_post_hash_input
          /migration_post_kem_fields in hdigest.
  smt(encode_inj).
qed.

(* Independent Finished input binding over K_abi2, sender role, and TH. *)
lemma migration_finished_input_binding e0 r0 e1 r1 :
  (migration_abi2_key e0 <> migration_abi2_key e1 \/
   r0 <> r1 \/
   migration_post_kem_digest e0 <> migration_post_kem_digest e1) =>
  migration_finished e0 r0 = migration_finished e1 r1 =>
  migration_finished_collision e0 r0 e1 r1.
proof.
  move=> hcomponent hfinished.
  rewrite /migration_finished_collision /migration_finished_hash_input
          /migration_finished_fields.
  rewrite /migration_finished /migration_finished_hash_input
          /migration_finished_fields in hfinished.
  smt(encode_inj).
qed.

lemma migration_finished_role_separation_bad_event e :
  migration_initiator_finished e = migration_responder_finished e =>
  migration_finished_collision e migration_initiator_role
                                 e migration_responder_role.
proof.
  move=> hfinished.
  apply (migration_finished_input_binding e migration_initiator_role
          e migration_responder_role).
  - by right; left; exact migration_roles_distinct.
  - move: hfinished.
    rewrite /migration_initiator_finished /migration_responder_finished.
    trivial.
qed.

(* Equal final accepted secrets under different committed state identities
 * imply a collision at H_accept or at the ContextBound H_context view.  Both
 * views are the same H_sha3 over different domain-separated LP8 preimages. *)
lemma mig_bind_k_state_bad_event_decomposition a0 a1 :
  migration_accepted_key a0 = migration_accepted_key a1 =>
  migration_accepted_key a0 <> None =>
  state_of a0.`acceptance_execution.`migration <>
    state_of a1.`acceptance_execution.`migration =>
  migration_accept_collision a0.`acceptance_execution
                             a1.`acceptance_execution \/
  migration_context_collision a0.`acceptance_execution
                              a1.`acceptance_execution.
proof.
  move=> hkey hnonbottom hstate.
  have hfinal :
      migration_final_key a0.`acceptance_execution =
      migration_final_key a1.`acceptance_execution.
  - move: hkey hnonbottom.
    rewrite /migration_accepted_key.
    smt().
  case (migration_accepted_hash_input a0.`acceptance_execution =
        migration_accepted_hash_input a1.`acceptance_execution) => hinput.
  - right.
    rewrite /migration_context_collision.
    have hctxneq := state_neq_migration_context_hash_input_neq
      a0.`acceptance_execution a1.`acceptance_execution hstate.
    split; first exact hctxneq.
    have habi2 :
        migration_abi2_key a0.`acceptance_execution =
        migration_abi2_key a1.`acceptance_execution.
    + move: hinput.
      rewrite /migration_accepted_hash_input.
      move=> hencoded.
      have hfields := encode_inj
        (migration_accepted_key_fields a0.`acceptance_execution)
        (migration_accepted_key_fields a1.`acceptance_execution) hencoded.
      move: hfields; rewrite /migration_accepted_key_fields; smt().
    move: habi2.
    rewrite /migration_abi2_key.
    trivial.
  - left.
    rewrite /migration_accept_collision.
    by split.
qed.

(* Different canonical state bodies add only the H_state collision case to the
 * preceding H_accept-or-H_context decomposition. *)
lemma mig_bind_k_full_state_bad_event_decomposition a0 a1 :
  migration_accepted_key a0 = migration_accepted_key a1 =>
  migration_accepted_key a0 <> None =>
  canonical_full_state_body a0.`acceptance_execution.`full_state <>
    canonical_full_state_body a1.`acceptance_execution.`full_state =>
  migration_accept_collision a0.`acceptance_execution
                             a1.`acceptance_execution \/
  migration_context_collision a0.`acceptance_execution
                              a1.`acceptance_execution \/
  migration_state_collision a0.`acceptance_execution
                            a1.`acceptance_execution.
proof.
  move=> hkey hnonbottom hbody.
  have ha0 : migration_accepted a0.
  - move: hnonbottom; rewrite /migration_accepted_key; smt().
  have ha1 : migration_accepted a1.
  - move: hkey hnonbottom; rewrite /migration_accepted_key; smt().
  have hw0 : migration_execution_well_formed a0.`acceptance_execution.
  - move: ha0; rewrite /migration_accepted; smt().
  have hw1 : migration_execution_well_formed a1.`acceptance_execution.
  - move: ha1; rewrite /migration_accepted; smt().
  case (H_state
          (canonical_full_state_body a0.`acceptance_execution.`full_state) =
        H_state
          (canonical_full_state_body a1.`acceptance_execution.`full_state))
      => hstatehash.
  - right; right.
    rewrite /migration_state_collision.
    by split.
  - have hidentity :
        state_of a0.`acceptance_execution.`migration <>
        state_of a1.`acceptance_execution.`migration.
    + move: hw0 hw1 hstatehash.
      rewrite /migration_execution_well_formed /state_of.
      smt().
    have hbad := mig_bind_k_state_bad_event_decomposition
      a0 a1 hkey hnonbottom hidentity.
    smt().
qed.

(* Four-field StateRevisionV1 corollary.  Revision divergence is not hidden by
 * comparing whole records: the premise still compares only accepted secrets. *)
lemma mig_bind_k_revision_bad_event_decomposition a0 a1 :
  migration_accepted_key a0 = migration_accepted_key a1 =>
  migration_accepted_key a0 <> None =>
  revision_of a0.`acceptance_execution <>
    revision_of a1.`acceptance_execution =>
  migration_accept_collision a0.`acceptance_execution
                             a1.`acceptance_execution \/
  migration_context_collision a0.`acceptance_execution
                              a1.`acceptance_execution \/
  migration_state_collision a0.`acceptance_execution
                            a1.`acceptance_execution.
proof.
  move=> hkey hnonbottom hrevision.
  have ha0 : migration_accepted a0.
  - move: hnonbottom; rewrite /migration_accepted_key; smt().
  have ha1 : migration_accepted a1.
  - move: hkey hnonbottom; rewrite /migration_accepted_key; smt().
  have hw0 : migration_execution_well_formed a0.`acceptance_execution.
  - move: ha0; rewrite /migration_accepted; smt().
  have hw1 : migration_execution_well_formed a1.`acceptance_execution.
  - move: ha1; rewrite /migration_accepted; smt().
  have hbody :
      canonical_full_state_body a0.`acceptance_execution.`full_state <>
      canonical_full_state_body a1.`acceptance_execution.`full_state.
  - apply: contra hrevision => hbodyeq.
    have hfields := encode_inj
      (canonical_full_state_fields a0.`acceptance_execution.`full_state)
      (canonical_full_state_fields a1.`acceptance_execution.`full_state) _.
    + by move: hbodyeq; rewrite /canonical_full_state_body.
    move: hw0 hw1 hfields.
    rewrite /migration_execution_well_formed /canonical_full_state_fields
            /revision_of.
    smt().
  exact (mig_bind_k_full_state_bad_event_decomposition
    a0 a1 hkey hnonbottom hbody).
qed.

op fixed_protocol_id, fixed_initiator_policy,
   fixed_responder_policy, fixed_negotiation_digest, fixed_selected_suite,
   fixed_floor, fixed_typed_prekem_digest, fixed_component_mode : bytes.
op fixed_kdf_suite, fixed_policy_version, fixed_ss_pq,
   fixed_ss_traditional, fixed_ct_pq, fixed_pk_pq,
   fixed_ct_traditional, fixed_pk_traditional,
   fixed_execution_policy_digest : bytes.
op fixed_state_chain, fixed_state_protocol, fixed_state_previous_digest,
   fixed_state_authority,
   fixed_state_execution_policy, fixed_state_floor, fixed_state_mode,
   fixed_state_suites : bytes.
(* Reachable Rust u64 witnesses: generation and epoch are nonzero and not MAX. *)
op migration_generation_one : bytes = [0;0;0;0;0;0;0;1].
op migration_epoch_one : bytes = [0;0;0;0;0;0;0;1].
op migration_epoch_two : bytes = [0;0;0;0;0;0;0;2].

op sample_full_state (epoch : bytes) : canonical_full_state = {|
  state_global_generation = migration_generation_one;
  state_chain_id = fixed_state_chain;
  state_protocol_id = fixed_state_protocol;
  state_epoch = epoch;
  state_previous_digest = fixed_state_previous_digest;
  state_authority_key_id = fixed_state_authority;
  state_execution_policy = fixed_state_execution_policy;
  state_floor = fixed_state_floor;
  state_component_mode = fixed_state_mode;
  state_allowed_suites = fixed_state_suites;
|}.

op sample_state_digest (epoch : bytes) : bytes =
  H_state (canonical_full_state_body (sample_full_state epoch)).

op sample_migration (epoch kem_direction : bytes) : migration_record = {|
  protocol_id = fixed_protocol_id;
  encapsulator_role = kem_direction;
  committed_epoch = epoch;
  initiator_policy = fixed_initiator_policy;
  responder_policy = fixed_responder_policy;
  authenticated_negotiation_digest = fixed_negotiation_digest;
  selected_suite = fixed_selected_suite;
  effective_floor = fixed_floor;
  committed_state_digest = sample_state_digest epoch;
  typed_pre_kem_digest = fixed_typed_prekem_digest;
  component_mode = fixed_component_mode;
|}.

op sample_migration_execution (epoch kem_direction : bytes)
    : migration_execution = {|
  kdf_label = migration_contextbound_domain;
  kdf_suite = fixed_kdf_suite;
  kdf_policy_version = fixed_policy_version;
  migration_ss_pq = fixed_ss_pq;
  migration_ss_traditional = fixed_ss_traditional;
  migration_ct_pq = fixed_ct_pq;
  migration_pk_pq = fixed_pk_pq;
  migration_ct_traditional = fixed_ct_traditional;
  migration_pk_traditional = fixed_pk_traditional;
  execution_policy_digest = fixed_execution_policy_digest;
  migration = sample_migration epoch kem_direction;
  full_state = sample_full_state epoch;
|}.

lemma sample_execution_well_formed epoch kem_direction :
  migration_kem_direction_valid kem_direction =>
  migration_execution_well_formed
    (sample_migration_execution epoch kem_direction).
proof.
  move=> hdirection.
  rewrite /migration_execution_well_formed /sample_migration_execution
          /sample_migration /sample_state_digest /sample_full_state.
  smt().
qed.

op sample_acceptance_at (epoch kem_direction role : bytes)
    : migration_acceptance = {|
  acceptance_execution =
    sample_migration_execution epoch kem_direction;
  acceptance_role = role;
  acceptance_current_revision =
    revision_of (sample_migration_execution epoch kem_direction);
  acceptance_initiator_finished =
    migration_initiator_finished
      (sample_migration_execution epoch kem_direction);
  acceptance_responder_finished =
    migration_responder_finished
      (sample_migration_execution epoch kem_direction);
|}.

op sample_acceptance (kem_direction role : bytes) : migration_acceptance =
  sample_acceptance_at migration_epoch_one kem_direction role.

lemma honest_initiator_accepts_at epoch kem_direction :
  migration_kem_direction_valid kem_direction =>
  migration_accepted
    (sample_acceptance_at epoch kem_direction migration_initiator_role).
proof.
  move=> hdirection.
  rewrite /migration_accepted /migration_role_peer_check
          /sample_acceptance_at.
  smt(sample_execution_well_formed).
qed.

lemma honest_responder_accepts_at epoch kem_direction :
  migration_kem_direction_valid kem_direction =>
  migration_accepted
    (sample_acceptance_at epoch kem_direction migration_responder_role).
proof.
  move=> hdirection.
  rewrite /migration_accepted /migration_role_peer_check
          /sample_acceptance_at.
  smt(sample_execution_well_formed).
qed.

lemma honest_initiator_accepts kem_direction :
  migration_kem_direction_valid kem_direction =>
  migration_accepted
    (sample_acceptance kem_direction migration_initiator_role).
proof.
  exact (honest_initiator_accepts_at migration_epoch_one kem_direction).
qed.

lemma honest_responder_accepts kem_direction :
  migration_kem_direction_valid kem_direction =>
  migration_accepted
    (sample_acceptance kem_direction migration_responder_role).
proof.
  exact (honest_responder_accepts_at migration_epoch_one kem_direction).
qed.

(* Honest witnesses prevent the concrete acceptance predicate from making the
 * binding theorem vacuous.  Both roles release the same key+revision record. *)
lemma honest_role_acceptance_nonvacuous kem_direction :
  migration_kem_direction_valid kem_direction =>
  migration_accepted_record
    (sample_acceptance kem_direction migration_initiator_role) <>
      None /\
  migration_accepted_record
    (sample_acceptance kem_direction migration_responder_role) <>
      None /\
  migration_accepted_record
    (sample_acceptance kem_direction migration_initiator_role) =
  migration_accepted_record
    (sample_acceptance kem_direction migration_responder_role).
proof.
  move=> hdirection.
  have hi := honest_initiator_accepts kem_direction hdirection.
  have hr := honest_responder_accepts kem_direction hdirection.
  rewrite /migration_accepted_record hi hr /sample_acceptance.
  trivial.
qed.

(* Both protocol roles are reachable under both independent KEM directions. *)
lemma honest_role_kem_direction_nonvacuous :
  migration_accepted_record
    (sample_acceptance migration_initiator_encapsulator
                       migration_initiator_role) <> None /\
  migration_accepted_record
    (sample_acceptance migration_initiator_encapsulator
                       migration_responder_role) <> None /\
  migration_accepted_record
    (sample_acceptance migration_responder_encapsulator
                       migration_initiator_role) <> None /\
  migration_accepted_record
    (sample_acceptance migration_responder_encapsulator
                       migration_responder_role) <> None.
proof.
  have [hinitiator hresponder] := migration_exact_kem_directions_valid.
  have hi := honest_role_acceptance_nonvacuous
    migration_initiator_encapsulator hinitiator.
  have hr := honest_role_acceptance_nonvacuous
    migration_responder_encapsulator hresponder.
  smt().
qed.

(* Exact 32-byte wrong-Finished constructor.  It selects zero32 unless that is
 * the expected value, in which case it selects one32. *)
op finished_zero32 : bytes =
  [0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;
   0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0].
op finished_one32 : bytes =
  [1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;
   1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1].

op wrong_finished (expected : bytes) : bytes =
  if expected = finished_zero32 then finished_one32 else finished_zero32.

lemma finished_samples_distinct : finished_zero32 <> finished_one32.
proof. by rewrite /finished_zero32 /finished_one32. qed.

lemma wrong_finished_distinct expected : wrong_finished expected <> expected.
proof.
  rewrite /wrong_finished.
  case (expected = finished_zero32) => hzero; smt(finished_samples_distinct).
qed.

lemma wrong_finished_exact_width expected : size (wrong_finished expected) = 32.
proof.
  rewrite /wrong_finished.
  case (expected = finished_zero32) => _.
  - by rewrite /finished_one32.
  - by rewrite /finished_zero32.
qed.

lemma sample_advanced_revision_distinct kem_direction :
  revision_of (sample_migration_execution migration_epoch_one kem_direction) <>
  revision_of (sample_migration_execution migration_epoch_two kem_direction).
proof.
  rewrite /revision_of /sample_migration_execution /sample_migration
          /migration_epoch_one /migration_epoch_two.
  trivial.
qed.

op migration_accepted_without_current_recheck
    (a : migration_acceptance) : bool =
  migration_execution_well_formed a.`acceptance_execution /\
  migration_role_peer_check a.

op sample_stale_acceptance (kem_direction role : bytes)
    : migration_acceptance = {|
  acceptance_execution =
    sample_migration_execution migration_epoch_one kem_direction;
  acceptance_role = role;
  acceptance_current_revision =
    revision_of (sample_migration_execution migration_epoch_two kem_direction);
  acceptance_initiator_finished = migration_initiator_finished
    (sample_migration_execution migration_epoch_one kem_direction);
  acceptance_responder_finished = migration_responder_finished
    (sample_migration_execution migration_epoch_one kem_direction);
|}.

lemma stale_current_recheck_negative_control kem_direction :
  migration_kem_direction_valid kem_direction =>
  ! migration_accepted
      (sample_stale_acceptance kem_direction migration_responder_role) /\
  migration_accepted_without_current_recheck
      (sample_stale_acceptance kem_direction migration_responder_role).
proof.
  move=> hdirection.
  have hstale := sample_advanced_revision_distinct kem_direction.
  have hwell := sample_execution_well_formed
    migration_epoch_one kem_direction hdirection.
  rewrite /migration_accepted /migration_accepted_without_current_recheck
          /migration_role_peer_check /sample_stale_acceptance.
  smt().
qed.

lemma stale_current_recheck_both_roles_negative_control kem_direction :
  migration_kem_direction_valid kem_direction =>
  migration_execution_well_formed
    (sample_migration_execution migration_epoch_one kem_direction) /\
  migration_execution_well_formed
    (sample_migration_execution migration_epoch_two kem_direction) /\
  revision_of (sample_migration_execution migration_epoch_one kem_direction) <>
    revision_of (sample_migration_execution migration_epoch_two kem_direction) /\
  (! migration_accepted
      (sample_stale_acceptance kem_direction migration_initiator_role) /\
   migration_accepted_without_current_recheck
      (sample_stale_acceptance kem_direction migration_initiator_role)) /\
  (! migration_accepted
      (sample_stale_acceptance kem_direction migration_responder_role) /\
   migration_accepted_without_current_recheck
      (sample_stale_acceptance kem_direction migration_responder_role)).
proof.
  move=> hdirection.
  have hi := sample_advanced_revision_distinct kem_direction.
  have hr := stale_current_recheck_negative_control kem_direction hdirection.
  have hwell0 := sample_execution_well_formed
    migration_epoch_one kem_direction hdirection.
  have hwell1 := sample_execution_well_formed
    migration_epoch_two kem_direction hdirection.
  rewrite /migration_accepted /migration_accepted_without_current_recheck
          /migration_role_peer_check /sample_stale_acceptance.
  smt().
qed.

op migration_accepted_without_responder_peer_check
    (a : migration_acceptance) : bool =
  migration_execution_well_formed a.`acceptance_execution /\
  a.`acceptance_current_revision = revision_of a.`acceptance_execution /\
  (a.`acceptance_role = migration_responder_role \/
   (a.`acceptance_role = migration_initiator_role /\
    a.`acceptance_initiator_finished =
      migration_initiator_finished a.`acceptance_execution /\
    a.`acceptance_responder_finished =
      migration_responder_finished a.`acceptance_execution)).

op sample_wrong_peer_i_acceptance (kem_direction : bytes)
    : migration_acceptance = {|
  acceptance_execution =
    sample_migration_execution migration_epoch_one kem_direction;
  acceptance_role = migration_responder_role;
  acceptance_current_revision =
    revision_of (sample_migration_execution migration_epoch_one kem_direction);
  acceptance_initiator_finished = wrong_finished
    (migration_initiator_finished
      (sample_migration_execution migration_epoch_one kem_direction));
  acceptance_responder_finished = migration_responder_finished
    (sample_migration_execution migration_epoch_one kem_direction);
|}.

lemma responder_peer_i_check_negative_control kem_direction :
  migration_kem_direction_valid kem_direction =>
  ! migration_accepted (sample_wrong_peer_i_acceptance kem_direction) /\
  migration_accepted_without_responder_peer_check
    (sample_wrong_peer_i_acceptance kem_direction).
proof.
  move=> hdirection.
  have hwrong := wrong_finished_distinct
    (migration_initiator_finished
      (sample_migration_execution migration_epoch_one kem_direction)).
  have hwell := sample_execution_well_formed
    migration_epoch_one kem_direction hdirection.
  rewrite /migration_accepted
          /migration_accepted_without_responder_peer_check
          /migration_role_peer_check /sample_wrong_peer_i_acceptance.
  smt().
qed.

op sample_wrong_peer_r_acceptance (kem_direction : bytes)
    : migration_acceptance = {|
  acceptance_execution =
    sample_migration_execution migration_epoch_one kem_direction;
  acceptance_role = migration_initiator_role;
  acceptance_current_revision =
    revision_of (sample_migration_execution migration_epoch_one kem_direction);
  acceptance_initiator_finished = migration_initiator_finished
    (sample_migration_execution migration_epoch_one kem_direction);
  acceptance_responder_finished = wrong_finished
    (migration_responder_finished
      (sample_migration_execution migration_epoch_one kem_direction));
|}.

op migration_accepted_without_initiator_peer_check
    (a : migration_acceptance) : bool =
  migration_execution_well_formed a.`acceptance_execution /\
  a.`acceptance_current_revision = revision_of a.`acceptance_execution /\
  ((a.`acceptance_role = migration_responder_role /\
    a.`acceptance_initiator_finished =
      migration_initiator_finished a.`acceptance_execution) \/
   (a.`acceptance_role = migration_initiator_role /\
    a.`acceptance_initiator_finished =
      migration_initiator_finished a.`acceptance_execution)).

lemma initiator_peer_r_check_negative_control kem_direction :
  migration_kem_direction_valid kem_direction =>
  ! migration_accepted (sample_wrong_peer_r_acceptance kem_direction) /\
  migration_accepted_without_initiator_peer_check
    (sample_wrong_peer_r_acceptance kem_direction).
proof.
  move=> hdirection.
  have hwrong := wrong_finished_distinct
    (migration_responder_finished
      (sample_migration_execution migration_epoch_one kem_direction)).
  have hwell := sample_execution_well_formed
    migration_epoch_one kem_direction hdirection.
  rewrite /migration_accepted
          /migration_accepted_without_initiator_peer_check
          /migration_role_peer_check /sample_wrong_peer_r_acceptance.
  smt().
qed.

lemma peer_finished_both_roles_negative_control kem_direction :
  migration_kem_direction_valid kem_direction =>
  (! migration_accepted (sample_wrong_peer_i_acceptance kem_direction) /\
   migration_accepted_without_responder_peer_check
     (sample_wrong_peer_i_acceptance kem_direction)) /\
  (! migration_accepted (sample_wrong_peer_r_acceptance kem_direction) /\
   migration_accepted_without_initiator_peer_check
     (sample_wrong_peer_r_acceptance kem_direction)).
proof.
  move=> hdirection.
  have hi := responder_peer_i_check_negative_control
    kem_direction hdirection.
  have hr := initiator_peer_r_check_negative_control
    kem_direction hdirection.
  smt().
qed.

(* Semantic omission controls are local countermodels for the named stage.
 * They do not claim end-to-end attacks or logical necessity of tactic hints. *)
op omitted_migration_fields (m : migration_record) : transcript =
  [ migration_v2_domain;
    migration_v2_schema;
    m.`protocol_id;
    m.`encapsulator_role;
    m.`initiator_policy;
    m.`responder_policy;
    m.`authenticated_negotiation_digest;
    m.`selected_suite;
    m.`effective_floor;
    m.`typed_pre_kem_digest;
    m.`component_mode ].

op omitted_migration_body (m : migration_record) : bytes =
  encode (omitted_migration_fields m).

op omitted_migration_policy_context (execution_digest : bytes)
                                    (m : migration_record) : bytes =
  encode [migration_v2_policy_context_domain;
          execution_digest;
          omitted_migration_body m].

op omitted_migration_contextbound_fields
    (e : migration_execution) : transcript =
  [ e.`kdf_label;
    e.`kdf_suite;
    e.`kdf_policy_version;
    e.`migration_ss_pq;
    e.`migration_ss_traditional;
    e.`migration_ct_pq;
    e.`migration_pk_pq;
    e.`migration_ct_traditional;
    e.`migration_pk_traditional;
    omitted_migration_policy_context
      e.`execution_policy_digest e.`migration ].

op omitted_migration_key (e : migration_execution) : bytes =
  H_context (encode (omitted_migration_contextbound_fields e)).

lemma omitted_state_context_negative_control :
  migration_execution_well_formed
    (sample_migration_execution migration_epoch_one
                                migration_initiator_encapsulator) /\
  migration_execution_well_formed
    (sample_migration_execution migration_epoch_two
                                migration_initiator_encapsulator) /\
  omitted_migration_key
    (sample_migration_execution migration_epoch_one
                                migration_initiator_encapsulator) =
  omitted_migration_key
    (sample_migration_execution migration_epoch_two
                                migration_initiator_encapsulator) /\
  state_of
    (sample_migration_execution migration_epoch_one
                                migration_initiator_encapsulator).`migration <>
  state_of
    (sample_migration_execution migration_epoch_two
                                migration_initiator_encapsulator).`migration.
proof.
  have [hinitiator hresponder] := migration_exact_kem_directions_valid.
  have hw0 := sample_execution_well_formed
    migration_epoch_one migration_initiator_encapsulator hinitiator.
  have hw1 := sample_execution_well_formed
    migration_epoch_two migration_initiator_encapsulator hinitiator.
  rewrite /omitted_migration_key /omitted_migration_contextbound_fields
          /omitted_migration_policy_context /omitted_migration_body
          /omitted_migration_fields /sample_migration_execution
          /sample_migration /state_of
          /migration_epoch_one /migration_epoch_two.
  smt().
qed.

op omitted_state_post_fields (e : migration_execution) : transcript =
  [ migration_post_kem_domain;
    migration_post_kem_schema;
    omitted_migration_body e.`migration;
    e.`migration_ct_pq;
    e.`migration_ct_traditional ].

op omitted_state_post_digest (e : migration_execution) : bytes =
  H_post (encode (omitted_state_post_fields e)).

op omitted_state_finished (e : migration_execution)
                           (sender_role : bytes) : bytes =
  H_finished
    (encode [migration_finished_domain;
             omitted_migration_key e;
             sender_role;
             omitted_state_post_digest e]).

op omitted_state_final_key (e : migration_execution) : bytes =
  H_accept
    (encode [migration_accepted_key_domain;
             omitted_migration_key e;
             omitted_state_post_digest e;
             omitted_state_finished e migration_initiator_role;
             omitted_state_finished e migration_responder_role]).

op omitted_state_accepted_key (a : migration_acceptance) : bytes option =
  if migration_accepted a then
    Some (omitted_state_final_key a.`acceptance_execution)
  else None.

(* End-to-end countermodel only for a deliberately broken variant that removes
 * epoch+digest from both places where the exact V2 context enters the chain:
 * ContextBound policy context and the post-KEM transcript. *)
lemma omitted_state_end_to_end_negative_control :
  let a0 = sample_acceptance_at migration_epoch_one
    migration_initiator_encapsulator migration_responder_role in
  let a1 = sample_acceptance_at migration_epoch_two
    migration_initiator_encapsulator migration_responder_role in
  migration_accepted a0 /\
  migration_accepted a1 /\
  omitted_state_accepted_key a0 = omitted_state_accepted_key a1 /\
  omitted_state_accepted_key a0 <> None /\
  revision_of a0.`acceptance_execution <>
    revision_of a1.`acceptance_execution /\
  state_of a0.`acceptance_execution.`migration <>
    state_of a1.`acceptance_execution.`migration.
proof.
  have [hinitiator hresponder] := migration_exact_kem_directions_valid.
  have ha0 := honest_responder_accepts_at
    migration_epoch_one migration_initiator_encapsulator hinitiator.
  have ha1 := honest_responder_accepts_at
    migration_epoch_two migration_initiator_encapsulator hinitiator.
  rewrite /omitted_state_accepted_key
          /omitted_state_final_key /omitted_state_finished
          /omitted_state_post_digest /omitted_state_post_fields
          /omitted_migration_key /omitted_migration_contextbound_fields
          /omitted_migration_policy_context /omitted_migration_body
          /omitted_migration_fields /sample_acceptance_at
          /revision_of /state_of
          /migration_epoch_one /migration_epoch_two.
  smt().
qed.

op omitted_post_fields (e : migration_execution) : transcript =
  [ migration_post_kem_domain;
    migration_post_kem_schema;
    migration_body e.`migration;
    e.`migration_ct_pq ].

op omitted_post_digest (e : migration_execution) : bytes =
  H_post (encode (omitted_post_fields e)).

op post_ct0 : bytes = [4].
op post_ct1 : bytes = [5].

op sample_post_execution (traditional_ct kem_direction : bytes)
    : migration_execution = {|
  kdf_label = migration_contextbound_domain;
  kdf_suite = fixed_kdf_suite;
  kdf_policy_version = fixed_policy_version;
  migration_ss_pq = fixed_ss_pq;
  migration_ss_traditional = fixed_ss_traditional;
  migration_ct_pq = fixed_ct_pq;
  migration_pk_pq = fixed_pk_pq;
  migration_ct_traditional = traditional_ct;
  migration_pk_traditional = fixed_pk_traditional;
  execution_policy_digest = fixed_execution_policy_digest;
  migration = sample_migration migration_epoch_one kem_direction;
  full_state = sample_full_state migration_epoch_one;
|}.

lemma omitted_post_ciphertext_negative_control :
  (sample_post_execution post_ct0 migration_initiator_encapsulator)
    .`migration_ct_traditional <>
  (sample_post_execution post_ct1 migration_initiator_encapsulator)
    .`migration_ct_traditional /\
  omitted_post_digest
    (sample_post_execution post_ct0 migration_initiator_encapsulator) =
  omitted_post_digest
    (sample_post_execution post_ct1 migration_initiator_encapsulator).
proof.
  by rewrite /sample_post_execution /post_ct0 /post_ct1
             /omitted_post_digest /omitted_post_fields.
qed.

op omitted_finished_hash_input (e : migration_execution) : bytes =
  encode [migration_finished_domain;
          migration_abi2_key e;
          migration_post_kem_digest e].

op omitted_finished (e : migration_execution) (_sender_role : bytes) : bytes =
  H_finished (omitted_finished_hash_input e).

lemma omitted_finished_role_negative_control :
  migration_initiator_role <> migration_responder_role /\
  omitted_finished
    (sample_migration_execution migration_epoch_one
                                migration_initiator_encapsulator)
    migration_initiator_role =
  omitted_finished
    (sample_migration_execution migration_epoch_one
                                migration_initiator_encapsulator)
    migration_responder_role.
proof.
  by rewrite migration_roles_distinct /omitted_finished.
qed.

op omitted_accept_hash_input (e : migration_execution) : bytes =
  encode [migration_accepted_key_domain;
          migration_abi2_key e;
          migration_post_kem_digest e].

op omitted_accept_key (e : migration_execution)
                       (_i _r : bytes) : bytes =
  H_accept (omitted_accept_hash_input e).

lemma omitted_accept_finished_negative_control :
  let e = sample_migration_execution migration_epoch_one
          migration_initiator_encapsulator in
  (migration_initiator_finished e, migration_responder_finished e) <>
    (wrong_finished (migration_initiator_finished e),
     migration_responder_finished e) /\
  omitted_accept_key e
    (migration_initiator_finished e) (migration_responder_finished e) =
  omitted_accept_key e
    (wrong_finished (migration_initiator_finished e))
    (migration_responder_finished e).
proof.
  simplify.
  smt(wrong_finished_distinct).
qed.
