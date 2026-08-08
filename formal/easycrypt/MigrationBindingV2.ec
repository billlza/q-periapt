(* Migration Contract V2: state-identity binding at the KDF abstraction boundary.
 *
 * BindingViaCR supplies the proved injective LP8 byte encoding and the abstract
 * hash/KDF H.  This file begins at KDF input bytes; it does not model the Rust
 * encoder, digest preimages, signatures, persistence, or protocol acceptance.
 *)
require import AllCore List BindingViaCR.

type state_identity = bytes * bytes.

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
op migration_state_v1_domain : bytes =
  [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
   73;79;78;45;83;84;65;84;69;47;118;49].
op migration_state_v1_schema : bytes = [0;1].

lemma migration_v2_contract_constants_exact :
  migration_v2_domain =
    [81;45;80;69;82;73;65;80;84;45;77;73;71;82;65;84;
     73;79;78;45;67;79;78;84;69;88;84;47;118;50] /\
  migration_v2_schema = [0;2].
proof. by rewrite /migration_v2_domain /migration_v2_schema. qed.

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

(* SHA3-256 for state commitments is modeled separately from the outer
 * ContextBound KDF/hash H, so their collision bad events remain distinct. *)
op H_state : bytes -> bytes.

op migration_execution_well_formed (e : migration_execution) : bool =
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

op migration_accepted : migration_execution -> bool.
op migration_derived_key (e : migration_execution) : key =
  H (encode (migration_contextbound_fields e)).
op migration_accepted_key (e : migration_execution) : key option =
  if migration_accepted e then Some (migration_derived_key e) else None.

module type MigrationAdversary = {
  proc find() : migration_execution * migration_execution
}.

module MigrationBindKState(A : MigrationAdversary) = {
  proc main() : bool = {
    var e0, e1;
    (e0, e1) <@ A.find();
    return migration_accepted_key e0 = migration_accepted_key e1 /\
           migration_accepted_key e0 <> None /\
           state_of e0.`migration <> state_of e1.`migration;
  }
}.

module MigrationReduction(A : MigrationAdversary) : CRAdv = {
  proc find() : bytes * bytes = {
    var e0, e1;
    (e0, e1) <@ A.find();
    return (encode (migration_contextbound_fields e0),
            encode (migration_contextbound_fields e1));
  }
}.

(* MIG-BIND-K-STATE: equal, non-bottom accepted keys under distinct state
 * identities give a collision in H. *)
lemma mig_bind_k_state_le_cr (A <: MigrationAdversary) &m :
  Pr[MigrationBindKState(A).main() @ &m : res] <=
  Pr[CR(MigrationReduction(A)).main() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
  proc.
  inline MigrationReduction(A).find.
  wp; call (_ : true); auto => />.
  rewrite /migration_accepted_key /migration_derived_key.
  smt(encode_inj state_neq_migration_contextbound_fields_neq).
qed.

op migration_context_collision (e0 e1 : migration_execution) : bool =
  encode (migration_contextbound_fields e0) <>
    encode (migration_contextbound_fields e1) /\
  H (encode (migration_contextbound_fields e0)) =
    H (encode (migration_contextbound_fields e1)).

op migration_state_collision (e0 e1 : migration_execution) : bool =
  canonical_full_state_body e0.`full_state <>
    canonical_full_state_body e1.`full_state /\
  H_state (canonical_full_state_body e0.`full_state) =
    H_state (canonical_full_state_body e1.`full_state).

(* Full MIG-BIND-K-STATE bad-event decomposition.  If two well-formed accepted
 * executions have the same non-bottom key but different canonical full-state
 * bodies, then either the outer context hash/KDF collides, or the state digest
 * collides.  The computational advantage bound is the union bound
 * Adv_CR(H_context) + Adv_CR(H_state).  EUF-CMA of transition signatures is a
 * separate protocol assumption and is not used by this KDF theorem. *)
lemma mig_bind_k_full_state_bad_event_decomposition e0 e1 :
  migration_execution_well_formed e0 =>
  migration_execution_well_formed e1 =>
  migration_accepted_key e0 = migration_accepted_key e1 =>
  migration_accepted_key e0 <> None =>
  canonical_full_state_body e0.`full_state <>
    canonical_full_state_body e1.`full_state =>
  migration_context_collision e0 e1 \/ migration_state_collision e0 e1.
proof.
  move=> hw0 hw1 hkey hnonbottom hstate.
  rewrite /migration_execution_well_formed in hw0.
  rewrite /migration_execution_well_formed in hw1.
  rewrite /migration_accepted_key /migration_derived_key in hkey.
  rewrite /migration_accepted_key /migration_derived_key in hnonbottom.
  rewrite /migration_context_collision /migration_state_collision.
  case (H_state (canonical_full_state_body e0.`full_state) =
        H_state (canonical_full_state_body e1.`full_state)) => hsdigest.
  - right; split; smt().
  - left.
    have hidentity : state_of e0.`migration <> state_of e1.`migration.
    + rewrite /state_of.
      smt().
    have hfields := state_neq_migration_contextbound_fields_neq e0 e1 hidentity.
    have hencoded :
        encode (migration_contextbound_fields e0) <>
        encode (migration_contextbound_fields e1).
    + smt(encode_inj).
    split; first exact hencoded.
    smt().
qed.

(* Negative control: omit both state-identity projections from V2 M0..M12. *)
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
op omitted_migration_key (e : migration_execution) : key =
  H (encode (omitted_migration_contextbound_fields e)).

op fixed_protocol_id, fixed_role, fixed_initiator_policy,
   fixed_responder_policy, fixed_negotiation_digest, fixed_selected_suite,
   fixed_floor, fixed_typed_prekem_digest, fixed_component_mode : bytes.
op fixed_label, fixed_kdf_suite, fixed_policy_version, fixed_ss_pq,
   fixed_ss_traditional, fixed_ct_pq, fixed_pk_pq,
   fixed_ct_traditional, fixed_pk_traditional,
   fixed_execution_policy_digest : bytes.
op fixed_state_generation, fixed_state_chain, fixed_state_protocol,
   fixed_state_previous_digest, fixed_state_authority,
   fixed_state_execution_policy, fixed_state_floor, fixed_state_mode,
   fixed_state_suites : bytes.
(* Concrete one-byte witnesses keep the omission countermodel executable
 * without introducing any sample-distinctness assumption. *)
op migration_epoch0 : bytes = [0].
op migration_epoch1 : bytes = [1].
op migration_digest0 : bytes = [2].
op migration_digest1 : bytes = [3].

lemma migration_epoch_samples_distinct :
  migration_epoch0 <> migration_epoch1.
proof. by rewrite /migration_epoch0 /migration_epoch1. qed.

lemma migration_digest_samples_distinct :
  migration_digest0 <> migration_digest1.
proof. by rewrite /migration_digest0 /migration_digest1. qed.

op sample_migration (epoch digest : bytes) : migration_record = {|
  protocol_id = fixed_protocol_id;
  encapsulator_role = fixed_role;
  committed_epoch = epoch;
  initiator_policy = fixed_initiator_policy;
  responder_policy = fixed_responder_policy;
  authenticated_negotiation_digest = fixed_negotiation_digest;
  selected_suite = fixed_selected_suite;
  effective_floor = fixed_floor;
  committed_state_digest = digest;
  typed_pre_kem_digest = fixed_typed_prekem_digest;
  component_mode = fixed_component_mode;
|}.

op sample_migration_execution (epoch digest : bytes) : migration_execution = {|
  kdf_label = fixed_label;
  kdf_suite = fixed_kdf_suite;
  kdf_policy_version = fixed_policy_version;
  migration_ss_pq = fixed_ss_pq;
  migration_ss_traditional = fixed_ss_traditional;
  migration_ct_pq = fixed_ct_pq;
  migration_pk_pq = fixed_pk_pq;
  migration_ct_traditional = fixed_ct_traditional;
  migration_pk_traditional = fixed_pk_traditional;
  execution_policy_digest = fixed_execution_policy_digest;
  migration = sample_migration epoch digest;
  full_state = {|
    state_global_generation = fixed_state_generation;
    state_chain_id = fixed_state_chain;
    state_protocol_id = fixed_state_protocol;
    state_epoch = epoch;
    state_previous_digest = fixed_state_previous_digest;
    state_authority_key_id = fixed_state_authority;
    state_execution_policy = fixed_state_execution_policy;
    state_floor = fixed_state_floor;
    state_component_mode = fixed_state_mode;
    state_allowed_suites = fixed_state_suites;
  |};
|}.

lemma omitted_migration_samples_same_key :
  omitted_migration_key
    (sample_migration_execution migration_epoch0 migration_digest0) =
  omitted_migration_key
    (sample_migration_execution migration_epoch1 migration_digest1).
proof.
  rewrite /omitted_migration_key /omitted_migration_contextbound_fields
          /omitted_migration_policy_context /omitted_migration_body
          /omitted_migration_fields /sample_migration_execution
          /sample_migration.
  trivial.
qed.

lemma omitted_migration_samples_distinct_state :
  state_of
    (sample_migration_execution migration_epoch0 migration_digest0).`migration <>
  state_of
    (sample_migration_execution migration_epoch1 migration_digest1).`migration.
proof.
  rewrite /sample_migration_execution /sample_migration /state_of.
  smt(migration_epoch_samples_distinct migration_digest_samples_distinct).
qed.

module OmitMigrationStateAdversary : MigrationAdversary = {
  proc find() : migration_execution * migration_execution = {
    return (sample_migration_execution migration_epoch0 migration_digest0,
            sample_migration_execution migration_epoch1 migration_digest1);
  }
}.

module OmitMigrationStateGame(A : MigrationAdversary) = {
  proc main() : bool = {
    var e0, e1;
    (e0, e1) <@ A.find();
    return Some (omitted_migration_key e0) =
             Some (omitted_migration_key e1) /\
           Some (omitted_migration_key e0) <> None /\
           state_of e0.`migration <> state_of e1.`migration;
  }
}.

lemma omitted_state_negative_control &m :
  Pr[OmitMigrationStateGame(OmitMigrationStateAdversary).main() @ &m : res] =
  1%r.
proof.
  byphoare => //.
  proc; inline OmitMigrationStateAdversary.find; auto => />.
  smt(omitted_migration_samples_same_key
      omitted_migration_samples_distinct_state).
qed.
