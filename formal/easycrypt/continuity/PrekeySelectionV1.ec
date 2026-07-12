(* ===========================================================================
 * Candidate PrekeySelectionV1 structural projection checks.
 *
 * STATUS: non-normative Continuity diagnostic. This proves LP8 projection
 * injectivity over all sixteen modeled fields and exhibits structural
 * collisions for security-relevant omissions. It does NOT prove SHA3
 * collision resistance, field authenticity, directory consistency, manifest
 * membership, unique leasing, one-time consumption, or rollback resistance.
 * =========================================================================== *)

require import AllCore List LifecycleContextV1.

op prekey_domain : bytes.
op prekey_schema : bytes.
op prekey_digest_domain : bytes.

type prekey_selection = {
  suite_digest : bytes;
  responder_account : bytes;
  responder_device : bytes;
  responder_device_epoch : bytes;
  responder_credential : bytes;
  bundle_epoch : bytes;
  directory_checkpoint : bytes;
  signed_manifest : bytes;
  classical_mode : bytes;
  classical_signed_id : bytes;
  classical_selected_id : bytes;
  pq_mode : bytes;
  pq_last_resort_id : bytes;
  pq_selected_id : bytes;
}.

op selection_fields (s : prekey_selection) : transcript =
  [ prekey_domain; prekey_schema; s.`suite_digest;
    s.`responder_account; s.`responder_device; s.`responder_device_epoch;
    s.`responder_credential; s.`bundle_epoch; s.`directory_checkpoint;
    s.`signed_manifest; s.`classical_mode; s.`classical_signed_id;
    s.`classical_selected_id; s.`pq_mode; s.`pq_last_resort_id;
    s.`pq_selected_id ].

op selection_record (s : prekey_selection) : bytes = encode (selection_fields s).
op selection_digest_preimage (s : prekey_selection) : bytes =
  encode [ prekey_digest_domain; selection_record s ].

lemma selection_fields_inj (s0 s1 : prekey_selection) :
  selection_fields s0 = selection_fields s1 =>
  s0.`suite_digest = s1.`suite_digest /\
  s0.`responder_account = s1.`responder_account /\
  s0.`responder_device = s1.`responder_device /\
  s0.`responder_device_epoch = s1.`responder_device_epoch /\
  s0.`responder_credential = s1.`responder_credential /\
  s0.`bundle_epoch = s1.`bundle_epoch /\
  s0.`directory_checkpoint = s1.`directory_checkpoint /\
  s0.`signed_manifest = s1.`signed_manifest /\
  s0.`classical_mode = s1.`classical_mode /\
  s0.`classical_signed_id = s1.`classical_signed_id /\
  s0.`classical_selected_id = s1.`classical_selected_id /\
  s0.`pq_mode = s1.`pq_mode /\
  s0.`pq_last_resort_id = s1.`pq_last_resort_id /\
  s0.`pq_selected_id = s1.`pq_selected_id.
proof. rewrite /selection_fields => h. smt(). qed.

lemma selection_record_inj (s0 s1 : prekey_selection) :
  selection_record s0 = selection_record s1 => s0 = s1.
proof.
rewrite /selection_record => h.
have hf := encode_inj _ _ h.
have hs := selection_fields_inj _ _ hf.
by smt().
qed.

lemma selection_digest_preimage_inj (s0 s1 : prekey_selection) :
  selection_digest_preimage s0 = selection_digest_preimage s1 => s0 = s1.
proof.
rewrite /selection_digest_preimage => h.
have hf := encode_inj _ _ h.
have hr : selection_record s0 = selection_record s1 by smt().
exact (selection_record_inj _ _ hr).
qed.

(* Omission controls use two distinct abstract values and otherwise identical
   samples. Each collision is structural and precedes any hash assumption. *)
op fixed_suite : bytes. op fixed_ra : bytes. op fixed_rd : bytes.
op fixed_re : bytes. op fixed_rc : bytes. op fixed_bundle : bytes.
op fixed_checkpoint : bytes. op fixed_manifest : bytes.
op fixed_cm : bytes. op fixed_cs : bytes. op fixed_csel : bytes.
op fixed_pm : bytes. op fixed_plr : bytes. op fixed_psel : bytes.
op value0 : bytes. op value1 : bytes.
axiom value_neq : value0 <> value1.

op sample_suite (x : bytes) : prekey_selection =
  {| suite_digest = x; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_suite (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`directory_checkpoint; s.`signed_manifest;
    s.`classical_mode; s.`classical_signed_id; s.`classical_selected_id;
    s.`pq_mode; s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_suite_collision :
  sample_suite value0 <> sample_suite value1 /\
  omit_suite (sample_suite value0) = omit_suite (sample_suite value1).
proof. rewrite /sample_suite /omit_suite. smt(value_neq). qed.

op sample_responder_credential (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = x; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_responder_credential (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`bundle_epoch;
    s.`directory_checkpoint; s.`signed_manifest; s.`classical_mode;
    s.`classical_signed_id; s.`classical_selected_id; s.`pq_mode;
    s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_responder_credential_collision :
  sample_responder_credential value0 <> sample_responder_credential value1 /\
  omit_responder_credential (sample_responder_credential value0) =
    omit_responder_credential (sample_responder_credential value1).
proof.
rewrite /sample_responder_credential /omit_responder_credential.
smt(value_neq).
qed.

op sample_bundle_epoch (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = x;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_bundle_epoch (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`directory_checkpoint; s.`signed_manifest; s.`classical_mode;
    s.`classical_signed_id; s.`classical_selected_id; s.`pq_mode;
    s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_bundle_epoch_collision :
  sample_bundle_epoch value0 <> sample_bundle_epoch value1 /\
  omit_bundle_epoch (sample_bundle_epoch value0) =
    omit_bundle_epoch (sample_bundle_epoch value1).
proof. rewrite /sample_bundle_epoch /omit_bundle_epoch. smt(value_neq). qed.

op sample_checkpoint (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = x; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_checkpoint (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`signed_manifest; s.`classical_mode;
    s.`classical_signed_id; s.`classical_selected_id; s.`pq_mode;
    s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_checkpoint_collision :
  sample_checkpoint value0 <> sample_checkpoint value1 /\
  omit_checkpoint (sample_checkpoint value0) =
    omit_checkpoint (sample_checkpoint value1).
proof. rewrite /sample_checkpoint /omit_checkpoint. smt(value_neq). qed.

op sample_manifest (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = x;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_manifest (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`directory_checkpoint; s.`classical_mode;
    s.`classical_signed_id; s.`classical_selected_id; s.`pq_mode;
    s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_manifest_collision :
  sample_manifest value0 <> sample_manifest value1 /\
  omit_manifest (sample_manifest value0) = omit_manifest (sample_manifest value1).
proof. rewrite /sample_manifest /omit_manifest. smt(value_neq). qed.

op sample_classical_mode (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = x; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_classical_mode (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`directory_checkpoint; s.`signed_manifest;
    s.`classical_signed_id; s.`classical_selected_id; s.`pq_mode;
    s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_classical_mode_collision :
  sample_classical_mode value0 <> sample_classical_mode value1 /\
  omit_classical_mode (sample_classical_mode value0) =
    omit_classical_mode (sample_classical_mode value1).
proof. rewrite /sample_classical_mode /omit_classical_mode. smt(value_neq). qed.

op sample_classical_signed (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = x;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_classical_signed (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`directory_checkpoint; s.`signed_manifest;
    s.`classical_mode; s.`classical_selected_id; s.`pq_mode;
    s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_classical_signed_collision :
  sample_classical_signed value0 <> sample_classical_signed value1 /\
  omit_classical_signed (sample_classical_signed value0) =
    omit_classical_signed (sample_classical_signed value1).
proof. rewrite /sample_classical_signed /omit_classical_signed. smt(value_neq). qed.

op sample_classical_selected (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = x; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_classical_selected (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`directory_checkpoint; s.`signed_manifest;
    s.`classical_mode; s.`classical_signed_id; s.`pq_mode;
    s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_classical_selected_collision :
  sample_classical_selected value0 <> sample_classical_selected value1 /\
  omit_classical_selected (sample_classical_selected value0) =
    omit_classical_selected (sample_classical_selected value1).
proof.
rewrite /sample_classical_selected /omit_classical_selected.
smt(value_neq).
qed.

op sample_pq_mode (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = x;
     pq_last_resort_id = fixed_plr; pq_selected_id = fixed_psel |}.

op omit_pq_mode (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`directory_checkpoint; s.`signed_manifest;
    s.`classical_mode; s.`classical_signed_id; s.`classical_selected_id;
    s.`pq_last_resort_id; s.`pq_selected_id ].

lemma omit_pq_mode_collision :
  sample_pq_mode value0 <> sample_pq_mode value1 /\
  omit_pq_mode (sample_pq_mode value0) = omit_pq_mode (sample_pq_mode value1).
proof. rewrite /sample_pq_mode /omit_pq_mode. smt(value_neq). qed.

op sample_pq_last_resort (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = x; pq_selected_id = fixed_psel |}.

op omit_pq_last_resort (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`directory_checkpoint; s.`signed_manifest;
    s.`classical_mode; s.`classical_signed_id; s.`classical_selected_id;
    s.`pq_mode; s.`pq_selected_id ].

lemma omit_pq_last_resort_collision :
  sample_pq_last_resort value0 <> sample_pq_last_resort value1 /\
  omit_pq_last_resort (sample_pq_last_resort value0) =
    omit_pq_last_resort (sample_pq_last_resort value1).
proof. rewrite /sample_pq_last_resort /omit_pq_last_resort. smt(value_neq). qed.

op sample_pq_selected (x : bytes) : prekey_selection =
  {| suite_digest = fixed_suite; responder_account = fixed_ra;
     responder_device = fixed_rd; responder_device_epoch = fixed_re;
     responder_credential = fixed_rc; bundle_epoch = fixed_bundle;
     directory_checkpoint = fixed_checkpoint; signed_manifest = fixed_manifest;
     classical_mode = fixed_cm; classical_signed_id = fixed_cs;
     classical_selected_id = fixed_csel; pq_mode = fixed_pm;
     pq_last_resort_id = fixed_plr; pq_selected_id = x |}.

op omit_pq_selected (s : prekey_selection) : bytes =
  encode [ prekey_domain; prekey_schema; s.`suite_digest; s.`responder_account;
    s.`responder_device; s.`responder_device_epoch; s.`responder_credential;
    s.`bundle_epoch; s.`directory_checkpoint; s.`signed_manifest;
    s.`classical_mode; s.`classical_signed_id; s.`classical_selected_id;
    s.`pq_mode; s.`pq_last_resort_id ].

lemma omit_pq_selected_collision :
  sample_pq_selected value0 <> sample_pq_selected value1 /\
  omit_pq_selected (sample_pq_selected value0) =
    omit_pq_selected (sample_pq_selected value1).
proof. rewrite /sample_pq_selected /omit_pq_selected. smt(value_neq). qed.
