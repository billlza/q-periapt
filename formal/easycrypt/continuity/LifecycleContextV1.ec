(* ===========================================================================
 * Candidate LifecycleContextV1 projection checks.
 *
 * STATUS: non-normative Continuity diagnostic. This development proves that
 * the three nested LP8 layers are injective over the modeled field projection,
 * and exhibits structural collisions when policy or direction is omitted.
 * It does NOT prove that Rust emits these bytes, that any field is authentic,
 * that the projection is protocol-complete, or that a ratchet provides FS/PCS.
 * =========================================================================== *)

require import AllCore List.

type bytes = int list.
type transcript = bytes list.

op be8 : int -> bytes.
axiom be8_size n : size (be8 n) = 8.
axiom be8_inj n m : be8 n = be8 m => n = m.

op lp8 (f : bytes) : bytes = be8 (size f) ++ f.
op encode (t : transcript) : bytes = foldr (fun f acc => lp8 f ++ acc) [] t.

lemma encode_nil : encode [] = [].
proof. by rewrite /encode. qed.

lemma encode_cons f fs : encode (f :: fs) = lp8 f ++ encode fs.
proof. by rewrite /encode. qed.

lemma lp8_cat_inj (a b x y : bytes) :
  lp8 a ++ x = lp8 b ++ y => a = b /\ x = y.
proof.
rewrite /lp8 -!catA.
have hsz : size (be8 (size a)) = size (be8 (size b)) by rewrite !be8_size.
rewrite (eqseq_cat _ _ _ _ hsz) => -[hb hax].
have hsa := be8_inj _ _ hb.
by move: hax; rewrite (eqseq_cat _ _ _ _ hsa) => -[-> ->].
qed.

lemma encode_inj (t0 t1 : transcript) : encode t0 = encode t1 => t0 = t1.
proof.
elim: t0 t1 => [|f fs ih] t1.
+ case: t1 => [|g gs] //.
  rewrite encode_nil encode_cons /lp8 -catA => h.
  have hsz : size (be8 (size g) ++ (g ++ encode gs)) = 0 by rewrite -h /=.
  move: hsz; rewrite size_cat be8_size; smt(size_ge0).
+ case: t1 => [|g gs].
  - rewrite encode_cons encode_nil /lp8 -catA => h.
    have hsz : size (be8 (size f) ++ (f ++ encode fs)) = 0 by rewrite h /=.
    move: hsz; rewrite size_cat be8_size; smt(size_ge0).
  - rewrite !encode_cons => h.
    have [-> heq] := lp8_cat_inj _ _ _ _ h.
    by rewrite (ih _ heq).
qed.

op lifecycle_domain : bytes.
op lifecycle_schema : bytes.
op policy_domain : bytes.
op digest_domain : bytes.

(* Fixed-width fields are abstract bytes here. `tail` represents the exact
   ordered Bootstrap or RootTransition tail field list. *)
type lifecycle_context = {
  kind : bytes;
  protocol_id : bytes;
  wire_version : bytes;
  suite_digest : bytes;
  session_id : bytes;
  initiator_account : bytes;
  initiator_device : bytes;
  initiator_epoch : bytes;
  initiator_credential : bytes;
  responder_account : bytes;
  responder_device : bytes;
  responder_epoch : bytes;
  responder_credential : bytes;
  identity_mode : bytes;
  direction : bytes;
  authentication_stage : bytes;
  tail : transcript;
  policy_digest : bytes;
}.

op body_fields (c : lifecycle_context) : transcript =
  [ lifecycle_domain; lifecycle_schema; c.`kind; c.`protocol_id;
    c.`wire_version; c.`suite_digest; c.`session_id;
    c.`initiator_account; c.`initiator_device; c.`initiator_epoch;
    c.`initiator_credential; c.`responder_account; c.`responder_device;
    c.`responder_epoch; c.`responder_credential; c.`identity_mode;
    c.`direction; c.`authentication_stage ] ++ c.`tail.

op body (c : lifecycle_context) : bytes = encode (body_fields c).
op full_fields (c : lifecycle_context) : transcript =
  [ policy_domain; c.`policy_digest; body c ].
op full_kctx (c : lifecycle_context) : bytes = encode (full_fields c).
op digest_fields (c : lifecycle_context) : transcript =
  [ digest_domain; full_kctx c ].
op digest_preimage (c : lifecycle_context) : bytes = encode (digest_fields c).

lemma body_fields_inj (c0 c1 : lifecycle_context) :
  body_fields c0 = body_fields c1 =>
  c0.`kind = c1.`kind /\
  c0.`protocol_id = c1.`protocol_id /\
  c0.`wire_version = c1.`wire_version /\
  c0.`suite_digest = c1.`suite_digest /\
  c0.`session_id = c1.`session_id /\
  c0.`initiator_account = c1.`initiator_account /\
  c0.`initiator_device = c1.`initiator_device /\
  c0.`initiator_epoch = c1.`initiator_epoch /\
  c0.`initiator_credential = c1.`initiator_credential /\
  c0.`responder_account = c1.`responder_account /\
  c0.`responder_device = c1.`responder_device /\
  c0.`responder_epoch = c1.`responder_epoch /\
  c0.`responder_credential = c1.`responder_credential /\
  c0.`identity_mode = c1.`identity_mode /\
  c0.`direction = c1.`direction /\
  c0.`authentication_stage = c1.`authentication_stage /\
  c0.`tail = c1.`tail.
proof. rewrite /body_fields => h. smt(). qed.

lemma body_inj (c0 c1 : lifecycle_context) :
  body c0 = body c1 =>
  c0.`kind = c1.`kind /\
  c0.`protocol_id = c1.`protocol_id /\
  c0.`wire_version = c1.`wire_version /\
  c0.`suite_digest = c1.`suite_digest /\
  c0.`session_id = c1.`session_id /\
  c0.`initiator_account = c1.`initiator_account /\
  c0.`initiator_device = c1.`initiator_device /\
  c0.`initiator_epoch = c1.`initiator_epoch /\
  c0.`initiator_credential = c1.`initiator_credential /\
  c0.`responder_account = c1.`responder_account /\
  c0.`responder_device = c1.`responder_device /\
  c0.`responder_epoch = c1.`responder_epoch /\
  c0.`responder_credential = c1.`responder_credential /\
  c0.`identity_mode = c1.`identity_mode /\
  c0.`direction = c1.`direction /\
  c0.`authentication_stage = c1.`authentication_stage /\
  c0.`tail = c1.`tail.
proof. rewrite /body => h. exact (body_fields_inj _ _ (encode_inj _ _ h)). qed.

lemma full_kctx_inj (c0 c1 : lifecycle_context) :
  full_kctx c0 = full_kctx c1 => c0 = c1.
proof.
rewrite /full_kctx => h.
have hf := encode_inj _ _ h.
have hp : c0.`policy_digest = c1.`policy_digest by smt().
have hb : body c0 = body c1 by smt().
have hs := body_inj _ _ hb.
by smt().
qed.

lemma digest_preimage_inj (c0 c1 : lifecycle_context) :
  digest_preimage c0 = digest_preimage c1 => c0 = c1.
proof.
rewrite /digest_preimage => h.
have hf := encode_inj _ _ h.
have hk : full_kctx c0 = full_kctx c1 by smt().
exact (full_kctx_inj _ _ hk).
qed.

(* Explicit omission controls. They show structural ambiguity, not an attack on
   SHA3 or an authentication protocol. *)
op fixed_kind : bytes. op fixed_protocol : bytes. op fixed_wire : bytes.
op fixed_suite : bytes. op fixed_session : bytes.
op fixed_ia : bytes. op fixed_id : bytes. op fixed_ie : bytes. op fixed_ic : bytes.
op fixed_ra : bytes. op fixed_rd : bytes. op fixed_re : bytes. op fixed_rc : bytes.
op fixed_mode : bytes. op fixed_stage : bytes. op fixed_tail : bytes.
op policy0 : bytes. op policy1 : bytes.
op direction0 : bytes. op direction1 : bytes.
axiom policy_neq : policy0 <> policy1.
axiom direction_neq : direction0 <> direction1.

op sample (policy direction_value : bytes) : lifecycle_context =
  {| kind = fixed_kind;
     protocol_id = fixed_protocol; wire_version = fixed_wire;
     suite_digest = fixed_suite; session_id = fixed_session;
     initiator_account = fixed_ia; initiator_device = fixed_id;
     initiator_epoch = fixed_ie; initiator_credential = fixed_ic;
     responder_account = fixed_ra; responder_device = fixed_rd;
     responder_epoch = fixed_re; responder_credential = fixed_rc;
     identity_mode = fixed_mode; direction = direction_value;
     authentication_stage = fixed_stage; tail = [fixed_tail];
     policy_digest = policy |}.

op omit_policy (c : lifecycle_context) : bytes =
  encode [ policy_domain; body c ].

op omit_direction_body_fields (c : lifecycle_context) : transcript =
  [ lifecycle_domain; lifecycle_schema; c.`kind; c.`protocol_id;
    c.`wire_version; c.`suite_digest; c.`session_id;
    c.`initiator_account; c.`initiator_device; c.`initiator_epoch;
    c.`initiator_credential; c.`responder_account; c.`responder_device;
    c.`responder_epoch; c.`responder_credential; c.`identity_mode;
    c.`authentication_stage ] ++ c.`tail.

op omit_direction (c : lifecycle_context) : bytes =
  encode [ policy_domain; c.`policy_digest;
           encode (omit_direction_body_fields c) ].

lemma omit_policy_collision :
  sample policy0 direction0 <> sample policy1 direction0 /\
  omit_policy (sample policy0 direction0) =
    omit_policy (sample policy1 direction0).
proof. rewrite /sample /omit_policy /body /body_fields. smt(policy_neq). qed.

lemma omit_direction_collision :
  sample policy0 direction0 <> sample policy0 direction1 /\
  omit_direction (sample policy0 direction0) =
    omit_direction (sample policy0 direction1).
proof.
rewrite /sample /omit_direction /omit_direction_body_fields.
smt(direction_neq).
qed.
