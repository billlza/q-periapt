(* ===========================================================================
 * Binding security of the ContextBound combiner, reduced to collision-resistance
 * of the hash — with NO binding assumption on the component KEMs.
 *
 * Target (docs/BINDING_SECURITY.md): MAL-BIND-K-CT (and, by the same argument,
 * MAL-BIND-K-PK and the context extension MAL-BIND-K-CTX).
 *
 * STATUS: MACHINE-CHECKED. `easycrypt BindingViaCR.ec` succeeds; reproduce with
 *   `make check`. The generic reduction `bind_le_cr` AND its three instantiated
 *   corollaries `bind_le_cr_kct` / `bind_le_cr_kpk` / `bind_le_cr_kctx` (concrete
 *   ciphertext / public-key / context projections) are verified, each reducing
 *   ONLY to collision-resistance of H. `encode_inj` (injective encoding) is a
 *   PROVED LEMMA, not an axiom; the proof bottoms out at two ELEMENTARY facts about
 *   an 8-byte big-endian length field (`be8_size`, `be8_inj`).
 *
 *   This file has TWO layers:
 *   (i)  `bind_le_cr` + `bind_le_cr_kct/kpk/kctx` — the generic reduction at the
 *        TRANSCRIPT-COLLISION level (K is an opaque adversary value, abstract `proj`).
 *   (ii) `malbind_kct_le_cr` / `malbind_kpk_le_cr` / `malbind_kctx_le_cr` — the
 *        KEM-AWARE game: the (MAL) adversary supplies the keypairs, K is DERIVED via
 *        `Decaps` + the combiner, and the win condition is on the hybrid ciphertext /
 *        public key / context. THIS is the layer to cite for "MAL-BIND-K-CT".
 *
 *   HONEST SCOPE of layer (ii) — read before citing (a reviewer will open this file):
 *   - It is the CDM MAL-BIND-K-CT game **specialized to the implicit-rejection
 *     setting**: the key type has no ⊥ and `Decaps` is total, so ML-KEM never returns
 *     ⊥ and CDM's `K≠⊥` conjunct holds BY CONSTRUCTION (it is subsumed, not dropped as
 *     "vacuous"). This is faithful for ML-KEM-class KEMs; it does NOT model
 *     explicitly-rejecting KEMs.
 *   - `decaps_pq`/`decaps_trad` are ABSTRACT, TOTAL, AXIOM-FREE. The reduction uses NO
 *     property of Decaps, so the result holds for EVERY total Decaps (ML-KEM included)
 *     ⇒ genuine "zero KEM binding assumption". The flip side: there is NO link to the
 *     FIPS-203 Decaps, and the shared-secret fields `ss_pq`/`ss_trad` are PRESENT in
 *     the hash but INERT in the K-binding argument (binding flows through the absorbed
 *     ct/pk/ctx fields — the hash-everything mechanism).
 *   - So the honest claim is "machine-checked CDM MAL-BIND-K-{CT,PK,CTX} for the
 *     implicit-rejection setting, over abstract Decaps, reducing to CR(H)" — NOT a
 *     fully faithful mechanization of CDM Figure 6 for arbitrary KEMs.
 *   - H's CR is a modeling assumption; IND-CCA2 robustness is on paper; there is no
 *     spec<->implementation linkage proof (docs/BINDING_SECURITY.md §5/§6).
 * =========================================================================== *)

require import AllCore List.

(* ---- Concrete byte / transcript model ------------------------------------ *)
type bytes = int list.   (* a byte string (each entry a byte value)           *)
type key.                (* the 32-byte combined shared secret                *)
type obs = bytes list.   (* an OBSERVABLE projection of a transcript: the
                            ciphertext (K-CT), public key (K-PK), or context.
                            Concrete (a list of the projected fields) so the
                            named corollaries below are CHECKED instantiations. *)

(* A fixed-width 8-byte big-endian length prefix, modeled by its two ELEMENTARY
   properties: a fixed-width BE integer field is 8 bytes wide and injective.
   Everything else about the encoding is PROVED below, not assumed. *)
op be8 : int -> bytes.
axiom be8_size n : size (be8 n) = 8.
axiom be8_inj  n m : be8 n = be8 m => n = m.

(* Length-prefix one field: its 8-byte BE length, then the field bytes. *)
op lp (f : bytes) : bytes = be8 (size f) ++ f.

(* A transcript is the ordered field list of ContextBound (LABEL, suite_id,
   policy_version, ss_pq, ss_trad, ct_pq, pk_pq, ct_trad, pk_trad, context).
   The canonical encoding (docs/BINDING_SECURITY.md §3.2) concatenates the
   length-prefixed fields in order. *)
type transcript = bytes list.
op encode (t : transcript) : bytes = foldr (fun f acc => lp f ++ acc) [] t.

lemma encode_nil : encode [] = [].
proof. by rewrite /encode. qed.

lemma encode_cons f fs : encode (f :: fs) = lp f ++ encode fs.
proof. by rewrite /encode. qed.

(* ---- Injectivity of the canonical encoding: PROVED (was an axiom) -------- *
 * Step 1: a length-prefixed field is "self-delimiting" — splitting two
 * length-prefixed concatenations on the 8-byte prefix recovers equal lengths
 * (be8_inj), hence equal field bodies and equal remainders (eqseq_cat).        *)
lemma lp_cat_inj (a b x y : bytes) :
  lp a ++ x = lp b ++ y => a = b /\ x = y.
proof.
rewrite /lp -!catA.
have hsz : size (be8 (size a)) = size (be8 (size b)) by rewrite !be8_size.
rewrite (eqseq_cat _ _ _ _ hsz) => -[hb hax].
have hsa := be8_inj _ _ hb.
by move: hax; rewrite (eqseq_cat _ _ _ _ hsa) => -[-> ->].
qed.

(* Step 2: lift field-wise self-delimitation to the whole field list. A nonempty
   encoding has size >= 8, so it can never equal the empty encoding; otherwise
   peel the head field with `lp_cat_inj` and induct. *)
lemma encode_inj (t1 t2 : transcript) :
  encode t1 = encode t2 => t1 = t2.
proof.
elim: t1 t2 => [|f fs ih] t2.
+ case: t2 => [|g gs] //.
  rewrite encode_nil encode_cons /lp -catA => h.
  have hsz : size (be8 (size g) ++ (g ++ encode gs)) = 0 by rewrite -h /=.
  move: hsz; rewrite size_cat be8_size; smt(size_ge0).
+ case: t2 => [|g gs].
  - rewrite encode_cons encode_nil /lp -catA => h.
    have hsz : size (be8 (size f) ++ (f ++ encode fs)) = 0 by rewrite h /=.
    move: hsz; rewrite size_cat be8_size; smt(size_ge0).
  - rewrite !encode_cons => h.
    have [-> heq] := lp_cat_inj _ _ _ _ h.
    by rewrite (ih _ heq).
qed.

(* ---- The hash, the combiner, and the observable -------------------------- *)
op H : bytes -> key.                          (* SHA3-256, modeled CR below.   *)
op combine (t : transcript) : key = H (encode t).
(* Instantiate: proj := ct_pq||ct_trad -> K-CT ; pk_pq||pk_trad -> K-PK ;
   context -> K-CTX (docs/BINDING_SECURITY.md §3.6). *)
op proj : transcript -> obs.

(* ---- Collision-resistance game for H ------------------------------------- *)
module type CRAdv = {
  proc find() : bytes * bytes
}.

module CR (A : CRAdv) = {
  proc main() : bool = {
    var x : bytes;
    var y : bytes;
    (x, y) <@ A.find();
    return x <> y /\ H x = H y;
  }
}.

(* ---- The X-BIND-K-* game (generic over the observable `proj`) ------------ *)
(* The (MAL) adversary outputs two transcripts colliding on the derived key K but
   DIFFERING on the observable. Both keys are total (our combiner never returns
   bottom), matching docs/BINDING_SECURITY.md §3.6. *)
module type BindAdv = {
  proc find() : transcript * transcript
}.

module Bind (A : BindAdv) = {
  proc main() : bool = {
    var t0 : transcript;
    var t1 : transcript;
    (t0, t1) <@ A.find();
    return combine t0 = combine t1 /\ proj t0 <> proj t1;
  }
}.

(* ---- Reduction: a Bind winner yields an H-collision ---------------------- *)
module B (A : BindAdv) : CRAdv = {
  proc find() : bytes * bytes = {
    var t0 : transcript;
    var t1 : transcript;
    (t0, t1) <@ A.find();
    return (encode t0, encode t1);
  }
}.

lemma combine_def (t : transcript) : combine t = H (encode t).
proof. by rewrite /combine. qed.

(* ---- Main theorem -------------------------------------------------------- *
 * Adv^{X-BIND-K-*}(A)  <=  Adv^{CR}(B(A)),  reducing ONLY to CR of H.
 * Instantiating `proj` gives MAL-BIND-K-CT / K-PK / K-CTX (§5.1).
 * ------------------------------------------------------------------------- *)
lemma bind_le_cr (A <: BindAdv) &m :
  Pr[Bind(A).main() @ &m : res] <= Pr[CR(B(A)).main() @ &m : res].
proof.
  (* Both games run A.find() once; whenever Bind wins, CR(B(A)) wins:
     (a) a combine-collision gives the H-equality; (b) a differing observable
     forces differing transcripts, hence — by the PROVED encode_inj — differing
     encodings, i.e. a genuine H-collision input. *)
  byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
  proc; inline B(A).find.
  wp.
  call (_ : true).
  auto => />.
  smt(encode_inj combine_def).
qed.

(* ---- Named corollaries: CONCRETE projections, DISCHARGED ----------------- *
 * The transcript is the ContextBound field list in canonical order:
 *   0 LABEL, 1 suite_id, 2 policy_version, 3 ss_pq, 4 ss_trad,
 *   5 ct_pq, 6 pk_pq, 7 ct_trad, 8 pk_trad, 9 context.
 * We instantiate the observable to each standard binding axis and DISCHARGE the
 * matching reduction, so K-CT / K-PK / K-CTX are machine-checked corollaries —
 * not merely the generic `bind_le_cr` over an abstract `proj`. *)

op proj_ct  (t : transcript) : obs = [nth [] t 5; nth [] t 7].  (* ct_pq , ct_trad *)
op proj_pk  (t : transcript) : obs = [nth [] t 6; nth [] t 8].  (* pk_pq , pk_trad *)
op proj_ctx (t : transcript) : obs = [nth [] t 9].              (* context         *)

(* A differing observable forces differing transcripts (any projection is a
   function, so equal transcripts project equally). *)
lemma neq_proj_neq (p : transcript -> obs) (t0 t1 : transcript) :
  p t0 <> p t1 => t0 <> t1.
proof. by apply: contra => ->. qed.

module BindCT (A : BindAdv) = {
  proc main() : bool = {
    var t0 : transcript; var t1 : transcript;
    (t0, t1) <@ A.find();
    return combine t0 = combine t1 /\ proj_ct t0 <> proj_ct t1;
  }
}.
module BindPK (A : BindAdv) = {
  proc main() : bool = {
    var t0 : transcript; var t1 : transcript;
    (t0, t1) <@ A.find();
    return combine t0 = combine t1 /\ proj_pk t0 <> proj_pk t1;
  }
}.
module BindCTX (A : BindAdv) = {
  proc main() : bool = {
    var t0 : transcript; var t1 : transcript;
    (t0, t1) <@ A.find();
    return combine t0 = combine t1 /\ proj_ctx t0 <> proj_ctx t1;
  }
}.

(* MAL-BIND-K-CT: a ciphertext-disagreeing key-collision yields an H-collision. *)
lemma bind_le_cr_kct (A <: BindAdv) &m :
  Pr[BindCT(A).main() @ &m : res] <= Pr[CR(B(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline B(A).find. wp. call (_ : true). auto => />.
smt(encode_inj combine_def neq_proj_neq).
qed.

(* MAL-BIND-K-PK: a public-key-disagreeing key-collision yields an H-collision. *)
lemma bind_le_cr_kpk (A <: BindAdv) &m :
  Pr[BindPK(A).main() @ &m : res] <= Pr[CR(B(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline B(A).find. wp. call (_ : true). auto => />.
smt(encode_inj combine_def neq_proj_neq).
qed.

(* MAL-BIND-K-CTX: the context extension (superset guarantee, NOT a standard
   X-BIND lattice point — see docs/BINDING_SECURITY.md §3.6 + §6 well-posedness). *)
lemma bind_le_cr_kctx (A <: BindAdv) &m :
  Pr[BindCTX(A).main() @ &m : res] <= Pr[CR(B(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline B(A).find. wp. call (_ : true). auto => />.
smt(encode_inj combine_def neq_proj_neq).
qed.

(* ---- Honest scope ---------------------------------------------------------- *
 * (1) The generic `bind_le_cr` above is at the TRANSCRIPT-COLLISION level (K is an
 *     opaque adversary value). The KEM-aware game is mechanized BELOW
 *     (`malbind_kct_le_cr`): K is DERIVED via Decaps + the combiner, the MAL adversary
 *     supplies the keypairs, win is on the hybrid ciphertext. It is the CDM game
 *     specialized to implicit rejection (⊥-free key, total Decaps ⇒ K≠⊥ holds by
 *     construction), over abstract Decaps — see that section's header for exact scope.
 * (2) Establishes the K-binds-{CT,PK,CTX} direction only. X-BIND-CT-* is
 *     structurally UNACHIEVABLE for an implicitly-rejecting KEM and is NOT claimed.
 * ------------------------------------------------------------------------- *)

(* ===========================================================================
 * KEM-AWARE CDM MAL-BIND-K-CT GAME (implicit-rejection setting) — closes the main gap.
 *
 * We MODEL the component KEMs' Decaps and DERIVE K = H(encode(ContextBound fields))
 * from them, then state the CDM MAL-BIND-K-CT game: the (MAL) adversary supplies the
 * keypairs and a colliding pair of executions. The reduction to CR(H) uses NO property
 * of Decaps — only injective absorption of the ciphertext fields; the "zero KEM binding
 * assumption" claim is thus literal (it holds for EVERY total Decaps, ML-KEM included).
 * SCOPE (honest): this is the CDM game SPECIALIZED to implicit rejection — the key type
 * is ⊥-free and Decaps is total, so CDM's `K ≠ ⊥` conjunct holds BY CONSTRUCTION
 * (subsumed; this is NOT a faithful encoding of the explicitly-rejecting case). The same
 * totality is why X-BIND-CT-* is structurally unachievable (no ⊥ to provoke). NB:
 * `ss_pq`/`ss_trad` are absorbed but INERT in the argument — K-binding flows through the
 * ct/pk/ctx fields (the hash-everything mechanism), and Decaps carries no FIPS-203
 * semantics, so this proves nothing ABOUT ML-KEM's Decaps, only about the combiner.
 * =========================================================================== *)

type sk.                                (* a component decapsulation key          *)
op decaps_pq   : sk -> bytes -> bytes.  (* ML-KEM Decaps:  dk,ct |-> ss. TOTAL, ABSTRACT *)
op decaps_trad : sk -> bytes -> bytes.  (* X25519 "Decaps": dk,ct |-> ss. TOTAL, ABSTRACT *)

op label_f : bytes.   (* fixed framing fields (LABEL / suite_id / policy_version) *)
op suite_f : bytes.
op pv_f    : bytes.

(* One hybrid execution: the adversary's CLAIMED keys (sk/pk may be mutually
   inconsistent — the malicious-key setting), a ciphertext pair, and context. *)
type texec = {
  sk_pq   : sk;  pk_pq   : bytes;  ct_pq   : bytes;
  sk_trad : sk;  pk_trad : bytes;  ct_trad : bytes;
  ctx     : bytes;
}.

(* The ContextBound field list (canonical order) DERIVED from an execution: the two
   shared secrets come from Decaps; every ct/pk/ctx is absorbed. *)
op fields (e : texec) : transcript =
  [ label_f; suite_f; pv_f;
    decaps_pq e.`sk_pq e.`ct_pq; decaps_trad e.`sk_trad e.`ct_trad;
    e.`ct_pq; e.`pk_pq; e.`ct_trad; e.`pk_trad; e.`ctx ].

op hkey (e : texec) : key = H (encode (fields e)).
lemma hkey_def (e : texec) : hkey e = H (encode (fields e)).
proof. by rewrite /hkey. qed.

(* The K-CT observable: the hybrid ciphertext (ct_pq, ct_trad). *)
op ct_of (e : texec) : bytes * bytes = (e.`ct_pq, e.`ct_trad).

(* A differing hybrid ciphertext forces differing field lists (ct_pq/ct_trad sit at
   fixed positions of `fields`, so equal lists give an equal ciphertext pair). *)
lemma ct_neq_fields_neq (e0 e1 : texec) :
  ct_of e0 <> ct_of e1 => fields e0 <> fields e1.
proof. rewrite /ct_of /fields => h. smt(). qed.

module type MalAdv = { proc find() : texec * texec }.

(* CDM MAL-BIND-K-CT: equal derived key, differing hybrid ciphertext. *)
module MalBindKCT (A : MalAdv) = {
  proc main() : bool = {
    var e0 : texec; var e1 : texec;
    (e0, e1) <@ A.find();
    return hkey e0 = hkey e1 /\ ct_of e0 <> ct_of e1;
  }
}.

(* Reduction: emit the two ContextBound encodings as the CR challenge. *)
module BK (A : MalAdv) : CRAdv = {
  proc find() : bytes * bytes = {
    var e0 : texec; var e1 : texec;
    (e0, e1) <@ A.find();
    return (encode (fields e0), encode (fields e1));
  }
}.

(* MAL-BIND-K-CT  <=  CR(H), with NO assumption on Decaps. *)
lemma malbind_kct_le_cr (A <: MalAdv) &m :
  Pr[MalBindKCT(A).main() @ &m : res] <= Pr[CR(BK(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BK(A).find. wp. call (_ : true). auto => />.
smt(encode_inj hkey_def ct_neq_fields_neq).
qed.

(* --- K-PK and K-CTX: same KEM-aware game + same reduction BK, other observable - *)
op pk_of (e : texec) : bytes * bytes = (e.`pk_pq, e.`pk_trad).
lemma pk_neq_fields_neq (e0 e1 : texec) :
  pk_of e0 <> pk_of e1 => fields e0 <> fields e1.
proof. rewrite /pk_of /fields => h. smt(). qed.

op ctx_of (e : texec) : bytes = e.`ctx.
lemma ctx_neq_fields_neq (e0 e1 : texec) :
  ctx_of e0 <> ctx_of e1 => fields e0 <> fields e1.
proof. rewrite /ctx_of /fields => h. smt(). qed.

module MalBindKPK (A : MalAdv) = {
  proc main() : bool = {
    var e0 : texec; var e1 : texec;
    (e0, e1) <@ A.find();
    return hkey e0 = hkey e1 /\ pk_of e0 <> pk_of e1;
  }
}.
module MalBindKCTX (A : MalAdv) = {
  proc main() : bool = {
    var e0 : texec; var e1 : texec;
    (e0, e1) <@ A.find();
    return hkey e0 = hkey e1 /\ ctx_of e0 <> ctx_of e1;
  }
}.

(* MAL-BIND-K-PK  <=  CR(H). *)
lemma malbind_kpk_le_cr (A <: MalAdv) &m :
  Pr[MalBindKPK(A).main() @ &m : res] <= Pr[CR(BK(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BK(A).find. wp. call (_ : true). auto => />.
smt(encode_inj hkey_def pk_neq_fields_neq).
qed.

(* MAL-BIND-K-CTX  <=  CR(H) — context extension (superset guarantee; §3.6/§6). *)
lemma malbind_kctx_le_cr (A <: MalAdv) &m :
  Pr[MalBindKCTX(A).main() @ &m : res] <= Pr[CR(BK(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BK(A).find. wp. call (_ : true). auto => />.
smt(encode_inj hkey_def ctx_neq_fields_neq).
qed.
