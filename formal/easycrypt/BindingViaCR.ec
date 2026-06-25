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
 *   HONEST SCOPE — read before citing as "machine-checked MAL-BIND-K-CT":
 *   - This is modeled at the **transcript-collision** level. `combine` is a TOTAL
 *     function abstracting the component KEM; there is NO explicit KeyGen / Encaps /
 *     Decaps / implicit-rejection ⊥. The MAL adversary's power is captured by
 *     letting it output two arbitrary transcripts. A FAITHFUL CDM KEM-game
 *     instantiation (adversary-supplied keypairs, Decaps, the K≠⊥ win condition) is
 *     argued ON PAPER (docs/BINDING_SECURITY.md §4.3), NOT yet mechanized. So the
 *     honest claim is "machine-checked CR-based binding reduction, instantiated to
 *     K-CT/K-PK/K-CTX," not "machine-checked CDM MAL-BIND-K-CT game."
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
 * (1) This is modeled at the TRANSCRIPT-COLLISION level: `combine` is a total
 *     function, abstracting the component KEM — there is no explicit Encaps/Decaps
 *     or implicit-rejection ⊥ here. The MAL adversary's power is captured by
 *     letting it output two arbitrary transcripts; a faithful CDM KEM-game
 *     instantiation (keypairs + Decaps + the K≠⊥ condition) is argued on paper
 *     (docs/BINDING_SECURITY.md §4.3), not yet mechanized.
 * (2) Establishes the K-binds-{CT,PK,CTX} direction only. X-BIND-CT-* is
 *     structurally UNACHIEVABLE for an implicitly-rejecting KEM and is NOT claimed.
 * ------------------------------------------------------------------------- *)
