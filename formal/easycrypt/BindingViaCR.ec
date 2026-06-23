(* ===========================================================================
 * Binding security of the ContextBound combiner, reduced to collision-resistance
 * of the hash — with NO binding assumption on the component KEMs.
 *
 * Target (docs/BINDING_SECURITY.md): MAL-BIND-K-CT (and, by the same argument,
 * MAL-BIND-K-PK and the context extension MAL-BIND-K-CTX).
 *
 * STATUS: MACHINE-CHECKED. `easycrypt BindingViaCR.ec` succeeds; reproduce with
 *   `make check`. The theorem `bind_le_cr` is verified, reducing ONLY to
 *   collision-resistance of H.
 *
 *   The canonical encoding is now CONCRETE (length-prefixed field concatenation)
 *   and its injectivity `encode_inj` is a PROVED LEMMA — it is no longer assumed.
 *   The proof bottoms out at two ELEMENTARY, self-evident facts about an 8-byte
 *   big-endian length field (`be8_size`, `be8_inj`: it is 8 bytes wide and
 *   injective), instead of the previous single opaque `encode_inj` axiom. Honest
 *   residual scope (docs/BINDING_SECURITY.md §5/§6): H's CR is a modeling
 *   assumption, IND-CCA2 robustness is argued on paper (not mechanized), and there
 *   is no spec<->implementation linkage proof.
 * =========================================================================== *)

require import AllCore List.

(* ---- Concrete byte / transcript model ------------------------------------ *)
type bytes = int list.   (* a byte string (each entry a byte value)           *)
type key.                (* the 32-byte combined shared secret                *)
type obs.                (* an OBSERVABLE projection of a transcript: the
                            ciphertext (K-CT), public key (K-PK), or context   *)

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

(* ---- Named corollaries (instantiate `proj`) ------------------------------ *
 * With `proj` := the ciphertext projection, `bind_le_cr` is exactly
 *   MAL-BIND-K-CT:  Adv^{MAL-BIND-K-CT}(A) <= Adv^{CR}(H).
 * With `proj` := the public-key projection, it is MAL-BIND-K-PK.
 * With `proj` := the context projection, it is the lattice extension
 *   MAL-BIND-K-CTX (a superset guarantee, NOT a standard X-BIND lattice point —
 *   see docs/BINDING_SECURITY.md §3.6 and the well-posedness caveat in §6).
 *
 * NB (honest scope, §5.2): this establishes the K-binds-{CT,PK,CTX} direction
 * only. X-BIND-CT-* is structurally UNACHIEVABLE for an implicitly-rejecting KEM
 * and is NOT claimed here. IND-CCA2 robustness is argued on paper (§4.3), not
 * mechanized.
 * ------------------------------------------------------------------------- *)
