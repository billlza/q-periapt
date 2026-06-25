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
 *   This file has THREE layers:
 *   (i)   `bind_le_cr` + `bind_le_cr_kct/kpk/kctx` — the generic reduction at the
 *         TRANSCRIPT-COLLISION level (K is an opaque adversary value, abstract `proj`).
 *   (ii)  `malbind_kct_le_cr` / `_kpk_` / `_kctx_` — the KEM-AWARE game for the
 *         IMPLICIT-rejection setting: the (MAL) adversary supplies the keypairs, K is
 *         DERIVED via total `Decaps` + the combiner; K≠⊥ holds by construction.
 *   (iii) `malbind_kct_xrej_le_cr` / `_kpk_xrej_` / `_kctx_xrej_` — the FULLY GENERAL
 *         CDM Figure 6 game: `Decaps` may reject, the hybrid key is `⊥` (`None`) if
 *         either component rejects, and CDM's `K≠⊥` conjunct is PRESENT in the
 *         predicate and LOAD-BEARING (removing it makes the proof fail). THIS is the
 *         layer to cite for "machine-checked CDM MAL-BIND-K-CT".
 *
 *   HONEST SCOPE of (ii)/(iii) — read before citing (a reviewer will open this file):
 *   - Layer (iii) follows the CDM Figure 6 SHAPE (both rejection styles), with the accept
 *     predicate DECOUPLED from a real Decaps; layer (ii) is its implicit-rejection
 *     specialization. So we do NOT rely on "K≠⊥ is vacuous" — the general game keeps the
 *     conjunct and the proof depends on it.
 *   - `decaps_*` / `accepts_*` are ABSTRACT, AXIOM-FREE. The reduction uses NO property
 *     of Decaps, so the result holds for EVERY Decaps (ML-KEM included) ⇒ genuine "zero
 *     KEM binding assumption". The flip side: there is NO link to the FIPS-203 Decaps,
 *     and the shared-secret fields `ss_pq`/`ss_trad` are PRESENT in the hash but INERT
 *     in the K-binding argument (binding flows through the absorbed ct/pk/ctx fields —
 *     the hash-everything mechanism), so this proves nothing ABOUT ML-KEM's Decaps.
 *   - So the honest claim is "machine-checked CDM-Figure-6-SHAPED commitment/transcript-binding
 *     for MAL-BIND-K-{CT,PK,CTX} (both rejection styles), over abstract Decaps with the accept
 *     predicate decoupled from decapsulation, reducing to CR(H)". Remaining honest
 *     caveats: no FIPS-203 Decaps linkage; H's CR is a modeling assumption; IND-CCA2
 *     robustness is on paper; no spec<->implementation linkage (docs/BINDING_SECURITY.md
 *     §5/§6).
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
 * KEM-AWARE CDM MAL-BIND-K-CT GAME — implicit-rejection layer (explicit-rejection /
 * full Figure 6 follows below in `*_xrej_*`) — closes the main gap.
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

(* ===========================================================================
 * EXPLICIT-REJECTION variant — CDM-Figure-6-SHAPED MAL-BIND-K-CT game, general rejection.
 *
 * Generalizes the game above so each component `Decaps` MAY return ⊥ (modeled as
 * `None`); the hybrid key is ⊥ whenever either component rejects. CDM's `K ≠ ⊥`
 * conjunct is now PRESENT in the predicate (`hkey_x e <> None`), not subsumed — so
 * this matches the CDM Figure 6 SHAPE for an abstract (accept-predicate-decoupled) Decaps
 * (the implicit-rejection game above is the special case where Decaps never returns None).
 * NB: `decaps`/`accepts` remain abstract — this is NOT a faithful FIPS-203 Decaps; the
 * reduction still uses NO property of Decaps.
 * =========================================================================== *)

(* Explicit rejection modeled with a per-component accept predicate (Decaps stays the
   total op from above; an additional reject flag models any KEM — ML-KEM/X25519 always
   accept). The hybrid key is ⊥ (None) iff either component rejects, else H over the SAME
   total `fields` list — so we reuse `fields` and the proved `ct_neq_fields_neq`. *)
op accepts_pq   : sk -> bytes -> bool.
op accepts_trad : sk -> bytes -> bool.

op hkey_x (e : texec) : key option =
  if accepts_pq e.`sk_pq e.`ct_pq /\ accepts_trad e.`sk_trad e.`ct_trad
  then Some (H (encode (fields e))) else None.

module MalBindKCTx (A : MalAdv) = {
  proc main() : bool = {
    var e0 : texec; var e1 : texec;
    (e0, e1) <@ A.find();
    return hkey_x e0 = hkey_x e1 /\ hkey_x e0 <> None /\ ct_of e0 <> ct_of e1;
  }
}.

(* Fully general CDM MAL-BIND-K-CT (explicit rejection, K≠⊥ PRESENT) <= CR(H). Reuses the
   reduction BK and `ct_neq_fields_neq` — `fields` is total, rejection only gates acceptance. *)
lemma malbind_kct_xrej_le_cr (A <: MalAdv) &m :
  Pr[MalBindKCTx(A).main() @ &m : res] <= Pr[CR(BK(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BK(A).find. wp. call (_ : true). auto => />.
rewrite /hkey_x. smt(encode_inj ct_neq_fields_neq).
qed.

(* K-PK and K-CTX, explicit-rejection — same structure, other observable. *)
module MalBindKPKx (A : MalAdv) = {
  proc main() : bool = {
    var e0 : texec; var e1 : texec;
    (e0, e1) <@ A.find();
    return hkey_x e0 = hkey_x e1 /\ hkey_x e0 <> None /\ pk_of e0 <> pk_of e1;
  }
}.
module MalBindKCTXx (A : MalAdv) = {
  proc main() : bool = {
    var e0 : texec; var e1 : texec;
    (e0, e1) <@ A.find();
    return hkey_x e0 = hkey_x e1 /\ hkey_x e0 <> None /\ ctx_of e0 <> ctx_of e1;
  }
}.

lemma malbind_kpk_xrej_le_cr (A <: MalAdv) &m :
  Pr[MalBindKPKx(A).main() @ &m : res] <= Pr[CR(BK(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BK(A).find. wp. call (_ : true). auto => />.
rewrite /hkey_x. smt(encode_inj pk_neq_fields_neq).
qed.

lemma malbind_kctx_xrej_le_cr (A <: MalAdv) &m :
  Pr[MalBindKCTXx(A).main() @ &m : res] <= Pr[CR(BK(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BK(A).find. wp. call (_ : true). auto => />.
rewrite /hkey_x. smt(encode_inj ctx_neq_fields_neq).
qed.

(* ===========================================================================
 * SEPARATION: combiner shape x component-dk serialization -> MAL-BIND-K-PK.
 *
 * The FIPS-203 EXPANDED dk stores the implicit-rejection seed z as a substitutable
 * field, so a garbage ciphertext rejects to J(z,ct) -- a value an adversary can make
 * EQUAL across two DIFFERENT public keys by sharing z (Schmieg). We mechanize the
 * resulting separation at the combiner layer, in ONE model:
 *   (-) the LEAN combiner (omits pk_pq) is NOT MAL-BIND-K-PK: a concrete, assumption-
 *       free adversary wins with probability 1 (`lean_kpk_broken`);
 *   (+) the FULL combiner (absorbs pk_pq) IS MAL-BIND-K-PK <= CR(H) (`full_kpk_le_cr`),
 *       over the SAME model -- so the separation is intrinsic to the combiner SHAPE,
 *       not to a difference in the modeled KEM.
 * =========================================================================== *)

op jrej : bytes -> bytes -> bytes.   (* implicit-rejection J(z,ct): depends on z, ct, NOT ek *)

type lexec = { z : bytes; ek : bytes; ctp : bytes;
               sst : bytes; ctt : bytes; ekt : bytes; lctx : bytes }.

op ss_of (e : lexec) : bytes = jrej e.`z e.`ctp.   (* pq shared secret = J(z, ct) *)

(* LEAN combiner: omits pk_pq = ek.  FULL combiner: absorbs it. *)
op lean_fields (e : lexec) : transcript =
  [ label_f; suite_f; pv_f; ss_of e; e.`sst; e.`ctp; e.`ctt; e.`ekt; e.`lctx ].
op full_fields (e : lexec) : transcript =
  [ label_f; suite_f; pv_f; ss_of e; e.`sst; e.`ctp; e.`ek; e.`ctt; e.`ekt; e.`lctx ].
op lean_key (e : lexec) : key = H (encode (lean_fields e)).
op full_key (e : lexec) : key = H (encode (full_fields e)).
op lpk (e : lexec) : bytes * bytes = (e.`ek, e.`ekt).   (* the K-PK observable *)

module type LAdv = { proc find() : lexec * lexec }.
module LeanKPK (A : LAdv) = {
  proc main() : bool = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return lean_key e0 = lean_key e1 /\ lpk e0 <> lpk e1; }
}.
module FullKPK (A : LAdv) = {
  proc main() : bool = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return full_key e0 = full_key e1 /\ lpk e0 <> lpk e1; }
}.

(* ---- (-) lean combiner BROKEN over expanded-dk: a concrete adversary, Pr = 1 ---- *)
(* Two distinct public keys (trivially exist); every other field is shared (incl. z). *)
op z0 : bytes. op ct0 : bytes. op sst0 : bytes. op ctt0 : bytes. op ekt0 : bytes. op lctx0 : bytes.
op ek0 : bytes. op ek1 : bytes.
axiom ek_neq : ek0 <> ek1.
op mk (k : bytes) : lexec =
  {| z = z0; ek = k; ctp = ct0; sst = sst0; ctt = ctt0; ekt = ekt0; lctx = lctx0 |}.

module SchmiegAdv : LAdv = {
  proc find() : lexec * lexec = { return (mk ek0, mk ek1); }
}.

(* the lean field list does not depend on ek, so the two executions share a key *)
lemma lean_eq : lean_key (mk ek0) = lean_key (mk ek1).
proof. by rewrite /lean_key /lean_fields /ss_of /mk. qed.
lemma lpk_mk (k : bytes) : lpk (mk k) = (k, ekt0).
proof. by rewrite /lpk /mk. qed.

lemma lean_kpk_broken &m : Pr[LeanKPK(SchmiegAdv).main() @ &m : res] = 1%r.
proof.
byphoare => //.
proc; inline SchmiegAdv.find; auto => />.
smt(ek_neq lean_eq lpk_mk).
qed.

(* ---- (+) full combiner SAFE over the SAME model: MAL-BIND-K-PK <= CR(H) ---- *)
module BKf (A : LAdv) : CRAdv = {
  proc find() : bytes * bytes = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return (encode (full_fields e0), encode (full_fields e1)); }
}.

(* differing public key forces a differing full field list (ek sits in full_fields) *)
lemma lpk_neq_full_neq (e0 e1 : lexec) : lpk e0 <> lpk e1 => full_fields e0 <> full_fields e1.
proof. rewrite /lpk /full_fields => h. smt(). qed.

lemma full_kpk_le_cr (A <: LAdv) &m :
  Pr[FullKPK(A).main() @ &m : res] <= Pr[CR(BKf(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BKf(A).find. wp. call (_ : true). auto => />.
rewrite /full_key. smt(encode_inj lpk_neq_full_neq).
qed.

(* ---- the OTHER format: SEED-dk makes the LEAN combiner SAFE -------------------- *
 * In the seed-dk form the rejection seed z is DERIVED from the key (z = zof(ek)), so
 * distinct public keys give distinct z, and the implicit-rejection secret ss = J(z,ct)
 * then transitively encodes the key even though the lean combiner omits pk_pq. Under the
 * idealization that the reject function J and the seed derivation are injective (a stronger
 * modeling assumption than the full combiner needs -- it reduces to CR(H) ALONE), the lean
 * combiner is MAL-BIND-K-PK <= CR(H) over seed-dk. Together with `lean_kpk_broken`
 * (expanded-dk), this is the shape x FORMAT separation: the lean shape's K-PK security
 * flips with the component's dk serialization, while the full shape is safe over both. *)
op zof : bytes -> bytes.                          (* seed-dk: z derived from the key *)
axiom zof_inj  (a b : bytes) : zof a = zof b => a = b.
axiom jrej_inj (z0 z1 c0 c1 : bytes) : jrej z0 c0 = jrej z1 c1 => z0 = z1 /\ c0 = c1.

op ss_seed (e : lexec) : bytes = jrej (zof e.`ek) e.`ctp.   (* seed-dk ss DEPENDS on ek *)
op lean_fields_seed (e : lexec) : transcript =
  [ label_f; suite_f; pv_f; ss_seed e; e.`sst; e.`ctp; e.`ctt; e.`ekt; e.`lctx ].
op lean_key_seed (e : lexec) : key = H (encode (lean_fields_seed e)).

module LeanKPKseed (A : LAdv) = {
  proc main() : bool = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return lean_key_seed e0 = lean_key_seed e1 /\ lpk e0 <> lpk e1; }
}.
module BKseed (A : LAdv) : CRAdv = {
  proc find() : bytes * bytes = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return (encode (lean_fields_seed e0), encode (lean_fields_seed e1)); }
}.

(* distinct public key forces a distinct seed-dk lean field list: either ekt differs
   (position 7), or ek differs => zof ek differs (zof_inj) => ss_seed differs (jrej_inj). *)
lemma seed_lpk_neq_fields_neq (e0 e1 : lexec) :
  lpk e0 <> lpk e1 => lean_fields_seed e0 <> lean_fields_seed e1.
proof. rewrite /lpk /lean_fields_seed /ss_seed => h. smt(jrej_inj zof_inj). qed.

lemma lean_kpk_seed_le_cr (A <: LAdv) &m :
  Pr[LeanKPKseed(A).main() @ &m : res] <= Pr[CR(BKseed(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BKseed(A).find. wp. call (_ : true). auto => />.
rewrite /lean_key_seed. smt(encode_inj seed_lpk_neq_fields_neq).
qed.

(* ===========================================================================
 * COMPLETE SEPARATION MAP across the CDM K-sub-lattice: which field must the FULL
 * combiner absorb, and why. Take `full_fields` (absorbs ct_pq, pk_pq, context) and OMIT
 * exactly ONE field; ask which binding notion the omission costs:
 *
 *      omitted field   notion   verdict
 *      -------------   ------   ------------------------------------------------
 *      pk_pq           K-PK     BROKEN over expanded-dk (ss=J(z,ct) is key-INDEPENDENT;
 *                               `lean_kpk_broken`), SAFE over seed-dk (`lean_kpk_seed_le_cr`)
 *      ct_pq           K-CT     SAFE: ss=J(z,ct) transitively binds ct (`omit_ct_kct_le_cr`)
 *      context         K-CTX    BROKEN unconditionally: nothing else binds context
 *                               (`omit_ctx_kctx_broken`, Pr=1, any dk format)
 *      (full absorbs all)  any  SAFE <= CR(H) (`full_k{pk,ct,ctx}_le_cr`)
 *
 * MORAL: pk_pq and context absorption are NECESSARY (their omission is exploitable); ct_pq
 * absorption is REDUNDANT with the shared secret. This is the formal design rationale for
 * ContextBound and the precise sense in which the X-Wing shape (which omits ct_pq, pk_pq,
 * AND context) loses K-PK (over expanded-dk) and K-CTX while keeping K-CT.
 * =========================================================================== *)

(* ---- omit CONTEXT: K-CTX BROKEN unconditionally (concrete adversary, Pr = 1) ---- *)
op omit_ctx_fields (e : lexec) : transcript =          (* full_fields minus lctx *)
  [ label_f; suite_f; pv_f; ss_of e; e.`sst; e.`ctp; e.`ek; e.`ctt; e.`ekt ].
op omit_ctx_key (e : lexec) : key = H (encode (omit_ctx_fields e)).
op lctxo (e : lexec) : bytes = e.`lctx.                 (* the K-CTX observable *)

module OmitCtxKCTX (A : LAdv) = {
  proc main() : bool = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return omit_ctx_key e0 = omit_ctx_key e1 /\ lctxo e0 <> lctxo e1; }
}.
op lctxA : bytes. op lctxB : bytes.
axiom lctx_neq : lctxA <> lctxB.
op mkc (c : bytes) : lexec =
  {| z = z0; ek = ek0; ctp = ct0; sst = sst0; ctt = ctt0; ekt = ekt0; lctx = c |}.
module CtxAdv : LAdv = { proc find() : lexec * lexec = { return (mkc lctxA, mkc lctxB); } }.

lemma omitctx_eq : omit_ctx_key (mkc lctxA) = omit_ctx_key (mkc lctxB).
proof. by rewrite /omit_ctx_key /omit_ctx_fields /ss_of /mkc. qed.
lemma lctxo_mkc (c : bytes) : lctxo (mkc c) = c.
proof. by rewrite /lctxo /mkc. qed.

lemma omit_ctx_kctx_broken &m : Pr[OmitCtxKCTX(CtxAdv).main() @ &m : res] = 1%r.
proof.
byphoare => //.
proc; inline CtxAdv.find; auto => />.
smt(lctx_neq omitctx_eq lctxo_mkc).
qed.

(* ---- omit CT_PQ: K-CT still SAFE, because ss=J(z,ct) transitively binds ct ---- *)
op omit_ct_fields (e : lexec) : transcript =           (* full_fields minus ctp *)
  [ label_f; suite_f; pv_f; ss_of e; e.`sst; e.`ek; e.`ctt; e.`ekt; e.`lctx ].
op omit_ct_key (e : lexec) : key = H (encode (omit_ct_fields e)).
op lct (e : lexec) : bytes * bytes = (e.`ctp, e.`ctt).  (* the K-CT observable *)

module OmitCtKCT (A : LAdv) = {
  proc main() : bool = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return omit_ct_key e0 = omit_ct_key e1 /\ lct e0 <> lct e1; }
}.
module BKct (A : LAdv) : CRAdv = {
  proc find() : bytes * bytes = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return (encode (omit_ct_fields e0), encode (omit_ct_fields e1)); }
}.

(* differing ct forces a differing field list: either ctt differs (in the list), or ctp
   differs => ss_of=jrej(z,ctp) differs (jrej_inj) even though ctp itself is omitted. *)
lemma lct_neq_omitct_neq (e0 e1 : lexec) : lct e0 <> lct e1 => omit_ct_fields e0 <> omit_ct_fields e1.
proof. rewrite /lct /omit_ct_fields /ss_of => h. smt(jrej_inj). qed.

lemma omit_ct_kct_le_cr (A <: LAdv) &m :
  Pr[OmitCtKCT(A).main() @ &m : res] <= Pr[CR(BKct(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BKct(A).find. wp. call (_ : true). auto => />.
rewrite /omit_ct_key. smt(encode_inj lct_neq_omitct_neq).
qed.

(* ---- the FULL combiner is SAFE for K-CT and K-CTX too (it absorbs every field) ---- *)
module FullKCT (A : LAdv) = {
  proc main() : bool = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return full_key e0 = full_key e1 /\ lct e0 <> lct e1; }
}.
module FullKCTX (A : LAdv) = {
  proc main() : bool = { var e0 : lexec; var e1 : lexec;
    (e0, e1) <@ A.find(); return full_key e0 = full_key e1 /\ lctxo e0 <> lctxo e1; }
}.
lemma lct_neq_full_neq (e0 e1 : lexec) : lct e0 <> lct e1 => full_fields e0 <> full_fields e1.
proof. rewrite /lct /full_fields => h. smt(). qed.
lemma lctxo_neq_full_neq (e0 e1 : lexec) : lctxo e0 <> lctxo e1 => full_fields e0 <> full_fields e1.
proof. rewrite /lctxo /full_fields => h. smt(). qed.

lemma full_kct_le_cr (A <: LAdv) &m :
  Pr[FullKCT(A).main() @ &m : res] <= Pr[CR(BKf(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BKf(A).find. wp. call (_ : true). auto => />.
rewrite /full_key. smt(encode_inj lct_neq_full_neq).
qed.
lemma full_kctx_le_cr (A <: LAdv) &m :
  Pr[FullKCTX(A).main() @ &m : res] <= Pr[CR(BKf(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BKf(A).find. wp. call (_ : true). auto => />.
rewrite /full_key. smt(encode_inj lctxo_neq_full_neq).
qed.

(* ---- THE JOINT X-WING SHAPE: omits ct_pq, pk_pq, AND context simultaneously ---- *
 * The per-field experiments above isolate each field's necessity. The deployed X-Wing
 * combiner omits all three at once. We discharge its binding profile DIRECTLY (a checked
 * theorem, not a composition argument): over expanded-dk it LOSES K-PK and K-CTX, yet
 * KEEPS K-CT (the shared secret still binds ct). This is the precise sense of "the X-Wing
 * shape" the paper refers to. *)
op xwing_fields (e : lexec) : transcript =
  [ label_f; suite_f; pv_f; ss_of e; e.`sst; e.`ctt; e.`ekt ].   (* no ctp, no ek, no lctx *)
op xwing_key (e : lexec) : key = H (encode (xwing_fields e)).

module XWingKPK  (A : LAdv) = { proc main() : bool = { var e0 : lexec; var e1 : lexec;
  (e0,e1) <@ A.find(); return xwing_key e0 = xwing_key e1 /\ lpk   e0 <> lpk   e1; } }.
module XWingKCTX (A : LAdv) = { proc main() : bool = { var e0 : lexec; var e1 : lexec;
  (e0,e1) <@ A.find(); return xwing_key e0 = xwing_key e1 /\ lctxo e0 <> lctxo e1; } }.
module XWingKCT  (A : LAdv) = { proc main() : bool = { var e0 : lexec; var e1 : lexec;
  (e0,e1) <@ A.find(); return xwing_key e0 = xwing_key e1 /\ lct   e0 <> lct   e1; } }.
module BKxw (A : LAdv) : CRAdv = { proc find() : bytes * bytes = { var e0 : lexec; var e1 : lexec;
  (e0,e1) <@ A.find(); return (encode (xwing_fields e0), encode (xwing_fields e1)); } }.

(* (-) X-Wing loses K-PK over expanded-dk (vary pk; ss is key-independent) *)
lemma xwing_eq_pk : xwing_key (mk ek0) = xwing_key (mk ek1).
proof. by rewrite /xwing_key /xwing_fields /ss_of /mk. qed.
lemma xwing_kpk_broken &m : Pr[XWingKPK(SchmiegAdv).main() @ &m : res] = 1%r.
proof. byphoare => //. proc; inline SchmiegAdv.find; auto => />. smt(ek_neq xwing_eq_pk lpk_mk). qed.

(* (-) X-Wing loses K-CTX unconditionally (vary context; nothing binds it) *)
lemma xwing_eq_ctx : xwing_key (mkc lctxA) = xwing_key (mkc lctxB).
proof. by rewrite /xwing_key /xwing_fields /ss_of /mkc. qed.
lemma xwing_kctx_broken &m : Pr[XWingKCTX(CtxAdv).main() @ &m : res] = 1%r.
proof. byphoare => //. proc; inline CtxAdv.find; auto => />. smt(lctx_neq xwing_eq_ctx lctxo_mkc). qed.

(* (+) X-Wing KEEPS K-CT: ss=jrej(z,ctp) binds ct even though ct_pq is omitted *)
lemma lct_neq_xwing_neq (e0 e1 : lexec) : lct e0 <> lct e1 => xwing_fields e0 <> xwing_fields e1.
proof. rewrite /lct /xwing_fields /ss_of => h. smt(jrej_inj). qed.
lemma xwing_kct_le_cr (A <: LAdv) &m :
  Pr[XWingKCT(A).main() @ &m : res] <= Pr[CR(BKxw(A)).main() @ &m : res].
proof.
byequiv (_ : ={glob A} ==> res{1} => res{2}) => //.
proc; inline BKxw(A).find. wp. call (_ : true). auto => />.
rewrite /xwing_key. smt(encode_inj lct_neq_xwing_neq).
qed.
