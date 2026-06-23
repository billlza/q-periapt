(* ===========================================================================
 * Binding security of the ContextBound combiner, reduced to collision-resistance
 * of the hash — with NO binding assumption on the component KEMs.
 *
 * Target (docs/BINDING_SECURITY.md): MAL-BIND-K-CT (and, by the same argument,
 * MAL-BIND-K-PK and the context extension MAL-BIND-K-CTX).
 *
 * STATUS: proof DEVELOPMENT. The argument is the one in docs/BINDING_SECURITY.md
 *   §4.2; this file renders it in EasyCrypt syntax. It has NOT been machine-checked
 *   in this environment (no EasyCrypt toolchain installed here). Run `make check`
 *   with EasyCrypt to discharge it; minor tactic adjustments may be needed. Until
 *   then this is a formalization, not a verified proof — see the honest framing in
 *   docs/BINDING_SECURITY.md §5 and §6.
 * =========================================================================== *)

require import AllCore.

(* ---- Abstract types ------------------------------------------------------ *)
type bytes.        (* byte strings on the wire / absorbed buffer              *)
type key.          (* the 32-byte combined shared secret                      *)
type obs.          (* an OBSERVABLE projection of a transcript: the ciphertext
                      (for K-CT), the public key (K-PK), or the context (K-CTX) *)
type transcript.   (* the full absorbed field tuple of ContextBound:
                      LABEL, suite_id, policy_version, ss_pq, ss_trad,
                      ct_pq, pk_pq, ct_trad, pk_trad, context                  *)

(* ---- Operators ----------------------------------------------------------- *)

(* The canonical, fixed-width big-endian length-prefixed encoding implemented by
   `pqt_core::combine` (Profile::ContextBound), docs/BINDING_SECURITY.md §3.2. *)
op encode : transcript -> bytes.

(* The observable the adversary must make DIFFER while keeping K equal.
   Instantiate: proj := ct_pq||ct_trad  -> MAL-BIND-K-CT
                proj := pk_pq||pk_trad  -> MAL-BIND-K-PK
                proj := context         -> MAL-BIND-K-CTX                      *)
op proj : transcript -> obs.

(* The hash (SHA3-256), modeled as collision-resistant below. *)
op H : bytes -> key.

(* The combiner: K = H(encode(transcript)). *)
op combine (t : transcript) : key = H (encode t).

(* INJECTIVITY of the canonical encoding. Combinatorial obligation discharged by
   fixed-width length prefixing + mandatory non-empty context (§3.2/§3.3); it is
   exactly the property exercised by the Rust negative-KAT
   `injective_encoding_prevents_boundary_collision` in pqt-core. Taken as an
   axiom here; provable separately by structural reasoning on the byte layout. *)
axiom encode_inj (t1 t2 : transcript) :
  encode t1 = encode t2 => t1 = t2.

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
(* The adversary (MAL: it may pick adversarial key material — captured by giving
   it full control of both transcripts) outputs two transcripts that collide on
   the derived key K but DIFFER on the observable. Both keys are total here
   (ML-KEM/our combiner never returns bottom), matching the §3.6 game. *)
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

(* ---- Main theorem -------------------------------------------------------- *
 * Adv^{X-BIND-K-*}(A)  <=  Adv^{CR}(B(A)),  reducing ONLY to CR of H.
 * Instantiating `proj` gives MAL-BIND-K-CT / K-PK / K-CTX (§5.1).
 * ------------------------------------------------------------------------- *)
lemma bind_le_cr (A <: BindAdv) &m :
  Pr[Bind(A).main() @ &m : res] <= Pr[CR(B(A)).main() @ &m : res].
proof.
  (* Relate the two games: both run A.find() once; whenever Bind wins, CR(B(A))
     wins, because (a) combine-collision gives the H-equality, and (b) a differing
     observable forces differing transcripts, hence — by encode_inj — differing
     encodings, i.e. a genuine H-collision input. *)
  byequiv (_ : ={glob A} ==> (res{1} => res{2})) => //; first last.
  + smt().
  proc; inline B(A).find.
  call (_ : true).            (* the single A.find() call, identical on both sides *)
  auto => /> t0 t1 hcomb hne.
  (* hcomb : combine t0 = combine t1   (i.e. H (encode t0) = H (encode t1))
     hne   : proj t0 <> proj t1
     goal  : encode t0 <> encode t1 /\ H (encode t0) = H (encode t1)          *)
  split.
  + (* encode t0 <> encode t1 *)
    move => henc.
    have hteq : t0 = t1 by apply (encode_inj t0 t1 henc).
    by move: hne; rewrite hteq.
  + (* H (encode t0) = H (encode t1) *)
    by move: hcomb; rewrite /combine.
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
