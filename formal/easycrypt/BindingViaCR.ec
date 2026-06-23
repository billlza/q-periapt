(* ===========================================================================
 * Binding security of the ContextBound combiner, reduced to collision-resistance
 * of the hash — with NO binding assumption on the component KEMs.
 *
 * Target (docs/BINDING_SECURITY.md): MAL-BIND-K-CT (and, by the same argument,
 * MAL-BIND-K-PK and the context extension MAL-BIND-K-CTX).
 *
 * STATUS: MACHINE-CHECKED. `easycrypt BindingViaCR.ec` succeeds (EasyCrypt dev /
 *   OCaml 5.4.1, Z3 4.16.0); reproduce with `make check`. The theorem `bind_le_cr`
 *   below is verified, reducing ONLY to collision-resistance of H plus the
 *   `encode_inj` axiom. Honest scope still applies (docs/BINDING_SECURITY.md §5/§6):
 *   `encode_inj` is taken as an axiom (provable separately; mirrored by the
 *   pqt-core negative KAT), H's CR is an assumption, IND-CCA2 robustness is argued
 *   on paper (not mechanized), and there is no spec↔implementation linkage proof.
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
(* The combiner unfolds to a single hash of the canonical encoding. *)
lemma combine_def (t : transcript) : combine t = H (encode t).
proof. by rewrite /combine. qed.

lemma bind_le_cr (A <: BindAdv) &m :
  Pr[Bind(A).main() @ &m : res] <= Pr[CR(B(A)).main() @ &m : res].
proof.
  (* Both games run A.find() once; whenever Bind wins, CR(B(A)) wins:
     (a) a combine-collision gives the H-equality; (b) a differing observable
     forces differing transcripts, hence — by encode_inj — differing encodings,
     i.e. a genuine H-collision input. *)
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
