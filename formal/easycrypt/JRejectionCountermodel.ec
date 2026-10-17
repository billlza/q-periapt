(* Semantic countermodel for omission claims without a rejection-function
 * binding assumption. This is not ML-KEM or an attack against SHAKE. It uses
 * a constant, exactly 32-element rejection output admitted by the unconstrained
 * function model. The outer hash is arbitrary: equal inputs alone cause the
 * collision. No injectivity axiom or hash-collision assumption is introduced. *)
require import AllCore List.

type bytes = int list.
type key.
op encode : bytes list -> bytes.
op H : bytes -> key.
op outer (fields : bytes list) : key = H (encode fields).

op reject (z ct : bytes) : bytes = nseq 32 0.
lemma reject_width (z ct : bytes) : size (reject z ct) = 32.
proof. by rewrite /reject size_nseq. qed.

(* An injective seed association, so the seed-format counterexample removes
 * only rejection-function injectivity, not the seed association's property. *)
op seedof (ek : bytes) : bytes = ek.
lemma seedof_inj (a b : bytes) : seedof a = seedof b => a = b.
proof. by rewrite /seedof. qed.

type execution = {
  z : bytes; ek : bytes; ctp : bytes; sst : bytes;
  ctt : bytes; ekt : bytes; context : bytes;
}.
op first : execution = {|
  z = [0]; ek = [0]; ctp = [0]; sst = [0];
  ctt = [0]; ekt = [0]; context = [0]
|}.
op different_ct : execution = {|
  z = [0]; ek = [0]; ctp = [1]; sst = [0];
  ctt = [0]; ekt = [0]; context = [0]
|}.
op different_pk : execution = {|
  z = [0]; ek = [1]; ctp = [0]; sst = [0];
  ctt = [0]; ekt = [0]; context = [0]
|}.

(* Ordered fields match the three comparison constructions in BindingViaCR.
 * The first three fixed fields stand for label, suite and policy version. *)
op omit_ct_fields (e : execution) : bytes list =
  [[]; []; []; reject e.`z e.`ctp; e.`sst; e.`ek; e.`ctt; e.`ekt; e.`context].
op xwing_fields (e : execution) : bytes list =
  [[]; []; []; reject e.`z e.`ctp; e.`sst; e.`ctt; e.`ekt].
op seed_fields (e : execution) : bytes list =
  [[]; []; []; reject (seedof e.`ek) e.`ctp; e.`sst; e.`ctp; e.`ctt; e.`ekt; e.`context].

lemma omitted_ct_inputs_equal : omit_ct_fields first = omit_ct_fields different_ct.
proof. by rewrite /omit_ct_fields /first /different_ct /reject. qed.
lemma xwing_inputs_equal : xwing_fields first = xwing_fields different_ct.
proof. by rewrite /xwing_fields /first /different_ct /reject. qed.
lemma seed_inputs_equal : seed_fields first = seed_fields different_pk.
proof. by rewrite /seed_fields /first /different_pk /seedof /reject. qed.
lemma ciphertexts_differ : (first.`ctp, first.`ctt) <> (different_ct.`ctp, different_ct.`ctt).
proof. rewrite /first /different_ct. smt(). qed.
lemma public_keys_differ : (first.`ek, first.`ekt) <> (different_pk.`ek, different_pk.`ekt).
proof. rewrite /first /different_pk. smt(). qed.

module OmitCtAttack = {
  proc main() : bool = {
    return outer (omit_ct_fields first) = outer (omit_ct_fields different_ct) /\
      (first.`ctp, first.`ctt) <> (different_ct.`ctp, different_ct.`ctt);
  }
}.
module XWingAttack = {
  proc main() : bool = {
    return outer (xwing_fields first) = outer (xwing_fields different_ct) /\
      (first.`ctp, first.`ctt) <> (different_ct.`ctp, different_ct.`ctt);
  }
}.
module SeedAttack = {
  proc main() : bool = {
    return outer (seed_fields first) = outer (seed_fields different_pk) /\
      (first.`ek, first.`ekt) <> (different_pk.`ek, different_pk.`ekt);
  }
}.

lemma omitted_ct_without_J_binding &m : Pr[OmitCtAttack.main() @ &m : res] = 1%r.
proof. byphoare => //. proc. auto. qed.
lemma xwing_without_J_binding &m : Pr[XWingAttack.main() @ &m : res] = 1%r.
proof. byphoare => //. proc. auto. qed.
lemma seed_without_J_binding &m : Pr[SeedAttack.main() @ &m : res] = 1%r.
proof. byphoare => //. proc. auto. qed.

(* The corresponding outer-hash collision witnesses are identical inputs.
 * These attacks therefore do not produce an outer-hash collision, regardless
 * of how encode and H are chosen, including an injective canonical encoder. *)
lemma omitted_ct_no_outer_collision :
  encode (omit_ct_fields first) = encode (omit_ct_fields different_ct).
proof. by rewrite omitted_ct_inputs_equal. qed.
lemma xwing_no_outer_collision :
  encode (xwing_fields first) = encode (xwing_fields different_ct).
proof. by rewrite xwing_inputs_equal. qed.
lemma seed_no_outer_collision :
  encode (seed_fields first) = encode (seed_fields different_pk).
proof. by rewrite seed_inputs_equal. qed.
