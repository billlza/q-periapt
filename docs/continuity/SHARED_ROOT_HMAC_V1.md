# A shared 32-byte HMAC root in the compression QROM

Status: a checked conditional single-root reduction, 2026-11-04. Its model makes
the SHA-256 compression function a quantum random oracle. It does not establish
that concrete SHA-256 is such an oracle, the actual accepted-prefix distribution,
the multi-epoch theorem or external review. It changes no product primitive,
format, API or declared security assumption. This supplies a construction-specific
route for the joint-use obligation in the [computational recovery note](COMPUTATIONAL_RECOVERY_V1.md).
The frozen draft, independent internal applicability review and source/encoding
checks are retained in the [evidence record](../../research/sdk-alpha1/evidence/20261104-shared-root-hmac/README.md).

## Experiment and exact encodings

Let h : {0,1}^512 x {0,1}^256 -> {0,1}^256 be one public quantum random oracle,
with arguments (message block, chaining value). IV is the actual fixed SHA-256
initial state. The joint initial state is exactly
`unif(h) x unif(R) x sigma_aux`, where R has 256 bits. An oracle-independent
quantum auxiliary state can be purified and absorbed into initial preparation
in the query-only model. The cited HMAC paper does not directly model arbitrary
quantum-state advice; no oracle-correlated advice is supplied for free here.
All oracle-dependent prefix preparation is part of the algorithm and is counted.
The algorithm has no raw-R, state,
compression-midstate or ciphertext-disclosure interface.

It may make q quantum queries to h, C classical queries to Col(a)=HMAC(a,R),
where a is exactly 32 bytes, and T classical queries to Row(m)=HMAC(R,m), where
|m|<=L bytes. Queries may be adaptive. Equal arguments are cached consistently.
The message-length bound includes the consumed key pad:
`8*(64+L) < 2^64`, equivalently `L <= 2^61-65` for integral byte lengths.

For a 32-byte x define the following 64-byte blocks, writing byte concatenation
and bytewise XOR explicitly; 0^r denotes r zero bytes:

    I(x) = (x || 0^32) XOR 0x36^64
    O(x) = (x || 0^32) XOR 0x5c^64
    B(x) = x || P
    P    = 0x80 || 0^23 || BE64(768)

P has 32 bytes. The encoded length is 768 bits because one 64-byte HMAC key pad
has already been compressed before the 32-byte message/digest. The last 32 bytes
of I(x), O(x), B(x) are respectively 0x36^32, 0x5c^32, P. These are distinct,
so the three block ranges are disjoint, for all x, without a probabilistic event.
Each map is injective in x.

Define alpha(a)=h(I(a),IV), beta(a)=h(O(a),IV), and Gamma(a)=(alpha(a),beta(a)).
The column is exactly

    Col(a) = h(B(h(B(R),alpha(a))), beta(a)).

For the row, let pad64(m) be m followed by SHA-256 padding whose encoded bit
length is 8*(64+|m|), not 8*|m|. Write Iter_h(s,blocks) for compression starting
at s. Then

    Row(m) = Iter_h(beta(R), pad64(Iter_h(alpha(R),pad64(m)))).

This is an NMAC form with the fixed 64-byte length offset in both padding calls.
It is not byte-identical to NMAC using an unshifted length suffix. Writing
`s=|m|`, its zero-padding count is `(55-s) mod 64`, chosen in `{0,...,63}`.
The suffix depends only on s, and the result contains complete blocks. Equal
padded strings have equal final length fields; within the allowed length domain
this forces equal s and hence equal message prefixes. Thus pad64 is injective.
The byte-string interface restricts the bit-string padding admitted by the
theorem. Its usual bit-string extension adds the same 512-bit offset; this is
a mathematical extension, not an admission of over-limit product inputs.
Set ell=1+ceil((L+9)/64); this bounds both the relevant padded-message block count
and all ordinary row compression calls after its two private key-pad calls.

The source correspondence is pinned to clean qualification source
`ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`. Its candidate manifest selects
`hkdf = 0.13.0`, `hmac = 0.13.0` and `sha2 = 0.11.0` exactly. The checks use
hmac 0.13.0 (`get_der_key`, `HmacCore::new_from_slice`,
`finalize_fixed_core`) and sha2 0.11.0 (`Sha256VarCore::update_blocks` and
`finalize_variable_core`). The former zero-pads a short key and precompresses both
key pads; the latter retains that consumed-block count in the final length field.
The candidate lock contains both sha2 0.10.9 and 0.11.0; the relevant HMAC/HKDF
path is tied to the selected 0.11.0 dependency, not the separate 0.10.9 entry.
This is the existing short-key HMAC construction; no primitive is replaced in
the implementation.

## First hybrid: replace only the compression calls containing raw R

Define F_R(tag,s)=h(tau_tag(R),s), with tau_in=I, tau_out=O, tau_message=B.
For each fixed (tag,s), the encoded point has probability at most 2^-256.
For distinct effective (tag,s) pairs, encoded points differ for every R: distinct
tags have disjoint block ranges and equal tags retain the distinct chaining value.

The two private interfaces can be evaluated using F_R, ordinary h calls and no
other raw use of R. Cache equal (tag,s) calls before using the private function;
different salts can have equal alpha, so a salt-only cache is insufficient.
There are at most C+2 fresh private calls: two fixed key-pad calls and at most C
message-block calls. There are at most Q1=q+3C+ell*T ordinary h calls, counting
the column's two public pad states and one outer call, and all row continuation
calls. Caller-chosen a or m may accidentally equal R; do not forbid this.

Apply Don, Fehr and Huang, Theorem 2, to this exact encoding:

    E1 = min(1, 4 sqrt(2 (C+2)^2 Q1 / 2^256)
                + 4 sqrt(2 Q1^2 (C+2) / 2^256)).

Source: https://arxiv.org/pdf/2206.08132, section 4.2.
The resulting private random table has mutually independent restrictions:
A=F(in,IV), D=F(out,IV), and f(s)=F(message,s), all independent of h. Reusing
A and D across row calls is mandatory. f is a random function, not a newly
sampled value on every repeated state. It is never directly exposed to the caller.

Now Row is NMAC_{A,D}^{pad64}; Col(a)=h(B(f(alpha(a))),beta(a)). These formulas
are statements about the first ideal hybrid. They do not assert that real
HMAC midstate values were independent before the replacement.

## Second hybrid: replace the row while retaining the actual column simulation

Apply Hosoyamada and Iwata, Proposition 6, to the NMAC row, with n=256, m=512,
independent 256-bit keys A,D, and the admissible pad64 padding. The adversary in
that reduction simulates each classical column by maintaining its own independent
f table and making the three necessary h calls. Thus Q=T and q_h<=q+3C.
It never needs the NMAC challenge's secret A or D. The padding's one-block
outer case also matches Appendix D of the cited paper.

Denote the proposition's bound by E_NMAC(T,q+3C,ell). Its stated asymptotic form
is O(sqrt((q+3C+T)^3 * ell^5 / 2^256)); no unspecified big-O constant is turned
into a numerical security level here. Replace Row by a private random function
U(m), independent of h and f. The simultaneous column has not been omitted.

Source: https://eprint.iacr.org/2021/774.pdf, section 5, Proposition 6.

## Third hybrid: replace the column without assuming public salt independence

Reindex the SAME entire compression oracle by the fixed bit permutation

    h_tilde((t,s),y) = h(y || t, s),

where t,s,y each have 256 bits. This is a bijection on all 768 input bits.
It can be performed coherently with one oracle call and its inverse wire
permutation; it does not invent a second independent hash oracle.
For example, alpha(a) becomes
`h_tilde((0x36^32,IV), a XOR 0x36^32)`; beta uses 0x5c instead.

Then the column is

    F1(alpha(a), (P,beta(a)))
    where F1(u,v) = h_tilde(v, f(u)).

This is exactly the function of Hosoyamada and Iwata, Proposition 4, with
n=256, m=512 and m'=0. A reduction evaluates alpha(a),beta(a) using h, then
queries F1 once. It also simulates the independent classical U table for rows.
Consequently Q=C, q_h<=q+2C, and q_star=max(C,q+2C). The proposition supplies
E_F1(C,q+2C)=O(sqrt(q_star^3/2^256)) within its q_star=o(2^(256/3)) regime.

The final column is a private random function V(alpha(a),beta(a)), independent
of h and U. Distinct salts whose public Gamma values coincide MUST share this
value. No injectivity of Gamma, collision-free assumption or new runtime check
is used. Equal salts, including a zero session identifier aliasing the zero
salt, preserve exact column reuse.

Source: https://eprint.iacr.org/2021/774.pdf, section 4, Proposition 4.

## Cross-interface equality and bound

The preceding independent-table ideal I has Row(m)=U(m) and Col(a)=V(Gamma(a)).
It is independent of hidden R, but does not enforce the real equality at the
cross-interface pair a=R,m=R. Do not claim pointwise equivalence there.

Define a coupled ideal J by keeping Col unchanged and setting

    Row_J(m) = V(Gamma(R)) if m is exactly the 32-byte R;
               U(m)      otherwise.

This preserves the shared HMAC pair and all repeated calls. Until the first
classical row query equal to R, I and J agree. I's whole observable computation
is independent of R, so that event has probability at most T/2^256. Public
quantum h queries do not change this independence in I. More explicitly, if
S is the set of distinct 32-byte entries in I's entire classical row-query list,
`Pr[Bad] = E[|S|]/2^256 <= T/2^256`. This does not assume uniformity after
conditioning on earlier missed guesses. An absorbing flag on the classical
row input gives I and J identical unnormalized good states. Their two remaining
bad states each have trace Pr[Bad], so their distinguishing distance is at most
Pr[Bad]. No public quantum-query input is measured in this argument.

The output-probability distinguishing bound between Real and J for the stated
interfaces is

    min(1, E1 + E_NMAC(T,q+3C,ell) + E_F1(C,q+2C) + T/2^256).

The published asymptotic bounds retain their stated query regimes. This is not a
trace-distance statement that reveals the hidden root or the private oracle table
to the distinguisher. Such extra access is outside the experiment and can defeat
the conclusion. No concrete security-bit claim follows from unspecified constants.

The independent-table ideal I is already reached after the first three terms;
the final term repairs the exceptional shared pair. Revealing R would invalidate
this experiment: a caller could recompute a column value from public h and test
whether it matches. No root-disclosure claim is hidden in the displayed bound.

## Remaining protocol work

The derivation retains the padding offset, complete q/Q accounting, simulation
of the other interface, fixed full-domain permutation and classical coupling.
In particular, replacing NMAC while silently
discarding the column, or replacing V(Gamma(a)) by independent V(a) without a
separate collision argument, is not this proposed proof.

The actual accepted prefix still has to supply a uniform R with the required
joint oracle/auxiliary-state distribution; an oracle-correlated root cannot just
be relabelled uniform. All captured state, reservation coins, identity authority,
public image/intent views, key reuse across epochs, downstream signatures,
confirmation and message/ACK key schedules must be preserved in the eventual
reduction. Existing symbolic acceptance and this one-root primitive experiment
do not replace those steps. External review of the finished construction remains
required before release.
