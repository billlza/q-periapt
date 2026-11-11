# One target root extraction in the shared compression QROM

Status: a checked conditional corollary, 2026-11-05. This applies the
[shared-root HMAC calculation](SHARED_ROOT_HMAC_V1.md) to the actual two HMAC
calls in `response::derive_root`. It supplies a quantum-oracle route for the
Extract/Expand step of the [computational recovery argument](COMPUTATIONAL_RECOVERY_V1.md).
It does not establish the actual accepted-prefix/ML-KEM premise, the full
multi-epoch claim, concrete SHA-256 security or external review. No product
primitive, format or selected security assumption changes.

## Experiment and source correspondence

Use the one compression oracle h and exact HMAC-SHA256 encoding of the linked
HMAC note. The whole procedure starts with the joint state
`unif(h) x unif(S) x sigma_aux`, where S has 256 bits. Preparation cannot read S.
It may query h, maintain quantum state, and choose a classical 32-byte salt r
and a classical Expand message m. All h-dependent preparation is executed and
counted, including preparation of r; no correlated oracle advice is free.
Independent auxiliary oracles/randomness can be included in the preparation.
An actual protocol reduction must supply this complete interactive experiment,
not merely a marginal statement about S and a fixed classical transcript.

One target operation then computes

```text
p = HMAC_h(r, S)
R = HMAC_h(p, m)
```

Its continuation consumes R and can perform arbitrary efficient subsequent
computation, including quantum h queries. It has no other raw-S or raw-p
interface and no additional state, ciphertext or reservation channel carrying
those values. Repeated evaluation of this same input pair is represented by
the same cached result in the proof game. The experiment has one distinct
Extract/Expand pair. Matching the two honest endpoints and their retries to
that pair is an authentication/KEM-simulation obligation, not an assumption
that unrelated invocations happen to have equal inputs.

For qualification source `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`,
[`derive_root`](../../research/continuity-identity-candidate/src/durable/messages/rekey/response.rs)
uses a 32-byte salt and contribution, HKDF-SHA256, and a 32-byte output. Its
single-block Expand message is

```text
m = REKEY_DOMAIN || "pending-root/HKDF-SHA256/"
    || hash("response-core", core) || 0x01
```

The components have 40, 25, 32 and 1 bytes, respectively: `|m|=98` and
`|info|=97`. Padding after the consumed 64-byte key pad has two inner blocks
and final bit-length field 1296. The outer digest has one padded block. Thus
the Extract uses four compression calls; Expand uses five, of which three
follow its two key-pad calls. The earlier definition
`ell=1+ceil((L+9)/64)` gives ell=3 for L=98.

The responder's `Stage::Signing`/`Stage::Ready` retains R with the response
body/wire and signing state. The proposer calls the same helper after restoring
the offer's private owner and decapsulating the response ciphertext, then checks
the response confirmation under R; see
[`completion`](../../research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs).
The helper returns R alone, and these stages do not serialize its temporary
PRK p or combined secret S. This is a local data-flow observation. Earlier
sealed reservations, whole images, public commitments and permitted acquisition
still require the separate disclosure simulation; no memory-erasure or
whole-program noninterference result is inferred from a local variable's scope.

## First hybrid: a single Extract answer

Apply the HMAC note's Real-to-independent-table-I calculation with hidden S,
C=1 and T=0. It replaces the column answer by `V(Gamma(r))`, with V independent
of h. Gamma is the actual pair of public pad states. The whole column family
has not become V(r); its aliases remain exactly as stated in the original
calculation. No row call occurs, so the NMAC replacement makes no change.

There has been no prior call to V. For this one query, V(Gamma(r)) is a uniform
256-bit value independent of h and the prepared state, even if Gamma(r) depends
on h. This exact resampling statement also holds with a quantum prepared state:
condition on h and the classical preparation result z=(r,m,...). The residual
state may be any rho(h,z), but the unused independent table entry at Gamma(r)
is still uniform. After tracing out the unused V table, the state factors as
the prepared classical/quantum state tensor a uniform p register. No quantum
h-query transcript is measured or supplied as free advice in this argument.

There are no later V queries except reuse of the cached answer. Sampling p
before preparation and withholding it until this call therefore gives exactly
the same experiment. The public Gamma computations can be retained. Simulate
Expand and the continuation from the returned p, counting their ordinary h
calls in q_ext. The first distinguishing error is bounded by

```text
eps_ext = min(1, DFH(3, q_ext+3) + E_F1(1, q_ext+2))
DFH(k,Q) = 4 sqrt(2 k^2 Q / 2^256) + 4 sqrt(2 Q^2 k / 2^256).
```

This directly retains the HMAC note's conservative C+2 private-call bound of
three, although the row-free operation only needs its column call. It does not
assert that all three private calls occurred. E_F1 is the same Proposition 4
bound and regime used there; no independent salt-state or collision-free-Gamma
assumption is introduced. The construction-level theorem inputs come from
[DFH Theorem 2](https://arxiv.org/pdf/2206.08132) and
[HI Proposition 4](https://eprint.iacr.org/2021/774.pdf).

## Second hybrid: a single Expand answer

In the preceding ideal game, p is uniformly sampled independently at the start;
the counted prefix executes without access to it. S and the discarded V table
have no remaining interface. Apply the Real-to-I calculation with hidden p,
C=0, T=1 and L=98. The row is replaced by an independent random table U(m).
Its sole fresh answer can be resampled as uniform R by the same conditional-state
argument. No column call occurs, so the F1 replacement makes no change.

The second error is bounded by

```text
eps_exp = min(1, DFH(2, q_exp+3) + E_NMAC(1, q_exp, 3)).
```

E_NMAC has the exact padding conditions and resource parameters of
[HI Proposition 6](https://eprint.iacr.org/2021/774.pdf), as checked in the HMAC
note. This uses independent-table I. There is no I-to-J repair term for this
experiment; in addition, the actual 98-byte row input cannot equal the hidden
32-byte p. Subsequent tags, signatures, state commitments and traffic must all
be recomputed consistently from the selected R. A fixed confirmation transcript
cannot be appended after independently replacing its root.

For every allowed final output bit, the two-call procedure and the procedure
that supplies an independent uniform R to the same continuation differ by at
most `min(1, eps_ext + eps_exp)`. This is an output-probability bound for the
specified query-limited experiment, not a statement that revealing its hidden
S/p or complete oracle table is permitted.

## Query accounting and composition boundary

The two q values count complete ordinary compression-oracle use in their own
reductions. In particular, the first reduction computes the five-call Expand
itself. In the second reduction the public Gamma(r) computation may still make
two h calls before the one private row query. Let B bound every other h query
of the preparation and continuation over all these games, including honest
simulation and adversarial queries. For this exact single 98-byte call shape,
one may conservatively substitute

```text
q_ext <= B+5
q_exp <= B+2

eps_root <= min(1,
    DFH(3,B+8) + E_F1(1,B+7)
  + DFH(2,B+5) + E_NMAC(1,B+2,3)).
```

This is not a measured protocol-wide B. Computing B requires a bounded full
interactive game, including counted historical preparation, retransmission and
other primitive simulations. Exact repeated target calls can use the original
result cache because they are deterministic, with no internal timing/work trace
in this experiment. This equivalence does not discard a publicly observable
retry, storage write, response or extra leakage interface.

If a separately proved actual-prefix/combiner replacement supplies the required
independent S with error eps_K, composition adds eps_K. That obligation remains
open. The uniform-root ideal reached here can initialize the shared-root HMAC
calculation only after the actual continuation is shown to expose its allowed
row/column interfaces and all preceding h queries are counted. Multi-epoch key
reuse, whole-image acquisition, authentication, message/ACK security and adaptive
target selection remain separate obligations.

The inherited asymptotic constants and query regimes are not converted into
concrete security bits. This conditional route does not select a new product
assumption or replace the required independent external assessment.

The raw-p exclusion is necessary for this particular root-replacement statement.
If the continuation is additionally given p, it can recompute HMAC_h(p,m) with
five ordinary calls and compare it with R. It accepts with probability one in
the real game and 2^-256 after an independent root replacement. Revealing S
likewise permits recomputing both calls from r,m. This is a counterexample to
an overbroad game statement, not an observed leak in the implementation. A
prefix reduction must account for actual disclosures rather than remove them
to satisfy this corollary.

## Verification scope

The [encoding evidence](../../research/sdk-alpha1/evidence/20261105-root-extraction-qrom/README.md)
pins the source and the actual hkdf 0.13.0, hmac 0.13.0 and sha2 0.11.0 dependency
closure. Sixty-four salt/contribution/core-digest combinations agree between the
direct library HKDF call and the manual compression construction. Each detects
an incorrect Extract padding offset, an incorrect Expand padding offset and
an incorrect Expand counter, for 192 negative comparisons. The manual paths
take exactly four and five compression calls. These are finite byte-encoding
checks, not empirical tests of pseudorandomness or of the quantum reductions.

The proof work here is the explicit two-hybrid application, single-entry quantum
state factorization and simulation/query inventory above. Its primitive premise
has the earlier independent internal applicability review; this corollary has
not itself received the designated external review or a machine-checked
computational proof.
