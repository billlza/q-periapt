# A conditional single-root oracle lemma

Status: a finite mathematical argument checked internally on 2026-11-04.
This develops one possible route for the shared-key-schedule obligation in
[the computational recovery note](COMPUTATIONAL_RECOVERY_V1.md). It does not
establish an HMAC-SHA256 instantiation, select a new product security assumption,
prove the actual accepted-prefix simulation, or complete the multi-epoch claim.
No protocol bytes, implementation checks or threat-model exclusions change.

The [retained draft and review](../../research/sdk-alpha1/evidence/20261104-shared-root-oracle/README.md)
include a counterexample to an incomplete real-game identification. The repaired
statement below counts the attacker's preparatory queries; it does not prohibit
them. This is a paper-and-pencil calculation, not a machine-checked proof or an
external security review.

## Game and query accounting

Let `n >= 1`, `N = 2^n`, `X = {0,1}^n`, and `M = {0,1}^{<=L}` for fixed finite
`L >= n`. Pair encodings are unambiguous. A random function
`O : X x M -> X` has its usual quantum XOR interface:

```text
U_O |k,m,y,w> = |k,m,y xor O(k,m),w>.
```

Initially the oracle, uniform hidden `R in X`, and auxiliary state have the
joint product distribution `unif(O) x unif(R) x sigma_aux`. The classical/quantum
state `sigma_aux` may be arbitrary before oracle processing, but is jointly
independent of the sampled oracle and root. Count every ordinary oracle
query, including preparation of oracle-dependent auxiliary state, honest
computations and any final distinguisher query, in an upper bound `q`. Prior
queries cannot be replaced by free oracle-dependent advice. The analysis may
sample `R` early while keeping it unused and undisclosed until the prescribed
root-interface stage; a late independent sample gives the same real-game law.

At that stage, permit two **classical** interfaces:

```text
Column(a) = O(a,R),  a in X
Row(b)    = O(R,b),  b in M.
```

There are at most `t` Row calls and any finite number of Column calls. Selectors
and the continuation may depend adaptively on the complete available transcript,
independent private randomness and prior oracle results. Their only access to
raw `R` is through these two interfaces. Other raw-root control flow, storage,
leakage or auxiliary predicates are outside this lemma and require a separate
simulation argument. Root-interface calls are distinguished from the ordinary
queries charged to `q`; counting all underlying primitive calls in `q` instead
is a conservative upper bound.

The ideal game replaces Column and Row by independent random tables `A(a)` and
`B(b)`, respectively, while keeping one independently sampled ordinary oracle
`F`. Repeated selectors reuse the same table entries. The ideal continuation is
otherwise identical. In particular, repeated `F(0,R)` calls share an entry, and
a zero session identifier aliases that same column selector.

For terminal states use `D(rho,sigma) = ||rho-sigma||_1 / 2`. The claim is

```text
delta = min(1, 2 q sqrt(2/N))
D(real, ideal) <= min(1, 2 delta + t/N).
```

This is an average over the uniform hidden root and oracle randomness, not a
pointwise guarantee for every fixed root. The bound is conservative.

## Coupled games

Sample independent random tables `A:X->X`, `B:M->X`, `F:X x M->X` and uniform
`R`. Define an ordinary oracle with the following precedence:

```text
P_R(k,m) = A(k)    if m is exactly the n-bit value R;
           B(m)    if k = R and m != R;
           F(k,m)  otherwise.
```

For fixed `R`, the disjoint input classes receive independent uniform values.
The intersection `(R,R)` uses `A(R)`. Thus `(R,P_R)` has the law of an
independent uniform root and random function. Define:

| Game | Ordinary queries, including preparation | Column | Row |
| --- | --- | --- | --- |
| I | `F` | `A(a)` | `B(b)` |
| J | `P_R` | `A(a)` | `B(b)` |
| K | `P_R` | `P_R(a,R)` | `P_R(R,b)` |

I is the ideal game. K is the real game because its **whole prefix and
continuation** use `P_R`, starting from oracle-independent auxiliary state.
Marginal uniformity of `P_R` alone would not justify retaining an auxiliary
state prepared from a different oracle; the counterexample below explains why.

## Comparing I and J

Fix the sampled tables and other randomness, collectively `theta`, and purify
the common initial state and classical operations. Keep measurement environments
private. I's pre-query state `psi_i^I(theta)` is independent of `R`: its private
interfaces use only `A`, `B` and transcript-selected inputs. Adaptive stopping
can be padded to `q` inactive query slots, for example with a uniform XOR-answer
register on which either oracle acts identically.

Expand the difference of the complete evolutions with **I prefixes and J
suffixes**. If `S_i^J` is the isometric suffix after slot `i`, the exact identity
is

```text
Psi_J - Psi_I = sum_i S_i^J (U_{P_R} - U_F) psi_i^I.
```

Only the ideal query states need root independence. A suffix can depend on `R`
and the full transcript while preserving norm. Define

```text
H_r = {(k,m): k=r or (|m|=n and m=r)}
w_i(r,theta) = ||Pi_{H_r} psi_i^I(theta)||^2.
```

The two query operators agree outside `H_r`. Each has operator norm one, so
their difference on the query state has norm at most `2 sqrt(w_i)`. For every
ideal query-input probability distribution `p_i(k,m)`, averaging over `r` gives

```text
E_r w_i = sum_(k,m) p_i(k,m)
          [1/N + 1_{|m|=n}/N - 1_{|m|=n and k=m}/N]
        <= 2/N.
```

The subtraction counts the row/column intersection only once. Inactive query
branches only decrease the mass. Triangle inequality and Jensen's inequality
therefore bound the mean terminal vector distance by `2 q sqrt(2/N)`.
For unit vectors, their half-trace-norm distance is at most their vector
distance. Convexity and discarding private environments preserve the bound.

This is the query-magnitude hybrid method of
[Bennett, Bernstein, Brassard and Vazirani, Section 3.1](https://arxiv.org/pdf/quant-ph/9701001).
The constants here follow from the displayed operator-norm calculation rather
than a change of normalization in that paper.

Keep a classical `R` register and a private history `H` of the already-classical
Row selectors from the start. They are not exposed or consulted by the
continuation. The same comparison yields

```text
D(rho_I^{R,H,V}, rho_J^{R,H,V}) <= delta,
```

where `V` is the observable terminal state. Keeping `R` throughout is essential;
one cannot first discard it and then infer a bound after appending it.

## Comparing J and K

In I, the whole adaptive selector history is independent of `R`. Let `S(H)`
be its distinct `n`-bit Row selectors and let Bad mean that some selector equals
`R`. Then

```text
Pr_I[Bad] = E_H |S(H)|/N <= min(1,t/N).
```

This conditions on the entire list, not on successive missed guesses. Bad is
a final measurement effect on the retained `R,H` registers, hence
`Pr_J[Bad] <= Pr_I[Bad] + delta`. The measurement and channel-contraction facts
used here are the half-trace-norm consequences of
[Watrous, Theorem 3.4 and Corollary 3.40](https://cs.uwaterloo.ca/~watrous/TQI/TQI.pdf).

J and K have the same ordinary oracle and exactly the same Column answers.
Their Row answers agree unless `b=R`. Add an absorbing private Bad flag at
classical Row submissions. This measures no quantum public query. Up to the
first flagged call, every operation and answer agrees, including the quantum
workspace. Consequently their **unnormalized** good branches are equal and
their bad branches have the same weight `p = Pr_J[Bad]`:

```text
rho_J = tau_good + tau_bad,J
rho_K = tau_good + tau_bad,K
Tr(tau_bad,J) = Tr(tau_bad,K) = p.
```

Positivity gives `D(J,K) <= p`. Equality only after normalization on success
would be insufficient. Combining the two comparisons proves
`D(I,K) <= 2 delta + t/N`, clipped at one. This step relies on classical root
interfaces; it does not provide a coherent-Row-query theorem.

Ordinary continuation calls with a derived key or message equal to `R` already
contribute to the hidden-row/column query mass. No new implementation exclusion
is imposed. Repeated inputs and coincident random outputs retain their ordinary
random-function semantics.

## Why preparatory queries must be counted

An earlier draft did not sufficiently qualify the identification of K with a
real prefix carrying oracle-dependent auxiliary state. Take `m0=0^n`, prepare
`X=F(0^n,m0)` with one oracle query, and then sample independent uniform `R`.
If that query is omitted from `q`, the remaining interaction has `q=t=0`:
make one Column call at zero and test whether its answer `Y` equals `X`.

For the same real oracle throughout, `Y=F(0^n,R)` and

```text
Pr_real[Y=X]  = 2/N - 1/N^2
Pr_ideal[Y=X] = 1/N.
```

The difference `(1/N)(1-1/N)` is positive, whereas a bound with `q=t=0` is
zero. Root independence has not been violated. The error was keeping `X(F)`
fixed while identifying a new `P_R` as the same real oracle. Starting before
that preparation and charging its query to `q` repairs the identification
without removing the attacker's prefix access. The literal coupled I/J/K
inequality in the draft is not contradicted.

## Remaining protocol obligations

The lemma preserves the two input roles of one hidden value and their exact
aliases in one ideal primitive. It does not make that primitive an established
model of HMAC-SHA256. Its application still needs:

- A source-bound accepted-prefix/combiner argument supplying a fresh root with
  the required oracle-relative and auxiliary-state distribution.
- A correspondence showing that every actual root dependence, including
  persistent encrypted state and permitted leakage, is simulated through the
  declared interface or justified in another hybrid.
- An actual HMAC instantiation argument or an explicitly reviewed choice of
  security assumptions; the product has not selected this idealization here.
- Message/ACK key separation, authentication, adaptive target selection and
  multi-epoch composition with explicit resource bounds.

The existing symbolic result, tests, platform qualification and external-review
requirements keep their separate meanings. No release status changes on the
strength of this lemma.
