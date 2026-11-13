# Independent review of the single-root ideal-oracle coupling

Reviewed 2026-11-04 UTC. This is a finite mathematical review, not an
implementation test, external security audit, HMAC theorem, or protocol proof.
No production source, product documentation, SDK, CI, or build was changed or
run for this review.

Inputs:

- shared-root-oracle-draft.md, especially lines 81–148;
  SHA-256 d3c29494a31feffa8d2c417f09fa72a4c055276e4b61f5c6c1b91df7edfecc11.
- ../../docs/continuity/COMPUTATIONAL_RECOVERY_V1.md, lines 218–265, read only
  to delimit the claim;
  SHA-256 6b5557505622db940eff81cc32390ba1965c8f302af5f6b4ed84542680336446.
  The relative path is from this review's directory. The actual reviewed file
  is ${CHECKOUT}/docs/continuity/COMPUTATIONAL_RECOVERY_V1.md.

## Conclusion and the one identification gap

For the literal coupled I/J/K games at draft lines 87–128, the claimed bound
holds with trace distance defined as D(rho,sigma) = (1/2)||rho-sigma||_1:

    N = 2^n
    delta = min(1, 2 q sqrt(2/N))
    D(I,K) <= min(1, 2 delta + t/N).

The proof below covers an adaptive quantum continuation, classical root
interfaces, and retention of the root and selector history in the final
comparison. It does not assume that J's query states remain root-independent,
and it does not measure quantum public-oracle queries to define Bad.

There is a distinct gap in draft lines 122–124 if “the real random-oracle
interface” includes an arbitrary oracle-correlated initial state. The marginal
fact that P_R is a random function does not identify its joint distribution
with such a state. Independence of R from the complete initial state and F
does not by itself fix this. A one-query-prefix counterexample is given below.
It invalidates that identification under omitted prefix-query accounting; it
does not invalidate the inequality for the explicitly constructed I/J/K.

## Precise finite game and distance convention

Let n >= 1, X = {0,1}^n, and M = {0,1}^{<=L}, with finite L >= n. Selectors
satisfy a in X and b in M. Thus B in the draft can be restricted to M; allowing
b outside M would leave P_R(R,b) undefined rather than create a cryptographic
case. Pair encodings are unambiguous. The public oracle is the usual XOR unitary:

    U_f |k,m,y,w> = |k,m,y xor f(k,m),w>.

Sample independent random tables A:X->X, B:M->X, F:X x M->X, and uniform R.
R is independent of their joint state and all initial auxiliary state, not
merely independent of each marginal separately. The literal coupled games
start with the same auxiliary state. The continuation has no access to R
except through the declared classical column and row interfaces; in I these
return A(a) and B(b). All ordinary oracle uses, including honest computations,
consume the q-query budget. There are at most t row calls. The finite game may
have adaptive stopping and arbitrary finite classical column calls.

Classical interfaces mean classical selector submission and classical answers;
a superposition of row selectors is not an additional permitted interface.
Classical measurements and private-table calls can be purified for the I/J
comparison by retaining their environments. Variable public-query counts can
be padded to q slots: a stopped branch uses an inactive query, equivalently an
XOR-answer register in the uniform superposition, on which either oracle acts
as the identity. No actual additional information is made available.

The quantitative statement concerns the terminal state after the counted
queries. Any subsequent oracle access by a distinguisher must also be counted
in q; an unqueried oracle is not supplied as a readable whole table.

## I/J: an exact expansion using only ideal query states

Fix all classical table choices and other classical sampling, denoted theta,
and choose a common purification of any conditional mixed initial state.
Because R is jointly independent, that initial purification can be chosen
independently of r. All non-public-query operations in I and J are the same:
they can depend on A, B and the evolving transcript, but have no direct R input.
Purifying classical measurements does not expose the retained environment.

Let |psi_i^I(theta)> be the state immediately before public-query slot i in the
complete ideal execution. It has no r dependence. Let S_i^J(r,theta) be the
isometric suffix after that slot, with all later public queries using P_r.
The elementary product-difference identity gives exactly

    |Psi_J(r,theta)> - |Psi_I(theta)>
      = sum_i S_i^J(r,theta) (U_{P_r} - U_F) |psi_i^I(theta)>.

Thus the prefix of every summand is I and its suffix is J. The suffix can
depend on R; its norm is still one. There is no assertion that an intermediate
hybrid's query state, or a J query state, is independent of R. The common
inter-query operations, including adaptive classical-interface interactions,
are already in the prefix/suffix products.

Define the hidden input set and its input-register projector by

    H_r = {(k,m): k=r or (|m|=n and m=r)},       Pi_r = projector onto H_r.

Write w_i(r,theta) = ||Pi_r psi_i^I(theta)||^2, including the active-query
flag if one is used. The query maps coincide outside H_r. Their operator
norms are one, so

    ||(U_{P_r} - U_F) psi_i^I(theta)|| <= 2 sqrt(w_i(r,theta)).

For any ideal query-input probability distribution p_i(k,m), averaging the
uniform r gives

    E_r w_i(r,theta)
      = sum_{k,m} p_i(k,m) [1/N + 1_{|m|=n}/N
                                - 1_{|m|=n and k=m}/N]
      <= 2/N.

An inactive branch only lowers the mass. This holds even when p_i depends on
the entire F, A and B execution. Independence from R, not independence from
those tables, is the property being used. The subtraction term includes the
row/column intersection without double-counting it.

For unit vectors, D(|u><u|,|v><v|) = sqrt(1-|<u,v>|^2) <= ||u-v||.
Average the product expansion over theta and r, use the triangle inequality,
and use E sqrt(w) <= sqrt(E w). It follows that

    E_{r,theta} ||Psi_J(r,theta)-Psi_I(theta)||
      <= sum_i 2 E_{r,theta} sqrt(w_i(r,theta))
      <= 2 q sqrt(2/N).

This is an average over the sampled root, not a bound for every fixed r.
The factor two comes from the difference of two oracle unitaries. No further
factor two is needed when converting Euclidean norm to the half-trace-norm
distance used here. The bound is conservative, not asserted optimal.

This is the ideal-state query-magnitude method underlying the proof of BBBV
Theorem 3.3; its constants here are derived directly above rather than imported
from a differently normalized statement. The authors' full PDF was available,
and only the relevant Section 3.1 argument was checked:
[Bennett, Bernstein, Brassard and Vazirani, Section 3.1, Theorem 3.3](https://arxiv.org/pdf/quant-ph/9701001).

## Keeping R and the selector history for the Bad effect

Retain a classical R register from the start, and record each already-classical
row selector in a private history H. Neither register is released or consulted
by the continuation. Conditional on r and theta, the preceding purified-state
comparison still applies. Convexity for the classical mixture and contraction
under tracing out the table labels and other environments therefore give

    D(rho_I^{R,H,V}, rho_J^{R,H,V}) <= delta,

where V is the final observable quantum/classical state. One may retain
additional ordinary registers too. This is stronger than first discarding R
and attempting to append it afterwards; the latter inference would not be
justified.

In I, the complete adaptive history H is independent of R. If S(H) is the set
of distinct n-bit row selectors in H, then

    Pr_I[Bad] = E_H |S(H)|/N <= min(1,t/N),
    Bad := “some row selector b equals R”.

This conditions on the entire selector list, not on the event that earlier
guesses missed. It therefore does not assume that R remains uniform after
conditioning on successive non-hits. Repeated selectors and adaptive stopping
are included.

The predicate Bad is a single final measurement effect on the retained R,H.
Every effect's probability difference is at most trace distance. Hence

    Pr_J[Bad] <= Pr_I[Bad] + delta <= t/N + delta.

The elementary trace-distance facts used here are the measurement bound and
contraction under channels, including partial trace. They are stated in
Watrous, Theorem 3.4 (Holevo–Helstrom) and Corollary 3.40 / equation (3.241):
[The Theory of Quantum Information, author PDF](https://cs.uwaterloo.ca/~watrous/TQI/TQI.pdf).
These specific passages were read; this is not a claim to have checked every
theorem in that book.

## J/K: identical unnormalized good branches despite public quantum queries

J and K use the same P_R for every public query. Column answers also coincide
exactly because P_R(a,R)=A(a). For a row selector b != R, both return B(b).
For b=R, J returns B(R) and K returns A(R); equality of those two random values
can occur, but marking that call Bad is still a valid upper bound.

For this comparison only, attach an absorbing Bad flag to classical row
submissions. This does not measure any public quantum query. It only records
a deterministic predicate of two already-classical values, R and b.
Inductively, the unnormalized state of all paths on which the flag is still
good is identical in J and K. On such paths all previous operations and
answers have been identical, including public quantum-oracle operations and
the joint state of any unmeasured workspace. The first-Bad branching probability
is consequently the same in J and K.

At termination, after optionally forgetting the flag, write

    rho_J = tau_good + tau_bad,J,
    rho_K = tau_good + tau_bad,K,
    Tr(tau_bad,J) = Tr(tau_bad,K) = p = Pr_J[Bad].

All these components are positive semidefinite. Therefore

    D(J,K) <= (||tau_bad,J||_1 + ||tau_bad,K||_1)/2 = p.

Using only equality of normalized states conditioned on success would omit
their probabilities; the common subnormalized tau_good is the required
statement. Quantum public queries are compatible with this argument because
the distinguishing row interaction is genuinely classical. If that interface
instead allowed coherent selectors, this decomposition would not be justified
by the same proof.

Finally,

    D(I,K) <= D(I,J) + D(J,K)
           <= delta + Pr_J[Bad]
           <= 2 delta + t/N,

and D <= 1 gives the stated clipping.

## Alias and dependence accounting

- Repeated column selectors share A; repeated row selectors share B. In
  particular, session_id=0 is preserved exactly.
- A column pair (a,R) equals a row pair (R,b) precisely when a=R and b=R.
  This is covered by Bad. Merely having a=R does not itself cause J/K to differ.
- Ordinary public calls, including calls using a returned/derived value as a
  key or message, are charged to q. Accidental equality of that value with R
  is already covered by hidden-row/column query mass. It needs no new
  implementation exclusion or independent collision assumption.
- Equality of outputs at distinct inputs is allowed by the random functions.
  It creates no missing alias rule.
- Any other use of raw R in selecting an input, control flow, initial state,
  leakage, or an uncounted oracle computation would fall outside the stated
  interface. Marginally uniform answers alone would not repair such a use.

## Concrete initial-state counterexample to identifying K with “real”

Draft lines 105–106 correctly prove that P_R is a random function for each
fixed R. This implies that (R,P_R) has the independent uniform/random-function
joint law. It says nothing by itself about an auxiliary state Z(F) that was
prepared using the base F, then held fixed while F was replaced by P_R.

Here is a one-query preparation, not an unbounded oracle-table advice attack.
Let m0=0^n and prepare X=F(0^n,m0) before sampling a fresh independent R.
If that preparation is omitted from q, the remaining interaction uses q=0
ordinary queries and t=0 row calls. Make just one allowed column call a=0^n,
obtain Y, and accept exactly when Y=X.

With the same actual oracle F throughout preparation and the real root call,
Y=F(0^n,R), so

    Pr_real[Y=X] = Pr[R=m0] + Pr[R!=m0]/N = 2/N - 1/N^2.

In I, Y=A(0^n) is independent of X, and

    Pr_I[Y=X] = 1/N.

The distinguishing probability gap is (1/N)(1-1/N)>0, while the advertised
q=t=0 expression is zero. R remains uniform and independent of the complete
prefix state and F; that premise alone has not been violated.

In the literal K coupling, however, the initial value is still X=F(0^n,m0)
while the response is P_R(0^n,R)=A(0^n). Literal I and K are identical in this
example, exactly as the proved inequality requires. The invalid step is
identifying that K with the real experiment's same-oracle joint prefix law.

## Minimal repair and stopping boundary

State the real-game version from an oracle-independent initial state. Include
in q every oracle query that prepares any oracle-correlated auxiliary state,
as well as every later ordinary honest or adversarial query. Sample R at the
start for the analysis, but disclose it to no interface; start the classical
root interfaces only at their prescribed point. Because (R,P_R) is an
independent root/random-function pair, this early hidden sampling has the same
observable real-game distribution as fresh root sampling after the prefix.
The proof then compares the entire prefix and continuation, using I states
throughout the expansion. This accommodates the attacker's actual prefix
queries; it does not prohibit them or assume away their auxiliary information.

If the starting state is instead supplied as arbitrary oracle-dependent
advice without such a preparation/query bound, the real-game identification
does not follow from the stated R-independence condition. No stronger
replacement assumption is adopted here.

This closes the finite coupled-game calculation, conditional on its explicit
interfaces and query accounting. It does not establish that Continuity's
extraction/prefix hybrid supplies the required root independence relative to
the full oracle and auxiliary state, that all actual root-dependent code fits
the two interfaces, or that HMAC-SHA256 can be instantiated by this oracle.
Those are precisely separate premises in the reviewed computational document,
not consequences of this lemma. No KEM, multi-epoch, storage, platform, or
release conclusion is claimed.

The unavailable full PDFs for ePrint 2021/774 and 2026/128 were not retried or
used as checked full theorems. No new security assumption or release blocker
is introduced by this review.
