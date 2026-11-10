# Complete ContextBound tuples to a native next-rekey message

Research proof artifact, 7 November 2026. Companion manuscript: `contextbound-connection.tex`. This new module follows the existing joint-continuation v0.4 results without changing their primitive bounds or joint schedule proof.

## 1. Result and exact scope

For the next rekey of one valid-established authoritative session, the remaining comparison from the random selected component to a uniform recovered contribution has output-bit gap

\[
\varepsilon_{\mathrm{CB},j}\le\Phi_{256}(d_j,Q_{H,j}),\qquad
\Phi_n(d,Q)=\min\{1,4\sqrt{2d^2Q2^{-n}}+4\sqrt{2Q^2d2^{-n}}\}.
\]

The concrete selected component is **ML-KEM-768** in a real-versus-uniform 32-byte shared-secret experiment. The other component is the actual X25519 computation, including its rejection behavior. Its raw DH output is not asserted to have a uniform 256-bit distribution.

The private hash index is the complete actual effective tuple, not an operation ID, origin, authority or full-offer provenance identifier. The native source invariant proves that the selected table entry feeds one old-root/complete-root-info pair in this next-rekey profile. That is the interface required by the retained single-root initialization bound.

Consequently,

\[
|b_j|\le B_j^{\rm cont}:=\min\{1,2\Phi_{256}(d_j,Q_{H,j})
+2\Delta_{{\rm init},j}+2\Delta_{{\rm sched},j}
+2\varepsilon_{{\rm AEAD},j}\}.
\]

This closes that candidate's previously explicit ContextBound continuation term. The separately stated original-game attribution/projection residuals, local record correspondence, component advantage and component correctness terms remain.

## 2. Oracle interfaces and counted preparation

`H` is the whole SHA3-256 random oracle; `h` is the independent SHA-256 compression oracle used by HMAC/HKDF. The complete experiment retains both throughout. Concrete native code calls the actual specified algorithms; these independent ideal-oracle interfaces are part of the cryptographic experiment, not a property established by the source audit.

An established starting session is built by executing its oracle-counted preparation, or starts with auxiliary data independent of the initially sampled oracles and hidden seeds. Roots, KEM material, signatures and records derived by an actual oracle-dependent prefix are not supplied as free correlated advice. No hop erases that preparation.

`Q_H` includes ordinary SHA3 work in preparation, policy/transcript/record computations, KEM algorithms, unrelated origins, public quantum queries, the complete continuation and terminal test. The `h` bounds retain their own complete ordinary compression budgets. A known ordinary query accidentally hitting a protected point remains an ordinary query and retains its actual oracle answer.

## 3. Actual encoding and hidden-component lemma

Let `LP(x)=BE64(byte_length(x)) || x`. The actual combiner encodes these ten fields, in order:

\[
(D_{\rm CB},\mathrm{suite},\mathrm{BE32}(v),s_M,s_X,c_M,p_M,c_X,p_X,C_{\rm policy}).
\]

Each field receives its own outer LP prefix. The nested last field is

\[
C_{\rm policy}=\operatorname{LP}(D_{\rm policy})
\Vert\operatorname{LP}(\mathrm{policyDigest})\Vert\operatorname{LP}(C_{\rm app}),
\]

\[
C_{\rm app}=H(\operatorname{LP}(D_R\Vert\texttt{response-kem})
\Vert\operatorname{LP}(O)),
\]

where `O` is the complete saved signed offer, including envelope/signature bytes, and the policy digest is that of the verified admitted policy. The trust-root SHA256 digest in the reservation binding is not an extra ContextBound field. Raw offer and original owner metadata remain in the provenance ledger. Two raw offers whose effective application-context hashes coincide do not receive different hash-cache keys solely because the raw offers differ.

| Field | Native byte length |
|---|---:|
| ContextBound domain | 23 |
| Suite | 17 |
| Policy version | 4 |
| Each shared-secret field | 32 |
| ML-KEM ciphertext/public key | 1088 / 1184 |
| Traditional ciphertext/public key | 32 / 32 |
| Nested policy context | 115 |
| Complete input | 2639 |

The selected ML-KEM secret occupies offsets 76 through 107, zero based.

**Lemma.** Let `U` be uniform on 256 bits and initially independent of both oracles and auxiliary state. Let `m` contain the other nine effective fields, including the traditional shared secret. Write `f(U,m)` for the actual encoded input. Suppose `U` has no channel outside the protected ContextBound interface and opaque private handles before its declared stops. Replace `m -> H(f(U,m))` by a private random function `T(m)`, caching repeats. With at most `d` distinct private inputs and `Q_H` complete ordinary SHA3 queries, every efficient output-bit probability changes by at most `Phi_256(d,Q_H)`.

**Proof.** For fixed `m` and string `w`, parsing `w` identifies at most one value of `U` satisfying `f(U,m)=w`, so the point probability is at most `2^-256`. Distinct effective `m,m'` encode different inputs for every `U` because parsing recovers all ten fields. Caching repeats gives all-secret freshness. These are the hypotheses of Don, Fehr and Huang, Theorem 2, with entropy parameter 256. It permits adaptive private queries. The independent `h` interface is unchanged auxiliary computation. Every ordinary `H` call, including a matching known computation, remains ordinary and is counted. There is no conditioning on collision avoidance, future acceptance or a selected future transcript. ∎

Reference: Don, Fehr and Huang, *Adaptive versus Static Multi-oracle Algorithms, and Quantum Security of a Split-key PRF*, arXiv:2206.08132, version 3, Section 4.2, Theorem 2 and equations (6)–(7). The retained primitive appendix already fixes this `Phi` convention.

**Cache counterexample.** Two original calls with the same effective tuple have equal real hash outputs with probability one. Per-origin independent ideal outputs would agree only with probability `2^-256`. Conversely, dropping any effective field can merge distinct real inputs. Thus origin consistency and hash consistency require separate tables.

## 4. Operational component game and original invocation routing

For `j=(g,a)`, slots are assigned at original entropy reservation, including attempts that later fail. Exact replay/copies retain the slot. A new draw is a new slot even if an external operation ID is reused. The private component result is cached at its first actual computation, before subsequent persistence or release.

The component game used by the bound is explicit:

1. Generate the selected ML-KEM key pair and supply the public key. Permit ordinary prechallenge decapsulation.
2. At the first actual encapsulation computation of original `a`, create the one challenge by a fresh native-distribution encapsulation. Return its ciphertext with either the real shared key or independent uniform `U`.
3. Afterwards the component oracle rejects the challenge ciphertext. Preserve the prechallenge transcript unchanged.

The adapter assigns that public key only to original generation owner `g`, with a locally sampled X25519 scalar and the actual admission/lease metadata. The original encapsulation binding must consume the full retained offer from `g`. An immutable contrary binding permanently prevents usable attribution to `(g,a)`, so it justifies the existing free stop. Byte equality does not transfer origin. Otherwise missing or unaccepted operations keep their actual execution.

After challenge creation, selected-owner PQ decapsulation routes by **PQ ciphertext bytes**:

```
if pq_ciphertext == challenge_pq_ciphertext:
    pq_secret = cached_challenge_key
else:
    pq_secret = component_decap_oracle(pq_ciphertext)
traditional_secret = native_X25519_decap(local_scalar, traditional_ct)
if traditional computation rejects:
    return the native error
return ContextBound(all actual effective fields)
```

A different traditional ciphertext/context does not permit sending the challenge PQ ciphertext to the CCA oracle. It can instead create a different complete private ContextBound tuple. Native work performed before a traditional-leg rejection is still counted.

A prechallenge query that happens to equal the later sampled challenge retains its original real answer. That earlier answer is not retroactively replaced by `U`, removed or rejected. Other original key owners keep their locally known actual algorithms even if their public-key bytes coincide.

For `sigma` in `{-1,+1}`, the whole derived distinguisher `D_j^sigma` outputs `1[Psi_j=sigma]`. Define

\[
a_j^\sigma=|\Pr[D_j^\sigma=1\mid\text{real challenge}]
-\Pr[D_j^\sigma=1\mid\text{uniform challenge}]|.
\]

Its real branch matches `V^[j]` up to the selected-pair correctness term `delta_j`; its uniform branch is exactly the defined `Vtilde^[j]`. These give the existing two signed-event inequalities. The bound calls this actual operational two-stage primitive experiment; equivalence with a challenge-up-front interface is not assumed. The existing correctness, record and permitted-projection terms are not set to zero.

For the next hidden-`H` hop, a new simulator may sample all actual KEM tapes locally, run their algorithms, then substitute independent `U` for designated protected component returns. It need not inherit the previous reduction's unknown challenge tape. Opaque private records and the same stops preserve the public experiment. All actual KEM SHA3 queries count in `Q_H`.

## 5. Target allocation and one native root use

The concrete profile starts with one authoritative established session: both endpoints have equal old root `r`, confirmed epoch and control parent, and no pending selected rekey. Old root/wrapping keys may be known. It admits native preparation, response, final, receipt, traffic, status and plaintext-free resume; failures/new draws, failed/uncertain writes, crash/reopen, active public packets, asynchronous confirmation and later epochs. It does not export the selected owner to arbitrary SDK calls or activate physical read-only copies as competing histories. These are an initial state and call surface; original eligibility is unchanged.

`m*` is the original `a`'s actual complete hybrid tuple after omitting `U`: its challenged PQ ciphertext, locally generated traditional ciphertext/secret, original offer-derived context, policy and public keys determine it. **It is not an arbitrarily chosen first family tuple.**

Mark `m*` before its first actual private ContextBound call, at any alias site, including a private computation followed by failed persistence. If a crash intervenes after the component challenge, the cached ciphertext and determined traditional leg still identify this target. A prior alias computation already allocates its table entry and cannot be ignored at later acceptance/release. Other tuples do not become targets. If `a` never produces a usable target, the original candidate score is zero rather than selecting another tuple.

At that first allocation, `S*=T(m*)` is fresh uniform and may be presampled/withheld. This does not claim uniformity conditioned on the future view. Repeats reuse `S*`; other `T` entries are locally sampled values available to the controller.

**Source lemma.** Fix an original pair `j=(g,a)` whose immutable encapsulation binding consumes the retained original offer from `g` for this next rekey. All protected uses of its original tuple `m*` feed one `(r,I_R)` pair on every subsequent trace, independently of final eligibility or attribution. Immutable contrary bindings use the already proved permanent-zero stop; a final ineligible branch does not justify a new early stop. Here

\[
I_R=D_R\Vert\texttt{pending-root/HKDF-SHA256/}
\Vert H(\operatorname{LP}(D_R\Vert\texttt{response-core})
\Vert\operatorname{LP}(C^*)),
\]

where `C*` is the complete original response core. The information string has 97 bytes.

**Proof.** A selected generation token reconstructs one retained signed offer and checks regenerated public material. The encapsulation token is retained with that exact raw offer; unequal offers conflict and completing/committed plans return saved flights. Pending ordinary message operations do not replace `state.rekey`. The fixed session/context/epoch/role/control-parent/offer prefix plus both full ciphertext fields fix the response core and complete info. Both endpoints retain the common old root.

The responder leaves the encapsulation-token stage for a retained-root stage before releasing the response. The proposer leaves the generation-token stage before installing the new root. Final/receipt installation sites are the live root updates. A crash before a transition recovers the same old token/root; a committed transition recovers its saved result. Hence no selected token is recomputed under the newly installed root. Induction over supported calls, authoritative write outcomes and crashes proves the claim. Read-only copies add no execution transition. ∎

Evidence: `contextbound_source/source_audit.md`, Section 6, and its fourteen-file `source_map.json`, pin `228c944fc476e3e57d6c08063cacb19bca5b360e`. Source and independent proof reviewers checked this profile. The finite source checker validates concrete framing/routing cases; it does not replace the cryptographic argument.

The protected-family statement makes no collision-free claim about independent numeric keys. Known independent computations that happen to match protected values remain covered by shared-oracle budgets.

## 6. Game chain and signed-score accounting

Keep the original candidate score

\[
\Psi_j=\mathbf1_{E\land A\land(I=j)}S_{\rm msg},\qquad
S_{\rm msg}=2\mathbf1[b'=b]-1,
\]

with zero after established local stops. `E` is original eligibility; `A` usable unique attribution; `I` the actual original pair. Each game runs the same terminal code on its **own** trace and ledger.

| Comparison | Meaning | Cost convention |
|---|---|---|
| Native to `V^[j]` | Existing stopped source/record/report interface | Signed score `rho_j` |
| `V^[j]` to `Vtilde^[j]` | Operational selected ML-KEM component | Signed score `a_j^+ + a_j^- + 2 delta_j` |
| `Vtilde^[j]` to `Wcont^[j]` | Complete protected tuples become private table `T(m)` | Bit gap `Phi_256(d_j,Q_H,j)` |
| Uniform contribution to uniform root | One original `P=F(r,S*)`, `R=F(P,I_R||01)` and repeats | Bit gap `Delta_init,j` |
| Uniform root to uniform selected message key | Existing joint schedule, confirmations, ACKs, successors | Bit gap `Delta_sched,j` |
| Final message game | Existing full one-key AEAD experiment | Guess advantage `epsilon_AEAD,j` |

The fresh table entry and source lemma supply the original single-entry root initialization interface. Combined secret/PRK have no additional raw-use/disclosure channels. The root comparison regenerates the whole continuation, including confirmations, traffic and future epochs, rather than replacing a root inside a fixed transcript. The fresh traffic entry/direction mark remains the one in the existing joint theorem.

For any bounded efficient `Psi`, the terminal test that outputs one with probability `(Psi+1)/2` converts output-bit gap `epsilon` into signed score gap `2 epsilon`. Hence

\[
|b_j-b_j^{\rm cont}|\le2\Phi_{256}(d_j,Q_{H,j}),
\quad
|b_j^{\rm cont}|\le2\Delta_{{\rm init},j}
+2\Delta_{{\rm sched},j}+2\varepsilon_{{\rm AEAD},j}.
\]

Substitution in the retained candidate-local proposition gives

\[
\operatorname{Adv}_{\rm msg}\le\min\left\{\frac12,\frac12\left(
\eta_{\rm attr}^{\rm nat}+\eta_{\rm proj}^{\rm nat}
+\sum_{j\in J}[\rho_j+a_j^++a_j^-+2\delta_j+B_j^{\rm cont}]
\right)\right\}.
\]

Both residuals are still probabilities in the original native experiment. Different candidate ideal continuations are not probabilities in one partitioned ideal world. All finite budgets are fixed before execution and include the whole derived preparation/continuation. No hop resets accumulated oracle work.

## 7. Eligible scores and the AEAD endpoint

A bit-independent view alone does not justify zero expectation for an arbitrary qualified score. Let the guess be always zero and invent `E=1[b=0]`. The qualified signed score has expectation `1/2` even if the remaining view is bit independent.

The existing first-message corollary requires the actual qualifying predicate to be efficiently evaluable from the available classical view and provenance ledger, without direct access to the hidden bit. It may depend on observed challenge ciphertext and subsequent protocol behavior: those are handled by the complete AEAD experiment. Guess the adversary's answer on qualified runs and an independent fair coin otherwise. The resulting actual AEAD advantage is exactly half the absolute expected qualified score. The endpoint term is `2 epsilon_AEAD`, not a fictitious zero mean. Original eligibility is retained and recomputed by that available score code.

Free stops must likewise be permanent. An acquired intact same-session version with an occurred selected origin was saved after that reservation; eligibility requires a cut before both selected origins and no acquired selected-session version after it. Its immutable provenance prevents any future eligible continuation for that candidate. A key-only/report projection without that certificate retains its original charged residual or comparison; it is not renamed a session acquisition.

## 8. Remaining extension, excluded from this theorem

Identical ContextBound tuples alone do not imply one root use. The same combined `S` can be fed to `F(r0,S)` and `F(r1,S)`, or expanded under different complete infos. Imported owners, active forks and arbitrary retrospective multi-epoch selection need their own source invariant or a multiple-root entry comparison.

A finite extension can use a hidden-HMAC column comparison for at most `C` available salts, followed by root rows indexed by `(Gamma(r), complete I_R)`, costing

\[
\varepsilon_{\rm Hjoint}(C,0,q_S,32)
+\sum_i\varepsilon_{\rm Hrow}(N_i,q_i,98).
\]

It requires predeclared budgets and a fresh target pair. For connection to the existing downstream root theorem, other salts and infos must be computable from the reduction's available data. Feeding the selected hidden root as a new salt for that same parent contribution adds a raw-root use outside the existing schedule. This is an available-data/source-handle constraint, not an assertion that two random numeric keys are unequal. **This extension is not invoked by the present theorem and is not promoted to a manuscript theorem in this delivery.**

## 9. Status

The complete LP8 encoding hypotheses, exact hash cache, signed-score conversion and bound substitution are proved here. The declared next-rekey source correspondence is established by the pinned source induction and independently reviewed. Cryptographic component/correctness inputs, cited QROM comparison, retained HMAC/HKDF bounds, AEAD experiment and original residuals remain explicit.

This module does not claim a uniform-key assumption for native raw X25519, an unproved conversion to a different component game, arbitrary multi-root closure, elimination of genuine projection/attribution residuals, or computational security established solely by finite tests.
