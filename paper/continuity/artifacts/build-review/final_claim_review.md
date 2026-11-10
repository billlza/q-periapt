# Final claim-scope review

Reviewed 7 November 2026. Scope: the abstract in `q-periapt-paper/paper/continuity/main.tex`, `introduction.tex`, and `discussion.tex`, compared with `work/joc_round4/theory/joint_continuation.md`, version 0.3. This is a wording and attribution review; it does not add a mathematical proof review, literature survey, experiment, or build check.

## Decision

**The reviewed wording is consistent with a conditional uniform-contribution continuation and does not present it as a completed native computational PCS theorem.** The three sections retain the distinction between the mechanized symbolic recovery result, quantitative interface/composition results, and the accepted-operation instantiation that connects actual component and combiner outputs to the uniform-contribution entry.

The new increment is presented primarily as a constructive composition. No sentence claims that shared-root HMAC, single-call root initialization, or generic HKDF block-table normalization was first discovered in this increment. The final wording also makes the role of the normalization input and the finite-interface scope explicit.

## Claim-to-result correspondence

| Reviewed wording | Supporting scope in version 0.3 | Assessment |
| --- | --- | --- |
| Abstract: “Starting from a uniform recovered contribution” and a selected first-message key | Section 7 and Corollary 4 start from a uniform combined contribution, pass through the actual Extract/Expand root entry, and then compose the schedule and one-use AEAD games. | Correct conditional entry. It does not identify the actual combined KEM output with a uniform value. |
| Introduction, contribution 2: confirmation-dependent traffic information, real confirmation/ACK verification, successor-root and next-seed disclosure | Sections 3–6 admit these operations explicitly. The controller regenerates its continuation after each replacement. The underlying public compression oracle is shared and its work is charged. | These retained interfaces are substantive composition features and are supported by the stated result. |
| Introduction, final paragraph: “The universal recovery result is symbolic”; quantitative results cover “the stated finite interfaces” | Theorem 2 concerns a typed controller with at most `M` distinct complete traffic information strings; the target entry and direction are designated before the entry's blocks are produced. | The universal and finite-interface claims are correctly separated. The earlier adaptive-origin stopping certificate does not itself enlarge the leaf theorem's target-selection interface. |
| Discussion: the specified one-use AEAD game bounds “this profile's ideal-contribution score” | Corollaries 3–4 use an available event, the declared application interface, and one encryption result cached from its first private computation. The network-facing challenge interface permits plaintext-free Resume, while plaintext-bearing application returns remain private. | Correct description of the proved application profile. Exact retries refer to the original private computation, including retries before public release. |
| Discussion: the next step connects the accepted ContextBound operation using the same original invocation, cache and accepted-prefix history | Sections 7–8 keep component replacement, the actual ContextBound hash hop, source correspondence and projection accounting in their established positions. | Correct placement of the remaining native instantiation. The text keeps both `rho_j` and the actual native projection residual; it does not absorb them into the schedule theorem. |
| Conclusion: exact exposure semantics, constructive simulations, a recovered-contribution-to-message continuation and a mechanized multi-epoch theorem | These correspond to distinct results and evidence classes in the paper. | Accurate aggregate statement. Native separating executions are described as executions, rather than as a computational proof of all native continuations. |

The finite interface has one coherent boundary: it admits the stated root/traffic/chain calls, finite traffic allocations, original-operation aliases, public control verification and computable later projections. The selected old seed and message key retain their declared uses, and the confidentiality challenge uses the specified application actor/interface. These conditions delimit the joint continuation; they do not weaken the separate symbolic theorem or erase already completed record/report results.

## Attribution and final wording refinements

The proof note's Sections 1, 11 and 12 identify the **composition and concrete simulator** as the increment. Shared-root HMAC, root initialization, exact Expand normalization and original-send caching are retained inputs. The new application combines them while handling confirmation-dependent information, shared PRK classes, complete-information aliases, the removal of hidden parent-row inputs, and allowed successor disclosures.

The introduction describes this result under “Constructive composition for persistent observations and key derivation.” The final sentence now reads:

> Using exact private-row normalization, the composition makes the next hidden-input reduction possible without leaving an unmodeled parent-row use of its secret.

The final joint-instantiation discussion now starts with an explicit scope cue:

> For the stated finite interface, Theorem … supplies a joint continuation through the actual confirmation, traffic and first-message schedule.

Both refinements were checked after integration. They improve precision; the underlying theorem statement and contribution remain unchanged. The discussion identifies the application profile and its next accepted-operation connection. No further wording issue, experiment, or proof gate is outstanding from this review.

## Reviewed snapshots

Hashes bind the files actually read; subsequent source edits require an ordinary diff review rather than inheriting this record automatically.

| Path | SHA256 |
| --- | --- |
| `q-periapt-paper/paper/continuity/main.tex` | `ded22e4ae5d6ad975d126c4b765cc2a1071b81604ce805463b1ef7d22778d69c` |
| `q-periapt-paper/paper/continuity/introduction.tex` | `4a864ece80c272d353f3efe4183c6cc929c681efb43f45f0b953138e053f3586` |
| `q-periapt-paper/paper/continuity/discussion.tex` | `31760c00fe5bda9f1c68351ab182032ec4661135846520f81353667afa39d172` |
| `work/joc_round4/theory/joint_continuation.md` | `6958aaf8c9f7a917f04e166e18198d2447262637f4438c3073e5508bcb8ff8d3` |

Only this review file was created for the task. No manuscript source was edited.
