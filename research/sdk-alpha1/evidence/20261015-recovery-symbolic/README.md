# Recovery symbolic research checkpoint

Exactly one lemma is accepted: `generation_secret_origin` in the captured
protected-state projection. Tamarin 1.12.0 / Maude 3.5.1 reports **verified,
182 steps**, using induction with the default smart heuristic and no depth bound.
The command exits zero in 42.74 seconds. The four other queries in that invocation
are explicitly **analysis incomplete**, because they were not selected; they are
not counted as proofs.

The [research model and scope](../../../continuity-recovery-symbolic/README.md)
separate generated-key provenance from complete recovery secrecy. The verified
necessary condition identifies generation-entropy leakage or capture of a
phase-1/2/3 record as modeled routes to knowing the honest generated key. It is
not a causal time bound, a maximum exposure bound, or a proof of secrecy after
one or more rekeys.

The model retains all ten plan phases, old-root disclosure, state capture before
or after wrapping-key exposure, later storage access, explicit entropy/identity
leakage and the signer-file/wrapping-key relationship. Ideal protected-state
confidentiality is a declared abstraction. The explicit nested-encryption
alternative is retained without an accepted proof. Independently initialized
session instances do not model several sessions sharing one device journal or
identity. Concrete hybrid/KDF/signature security, exposed ML-DSA coins,
per-message state, policy/lifecycle and implementation refinement remain open.

The original existential counterexample queries could use an extra later
snapshot. Their corrected versions permit exactly one Snapshot at the named cut
and exclude unrelated identity/entropy leakage. No result was accepted from the
looser queries. Later body fields were corrected to hash prior wires as the Rust
prefix constructors do. Equality actions implement signature/confirmation checks;
`no_precomp` annotations and oracle rankings alter search strategy, not the
required rule premises.

Unsuccessful attempts are retained: the initial system Tamarin 1.10.0/Maude 2.7.1
prototype was superseded after signer-file review; later bounded searches timed
out, and one exhausted its 2 GiB heap. Pinned-tool searches also timed out, so
these results do not establish an old-tool defect. The custom ranking's
induction attempt timed out; the same theory and resource bounds with the default
smart ranking produced the accepted 182-step lemma. This is a proof-search
observation, not a controlled performance benchmark. The first shortest-term
heuristic generator had a Python indentation error before writing its output;
the corrected standalone heuristic and its failed proof attempt are retained.

Official arm64 Tamarin and Maude archives were downloaded, checked against exact
release-asset digests, extracted inside the task directory and executed. The
repository's fixed version/health contract passes. Archive URLs, sizes, digests,
architecture, dynamic dependencies and command receipts are included. The global
installation is untouched and no Intel Mac target is added. These compiler/tool
checks do not imply a proof result.

`CAPTURE.zip` has 131 members and SHA-256 `7085520edd9baddd27722cd7df066d1ef94ccf637bbc8a91ba7b36af1fcab231`.
Readback verifies every member digest, the exact accepted theory bytes and the
one-verified/four-incomplete summary. Its theory SHA-256 is `7802d0a937cd3f1afd75cb256c4cadc17b714f042f4894f4d471b3ea3d7bf902`.
Only public proof logs, source, recipes and tool metadata are selected; no SDK
private cohort is opened or exported. Stable drafts for follow-up searches may
be present as source, but active follow-up logs/results are excluded. The
separate all-lemma follow-up is not counted in this checkpoint.

Source base is `29c6b052701645065cfe93472d019e84db1f637b`; this adds research and
evidence only. No SDK production transition, wire or security gate changed.
Complete recovery proof, current-source hosted checks and the overall 0.2.0
release objective remain open.
