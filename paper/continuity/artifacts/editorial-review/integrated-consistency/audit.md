# Integrated consistency audit: original sources to recovery and bootstrap

## Result and scope

The integrated original-source, disclosure, and whole-execution accounting is consistent across the main online recovery result and the two bootstrap source connections at canonical commit `c7581ebc21f5d080d90840c13b52c793bcac9317`. This audit checked the dependencies of Theorem 5.28 (`thm:native-online-message`), Theorems 5.38–5.39 (`thm:bootstrap-source-schedule`, `thm:bootstrap-terminal`), and Theorem 5.42/Corollary 5.43 (`thm:bootstrap-initial-schedule`, `cor:bootstrap-initial-terminal`). The source labels are authoritative; the numbers are those in the existing canonical build.

One source-to-formula clarification is recommended: explicitly define the bootstrap salt `t_1` as the **32-byte framed SHA3-256 digest** of the Reply core, and give the three bootstrap information strings. The current phrase “Reply core” leaves the byte string and its digest insufficiently distinguished. The pinned implementation uses the digest, which satisfies the 32-byte salt interface used by the compression-level proof. A deterministic byte witness below demonstrates the difference between the two readings. The proposed edit preserves all hypotheses, theorem statements, and probability coefficients.

The audit completed the following substantive checks:

- original sampling slots, first private computations, immutable versions, and executed-slot attribution;
- effective ContextBound tuples, root descriptors, traffic material handles, and original chain indices;
- complete acquisitions, named projections, signer disclosure, bootstrap recipe closure, and endpoint-specific raw-capture residuals;
- signed-score versus event-bit costs, the ordinary KEM and signature bridges, the online prefix sum, and both bootstrap localization sums;
- the pinned bootstrap source's salt bytes, HKDF information lengths, activation/chain/ACK row lengths, and Initial-nonce accounting.

The manual review uses the baseline sources listed below. `source-manifest.json` records SHA-256 identities of every top-level TeX module and the selected archived implementation inputs, together with their label locations. The TeX inventory, bytes, and labels come directly from the fixed baseline Git object. Its inventory serves source identification; this report specifies the actual review scope. `focused-checks.json` records the newly executed, independent Python byte calculations. Existing native test and artifact receipts retain their original execution provenance.

## 1. Identity is preserved at each change of abstraction

| Object | Identity used in the proof | Connection verified |
| --- | --- | --- |
| Generation/encapsulation reservation | Original independent sampling event, complete binding, and `res(o)` | `def:reservation-origin` in `security-model.tex`; `lem:executed-slot-stability` in `source-attribution.tex` |
| Durable payload version | Immutable payload identity and first `save(v)` | `eq:origin-causality`, `def:record-acquisition`; copies and enclosing objects retain the original version |
| Selected KEM source pair | Original `(g,a)`, with the selected key and encapsulation installed at their first actual private computations | `contextbound-connection.tex`, “The original-operation component adapter”; `lem:cb-native-root-use` |
| ContextBound answer | Complete effective nine-field remainder together with the hidden PQ component | `lem:cb-hidden-component`; exact effective aliases share a table entry even when origin labels differ |
| Root-entry answer | Effective salt-pad class `Gamma(r)` and complete root information string | `thm:multiple-root-entry`, `lem:entry-information-length`; the single native recovery root uses its retained 97-byte information string |
| Traffic material | One root schedule and its complete traffic information string | `thm:joint-message-leaf`, `lem:native-online-chain-correspondence` |
| Chain step | Complete material handle, direction, and original index `(M,d,i)` | `eq:prefix-chain`, `lem:native-online-chain-correspondence`; matching endpoint aliases share a result, independent materials retain separate histories |
| Bootstrap class | Complete admitted `(ctx, Initial, Reply)` including signature bytes | `def:bootstrap-online`, `lem:bootstrap-deferred`; same-body signature aliases retain their upstream family and their actual full-wire downstream descriptors |
| Initial-source long family | `(actual S_1, alpha(t_1), beta(t_1))`, ranked at first long request | `lem:bootstrap-initial-origin`, `lem:bootstrap-initial-allocation`; failed verification and persistence still allocate the original rank |

### Reservation time and computation time have different jobs

The cut test uses the original draw time. Embedding a challenger at the first private computation preserves that time through an opaque reservation handle. This is sound on the specified stopped interface because the unopened tape has no earlier value-dependent observation. The source and record comparisons establish that interface before the unknown component tape is embedded. Both bootstrap profiles use the same ordering.

A failed first retention can leave a sampled but unused reservation. A later successful operation then has a different origin. `live-core-instantiation.tex` gives exactly this trace with `g_1` and `g_2`; the general metadata selector retains its attribution residual. The executed-slot selector registers `g_2` when it is actually computed and receives the proved signature/hash attribution bound. The integration does not silently identify these selectors.

The authoritative pending plan is retained before the first KEM or message-encryption computation. Once computation has occurred, later failures recover that plan, its result, or the committed state. Thus original results can be cached before their durable outcome. This supports both the single original KEM challenge and the single original encryption tuple required by Theorem 5.28.

### Receiver-first computation is represented correctly

The proof ledger counts a receive-side chain advance, including a skipped index followed by authentication failure, as the index's first private computation. Retrying from the earlier persisted native counter retrieves the already allocated proof result. A taken skipped key creates no new marking opportunity. The complete material handle prevents equal numeric epoch/index pairs from merging unrelated schedules.

The AEAD interface in `native-chain-composition.tex` explicitly permits classical decryption before the at-most-one encryption call. The integrity flag is latched at the fresh installation, even if the target send occurs later. The proof's Boolean localization retains that history; later honest encryption does not retroactively remove the witness.

## 2. Disclosure interfaces match the reductions

### Acquisition and eligibility

`def:record-acquisition` separates acquisition of complete bytes from readability after wrapping-key disclosure. The recovery predicate `eq:eligibility` uses acquired versions, including versions inside containers and versions for any phase or epoch of the selected session.

For a fixed occurred candidate reservation `o`, a target-session version retaining that source has `res(o) <= save(v)`. Every eligible final cut satisfies `c < res(o)`. Its acquisition therefore implies `c < save(v)` and permanently falsifies the candidate's final eligible conjunction, even when the cut is chosen later. This is the certificate in `lem:adaptive-origin-stop`; it supports the pre-return local stop used by `lem:native-online-chain-correspondence`.

Equivalently, if `L_s` is the greatest original save time of any acquired target-session version, the temporal part of eligibility is `L_s <= c < min(res(g),res(a))`. The comparison is an unconditional eligible score/event calculation. It does not divide by the probability of eligibility or condition the primitive experiment on the selected candidate.

### Named projections and complete records

| Observation | Treatment in the integrated statement |
| --- | --- |
| Earlier unmarked message key | Supplied by the independent step representation after Continue; its bytes may influence the later mark |
| Marked step's successor seed | Supplied after that pair is derived, then used for the real suffix |
| Opposite traffic direction, other complete traffic entries, declared successor-root observations | Retained as the complete ordinary continuation in the joint/prefix comparisons |
| Current protected root, prefix seed, PRK, or marked message key | Used through its declared primitive/opaque interface |
| Complete post-cut target-session record | Invokes the original acquisition eligibility certificate, including when it contains an otherwise available named successor |
| Source signing secret key or signer-file return | Uses the target-key/family stopping rule of the signature bridge; public identity labels retain their public role |
| Additional report/dependency projection | Uses the separately declared report interface and its selected-candidate residual |

These interfaces give `B_j = empty` for the stated live core. The report extension retains `eta_proj` and its own comparison costs in `thm:report-reverse-composition` and `cor:report-exposure-residual`. The main theorem's last paragraph preserves that extension without counting an undeclared report observation as a free live-core response.

### Bootstrap closure and raw acquisitions

The online bootstrap recipe rule retains cumulative source openings, acquired versions, and wrapping-key disclosures. Deletion does not erase the observer's history. Opening the surviving source before registration excludes every descendant whose later public/available ingredients complete the ACK recipe. Opening an individual Initial-source long parent excludes that parent's descendants; other long families retain their ordinary interfaces. After registration, a recipe-return request stops before the return and preserves an already latched terminal event.

The record comparison has a separate, precisely placed capture term. `eq:bootstrap-capture` and `eq:bootstrap-initial-capture` measure marked **raw acquisition** in each adjacent endpoint's own history. The Initial-source union covers all later opaque families before the long-allocation partition, so its capture cost is charged once per pair and endpoint. Guarded readability determines recipes; the conservative raw mark determines where unknown-byte rendering requires the stated residual. These uses remain consistent through root and activation comparisons.

Registration is before the first private ACK computation or use. In the pinned source, activation derives the ACK key, so this is the first activation boundary. The pending root exists earlier and may be retained across recovery. `lem:bootstrap-deferred` consequently samples an unobserved independent root-table entry at first exposure/activation without changing its original descriptor or the preceding available history.

## 3. Whole-execution budgets and coefficients close

### Main result, Theorem 5.28

The original-game partition is performed once in `lem:native-local-score`/`prop:native-local-accounting`. Every later comparison reruns the same available terminal code in its own world. The source-attribution residual remains measured in the original native game.

| Comparison | Confidentiality signed-score cost | Integrity event-bit cost |
| --- | --- | --- |
| Original attribution failure | `eta_attr` before the candidate sum | `eta_attr` before the candidate sum |
| Record rendering/commitments | `2 epsilon_rec,j` | `epsilon_rec,j` |
| Selected KEM component and correctness | `a_j^+ + a_j^- + 2 delta_j` | `a_j^msg + delta_j` |
| Complete ContextBound table | `2 Phi_256(d_j,Q_H,j)` | `Phi_256(d_j,Q_H,j)` |
| Single root entry | `2 Delta_init,j` | `Delta_init,j` |
| Traffic and online chain | `2 Delta_prefix,j(L)` | `Delta_prefix,j(L)` |
| Selected-key primitive | `2 epsilon_AEAD,j` | `epsilon_INT,j` |

The main confidentiality expression divides the resulting centered-score bound by two and clips at `1/2`. The integrity expression clips an event probability at one. The per-candidate `B_j^chain` and `Omega_j^chain` clips are valid because the respective signed score magnitude and event probability are each at most one. The corresponding equations are `eq:native-chain-continuation`, `eq:native-chain-integrity-cost`, `eq:native-online-confidentiality`, and `eq:native-online-integrity`.

`eq:prefix-error` uses fixed index comparisons through at most `L` steps. It adds one column and one two-call row comparison per possible index. The predecessor's decision to continue is known when its successor seed is allocated, and the current mark is chosen before its pair is generated. This allows the reduction to install the hidden seed/AEAD key without guessing the eventual index. The displayed sum is the index-dependent cost; all ordinary budgets also cover known earlier keys, real suffix computation, verification, failed attempts, aliases, preparation, and the terminal test. For `L=1`, the expression reduces to the existing first-message schedule cost.

### Ordinary component instantiations

`prop:kem-deferred-challenge` gives one `zeta_pre(q^-)` cost for each Boolean operational KEM test. Its withheld challenge is unused during the real decapsulation prefix; conditional on the static public oracles and key, the selected original message is uniform and independent of that prefix. The collision bound counts a fixed prefix's at most `q^-` recovered-message values. Both challenge branches have the same pre-release hit probability, which justifies the single event cost in the probability-gap convention. Thus the main score's two tests receive two such substitutions, while each integrity/bootstrap endpoint test receives one. The source-pair indices and the message-index sum are preserved.

`thm:native-mldsa-reservation-bridge` preserves family lineage, the complete `(randomizer, public representative)` cache, and the original-message ledger at first signing computation. A family ledger is contained in the native actual-key ledger, giving the required direction of the fresh-message implication. Independent owners with coincident public components retain their generation/disclosure distribution. Both shared-XOF comparison budgets include other-owner work and the final verification. The executed-slot attribution proof uses that complete signing experiment after the online chain interface is added.

### Bootstrap endpoints and family multiplicities

For each adjacent ACK pair, absent-registration terms cancel before fixed-source localization. The two endpoints retain separate association and capture probabilities. The reply-source schedule charges one complete upstream-and-tail comparison for each `(r,j,b)` with `j in [G] x [A]` and `b in {0,1}`. Its uniform form therefore has the existing `2 R G A` factor plus `2 R alpha + sum_r eta_cap,r`.

For the Initial-surviving profile, `eq:bootstrap-initial-upstream` first compares the **entire** hidden-first service: the SDK short entry and every adaptive long entry for the fixed original source. Only the resulting independent long-table value is localized by first-allocation rank in `lem:bootstrap-initial-allocation`. Hence `eq:bootstrap-initial-uniform` has `2 R G A (E^I + L T^I)`: the long-family bound multiplies the downstream parent tail. The source, record, KEM, ContextBound, and joint-entry costs in `E^I` already cover all long requests and are charged once at that level.

The bootstrap entry theorem retains the shared raw input when a hidden-first long call uses the known half equal to the short padding block. Its class key contains both that half and the effective inner salt state; the complete long descriptor also retains the outer state. The middle replacements distinguish the short outer block from the padding block by their encoded bit lengths (768 and 1024). The per-allocation maxima `A_i` remain valid even when the one short call occupies different ranks in different worlds.

Both historical-activation statements then add the complete-class collision probability, their own schedule comparison, the final registered-key MAC-row comparison, and the existing verification term `q_v / (2^256-q_v+1)`. The MAC comparison uses the actual 107-byte authenticated input. Its marked-record cost is evaluated in that final schedule endpoint. Honest responder activation releases the relevant tag; an accepted exact replay therefore has the corresponding earlier activation. The latched event remains defined when later disclosure triggers the global stop.

### Concrete byte budgets

The new independent source-backed calculation confirms these existing row lengths:

| Native input | Length in bytes |
| --- | --- |
| Bootstrap `I_s, I_R, I_I` | 62, 70, 70 |
| Their single-block Expand messages | 63, 71, 71 |
| Bootstrap root `I_B` | 93 |
| Activation `I_A` | 111 |
| Activation row messages | 112, 144, 144, 144, 144 |
| Chain row messages | 57, 89 |
| Epoch-zero ACK authenticated string | 107 |

The reply-source nonce term `binom(G,2) 2^-256` also has the correct original-slot bound. In the archived `bootstrap/staged.rs`, `InitiationPlan::reserve` performs `reserve_key` and then exactly one fresh Initial-nonce draw. Decoding restores that nonce. Thus the number of fresh Initial nonces is at most the reply-key reservation bound `G`, including reservations whose later retention fails. The Initial-source profile independently uses its explicit nonce-slot bound `N`.

## 4. Source-to-formula clarification: Reply-core digest

### Baseline text and exact native behavior

`bootstrap-authentication.tex`, the paragraph immediately before `eq:bootstrap-schedule`, introduces `t_1` as “the Reply core.” `bootstrap-initial-source.tex`, the proof of `lem:bootstrap-initial-origin`, says that the Reply core supplies the salt. The joint-entry compression equations use the pad maps `I(a), O(a)` defined for 32-byte salts in `joint-primitive-bounds.tex`.

The archived native source is explicit:

- `artifacts/bootstrap/initial/source/research/continuity-identity-candidate/src/bootstrap.rs`, `response_body` (around lines 960–969), appends the ciphertext, computes `hash(b"reply-core", &body)`, passes that **digest** to `schedule`, and only then appends the responder confirmation tag.
- The same file's `finish_initiator` (around lines 1022–1029) hashes exactly `body[..REPLY_CORE]` before reconstructing the schedule.
- Its `derive` function (around lines 885–894) takes `salt: &[u8; 32]`, and its three calls append the labels `handshake-seed`, `confirmation-responder`, and `confirmation-initiator` to the 48-byte bootstrap KDF domain.
- `crypto.rs::digest`/`digest_start` (around lines 202–224) use SHA3-256 with the big-endian 64-bit domain length and payload length framing. The Reply-core wire contains 104 prefix bytes and 1120 ciphertext bytes, for 1224 bytes before confirmation and signature.

### Deterministic consequence of the two readings

`focused_checks.py` constructs a synthetic correctly sized core and two fixed 32-byte contribution values. It computes the actual framed SHA3-256 digest and the HMAC Extract under that 32-byte digest. It also computes HMAC Extract using the 1224-byte core directly as the salt. These PRKs differ; `focused-checks.json` retains the exact values and input digest.

The long raw-core reading would invoke HMAC's long-key normalization and therefore would not instantiate the displayed 32-byte pad maps. The source's digest reading supplies exactly the stated primitive interface. The fixture demonstrates this encoding distinction and is not presented as a protocol attack or a valid KEM execution.

### Exact proposed source edits

`proposed-clarifications.patch` changes only two explanatory passages:

1. Before `eq:bootstrap-schedule`, define `y_core` as the Reply prefix and ciphertext ending before confirmation and signature, define `t_1 = H_reply-core(y_core)` as 256 bits under the framed source hash, and set the three complete information strings using the native labels.
2. In the proof of `lem:bootstrap-initial-origin`, refer to the 32-byte Reply-core digest `t_1` as the salt.

The patch leaves every displayed theorem, hypothesis, residual, and cost coefficient unchanged. It connects the intended native operation to the existing joint-entry interface directly. This audit package records the reviewed baseline and the exact proposed source changes.

## 5. Evidence and reproducibility

The audit's source baseline is fixed at the commit above. Reproduction requires that Git commit and its blobs to remain available, together with the archived implementation inputs and source-pin files at their recorded paths. The checker obtains the historical TeX inventory with `git ls-tree` and its bytes and labels with `git show`. It verifies the ten archived workspace inputs against the baseline before using them. The checkout's current HEAD and edited manuscript may advance independently of this historical review.

Run the calculation and its optimized-mode negative control from the repository directory with:

```sh
python paper/continuity/artifacts/editorial-review/integrated-consistency/run_audit_checks.py
```

The focused checker records 51 historical source identities, checks the native source ordering, recomputes the exact row lengths and the salt-interpretation witness, and writes its receipt within this audit directory. It requires enabled Python assertions and rejects optimized interpreter configurations (`-O`, `-OO`, or a nonzero `PYTHONOPTIMIZE`) with exit code 2 before reading inputs or writing a successful receipt. The verification runner executes the ordinary calculation and an explicit `-O` negative control, verifies that the latter preserves the successful receipts, and records both commands, the exact interpreter/runtime, UTC execution times, elapsed nanoseconds, exit codes, and stdout/stderr log hashes in `verification.json`. The archived source trees retain their original `SOURCE_PINS.json` files; this audit records their hashes and does not replace those pins.

Completed mathematical review references are: `security-model.tex`; `candidate-local-accounting.tex`; `opaque-rendering.tex`; `primitive-inputs.tex`; `report-composition.tex`; `native-correspondence.tex`; `contextbound-connection.tex`; `kem-ordinary-bridge.tex`; `joint-continuation.tex`; `joint-primitive-bounds.tex`; `multiple-root-entry.tex`; `sdk-purpose-connection.tex`; `live-core-instantiation.tex`; `source-attribution.tex`; `reservation-signature-bridge.tex`; `native-authentication.tex`; `chain-prefix-continuation.tex`; `native-chain-composition.tex`; `bootstrap-entry.tex`; `bootstrap-authentication.tex`; and `bootstrap-initial-source.tex`.

Within this scope, the original-slot counts, alias semantics, disclosure stops, and integrated probability sums are supported by their stated source and proof interfaces. The recommended digest definition is the concrete correction identified by this read-through. The fixed baseline and source manifest preserve the review's scope through later manuscript revisions.
