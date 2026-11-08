# Q-Periapt JoC research state

## Current direction

The manuscript is **Exposure and Recovery with Persistent Randomness Reservations**, targeting Journal of Cryptology. Its continuous branch is `paper/joc-persistent-recovery`, with [draft PR #119](https://github.com/billlza/q-periapt/pull/119) against `main`. Continue this same PR for manuscript and directly used proof/evidence updates. [WORKFLOW.md](WORKFLOW.md) records the build and update procedure.

The confirmed author is **Ziang Li (李子昂)**, Department of Engineering, Durham University. Correspondence: **2403871950@qq.com**. Alternative contact: **bhmq03@durham.ac.uk**. The current author list contains one person.

## Joint schedule and retained source profile

The prior origin-normalization, guarded record-exposure, private-image simulation, reverse-report composition and candidate-local accounting results remain in place. The preceding computation increment established:

1. **Lemma 5.9:** an exact HKDF block-table representation for adaptive complete information strings. Applied before the selected-seed Extract hop, it removes the parent row's internal input containing that seed.
2. **Theorem 5.10:** a joint shared-compression-oracle continuation from a uniform epoch root to the first message key of a designated fresh traffic allocation. Its finite M budget retains full-info aliases, zero-salt/session-salt aliases, real confirmation/ACK verification and successor-root/next-seed disclosure.
3. **Corollary 5.11 and the recovered-contribution entry:** the one-message AEAD reduction and the actual root Extract/Expand comparison, with their explicit score factors and complete query budgets.

The target material and direction are marked before that new material produces any blocks. Repeated complete information strings keep the same material identity. The network interface uses plaintext-free Resume; the honest application owns plaintext-bearing Send and delivery. The source profile records the same-ID guess-Send counterexample for an enlarged public caller interface. Existing eligibility and original-game projection accounting are preserved.

The full frozen proof and its 22-point cross-check are in [the joint-continuation artifact](../artifacts/joint-continuation/README.md). The [live profile](../artifacts/live-profile/source_profile.md) and source map bind actual constructors and observations to the declared experiment. Twenty-four inspected files are byte-identical at source pin `228c944fc476e3e57d6c08063cacb19bca5b360e` and development checkpoint `1c68aa666db22d36ee136be1ec712545a9e74f03`.

## Accepted operation to recovered contribution

The accepted-operation-to-uniform-contribution connection is now complete for the next rekey of an established authoritative session and its marked first-message interface:

1. **Lemma 5.12** applies the cited adaptive hidden-input theorem to the complete ten-field LP8 ContextBound encoding, with bit gap `Phi_256(d_j,Q_H,j)`. Exact repetitions are cached by the effective tuple, including the other shared secret. Origin metadata and hash-table identity remain distinct.
2. The **operational component adapter** installs the ML-KEM-768 public key at the original generation and creates its one challenge at the original encapsulation's first actual computation. It preserves prechallenge answers; afterwards the selected PQ ciphertext is intercepted regardless of traditional ciphertext/context. X25519 and its failures remain actual native computations. The stated component advantages refer to this two-stage experiment; no unproved conversion to a different game is assumed.
3. **Lemma 5.13** proves that the original target tuple uses one old-root/complete-root-info pair. The induction applies online to every supported continuation of the matching immutable binding, including failed, crashed and ultimately unaccepted executions, independently of future eligibility. The target is allocated at its earliest private computation through any alias.
4. **Theorem 5.14** substitutes that comparison into the retained candidate-local bound. The random-component score obeys `|b_j| <= min(1, 2 Phi_256(d_j,Q_H,j) + 2 Delta_init,j + 2 Delta_sched,j + 2 epsilon_AEAD,j)`. Original-game attribution/projection residuals, local correspondence, actual component-event gaps and correctness costs retain their previous locations.

The [frozen proof and independent review](../artifacts/contextbound-connection/README.md) include the complete game chain, source induction, counterexamples and exact file hashes. The self-contained checker has 36 format/adapter cases. The separate source audit has 14 files and 12 static assertions at the unchanged native/development pins. These executable checks support concrete interfaces; the mathematical claim is supported by its proof and statement-by-statement review.

The two oracle interfaces are explicit: whole SHA3-256 for ContextBound and independent SHA-256 compression for HMAC/HKDF. Preparation, other native work, continuation and terminal tests are all counted. The operational profile retains private honest application data and plaintext-free public resumption. Raw X25519 is not assumed to be a uniform-256-bit KEM challenge.

## Finite multiple-root entry

**Theorem 5.15** proves the finite entry service from one hidden uniform contribution to several adaptive root descriptors. The cryptographic identity is the full pair `(Gamma(r), I)`, with `Gamma(r)` the two public HMAC pad states and `I` the complete root information. Its table is shared across callers, aliases and resumptions; source provenance remains in the separate origin ledger.

One hidden-contribution column comparison and a sequence of adaptive class-row comparisons produce a private table of independent roots. The finite bounds distinguish available salt strings `D`, pad-state classes `C` and complete information entries `N_i`. The ordinary-query budgets are `q_S = B + 2D + 5 sum_i N_i` and `q_i = B + 2D + 5 sum_(k>i) N_k`, with the complete surrounding execution in `B`.

A mark selects a descriptor before its first root evaluation. It may select a new information entry in a class that already produced other roots. All aliases of that target share the retained schedule handle. Unmarked roots are available to the controller and may become later salts. **Corollary 5.16** composes this entry with the retained first-message theorem, giving `min(1, 2 Delta_mr + 2 Delta_sched + 2 epsilon_AEAD)`. The ContextBound comparison supplies the preceding `2 Phi_256` term for a candidate whose stopped execution realizes this controller.

The [multiple-root artifact](../artifacts/multiple-root-entry/README.md) contains the integrated theorem, a complete constructive proof, a worked controller and a 25-point independent review. It distinguishes PRK allocation from target-root allocation and preserves numerical key coincidences through the shared oracle. This completes the finite multiple-root mathematical extension proposed after the next-rekey result.

## Owned SDK purpose-key correspondence

The concrete broader workload is now the SDK's `SharedSecret::derive_key` interface. A length-parameterized form of the finite entry comparison covers its exact information strings, including the suite, ContextBound profile, authenticated policy state, trust-root digest, purpose, protocol label, context and output size. The fixed 27-byte salt has the same HMAC padded key block as its 32-byte zero-extended representation.

Complete information strings index one shared key table. Each accepted derivation creates a separate `DerivedKey` owner, so repeated descriptors preserve key bytes while close and export operations follow their own guards. Source closure, runtime closure and exported copies keep the source's actual lifecycle behavior. The proof uses a finite lifetime descriptor budget; Rust in-flight admission and FFI handle capacity retain their distinct operational meanings.

The entry comparison permits all derived keys to be exported and establishes their joint pseudorandom separation while the parent contribution and Extract value remain within the KDF interface. The existing five-purpose dual-peer workload has five descriptors, 144-byte information strings and 145-byte row messages. Its conservative ordinary-query budgets are `B + 32` for the hidden-contribution column and `B + 2` for the hidden-PRK row. At full SDK limits the row length is 65,899 bytes and the compression length parameter is 1,031.

A separate one-key application experiment marks a fresh descriptor before its first private evaluation and routes every target alias through one controlled AEAD interface. Its qualified score bound is `min(1, 2 Delta_sdk + 2 epsilon_AEAD)`. The complete-tuple ContextBound term composes when the stopped contribution family realizes the stated controller. The durable rekey driver retains its established 97-byte root-information profile.

The [SDK correspondence artifact](../artifacts/sdk-purpose-connection/README.md) contains the full proof, native source map, independent review and retained Rust test outcomes. The completed current-source CI already passed the five relevant native tests; the manuscript update performs a separate source and mathematical review.

## Focused continuation

The finite entry theorem now has two concrete uses: the established next-rekey continuation and the owned SDK purpose-key table. A useful next extension is a declared application that uses several purpose outputs together, such as directional traffic keys and confirmation keys. Its experiment must specify the actual confirmation transcript, verification responses, nonce policy and plaintext interface. The key-table comparison supplies the joint uniform-key entry; the remaining work is that application's authentication and message composition. This is an additional research result with its own interface and proof obligations.

## SkyBridge allocation

[skybridge-scope.md](skybridge-scope.md) reads the real SkyBridge original and later manuscripts. The JoC appendix now states their connection through authenticated transcript handling, operation admission and recovery release. SkyBridge's migration contract, forward-secrecy analysis, platform realization and migration experiments remain a coherent independent research line. The ContextBound substrate is from the earlier Q-Periapt binding manuscript and is identified separately.

## Validation identity

`integration_record.json` is the current local verification snapshot. It binds the PDF, single-file source, proof modules and source profile. The manuscript and exported source are compiled for each integrated update. New mathematical reviews and build checks have separate receipts; executable finite-model checks retain their exact execution identity. Historical native, formal-model and reference-corpus evidence keeps its recorded source and execution dates. Remote workflow outcomes are attached to the dedicated PR's actual head commit.

The manuscript uses one title and stable deliverable filenames. Git commits and artifact hashes identify its updates. [The layout decision](../format/layout_decision.md) records the official JoC instructions and an inspected single-column published example. Connected arguments organize the text; precise interface conditions remain in definitions and theorem hypotheses.
