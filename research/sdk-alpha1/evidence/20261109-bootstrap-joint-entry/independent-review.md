# Independent review of the joint bootstrap entry comparison

## Disposition

The two primitive entry comparisons and their conditional three-label tail
composition are accepted under the available-controller interface stated in
`docs/continuity/BOOTSTRAP_JOINT_ENTRY_V1.md`. The reviewed source snapshot is
`b1cff2a045d23aecf75aef12122e5080a8419676`. This review binds the final document,
updated assessment, checker, source pins and result bytes in
`independent-review.json`.

The completed result covers the hidden-first short/long service and the
hidden-second long service. Its effective descriptors preserve retries and
pad-state aliases. The assessment accurately retains original-contribution
and disclosure attribution, followed by terminal full-class reconciliation,
as the remaining source integration.

## Mathematical checks

1. **Actual encodings.** The bootstrap source concatenates two 32-byte
   contributions into one 64-byte IKM, then recomputes the same Extract for
   its three labels. The initial SDK Extract uses the inspected 27-byte salt.
   Its zero extension to 32 bytes leaves HMAC's key-pad blocks unchanged.
   Both message-length encodings include the already consumed 64-byte pad.

2. **First replacement.** For fixed `(known_half,state)`, the hidden-first
   and hidden-second raw encodings each have at most one preimage of any full
   compression input. Distinct effective queries remain distinct for every
   secret. The hidden-first short call and a long call with known half `P`
   share the same raw class when their inner states agree.

3. **Joint descendants.** The mappings `(short,b) -> (z||P,b)` and
   `pad -> (Q,z)` are injective in the secret. Their block ranges are disjoint
   because the fixed final length fields encode 768 and 1024 respectively.
   This separation holds for every value of the secret, including equality
   with a chosen chaining state. One application therefore produces the short
   and padding tables jointly.

4. **Long outer replacement.** After the parent padding table has been
   replaced, each pad value has only the declared long-outer interface. A
   challenge handle can be assigned at its fixed allocation slot before its
   first child use. Distinct outer states give distinct encoded inputs for
   every challenge. Never-allocated slots yield identical games.

5. **Shared-oracle collisions and adaptation.** Other real table entries
   remain known to their reduction and are evaluated with the same public
   compression oracle. Numerical coincidences therefore retain their real
   correlations in each real interface. No equality test on an unavailable
   challenge value, collision-free conditioning or eventual-target guess is
   used. Each reduction includes preparation and the full continuation.

6. **Query accounting.** Global call bounds are separate from per-slot
   worst-case bounds. The sole distinct SDK short query can occupy different
   slots across executions. Simulator caches use available interface
   descriptors, so their implementation requires no comparison of hidden
   bytes. Distinct descriptors that coincide numerically may each incur a
   public call; both fit within the displayed upper bound.

7. **Tail interface.** The composition explicitly installs each fresh long
   PRK in an opaque three-label wrapper with no raw-PRK disclosure. Its
   original protection marks, alias relations and real unprotected
   activations are retained. The resulting conditional composition has the
   declared finite sum of entry and tail costs.

The primary external theorem was inspected in Don, Fehr and Huang,
*Adaptive Versus Static Multi-oracle Algorithms, and Quantum Security of a
Split-key PRF*, [Theorem 2 and its hypotheses, pp. 9–10](https://arxiv.org/pdf/2206.08132).
The three applications meet its point-entropy and every-secret freshness
conditions with cached repeats. Its bound already handles adaptive classical
private queries and quantum public queries; no additional conversion factor
is inserted.

## Corrections incorporated during review

The initial draft conflated the global one-short-query bound with the sum of
fixed per-slot worst-case bounds. The revised statement separates them, and
the ordering controls now include short calls after earlier long calls. The
query-budget paragraph now states the available cache keys explicitly. The
tail's opaque three-label restriction and the distinction between symbolic
handle identity and equality of independently sampled bytes are also explicit.

## Independent execution

The checker was executed separately and its complete output is byte-identical
to the retained `RESULT.json`. All seven source Git blobs were independently
matched to the fetched remote tree, in addition to the checker's length and
SHA-256 verification. The retained controls reproduce:

- 32 short and 32 long compression equations against the standard-library
  HMAC implementation;
- 8,192 raw points and 1,280 tagged points on the declared finite domains;
- 720 ordering cases, including all six insertion positions of the SDK short
  call among the five long calls;
- one global distinct short query with possible raw slots 0, 1 and 2, whose
  separate observed slot maxima sum to three;
- the two padding faults and four cache-identity counterexamples.

These controls verify the specified encodings, aliases and accounting cases.
The full-width computational claim rests on the mathematical reductions
reviewed above.
