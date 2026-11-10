# Deferred challenge: independent internal mathematical review

Reviewed 10 November 2026. Module SHA-256:
`871a4a3a0a8744f0288a5a9c8adee47dd8738d0c341f333a8ed465d7fafd025f`.
The draft argument was read separately from its author check, against the
existing operational adapter and the ordinary challenger interface. This is
an internal argument review, distinct from journal peer review.

## Result

The proposition is valid under its stated common-static-oracle model and
classical component-call interface. It supplies the claimed ordinary IND-CCA
instantiation without changing the existing native experiment.

## Checked reasoning

1. **Executable ordinary adversary.** The reduction receives the public key,
   challenge ciphertext and real-or-uniform key up front. It initially gives
   its controller only the public key. It compares each classical selected-key
   request to the retained ciphertext before forwarding; equality stops with
   output zero and never makes a forbidden ordinary-oracle call. Its later
   release and exclusion rules match the operational experiment.

2. **The full real prefix.** The independence argument uses the hypothetical
   full real decapsulation process, including queries after earlier potential
   intersections. It does not condition that process on previous misses.
   Fixing the public functions and key-generation coins leaves the unused
   uniformly sampled 32-byte encapsulation message independent of this prefix.
   An adaptive challenge request, or the absence of a request, is part of the
   same process.

3. **Quantum public queries.** For fixed functions, every operation on the
   adversary's conditional density operator in that prefix is independent of
   the unused message. Computing a private challenge earlier neither changes
   these functions nor acts on the adversary's register. The reduction measures
   no public quantum query and performs no oracle reprogramming.

4. **Message recovery and the set bound.** Deterministic K-PKE decryption maps
   each length-admitted queried ciphertext to one 32-byte message. If the
   honestly generated challenge recovers its message, an intersection places
   that uniformly sampled message among at most `q_pre` possible values.
   Malformed queries cannot equal the generated challenge. Repeated queries
   cannot enlarge the set. The honest message-recovery failure event is charged
   separately, giving `min(1, q_pre / 2^256 + delta_mr)`.

5. **One Boolean coefficient.** Both key-bit experiments share the same
   prechallenge process and intersection probability `p`. Stopping removes
   output-one masses `gamma_0` and `gamma_1` lying in `[0,p]`; their difference
   has absolute value at most `p`. This establishes one intersection term per
   Boolean advantage. Each existing `a_j^+` and `a_j^-` test receives one term;
   direct signed scores retain the manuscript's existing factor of two.

6. **Correctness terms.** `delta_mr` concerns the K-PKE plaintext, whereas the
   existing adapters' correctness terms concern the final KEM shared key.
   These events are not silently equated. The proposition makes no numerical
   claim about `delta_mr`.

7. **Native correspondence.** Opaque retained slots, original generation and
   encapsulation identities, exact replay caches, source-association failure
   and candidate-local record stops remain the existing operational adapter's
   responsibilities. The bridge grants no selected-tape reveal oracle and
   introduces no additional source or message-index guess. Other local owners
   and their numerical public-key coincidences stay inside the controller.
   Bootstrap consistency monitors and the complete ContextBound raw-use
   conditions retain their existing role.

8. **Resources.** One ciphertext equality check per classical component
   request is the only additional operation. The whole original preparation
   and continuation remain counted. No additional decapsulation or public
   oracle queries are introduced.

## Primary algorithm checks

The official [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
was inspected directly on 10 November 2026. Algorithm 15 (printed page 31)
is deterministic K-PKE decryption with a 32-byte result. Algorithm 17 (printed
page 33) derives the coins and encrypts its 32-byte input with K-PKE.
Algorithm 20 (printed page 37) samples that input uniformly before calling the
internal encapsulation. These properties support the set bound. The proof
continues to use the common public-oracle model declared by the manuscript.
