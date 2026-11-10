# Independent live-core review

**Verdict: PASS for integration.** The delivered corollary has the correct probability-to-score normalization, a precise interface for its zero projection residual, and a source-supported counterexample to eliminating the general attribution term using signatures alone. No blocking finding remains.

## Reviewed identity

- Manuscript base: `da521d8388f5f0c64697387bf80b0b5b7837fb34`.
- Source pin: `228c944fc476e3e57d6c08063cacb19bca5b360e`.
- Candidate comparison: `1c68aa666db22d36ee136be1ec712545a9e74f03`.
- Fragment SHA-256: `396c6f686ad53d045b1e6f5721693a6ffb9d7a0f56856a02d5b2fae9766a633e`.
- Seven inspected source files are byte-identical at the pin and candidate; exact hashes and immutable URLs are recorded in `independent_live_source_hashes.json`.

This review reads the mathematical interfaces and fixed source. It reports no new native execution or proof-assistant result.

## Established results

The existing real-record corollary gives a terminal-bit distance of at most `eps_rec` and a bounded signed-score distance of at most `2 eps_rec`. Substituting `rho_j <= 2 eps_rec,j` into `eq:cb-native-bound` therefore preserves the existing outside factor `1/2`. The general native attribution term, the two component event costs, their two delta terms, and the already established continuation bound all remain in the correct places. The candidate-local sum is preserved.

The record budgets cover all fresh seals, including a seal followed by commit failure. Distinct digest inputs and whole-computation oracle queries are deterministic bounds fixed before execution and valid in the corresponding comparison worlds. Exact copies and pending-target application reuse their original seal handle. Atom-free rows have zero private inputs. The nonce-collision term belongs specifically to the structural private-wire equality comparison, so setting it to zero when that operation is absent is consistent with `cor:real-to-opaque`.

The claim `eta_proj,nat = 0` now has an exhaustive interface. Plaintext-bearing Send and delivery belong to the private application. The network has exact Resume and the declared control, message, ACK, status and commitment interfaces. Full target-session acquisition after the cut triggers the original acquisition stop. The partial secret-field surface contains exactly the successor-root and next-chain projections with the established ownership and phase checks. Within those declared calls, every reply has the existing simulation. The separate report/cleanup extension retains its own projection accounting.

## Reservation-selector counterexample

The source reserves a key, installs a transaction-local `Plan::Key`, and attempts persistence before calling `generate_key` (`rekey.rs:363-374`). The revised example makes this first write fail before a complete pending target or image becomes durable. Reopening can then recover the prior authoritative image and allocate a new original reservation. A real accepted exchange can use `(g2,a2)` while the general selector names `(g1,a2)`.

This example respects the paper's separate ledgers: original draws include failed attempts; a complete durable object creates a Saved event; `ReservedFor` checks reservation-event metadata; `Attr` checks whether the named pair produced the accepted target. With the stated cut order and unexposed identities, target entropy and target acquisitions, eligibility can hold while attribution fails. No signature forgery or transcript-hash collision is required. The revised wording correctly excludes the different case where an unknown-outcome write already left a complete durable pending target.

## Source-resolved follow-up

Registering the first actual private generation/encapsulation before it returns gives a meaningful future interface for relating the accepted exchange to executed source slots. The fragment does not assert that this alone completes the signature reduction. This scope is correct: `SigningReservation` persists ML-DSA randomness together with its signer/operation/purpose/body binding (`crypto.rs:340-404`), and the later signing operation consumes those coins. A standard signing-oracle response does not by itself supply that retained-object representation.

The displayed theorem consequently retains `eta_attr,nat`. A dedicated source-association and signing-interface reduction is a separate research dependency; its absence does not invalidate the live-core substitution delivered here.

## Closed review requests

All three precision requests are incorporated: the failed reservation precedes complete durable persistence, the live-core interface is exhaustive, and resource bounds are fixed before execution across comparison worlds. The reviewed fragment is ready for integration with these conditions intact.
