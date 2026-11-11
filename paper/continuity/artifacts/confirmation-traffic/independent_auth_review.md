# Independent confirmation and first-message authentication review

**Decision: PASS.** The finalized fragment and its bibliography support the stated joint authentication bound on the declared uniform-root, marked-first-message interface. There are no remaining blocking findings. The reviewed `confirmation-traffic.tex` has SHA-256 `a87f4b713a71e5def995ea93b9f602f0a7d8bb9cb3c5335270947c87ae17833e`.

The accompanying JSON records 20 checks, the exact hashes of all five manuscript inputs, and the hashes of three independently read native source files at `228c944fc476e3e57d6c08063cacb19bca5b360e`. This review performed no new code tests or runtime work and changed no manuscript file.

## Probability and oracle accounting

Applying the existing joint-schedule theorem to the union event gives one output-bit loss, `Delta_sched`. In its independent-key game, confirmation is bounded by three adaptive HMAC row replacements, a classical guessing term, and the full-core collision event. Message integrity is bounded separately in the same game using the real confirmation services and locally sampled other keys. The resulting union bound therefore pays neither a second schedule loss nor a second confirmation replacement loss.

The HMAC query accounting is valid. `T_d` counts distinct messages from both honest tag construction and expected-tag computation during verification; `V_d` counts all verification guesses, including repetitions. The fixed role order leaves only later rows real, so `q_d = B_c + 4 sum_{e>d} T_e` conservatively covers their compression work. The replaced row's own private computation is charged by the existing adaptive row lemma. Preparation, application work and final testing remain inside the complete budgets.

The private ideal row has a classical verification interface even though the public `H` and `h` oracles are quantum-accessible. The forced-rejection execution reveals no predicate of an unissued table value. Its adversary state and public replies match the real ideal-row execution until the first internal tag equality. Each candidate equality has unconditional probability `2^-256` in this comparison execution, so a union bound handles repeated guesses without incorrectly treating the real game's conditional success probabilities as constant. The final text explicitly stops before subsequent persistence or a public response; this also covers a matching tag followed by a failed write.

## Collision reference

I independently read the [published Rinton Press paper](https://www.rintonpress.com/xxqic15/qic-15-78/0557-0567.pdf), Theorem 7 on printed page 562. Its collision-finding statement uses a universal constant times `(q+2)^3/N`. The finalized fragment and bibliography cite that published version consistently. A fresh complete core sharing an issued same-role digest supplies two distinct, length-framed input strings, so this is a collision event. The query budget includes the entire derived experiment's ordinary and honest `H` queries and terminal testing. The independent public compression oracle and private tables are auxiliary operations in this collision algorithm.

## Origin and native receive boundaries

An honest tag origin is recorded at first private construction, before write or release; verification's internally computed expected tag creates no honest origin. Endpoint aliases and alternate signatures on an already logged core preserve the original core entry. This establishes the event required for the confirmation proof without treating a replay as a fresh forgery.

The one-time AEAD reduction also registers the original encryption at its first private computation and reuses that exact result for Resume. It supplies all selected-key decryptions to the explicitly declared integrity challenger. Successful authentication followed by a new inbox installation, absent an honest encryption origin, implies a successful new decryption pair. A later storage failure only narrows the native installation event and does not increase the reduction's required power.

I directly checked the pinned native `traffic.rs`, `messages.rs` and `delivery.rs`:

* `send_input` binds the reserved ID, plaintext and associated data, and a retained send returns its original wire. `resume_message` admits no replacement payload or fresh ID.
* `Traffic::receive` performs the selected AEAD check before inserting a new `Incoming` entry. `DeviceJournal::receive_message` persists a newly inserted entry before returning plaintext.
* The existing-inbox path returns the retained plaintext after its intent check; it creates no fresh authenticated entry. `PreviouslyConsumed` reports historical consumption, including a retired prefix whose old key and intent commitment are gone. It authenticates no replacement bytes.

One factual sentence was corrected during review: native `Incoming` stores the receive-intent digest and plaintext, not the ciphertext itself. The final fragment now says this precisely; the proof's ghost ledger retains the exact `(AAD,ciphertext)` identity. The event definition and inequality are unchanged.

## Composition scope

The previous confidentiality corollary keeps its private-application and plaintext-free Resume interface; confirmation operations remain part of its counted continuation. The new authentication proposition begins at `G_R`. Its final paragraph correctly reserves native record/component comparisons for the authentication event's own terminal bit and does not reuse the confidentiality theorem's `a_j^+` and `a_j^-` distinguishers. The stated one-key AEAD integrity quantity remains an operational assumption; the fragment does not manufacture a concrete quantum ChaCha20-Poly1305 integrity bound or a full native authentication theorem.
