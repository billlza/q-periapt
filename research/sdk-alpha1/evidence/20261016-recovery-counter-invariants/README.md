# Multi-epoch counter constructor invariants

Source: `1c9e66f30a257f0d0e0f81da0de0c18c05f9fb50`.
Pinned Tamarin 1.12.0 and Maude 3.5.1 on Apple Silicon macOS.
Two structural properties have complete proofs and independent, no-search
certificate replays:

| Property | Checked steps | Dependency |
| --- | ---: | --- |
| `produced_counter_has_public_constructor` | 35 | None |
| `application_counter_has_public_constructor` | 17 | The complete produced-counter proof |

Both properties establish the counter's outer form: `zero` or `succ(previous)`.
They do not prove counter uniqueness, nonce safety, message secrecy, computational
security or correspondence with the SDK. The generation-secret origin conjecture,
both original two-round witnesses and the multi-epoch secrecy obligation remain
unproved. The prior local-root inheritance result remains a separate checkpoint.

The model adds seven deterministic `CounterState` action facts, one for every
produced `SendState`, including both closing reservations that preserve an old
counter. The first observation census caught an omitted responder reservation;
the incomplete generator and correction are retained. Removing only these labels
recovers the original operational theory. Parsed comparisons retain all original
rules, restrictions and four complete queries, and compare all seven declarations
between the extended source and certificates. The original theory has the same
executions under this observation projection; no disclosure rule, protocol round
or attacker capability is restricted. Fact-precomputation and priority annotations
only change proof search.

The initial produced-counter proof uses 90 steps and independently replays. After
prioritizing the five counter-carrying `SendState` premises, the same property has
a 35-step proof, also independently replayed. The application-counter proof then
uses that verified invariant. The bare model has no reusable premise; the captured
joint certificate explicitly marks the produced-counter lemma reusable and retains
its entire proof. The final replay requires both properties, checks the complete
seven-query inventory and revalidates model and certificate identities.

A real negative control removes only the helper proof body. Tamarin exits zero
and still verifies the application property conditionally, but leaves the helper
incomplete. The acceptance check rejects the conjunction. Thus a successful target
line alone cannot qualify this result. Additional identity controls reject a
changed counter observation, changed original action and missing original security
query.

The capture retains earlier bounded failures: an idle two-round witness, two
generation-origin ranking experiments, and a direct application-counter search.
None yielded a security verdict. A partial proof and read-only loopback views
expose an unresolved branch with an impossible same-role peer premise; that local
observation is not a complete explanation of every failed search. The viewer was
stopped after inspection. The first custom ranking rejected a legitimate empty
oracle input; its failure and the correction against the pinned
[upstream contract](https://github.com/tamarin-prover/tamarin-prover/blob/82780bbaf3328a45f624ddb41e51bf75425f851c/lib/theory/src/Theory/Constraint/Solver/ProofMethod.hs#L605)
are retained. Every logged ranking is checked as a permutation of its full input.

The integrated model matches the qualified complete theory, and its clean standalone
source checkout passes the `sdk-020` source gate. No SDK runtime code or private
device cohort changed. This experimental model remains separate from the three
single-exchange CI profiles; hosted replay and full release qualification remain
open.

`CAPTURE.zip` contains 241 members and expands to 11,219,727 bytes. Its SHA-256 is
`57cc68a1272701e4e2f92cb69f81d21f6a3f9c26c8833692b5e7df92ba9dabf8`.
All members were read back and rehashed. `CAPTURE.json` records their identities;
the archive includes the models, complete certificates, terminal outputs, source
comparisons, explicit dependency check and actual rejection control. Reproduction
requires the recorded pinned tools and repository source.
