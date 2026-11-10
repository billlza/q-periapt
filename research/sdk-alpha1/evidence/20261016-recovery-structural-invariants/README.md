# Multi-epoch structural invariants

Source: `6c13c486e9aa3a1ac852f2127fc4cbb30c5e63d5`.
Pinned Tamarin 1.12.0 and Maude 3.5.1 on Apple Silicon macOS.
Two additional properties have complete proofs and independent certificate replays:

| Property | Checked steps | Prior reusable premises |
| --- | ---: | --- |
| Produced send-state role is `A` or `B`; epoch is `zero` or `succ(previous)` | 191 | None |
| A Ready root is at epoch zero or has outer constructor `h` | 8 | None |

These are structural facts. They establish neither role authentication nor root
entropy, agreement or secrecy. Generation-secret origin, both original two-round
witnesses and multi-epoch message secrecy remain unproved. The model still has
unbounded alternating rounds, inherited roots, shared session/context and the
same identity, entropy and retained-record disclosures.

The role/epoch replay checks its 191-step proof together with the complete
35-step produced-counter and 17-step application-counter proofs. The latter
depends on the produced-counter property; the other properties have no earlier
reusable premises. This joint replay completes in 192.70 seconds. A later
four-property replay reaches its 900-second bound and is rejected. The root
property is first in that certificate and has no prior premise, so a separate
replay retains its exact statement and proof body plus the complete operational
theory, omitting only later proof obligations. It verifies in 146.42 seconds.
The timeout is retained and is not relabelled as success.

Composition checks compare the complete parsed statements and operational model
across both independent certificates. The dependency graph is acyclic and fully
discharged: root, role/epoch and produced-counter proofs are independent;
application-counter uses the checked produced-counter proof. There are no global
source lemmas. Every original complete query is retained in the integrated model,
and the bare model introduces no reusable assumptions. No protocol rule, equation,
disclosure, observation or restriction changes in this checkpoint.

The root search uses a logged goal-ordering function. Every recorded ranking is a
complete permutation of its input; the independent replay uses neither that
function nor proof search. Raw sources, certificates, terminal outputs, source
comparisons and process-closure checks are retained. The preparation record for
step 108 has a misleading prior-inventory label: its input has seven queries and
its output eight. The explicit parsed comparisons check those inventories; the
integrated model and final context have nine complete queries.

Three 600-second searches remain unsuccessful: generation origin with the two
counter premises, signing-key origin with those premises, and generation origin
with all four separately certified structural premises. None returns a terminal
security verdict. The last input contains conditional helper declarations and
cannot qualify a theorem merely from an isolated target-success line. Its
external helper proof identities are recorded, but the target itself remains
unproved. These failures are included in the capture.

The integrated source passes the `sdk-020` source gate from a clean standalone
checkout. SDK runtime code and private device cohorts are unchanged. This research
model remains outside the three single-exchange CI profiles. Hosted qualification,
computational security, SDK correspondence and full release readiness remain open.

`CAPTURE.zip` contains 130 members and expands to 3,290,332 bytes. Its SHA-256 is
`92c625266a22a6d62595c7b46ec37a69a739db322283123251752b3c695a1087`.
Every member was read back and rehashed; `CAPTURE.json` records its identity.
The earlier [counter checkpoint](../20261016-recovery-counter-invariants/README.md)
retains the actual negative control that rejects a conditional target proof when
its helper proof is missing. Reproduction requires the recorded pinned tools and
source revision.
