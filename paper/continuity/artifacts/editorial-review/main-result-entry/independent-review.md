# Final semantic review of the main-result entry

Date: 10 November 2026.

Review baseline: `c0eac5469fe184338b0eb343ee46ab23736caa6b`.

This is a separate final internal review of the integrated two-module diff,
following the editing pass and integration review. It checks the final exposition
against the retained formal experiment, controller and theorem. The review
does not re-prove the unchanged results or replace external peer review.

## Reviewed source identity

| Module | SHA-256 |
| --- | --- |
| `introduction.tex` | `18129e1d1a935a69ea34f6239e09b59fa01b3e209dd810f396220fe67cb432a1` |
| `computational-roadmap.tex` | `26533cacec6b94b4b6cf0b83778aa538e7ba0f690c2f6b42409524dd3464db76` |
| `security-model.tex` | `4d78ea142a89805869c76b7d8b47c1d2e5f9c410185f40e709c7c22b161e58b7` |
| `native-chain-composition.tex` | `e4fda73318c6f16a672f7efde4f0c3659587f23f1a082e20e52e5d149007c04e` |
| `chain-prefix-continuation.tex` | `56993018a53e571fd2afb930004333df393e96460484ec98e8d2de681d9f0f31` |
| `contextbound-connection.tex` | `4d437b36d9ccdaae04cb8b1326b350a4d5d185ac6eec818eb905a56bd046c235` |
| `source-attribution.tex` | `053ff691e18f6040aa38bd44b290c97e0c49fdb86fa2568329ccbc0f10d1831e` |
| `reservation-signature-bridge.tex` | `4df0820763a712cf3ee20c4bebbb97a6b7f477225c25e15c75131505cbe9402c` |

## Findings

The final overview agrees with the declared scope of
`thm:native-online-message`. Its setting remains the next rekey of an
established session with one authoritative history per endpoint and passive
copies. Known predecessor roots and wrapping keys, adversarial network and
recovery scheduling, earlier message-key observations, and the declared
successor projections retain their existing interfaces. The text explicitly
retains the theorem's finite interfaces and primitive assumptions.

The eligibility summary agrees with `eq:eligibility`. Both named original KEM
reservations follow the eventual cut. The target signing **secret keys** and
designated target-epoch entropy remain unexposed under the specified disclosure
interfaces; public identity labels and verification keys remain public. The
statement that every acquired target-session version was first saved at or
before the cut is equivalent to the original exclusion of an acquired
target-session version with a later save event. It concerns acquisition of
the original version across target-session roles and epochs, including
encrypted copies. It does not substitute a readability condition or the
creation time of a later physical copy.

The four-row selection table preserves the separation between local reduction
indices and native adaptive selection. The fixed candidate's original
encapsulation binding determines its effective tuple before the first private
ContextBound hash at any protected alias. The complete traffic entry and
direction are designated before block allocation. Continue/Mark precedes the
message step's first private computation at either endpoint, including
receive-side skipped steps and failed attempts. The terminal selector still
identifies the same accepted challenge send, its original reservation handles
and a recovery cut from the complete interaction. No row adds a retrospective
choice of an already computed message step or transfers the challenge bit to
another send.

The successor statement is also exact: the marked step's paired successor
seed is available after derivation, and subsequent chain computation is real.
Acquiring a complete version containing that seed remains a complete-record
acquisition with its original scope and save time. The roadmap retains private
application plaintexts and payload-bearing delivery, together with the
plaintext-free Resume interface available to the network.

The stated outcomes use the unconditional eligible-message advantage and the
joint eligible fresh-installation event of
`eq:native-online-confidentiality` and `eq:native-online-integrity`. They are
not converted to probabilities conditioned on eligibility. The fresh
authenticated-installation event remains recorded against the earlier honest
encryption ledger, including a receive before the eventual accepted send.
The unchanged full theorem retains its corresponding pre-encryption
decryption convention. The overview's executed-slot attribution statement
agrees with the source-attribution proposition and ordinary hedged ML-DSA
bridge.

The shortened descriptions of the 49 matched executions and 28 retry
executions retain their measured scope. They do not add a comparative security
or performance claim. The bootstrap and purpose-key paragraphs remain pointers
to their established instances. The original dependency table and the distinct
Boolean-event/signed-score costs are preserved.

No semantic mismatch was found in the reviewed final diff.

## Preservation and document evidence

An independent recomputation checked the base and current hashes for all 40
modules listed in `source-preservation.json`, then compared statement, proof
and displayed-math source blocks directly against the base commit. It found
57 statement/definition/remark environments, 52 proof environments and 168
displayed-math groups, all byte-identical. The 38 modules outside the two
edited exposition modules are wholly identical. There were no manifest/hash
mismatches.

The inspected build receipt reports a passed build with 119 pages, a 233-word
abstract, seven keywords and no failures. The separately produced
`source-export-check.json` reports an exact nine-file source inventory, a fresh
build, identical complete plain and layout text, 48 embedded fonts, and zero
unresolved references or overfull boxes. This review checked those receipts;
the visual inspection has its own record.

The source-preservation receipt inspected here has SHA-256
`3d87c8e2e5cdd838bcfbb8c0cdd6696c8dd5f0f0fc489a207ddd523cd05fa2a0`.
The source-export receipt has SHA-256
`988d2007edf236f2e8e20490427cadd52c188f7cf647cdafa791ce11a1095bba`.
