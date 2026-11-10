# Main-result entry and online selection boundaries

Base manuscript: `c0eac5469fe184338b0eb343ee46ab23736caa6b`.

This pass makes the central experiment and result directly accessible in the
introduction and at the beginning of the computational development. The native
online selected-message theorem supplies the main result. The new overview
identifies its next-rekey setting, original-source eligibility, permissible
earlier-key and successor observations, and its confidentiality and integrity
conclusions. The following technical-contribution paragraphs explain how the
private-state and primitive comparisons establish that result.

The computational opening gives a compact table of the four allocation and
selection boundaries. The existing proof-dependency table and bit-versus-score
accounting remain in place. Repeated route descriptions and detailed validation
summaries are shortened. The two edited modules add 129 whitespace-delimited
words in total. Document pagination is determined by the integrated build.

## Correspondence of the overview to the formal statement

| Overview statement | Retained establishing interface or result |
| --- | --- |
| One established session's next rekey, one authoritative history per endpoint and passive copies | The single-root source profile in `contextbound-connection.tex` and the online native controller in `native-chain-composition.tex` |
| Known predecessor root and wrapping keys | The same concrete source profile and `def:recovery-game` |
| Both original KEM reservations after the eventual cut | The two strict event inequalities in `eq:eligibility`; replay preserves the original reservation event |
| Target signing secret keys and designated target-epoch entropy remain undisclosed | The identity and entropy conjuncts of `eq:eligibility`, evaluated over the complete execution; public identity labels and verification keys remain public |
| Every acquired target-session version was first saved at or before the cut | The negated-existence conjunct of `eq:eligibility`, using acquired versions `C_T` across every role and epoch of the target session |
| Earlier message keys may influence online selection | The Continue/Mark controller in `native-chain-composition.tex` and the finite prefix interface in `chain-prefix-continuation.tex` |
| Mark precedes the step's first private computation at either endpoint | The shared `(material, direction, index)` ledger in `lem:native-online-chain-correspondence`, including receiver skips, failed authentication and failed writes |
| The marked step's paired successor is available after derivation and the suffix is real | The named successor projection and prefix interface; a complete version containing that seed still retains its separate acquisition scope |
| The terminal selector identifies the same accepted challenge send | The original one-challenge condition and adaptive selector in `security-model.tex`, retained by the online controller |
| Unconditional eligible-message advantage and fresh authenticated-installation event | `eq:native-online-confidentiality` and `eq:native-online-integrity`, including an installation recorded before the eventual accepted send |
| Executed-slot attribution has an ordinary hedged-signature instantiation | The last paragraph of `thm:native-online-message`, `prop:executed-source-attribution` and `thm:native-mldsa-reservation-bridge` |

The table records boundaries at which values must be designated. A candidate
pair is an index of a local reduction; the terminal selector in the native
experiment may still select its source pair and recovery cut adaptively. The
table therefore does not turn the native game into a fixed-target experiment.
The effective tuple, traffic entry and marked step retain their respective
first-allocation boundaries across aliases. The overview retains the finite
interfaces and primitive assumptions of the full theorem.

The integrity event is an eligible fresh authenticated receive and inbox
installation under the marked step. The overview uses the theorem's event
bound, without replacing it by a conditional probability given eligibility.
The one-key AEAD convention allowing decryption before the honest encryption
remains in the unchanged full statement.

## Preservation and scope

`source-preservation.json` compares all 40 canonical root-level TeX modules
with the exact base commit. All 57 statement/definition/remark environments,
52 proof environments and 168 displayed-math groups are byte-identical. The
38 modules outside the two edited exposition modules are entirely identical.
All references used in the edited modules resolve to canonical source labels.

No execution artifact, primitive bound, source pin, formal model, proof,
historical review or bibliography entry is changed by this pass. The 49 matched
executions and 28 retry executions retain their existing evidence. The
descriptions of their measured service and exposure results retain the same
scope. This record is the editing pass's source correspondence; independent
semantic review and the final document build have their own records.
