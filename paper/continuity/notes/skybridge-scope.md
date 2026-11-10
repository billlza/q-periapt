# SkyBridge Compass material and the scope of the Continuity manuscript

Reviewed 7 November 2026.

## Editorial decision

Preserve SkyBridge Compass as a distinct research line, and retain a short account of its connection to the present paper. Its policy-governed authenticated establishment, complete-transcript handling and recovery-release boundary provide useful application context. The present paper develops original-reservation provenance, record acquisition, and computational simulations of private records and dependent reports.

The current three contributions remain the organizing structure. The ContextBound definition and its source pointers belong in the construction; an optional paragraph in the artifact appendix can explain the connection to SkyBridge. The full SkyBridge migration contract, handshake analysis, concurrency mechanisms and evaluation remain with their own manuscript and evidence.

These are two different bodies of earlier material:

- The earlier [Q-Periapt manuscript](https://github.com/billlza/q-periapt/blob/228c944fc476e3e57d6c08063cacb19bca5b360e/paper/q-periapt.tex), *Proof-to-Byte: Assumption-Minimal, Cross-Substrate Binding Assurance for PQ/T Hybrid KEMs*, concerns ContextBound binding, field separation and implementation assurance. Its relation to Continuity is the cryptographic substrate and its concrete encoding.
- The [SkyBridge Compass manuscript](https://github.com/billlza/Skybridge-Compass/blob/d49d2a9ed4e1fb00905adeb06c02989562e375af/Docs/TDSC-2026-01-0318_IEEE_Paper_SkyBridge_Compass_patched.tex), *SkyBridge Compass: A Crypto-Agile P2P Handshake Framework for Remote Desktop and File Transfer with Auditable Downgrade Policy and Post-Quantum Readiness*, concerns authenticated establishment and a crypto-agile migration contract.

The historical TDSC submission is treated as an unpublished project manuscript, not as a prior journal publication. A public source archive supplies provenance; it does not change that publication status.

## Versions actually examined

The [submission README](https://github.com/billlza/Skybridge-Compass/blob/d49d2a9ed4e1fb00905adeb06c02989562e375af/Docs/README_SUBMISSION_TDSC-2026-01-0318.md) identifies `tdsc-2026-01-0318` and commit `805c83a85d2279c3913745fdbabf4157ed3e332c`. The later repository snapshot examined here is `d49d2a9ed4e1fb00905adeb06c02989562e375af`.

| Snapshot | Material examined | Relevant content |
| --- | --- | --- |
| [Original submission source, `805c83a…`](https://github.com/billlza/Skybridge-Compass/blob/805c83a85d2279c3913745fdbabf4157ed3e332c/Docs/TDSC-2026-01-0318_IEEE_Paper_SkyBridge_Compass_patched.tex) | Abstract, introduction, five contributions and security-model wording | Suite/provider/policy separation; controlled fallback and audit events; transcript and signature binding; concurrency and fault handling; reproducible measurements. The security section presents invariants, proof sketches and a minimal symbolic model. |
| [Later main manuscript, `d49d2a…`](https://github.com/billlza/Skybridge-Compass/blob/d49d2a9ed4e1fb00905adeb06c02989562e375af/Docs/TDSC-2026-01-0318_IEEE_Paper_SkyBridge_Compass_patched.tex) | Abstract and contributions; D1–D4; security properties; simultaneous-open arbitration; transcript/KDF handling; attempt-state rules; migration-threat evaluation | Three contributions: the auditable migration contract, a portable reference implementation and reproducible benchmarks. The paper also presents the v1/v2 forward-secrecy distinction. |
| [Later supplementary manuscript](https://github.com/billlza/Skybridge-Compass/blob/d49d2a9ed4e1fb00905adeb06c02989562e375af/Docs/TDSC-2026-01-0318_supplementary.tex) | Regression properties and Formal-to-Code Traceability table | Implementation-facing mappings and additional evaluation context, including the version issue identified below. |
| [Model](https://github.com/billlza/Skybridge-Compass/blob/d49d2a9ed4e1fb00905adeb06c02989562e375af/formal/skybridge_v2.spthy), [model README](https://github.com/billlza/Skybridge-Compass/blob/d49d2a9ed4e1fb00905adeb06c02989562e375af/formal/README.md) and [retained summary](https://github.com/billlza/Skybridge-Compass/blob/d49d2a9ed4e1fb00905adeb06c02989562e375af/formal/tamarin-report/skybridge_v2_summary.txt) at `d49d2a…` | Named lemmas, relevant conditions and the existing execution summary | The summary lists **13 verified lemmas**. This review inspected the files; it did **not rerun Tamarin**. |

The original submission and the later saved manuscript are different revisions. The later model's 13-result summary is attributed to that later evidence, rather than retroactively to the original submission. The summary includes execution witnesses, negotiation integrity, signature origin and injective agreement, secrecy, v2 forward secrecy, and policy-governed classic establishment.

In the examined `ForwardSecrecy_v2` lemma, the matching initiator/responder session is explicit, the trace contains no ephemeral-secret reveal, and relevant signing-key reveals before the initiator's commit are excluded; later long-term reveals are allowed. This is a forward-secrecy statement about the established root. Continuity's recovery condition instead follows the original reservations and acquired record versions associated with a selected future operation.

## What to retain, and why

| SkyBridge material | Connection to this paper | Placement |
| --- | --- | --- |
| Complete-wire transcript binding and authenticated peer identity | MessageB binds MessageA. Simultaneous-open arbitration verifies the signature and canonical peer bindings before superseding an attempt. Unknown TLVs retain their original bytes in the transcript. These mechanisms illustrate the precise identity and observation questions relevant to accepted-operation attribution and complete-prefix caches. | Brief source/application context. The current proof uses Continuity's own offer/response interface and source correspondence. |
| D2: local-only, pre-send fallback and explicit failure classes | The migration contract assigns different transitions to local capability failures, timeouts and verification failures. This supports faithful treatment of actual error and retry semantics in a simulation. | A short explanation where interface semantics matter; retain the full migration-policy analysis in SkyBridge. |
| D4: control-only bootstrap followed by PQC rekey before business traffic | The design separates temporary recovery authority from application-data release. It motivates the additional question of which original randomness the completed rekey consumes and which records an adversary acquired. | An application-motivation sentence or appendix paragraph. Describe D4 as the stated design contract, with the version qualification below. |
| D3: structured audit events and a session-local hash chain | The event schema identifies public observations of the policy decision. It is a different concrete object from the private-state MAC transcripts handled by the current dependent-report theorem. | Mention only the observation interface used by an application. Retain the complete audit design and measurements in the SkyBridge manuscript. |
| v2 ephemeral contribution and the retained forward-secrecy analysis | The v1/v2 distinction has its own cryptographic object and compromise conditions. It complements the later question of how saved randomness affects recovery. | Preserve the result in the separate handshake research line; use precise background wording if referenced. |
| `finishOnce`, single-flight arbitration and local secret ownership | `finishOnce` resolves timeout/message-arrival races over an asynchronous continuation. Continuity's persistent machine addresses resumption of an original operation after process loss. | Preserve the concurrency and implementation results in their original setting. Map an operation explicitly if it is later included in the persistent interface. |
| Migration-threat and performance evaluation | FDR/SDR measure downgrade outcomes; ECR/PCR measure evidence completeness and decision replayability. These experiments address different dependent variables from source identity, joint readability and reconstructible message sets. | Keep the measurements and their snapshot identities with SkyBridge. Fault interventions can inform a future experiment that states a matching research question. |

This division preserves the technical content of the earlier work while keeping the present argument focused. It also keeps ContextBound's static binding properties distinct from original-operation provenance: a field-binding property constrains relations among values, whereas the record model tracks a particular draw and the versions retaining it, including independent draws whose public outputs happen to coincide.

## Specific supplementary-table version issue

The later supplementary manuscript's **Formal-to-Code Traceability** table lists these six labels:

- `TimeoutCannotTriggerClassicFallback`
- `FallbackRateLimitEnforced`
- `DowngradeEventRequiredWithContext`
- `BootstrapControlOnlyUntilPQCRekey`
- `ConcurrentOpenSingleFlight`
- `AuthenticatedSupersedeBinding`

They are not lemma names in the examined `skybridge_v2.spthy` or its retained 13-result summary. The actual names include `NoSilentClassicFallback_Default`, `ClassicRequiresDowngradeOrClassicPolicy` and `ForwardSecrecy_v2`, with their own event predicates and conditions. The table therefore needs a version-aware mapping before it is used to attribute additional mechanized results. In this manuscript, D4 supplies design context; the current record and report theorems use their separately stated interfaces. This editorial decision does not depend on revising or rerunning the SkyBridge artifact.

## Application to the current manuscript

The relevant current modules are the [construction](../construction.tex), [reservation and acquisition model](../security-model.tex), [private-record simulator](../opaque-rendering.tex), [report composition](../report-composition.tex), and [candidate-local accounting](../candidate-local-accounting.tex). Their theorem statements and evidence identities remain their own.

The [artifact appendix](../artifact-map.tex) is the appropriate location for a short project-lineage paragraph and fixed source link. The current three contributions, ContextBound construction paragraph and source pointers remain intact. No new SkyBridge chapter, historical benchmark table or additional baseline requirement follows from this scope decision.

## Source identity record

Retrieved bytes were checked against the corresponding Git blob identities. The table below binds the principal sources used by this note. Numerical benchmark outputs were not rerun or revalidated in this review.

| File and revision | Bytes | Git blob SHA |
| --- | ---: | --- |
| Original main TeX at `805c83a…` | 96,627 | `41a990b634dc97d2d06f33af69dcc621bd2b4b05` |
| Later main TeX at `d49d2a…` | 122,627 | `6f1659c1e75680d422cfdea8b2322e6daa6366ba` |
| Later supplementary TeX at `d49d2a…` | 72,572 | `2391317f81556ba72974ac1e77196c8532291f72` |
| `formal/skybridge_v2.spthy` at `d49d2a…` | 25,844 | `85cba3402be55b30e62b6bb0d3c4f6f3f67387d3` |
| `formal/tamarin-report/skybridge_v2_summary.txt` at `d49d2a…` | 995 | `46155ef36912ebe1610af865d29671b42de0cfd4` |

The historical paper files retain their original author metadata. Author metadata for the current Continuity manuscript is maintained separately in its own source and `author-metadata.json`.
