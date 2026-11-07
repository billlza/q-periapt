# Original-operation KEM challenge adapter: source and game boundary

The [manual reduction](../../../../docs/continuity/KEM_CHALLENGE_ADAPTER_V1.md)
defines a fixed-pair virtual private-record game and an adapter to its specified
component IND-CCA experiment. It handles challenge-ciphertext repeats without
forbidden oracle requests, preserves nonchallenge decapsulation and implicit
rejection, and charges one correctness event for the selected challenge pair.
The observation is an unconditioned `Eligible AND D_output` event, not a
distribution obtained by conditioning away hard eligible traces.

The virtual record interface is explicit. This is not a completed native
accepted-prefix simulation: unknown target coins cannot be fabricated in a
recoverable token, and inability to simulate an eligible disclosure cannot be
reported as a product error or success. Complete acquisition/record refinement,
adaptive target accounting and the actual shared-oracle primitive assumptions
remain open. MAIN and its original corruption conditions are unchanged.

At source `baa4e975a2502cbb2a33e1e18dd19b37be663abe`, the source audit records
the original offer/response reservation and replay paths. In particular, the
response body/root/signing reservation is persisted before signing, and the
ready wire before release. The accepting proposer verifies the signature and
retained-offer prefix before key reconstruction/decapsulation, then compares
the reconstructed public key with the offer. Exact cached responses/finals and
`FinalReady`'s earlier send cutover remain separate paths.

`SOURCE_AUDIT.json` records source hashes and exact locations for these checks,
the private purpose enum, the response signing site and cutover helper uses.
It is a source/encoding inventory, not a proof checker or a compiler analysis.
The reduction is justified by the written coupling argument and its stated
interfaces; no new KEM, native test, Tamarin execution or external review is
claimed. Existing alias and shared-journal experiments retain their own source
and execution scopes.

`CAPTURE.zip` contains the audit procedure/output, selected pinned sources,
exact retained MAIN formula/hash and the linked proof/review documents.
`FILES.json` and `SHA256.json` record complete member/volume readback. No private
state, keys or operation tokens are included. This capsule does not freeze a
review/release candidate or establish whole-protocol security.
