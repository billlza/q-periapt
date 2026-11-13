# Restoring independently inspectable proof fragments

`artifact/continuity_proof_fragments.py` is a proof-editing utility, not a theorem
checker. It transfers only closed replacements for exact open case paths from a
same-theory diagnostic output into a hash-bound complete original certificate.
All unrelated subtrees and other lemma proofs remain byte-for-byte unchanged.
It rejects changed rules or query contracts, missing or duplicate paths, overlaps,
replacement of closed material, and open or annotated invalid fragments.

A diagnosis may leave supporting lemmas as `by sorry` to inspect one proof context.
Never use that diagnostic as an accepted certificate: all original supporting
proofs must be restored, and the complete result must be replayed independently.
The editing report always says `security_proof_verified: false` and
`release_claim_eligible: false`. Successful editing is not proof validation.

Example, with independently verified inputs and a fresh output path:

```sh
sh artifact/python-run.sh artifact/continuity_proof_fragments.py \
  --original /absolute/original.spthy \
  --original-sha256 ORIGINAL_SHA256 \
  --candidate /absolute/diagnostic.spthy \
  --lemma epoch_generation_secret_derivation_origin_with_phase_roots \
  --output /absolute/restored.spthy
```

Then replay the complete restored file using the repository-pinned Tamarin and
Maude, without `--prove` or an oracle, and retain the full terminal inventory.
A zero prover exit alone is insufficient. An incomplete selected theorem remains
incomplete; verified helper statements do not substitute for the main secrecy
statement. Do not replace the frozen research capture or its pins merely because
a fragment has closed. A new reviewed capture must preserve source/model/query
identity and all unsuccessful runs.
