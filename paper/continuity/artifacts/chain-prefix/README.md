# Online selected message in a finite chain

This packet supports Section 5's finite-chain continuation. A message
can be selected online before its first private computation, after
earlier message keys have been disclosed. The selected successor seed
may then be disclosed while the target key stays behind its one-use
AEAD interface.

The proof has the original three joint-root/traffic comparisons and
two comparisons per potentially protected chain position. Each
Extract hop is followed by a row hop and an exact HKDF block-table
rewrite. That rewrite removes the successor seed's raw occurrence
inside its parent row and permits the next comparison. Selection uses
available history and does not require guessing the eventual index.

- `../../chain-prefix-continuation.tex` contains the theorem, proof and
  confidentiality/integrity corollary.
- `proof.md` records the complete hybrid construction, timing,
  alias handling, source correspondence and counterexamples.
- `source_identity.json` and `sources/` retain three exact native files
  at the original source pin and the inspected integration checkpoint.
- `check_prefix.py` performs exact finite ideal-distribution controls,
  first-computation/retry controls, source checks and an actual
  HMAC/HKDF prefix-seed recovery counterexample.
- `checks.json` records the executed checks. They validate the stated
  finite interface and source equations; the compression-oracle result
  is established by the mathematical proof.

From the repository root:

```sh
sh artifact/python-run.sh paper/continuity/artifacts/chain-prefix/check_prefix.py
```

The historical native next-rekey result and all 49 matched/28 retry
executions retain their sources and outcomes. This packet adds a
finite-chain mathematical continuation and its validation controls.
