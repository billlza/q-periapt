# Signing reservations and ordinary unforgeability

This supplement gives the complete generic reservation-to-ordinary reduction and its native ML-DSA-65 instantiation. The native theorem reaches **ordinary hedged ML-DSA EUF in the same shared random-XOF model**, including quantum public queries. Its two statistical comparisons jointly account for the key-generation seed expansion and the secret-key hedging slice.

For one selected family,

\[
p_{\rm res}^{H}(A)\le p_{\rm EUF}^{H}(B)
+\min\{1,\tbinom q2 2^{-256}\}
+\delta(q_*^{\rm res})+\delta(q_*^{\rm ord}),
\]

where `delta_ROM(v) = min(1,v/2^256)` and `delta_QROM(v) = min(1,2v/2^128)`. The ordinary signing-query cap is the number of distinct executed original-randomizer/descriptor pairs. The `q_*` budgets cover every call capable of addressing the hidden 34-byte seed input or 128-byte hedge slice in the relevant complete experiments. Fixed worst-case caps are used across the hybrids. The selected-family reduction supports adaptive owner creation and non-target key disclosures with the explicit factor `U`.

The ledger retains original messages and every private invocation, including a signature whose publication fails. Exact aliases and retries share the original operation. Different messages with the same descriptor are handled by the pair cache. Native full-pair freshness projects to the selected ML-DSA owner-index ledger without assuming distinct public keys or distinct components.

## Proof and review

- [Full proof](proof.md) gives the generic joint-PRF bridge, native ROM/QROM construction, actual-key/lineage relationship, query accounting, and native-pair corollary.
- [Manuscript module](proposed.tex) contains the reviewed theorem statements and compact proofs.
- [Independent review](generic_bridge_review.md) and [frozen review identities](independent_bridge_review_identity.json) record the accepted mathematical statements and the precise proof/module bytes.
- [Literature positioning](literature-positioning.md), [related-work paragraph](positioning.tex), and [bibliographic additions](references-additions.bib) connect the result to nonce-based cryptography and hedged Fiat–Shamir/ML-DSA work.
- [Integration replacements](integration_replacements.json) supplies three contribution passages and two consistency updates against the recorded integration checkpoint. The proposed abstract has 243 words under the manuscript's whitespace-count gate.

The proof uses the declared random-XOF and opaque-owner interface. The ordinary native EUF advantage retains the full computational resource requirements. The mathematical review is accompanied by finite classical controls and byte-level source correspondence.

## Self-contained reproduction

Python 3.10 or later and the standard library suffice. From this supplement's directory:

```sh
python check_bridge.py
python -O check_bridge.py
python review_generic_controls.py
python -O review_generic_controls.py
```

The default author checker reads the audited source copies in `sources/`. It verifies the fixed manifest digest, all 24 source/metadata/license file identities, the two lockfile pins, exact external-randomizer routing, native framing, and the XOF input-length inventory. It requires no repository checkout, package download, Rust build, or network access. Each command emits JSON and exits nonzero on a failed check.

For the finite controls alone:

```sh
python check_bridge.py --finite-only
python -O check_bridge.py --finite-only
```

To additionally compare an external native checkpoint and authenticate the original published crate archive:

```sh
python check_bridge.py \
  --repository /path/to/q-periapt-checkpoint \
  --crate-archive sources/fips204-0.4.6.crate
```

`--repository` expects the native source files and license files identified by `source_identity.json`; the paper-only branch does not need to contain the SDK. `--crate-archive` verifies the original archive checksum and compares every included upstream source/license byte with that archive. The archive is an optional extra for reproduction; the default hosted check uses the authenticated extracted source packet.

The author controls cover component/pair-ledger inclusion, failed publication with descriptor aliases, all target seed re-expansions and hedge retries, adaptive family selection, and disjoint hidden-support query mass. The independent controls additionally include explicit countermodels for per-slot caching, unrestricted foreign-key disclosure through ordinary signing oracles, and an incorrectly shared observable query cap. The receipts report finite/source checks rather than Rust execution or formal verification.

## Source identity and licensing

The native checkpoint is `358b921ab3469ce49f166633fc9a762ff6ed7e3d`. Both lockfiles pin `fips204 0.4.6` to the published archive checksum:

`c9fb5a367b9846933e271a3c2a992930743f82ae5e8cb7faa780715a80fa0b15`.

The authenticated package records upstream commit `8d456d989dce681233ef963d3c3306da8f76d7c7`. Exact source paths, SHA256 digests, Git blob identities and byte lengths are in [source_identity.json](source_identity.json). The upstream package's Apache/MIT license files and the applicable native source license files are retained beside the copied sources. These files are an audit snapshot; the supplement does not build or redistribute a modified cryptographic library.

The checked context literal has 42 bytes, giving a protocol descriptor input of `155 + body_length` bytes. The remaining target SHAKE256 input lengths are 66, 48, 832 and 1952 bytes. Matrix expansion uses SHAKE128. This source correspondence justifies excluding target rejection-loop calls from the sensitive-domain query budget while retaining their full computational cost.

## Receipts

[author_check_receipt.json](author_check_receipt.json) records the normal/optimized pairs for the self-contained audit, finite controls, and external-checkpoint/original-archive comparison. All three pairs are byte-identical. [independent_bridge_review_checks.json](independent_bridge_review_checks.json) records the independent control and source checks. The original outputs are retained alongside the receipts.

`artifact_manifest.json` inventories this supplement except the manifest itself. It includes the literature note and applicable source licenses. The proof/module identities in the independent review remain the acceptance record for the mathematical statements.
