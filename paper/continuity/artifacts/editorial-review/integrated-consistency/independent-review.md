# Independent review of the integrated bootstrap clarification

## Conclusion

The integrated manuscript precisely identifies the native bootstrap salt and its three KDF information strings. The change preserves all 57 formal statement blocks and all 168 displayed formula blocks from baseline `c7581ebc21f5d080d90840c13b52c793bcac9317`. Of 52 proof blocks, 51 remain byte-identical; the remaining proof changes one explanatory sentence identifying the salt as the 32-byte Reply-core digest.

The comparison covers the 40 modular TeX sources. Thirty-eight complete modules remain byte-identical. The two edited modules are `bootstrap-authentication.tex` and `bootstrap-initial-source.tex`. The generated `joc-submission.tex` contains the same integrated definitions and proof sentence and is counted separately to avoid duplicating the manuscript's statements and proofs. All 40 module label sequences are preserved.

## Exact formal-content preservation

| Content | Baseline | Integrated | Byte-identical | Changed |
| --- | ---: | ---: | ---: | ---: |
| Formal statement blocks: theorem, lemma, proposition, corollary, definition, remark | 57 | 57 | 57 | 0 |
| Displayed formula blocks: 60 equation/align environments and 108 bracket displays | 168 | 168 | 168 | 0 |
| Proof blocks | 52 | 52 | 51 | 1 |
| Complete modular source files | 40 | 40 | 38 | 2 |

`source-preservation.json` gives each module's baseline and integrated byte length and SHA-256, each formal/proof/display block's two hashes and locations, and the preserved label-sequence result. The unchanged displayed equations retain their hypotheses, residuals, and probability coefficients. The introductory paragraph adds the four inline equalities defining `t_1`, `I_s`, `I_R`, and `I_I`.

## The single proof change

The changed proof belongs to `lem:bootstrap-initial-origin` in `bootstrap-initial-source.tex`.

Baseline sentence:

```tex
actual $S_1$ and uses the Reply core as its salt, giving
```

Integrated sentence:

```tex
actual $S_1$ and uses the 32-byte Reply-core digest $t_1$ as its salt, giving
```

Substituting precisely that sentence in the baseline proof produces the complete integrated proof byte-for-byte. The proof's remaining text and displayed expressions are preserved.

## Native source correspondence

The archived `bootstrap.rs` and `crypto.rs` under `artifacts/bootstrap/initial/source/research/continuity-identity-candidate/src/` were inspected directly and remain identical to their baseline blobs.

- `response_prefix` and `response_body` build the Reply prefix and append its ciphertext. `response_body` computes the framed `reply-core` hash, calls `schedule` with that digest, and subsequently appends the responder confirmation tag. The outer signature is produced after this body is formed.
- `finish_initiator` reconstructs the same digest from exactly `body[..REPLY_CORE]`. This confirms the integrated definition's core boundary at both endpoints.
- `schedule` takes the digest as a 32-byte value; `derive` accepts `salt: &[u8; 32]` and passes it to HKDF Extract. The integrated `t_1` definition consequently supplies the salt type used by the compression-level entry equations.
- `derive` concatenates the 48-byte bootstrap KDF domain with the labels `handshake-seed`, `confirmation-responder`, and `confirmation-initiator`. Their complete information lengths are 62, 70, and 70 bytes; the corresponding one-block Expand messages remain 63, 71, and 71 bytes.
- `crypto.rs::digest_start` frames the domain and payload with their big-endian 64-bit lengths before SHA3-256. The integrated reference to the distinct framed source domain preserves this computation.

The integrated text therefore closes the specific byte-identity ambiguity recorded by the baseline consistency review. The existing joint-entry and bootstrap conclusions retain their formal statements and costs.

## Recalculation

The preserved comparison requires the baseline Git object and the integrated module bytes identified in `source-preservation.json`. Run:

```sh
python paper/continuity/artifacts/editorial-review/integrated-consistency/record_source_preservation.py --check
```

The check recomputes the historical-versus-integrated hashes, block comparisons, labels, exact proof substitution, and source correspondence input identities. It reads the saved report and receipt without rewriting them. `focused-checks.json`, `verification.json`, and the baseline audit receipts are preserved.
