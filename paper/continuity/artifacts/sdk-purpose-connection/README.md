# Native SDK purpose-key table

This artifact connects the finite entry-table proof to the pinned Rust SDK's existing `SharedSecret::derive_key` workflow. One protected contribution supports several complete purpose infos, with exact key-value aliases and independently live native owners. The length-parameterized proof preserves the established durable pending-root theorem and its 97-byte info.

## Results

- The 27-byte fixed SDK Extract salt has a pointwise equivalent 32-byte zero extension.
- The complete info has `107 + label_length + context_length` bytes; the permitted range is 108–65898, giving a maximum Expand-message length of 65899.
- The native five-purpose fixture has five effective descriptors, 144-byte infos, 145-byte Expand messages, and conservative ordinary-query budgets `B + 32` for the column comparison and `B + 2` for its row comparison.
- The owned-key correspondence preserves repeated derivations, separate source/derived owners, runtime closure, admission and the inspected FFI publication metadata.
- The table theorem supplies joint pseudorandom key separation and a visible-key collision bound. A fresh descriptor held by a trusted application supplies the conditional one-key AEAD consequence through the existing application experiment.

## Files

| File | Role |
|---|---|
| `sdk-purpose-connection.tex` | Independently includable manuscript subsection; depends on the retained primitive and finite-entry modules |
| `source_correspondence.md` | Full encoding, source induction, reductions, durable-source audit and counterexample repairs |
| `source_map.json` | Eighteen pinned source files, exact claim ranges, hashes and comparison-checkpoint byte parity |
| `check_native_root.py` | Standard-library source-binding, HMAC/framing and finite owner/controller checks |
| `validation_report.json` | Executed checker results, including each check's category |
| `native_test_receipt.json` | Identity and observations of the retained successful native Rust execution |
| `native_test_excerpt.log` | The five native purpose-test outcomes from that execution |
| `FREEZE.json` | SHA-256 binding for the final deliverables and evidence |

Source pin: `228c944fc476e3e57d6c08063cacb19bca5b360e`.
Comparison checkpoint: `1c68aa666db22d36ee136be1ec712545a9e74f03`.
All eighteen inspected files have identical bytes at those two commits and in the inspected worktree.

The retained native evidence is the successful job `128494629029` of run `42402999612`, executed on 2026-11-07. It contains five native Rust purpose tests. The new checker performs its separate source/algebra/controller checks. Source ranges and finite checks support inspection of the correspondence; the cryptographic conclusion is established by the stated primitive reductions.

## Reproduce the independent checks

With a checkout containing both retained commits, run:

```sh
python check_native_root.py --source-root /path/to/q-periapt --output-dir /path/to/artifact-output
```

The script reads the source checkout and writes only its two JSON outputs in the designated output directory. It uses Python's standard library. Native Rust execution is represented separately by the retained CI receipt.
