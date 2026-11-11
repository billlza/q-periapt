# ContextBound-to-message connection

This artifact freezes the fifth manuscript research increment, dated 7 November 2026. It completes the previously explicit ContextBound comparison for the next rekey of an established authoritative session and the retained marked first-message interface.

## Mathematical results

- **Lemma 5.12:** the actual ten-field LP8 encoding satisfies the adaptive hidden-input comparison, with output-bit gap `Phi_256(d,Q_H)`.
- **Lemma 5.13:** every protected use of the original target tuple in the declared next-rekey profile feeds one old-root/complete-root-info pair. The invariant is online and does not condition on final acceptance or eligibility.
- **Theorem 5.14:** the selected-component continuation bound is substituted into the existing candidate-local native accounting, with its original residuals and operational component/correctness terms preserved.

`contextbound-connection.tex` is the exact frozen copy of the integrated module. `contextbound_connection.md` supplies the full experiment, proof, source reasoning, counterexamples and next extension. Its drafting reference `contextbound_source/source_audit.md` resolves here to the adjacent `source_audit.md`; no mathematical text was altered during packaging.

`independent_review.md` and `independent_review.json` record the independent statement-by-statement mathematical and source cross-check, including exact input hashes. This is an independent argument review, not a machine-checked proof. `FREEZE.json` binds the final artifact files. The preceding joint-continuation v0.4 and primitive modules are retained unchanged.

## Source and executable evidence

`source_audit.md` maps the complete encoding, actual ML-KEM/X25519 adapter and next-rekey root-use induction to fourteen native files. `source_map.json` records an explicit successful check against native pin `228c944fc476e3e57d6c08063cacb19bca5b360e`, development checkpoint `1c68aa666db22d36ee136be1ec712545a9e74f03`, and the supplied native worktree. It contains twelve static assertions. `source_README.md` gives the detailed audit procedure.

Run the self-contained format and finite adapter checks from this directory:

```sh
python3 check_contextbound_adapter.py --output check_receipt.json
```

The 36 checks include six retained core SHA3 known-answer cases, a synthetic fixture using the actual 2,639-byte native encoding, exact tuple aliases, component-challenge routing, prechallenge history preservation, retry provenance and explicit wrong-cache negative controls. Distinct model handles do not claim numerical cryptographic values cannot collide.

For a native checkout containing both exact source revisions:

```sh
python3 audit_source.py --repo /path/to/native-checkout --output source_map.json
```

Missing revisions, changed selected worktree files and failed assertions fail this command. It does not fetch another source or silently substitute a different checkout. The self-contained manuscript CI runs the first command; the explicit source audit is retained with its own source identity.

## Scope and evidence boundary

The concrete component game is an explicitly stated two-stage ML-KEM-768 real-versus-uniform experiment. The native X25519 leg retains its actual algorithm and rejection behavior. Whole SHA3-256 and SHA-256 compression are separate ideal-oracle interfaces with complete preparation/continuation budgets. Hash-table keys are complete effective tuples; original-operation and CCA identities use their separate required keys.

No native Rust, Tamarin or benchmark execution was rerun in this increment. Their retained historical receipts remain attached to their original revisions. The finite multiple-root entry construction is a next research extension recorded in the proof note, not an additional theorem claimed by this increment.
