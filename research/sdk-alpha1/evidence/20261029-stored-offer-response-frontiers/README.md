# Stored offer and response origins: complete-tree replay

The latest complete tree remains **incomplete**. Tamarin independently replayed
382 steps of `epoch_generation_secret_derivation_origin`, with 42 open leaves.
No additional Stored producer closed in this experiment. More proof steps and
more specific branches are not a percentage of security completion.

## Experiment and restoration

The parent is the independently checked 716 tree, SHA-256
`b0cffe0a3c3568d39dce0a4418fe9f251dbc146dad164870c70ac24fa6c17085`.
It had 33 open leaves. The diagnostic run retained the three closed Stored
producers and focused on Offer Commit (3 leaves), Response Compute (2), and
Response Commit (8). Five other complete subtrees were saved verbatim and
temporarily represented by open leaves only for frontier collection.

The 18-leaf focused input produced 17 actual frontier captures in 305.440 seconds;
one Offer Commit leaf closed automatically. The collector selected no proof
method. The resulting 292-step diagnostic tree is deliberately not the complete
tree and cannot be compared with the complete parent's step count.

Twelve uniquely identified observed goals were then applied: nine knowledge
chains and three phase-producer premises. Every saved sibling subtree was
restored before a separate replay with no search or oracle. It took 304.295
seconds. The final complete output SHA-256 is
`8dfd3d7f906a562d642bdbe0d1510ba03df53d9310baafb43dab9c7e44a66069`.

The complete replay preserves byte-for-byte the other 17 knowledge-source
branches, all five restored Stored subtrees, and the three already closed Stored
subtrees. All 29 query formulas, modes and attributes are unchanged. The
operational prefix SHA-256 remains
`3cb837646fa2097468d1fad0a10433f50d5c31b6be5553f20085170c3eef0266`.

The final Stored open-leaf counts are: Final Commit 4, Final Reservation 5,
Offer Commit 6, Receipt Accept 3, Receipt Commit 3, Receipt Reservation 5,
Response Commit 8 and Response Compute 8. Key Reservation, Offer Signing and
Response Reservation remain closed. The maximum remaining open prefix is 11;
the total depth limit remains 16.

Both processes had Tamarin exit 0 but driver exit 1 and `accepted: false` because
the selected theorem remained incomplete. There was no timeout or invalid proof
step. Fourteen auxiliary all-trace statements and the 414-step initial traffic
witness replayed successfully; neither establishes the multi-epoch main secrecy
or recovery reachability statements.

## Correction and next research step

The first restoration preparer matched repeated case names across the entire
lemma. Its uniqueness assertion refused to construct an input, and no prover
started. The corrected preparer scopes replacements to `Snapshot_case_5` and
checks all other source branches unchanged. The refused preparation is retained.

Further blind unfolding is not justified by this result. Inspect the common
phase-payload shape obligation around Offer2, Response4 and Response5. Any new
auxiliary invariant must first be independently proved under the unchanged full
rules and leak model before being reused. Do not assume it, remove a threat,
raise the bounds or discard the restored history to obtain a green result.

`CAPTURE.zip` includes the parent, both inputs and outputs, exact selected goals,
restored sibling material, process records and tool identities. The manifest and
readback bind every member. This is research evidence, not release qualification;
the full P0 proof and 0.2.0 objective remain open.
