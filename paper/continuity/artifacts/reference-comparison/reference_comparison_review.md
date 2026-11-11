# Independent review of the retained seven-schedule comparison

Review date: 8 November 2026.

## Result

All **35 profile/schedule pairs**, their **70 displayed numeric cells**, and the complete inventory of **420 snapshot cases** agree with the four retained source JSON files. The mean-byte values were recomputed independently with integer arithmetic and nearest-ties-to-even rounding to three decimal places. The reconstructed-key values were independently selected at `(cut_before_send=1, owner=0)`. Every case partitions exactly the `2048 - cut` future sends into the recorded reconstructed and unreconstructed counts.

The four source packets match their SHA-256, byte-length and Git blob records. Their Git blob identities were independently checked at both original source commit `228c944fc476e3e57d6c08063cacb19bca5b360e` and observed integration commit `358b921ab3469ce49f166633fc9a762ff6ed7e3d`. The seven-schedule inventory, 2,048 sends per trace, 205 losses in the lossy schedule, and 158 duplicate rejections in the duplicate schedule agree across all five profiles.

The native reference harnesses select endpoint A as the sender of sequence zero and capture the coordinate before sequence one. The table's “endpoint A immediately after its first send” description matches that coordinate. The displayed bytes use total emitted component-wire bytes divided by all 2,048 sends, while the displayed reconstruction count concerns the 2,047 future sends after that snapshot. These are separate, explicitly stated denominators.

## Failure controls

Eight injected changes were rejected at the intended boundary: duplicate or missing snapshot coordinates, an altered reconstruction count, an unknown schedule, a mismatched inner summary schedule, an incorrect delivery count, a Boolean owner index, and a balanced reconstruction-count change. The balanced change preserved `derived + not_derived` and was rejected by the immutable source-byte pin. This confirms that arithmetic consistency alone is not being used to authenticate the retained results.

## Interpretation

This is a deterministic reanalysis of already recorded reference executions. The reconstructed-key figures count the retained predictor's exact matches, and the byte figures cover the component wire. The source packets retain each profile's construction and capture semantics; the table supplies a common communication schedule and snapshot coordinate. The current computation does not create a new native execution identity.

The independently reproduced receipt is `reference_comparison_review.json`; `review_reference_comparison.py` contains the independent calculation and negative controls. The receipt binds the four source files and the exact analyzer, output JSON and LaTeX table reviewed here.
