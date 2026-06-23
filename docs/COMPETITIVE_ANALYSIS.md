Wrote `/Users/bill/Desktop/Desktop/q-periapt/docs/COMPETITIVE_ANALYSIS.md` (polished GFM, ~270 lines).

Key honesty decisions, grounded in both the blueprint and the adversarial review (and verified against actual repo state — no wired backend, empty `formal/`, stub FFI):

- **Removed fabricated numbers**: the "~8–10% encap/decap win" and the absolute "1,774 vs 12,586" cycle counts. Replaced with directional framing ("~1 block vs ~10 blocks"), an explicit note that the hash delta is a small fraction of ML-KEM-dominated encap/decap, and "measured value TBD in M4."
- **Reframed the two soft "wins"** per review: cross-platform = *reduced audit/bug surface* (not unique interop, since FIPS 203 / RFC 7748 primitives already interop); P99 = *methodology / don't mis-measure* (not "beats Cloudflare"), with all unsourced percentages dropped.
- **Led with the one genuinely structural win**: crypto-agility + HQC assumption diversity, which X-Wing (fixed construction) and PQ3 (vendor redeploy) cannot do without forking.
- **Verdict legend distinguishes** structural wins from process wins that are conditional on unbuilt CI.
- **Status tagging throughout** plus a dedicated §6 "Known critical gaps" so the design intent is never read as shipped, sound code (FastXWing length bug, missing C2PRI guard, missing implicit-rejection, no backend/KATs, non-functional policy enforcement).
- **Tie column is honest**: same ML-KEM/ML-DSA/SLH-DSA, FastXWing is parity-only, standardized objects we track not author; plus the explicit "don't conflate `0x11EC` concatenation with X-Wing's SHA3 combiner" warning.
- **Cannot-win table** kept FIPS 140-3, primitive perf, combiner CPU, standards-setting, audit completeness, production maturity.
- Carried the CT-CI limits the review flagged (tool coverage gaps off x86_64-linux, per-backend non-uniform CT, dudect≠assembly-proof, ML-DSA rejection-sampling carve-out, HQC excluded from CT claims).

No marketing language; every comparative verb is matched to evidence or marked as design intent.