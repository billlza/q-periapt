# CodeQL quality query resource control

This isolated workflow replays the three unchanged custom quality queries and their original assertions from merge commit `605de309dbcf5ebdca6652e1487e9425c6e38a4b`. The frozen database comes from failed CodeQL run 37680196785, artifact 11515742809. It does not extract current product sources or upload SARIF.

The original Metrics query was interrupted at 300 seconds, including compilation time. This experiment changes only the per-query diagnostic allowance to 1200 seconds, retaining four evaluator threads, 14000 MB, warning rejection, all 26 metrics, the exact 418-file inventory and every original quality assertion. The inventory and query sources were verified against the frozen merge tree; the full downloaded artifact must match its pinned service SHA-256 before extraction.

Results and any timeout remain failures when incomplete. Prior database results and cache, if bundled, are retained; timing is not a cold extraction measurement. A successful frozen replay cannot qualify the current product commit, establish absence of vulnerabilities, or approve release.
