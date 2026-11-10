# Native artifact transport preempted independent verification

[PR #117 job 126445763003](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126445763003)
failed on actual merge checkout `9aa535b48b464ec4d4a8b5a4b20221049a6067b9`.
Its native Debug suite, sealed-SDK checks, formatting and documentation steps
passed. The retained test summaries show 1,450 library tests plus 32 other
candidate tests, with the separate capacity case filtered from this partition,
and 31 sealed-SDK tests. These are that old PR merge's results, not current
maintenance-cohort or complete platform qualification.

Step 15's native-results upload reported
`Failed to CreateArtifact: Unable to make request: ENOTFOUND`.
The following Python setup and independent public-byte verifier were skipped.
The final always-run public-vector upload then failed because its inputs had
not been generated. The complete job metadata and 589,283-byte decoded log
agree with this sequence; log SHA-256 is
`28eef90fa9b47b2cd8b437104789206c3d0ad691c1736e2f4a0321198bc87bb8`.

The workflow put transport before required verification. GitHub implicitly
requires previous success for those verification steps because their conditions
contain no status-check function. The later upload explicitly uses `always()`.
This explains the skipped verifier and secondary missing-files error.
[GitHub's documented status conditions](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions)
support that control-flow interpretation. The underlying network/name-resolution
cause is not established by the log, and is not claimed repaired.

The local correction moves the unchanged native-results upload to the end of
the job, after independent public verification and the public-vector upload.
Thus a transport failure cannot prevent that earlier verification. Both uploads
remain mandatory, use their original failure conditions, and retain
`if-no-files-found: error`; a failed upload still fails the job. Verification
commands, matrix, selected tests, time limits and artifact payloads are unchanged.

Two checks reject the original order and pass the corrected order. The complete
15-test workflow regression then passes, including controls that move transport
back before verification or weaken native failure retention/missing-file errors.
A separate comparison confirms the exact same step-body multiset, job header
and surrounding workflow; only step order changes. This is local validation,
not a simulated or actual successful GitHub upload.

The 03:50:42 UTC snapshot retains twelve runs: 289 successes, 20 queued, three
running, 18 failures and two skips. The four open CI runs and both PR heads
were refreshed; eight terminal run inventories retain their earlier final rows.
Both PR heads remain `475cd239` and `6084f3bf`. The effective wave is open, so
no push, rerun or cancellation was performed. The corrected-source hosted job
must still execute its independent verification and successfully preserve its
required artifacts before this CI failure can close.

`CAPTURE.zip` contains the complete decoded log, job/step metadata, source-bound
failed workflow, current baseline/corrected workflows, before/after checks and
complete local regression output. Its 22 members were reread byte-for-byte.
The 230,334-byte archive has SHA-256
`a91555af91a3f4b787417cef01feb084025e935a7250cd4bb6ffa769689c1c93`.
`CLASSIFICATION.json` states the observed failures and remaining boundary;
`FILES.json` pins every member. Neither remote artifact is claimed uploaded.
