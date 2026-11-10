# Linux bounded fuzz execution

[Run 37680568824](https://github.com/billlza/q-periapt/actions/runs/37680568824)
completed on x86_64 Linux. All three targets ran with AddressSanitizer and the
same bounded job and environment from product commit `d51b2c30`. The auxiliary
commit `d59a45b7` differs only in workflow files. `EXPERIMENT.json` records that
comparison; this does not qualify later source changes or the full product CI.

Executed callback counts were 2,675,310 (combine), 1,889,328 (ML-KEM decapsulation)
and 53,807,935 (transport). Early-rejected inputs still count as callbacks; these
are not counts of completed cryptographic operations. The job succeeded and all
three logs contain one positive final count with no reported sanitizer failure.
This remains a short robustness check, not a security or constant-time proof.

`READBACK.json` records the service-matched SHA-256 of the complete downloaded
artifact and its successful ZIP CRC check. Logs preserve their raw text and
hashes in JSON. `corpora.json` retains every final fuzz corpus/artifact member
with its original path, bytes and hash. Tool versions are retained separately.

The first product CI attempt at `4fc8412a` failed before fuzz execution because
the stable Rust setup omitted its required toolchain input. Commit `d51b2c30`
corrects that error; this successful auxiliary run verifies the corrected job.
The product branch correction remains subject to its own next CI run.
