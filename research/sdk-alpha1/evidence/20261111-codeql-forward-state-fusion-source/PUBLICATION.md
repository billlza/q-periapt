# Unit forward-state fusion source qualification

The fixed Stage3/Stage4 fusion compiled successfully with the official CodeQL
2.27.2 CLI and explicit dynamic join mode `all`. Its optimized RA removes the
selected stages' `fwdFlow0/7` and `fwdFlow1/7` entities while preserving the
six-column closure and complete downstream read consumers. The sealed source
argument, all three compiler records, source/runtime identities, actual installer
readback, and 48 focused controls are retained unchanged.

[PUBLIC_SOURCE_BINDING.json](PUBLIC_SOURCE_BINDING.json) binds those original
records to public source commit
[9c0d63d4](https://github.com/billlza/q-periapt/commit/9c0d63d4d258f126af92a8bda64aec090019a1b3),
with tree `85fcc41a318020290955f6862b65b99a96b79691`. All nine fusion artifact
files are byte-identical to the original reviewed local candidate. Its public
parent also contains the independently qualified checkout change.

The added [combined control result](combined-controls/RESULT.json) records
294 passing tests on that exact source tree. The unittest interval is 10.798
seconds; the supervising process wall interval is 11.609465699 seconds. The
original log and candidate file identities are retained beside that result.

`MANIFEST.json` remains the original 24-file packet manifest, unchanged.
`PUBLICATION_MANIFEST.json` covers the full augmented packet. The full-query
fixture has a separate receipt and result-comparison scope.
