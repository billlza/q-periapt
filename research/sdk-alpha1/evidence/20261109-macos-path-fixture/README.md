# macOS temporary-directory alias regression

The current-source macOS contract job in run 42546147136 failed before Rust analysis: a fixture supplied an unresolved query-pack path under `/var`, while the query resolver returned canonical `/private/var` paths. The production entry point already resolves its query pack strictly.

This change makes the fixture use the same canonical input and adds a symbolic-parent regression across the three profiles and complete/incomplete outputs. Direct query escape and an in-pack symlink to an outside query are both rejected before any success receipt. No production validator, query, resource limit, or publication gate is weakened.

`VALIDATION.json` binds the changed source and unchanged production module and records all 162 targeted tests passing. The raw test output and the pre-fix symbolic-parent reproduction accompany it. Validation used the original current-source Rust identities and a real local Git index; it did not substitute a fabricated source commit.
