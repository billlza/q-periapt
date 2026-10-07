# CodeQL evaluator resource control

This isolated diagnostic branch consumes the immutable Rust database from failed
run 37619119723. Its PR merge commit is 309cc4d6d2c8aa7deba23f4f1a81b23c327b956a;
its tree equals feature head fe06176bc6c30c8cda45707fc1208b91b70b507d.

Two ordinary Ubuntu 24.04 jobs use the same CodeQL 2.27.1 bundle, original 39
queries, local threat model, 14575 MB memory setting, and retained database/cache.
Only the evaluator thread count changes: four versus one. Each evaluation has
an 85 minute wall-clock bound, approximately the failed run's remaining query
time after extraction. Failure and timeout remain failures, with diagnostics.

The database already has 38 BQRS results and interrupted evaluation caches. Both
jobs start from identical archive bytes. This does not measure cold extraction.
Successful runs decode every query result and record row-order-independent
hashes for comparison. A successful control is not a release gate or proof that
the latest product source passes CodeQL. Product CI remains unchanged.

No alert upload, merge, release, or product source modification is performed.
