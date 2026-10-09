# Retained CodeQL inventory at b1006eb3

Rust job **113743698090**, run **37907286669**, completed analysis, post-analysis
source checks, database quality checks, SARIF upload and diagnostic retention.
All required steps succeeded. The 474,691,041-byte diagnostic ZIP was downloaded
and matches the API SHA-256
`38bb9c606659b0610d828fa958b87ea72f0814bde07baa3f5a5380dd797bbd6c`.

The aggregate security check **113744976445 failed**: it reports 1,617 new
alerts (181 critical, 1,390 high, 46 medium). The open PR inventory contains
1,626 alerts, all bound to merge `54c5409379e9c596944253e0c8c01721143ed582`.
The raw Rust SARIF contains **819 results**. These are distinct scopes and are
not counts of individually confirmed vulnerabilities.

This checkpoint adds **no dispositions**. The nine dispositions in the earlier
67e1a5b0 review remain bound to that separate 809-result analysis; they are not
automatically subtracted from this inventory. No remote dismissal, rule change
or passing aggregate security claim occurred.

`INVENTORY.json` records rule counts and archive identities. `INVENTORY.zip`
retains the complete Rust SARIF, complete current open-PR alert inventory,
aggregate check and first100 annotations, job/run metadata and original archive
index. The large diagnostic ZIP is retained locally without duplicating it into
repository history. This fulfills preservation of the prior analysis before the
next authorized same-ref CI push; it does not qualify release readiness.
