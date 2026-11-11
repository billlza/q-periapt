# Follow-up review of two singleton Python high results

Both singleton results have now been reviewed against their actual inputs. The relevant four files match both scanned merge `f99a1100a74a10cb649a6f2a5fc61430f1174436` and integration `9bcac7036b78d23d48d307165ed5ff2f45b656b6` byte for byte.

| SARIF result | Observed semantics | Result |
|---|---|---|
| `python:1`, cleartext storage | A public token-shaped literal is deliberately written into a temporary binary; the scanner must reject it without echoing the sentinel. | Required negative control, reviewed; keep the test. |
| `python:2`, weak sensitive hashing | A synthetic certificate literal receives a compatibility SHA-1 fingerprint and a separate SHA-256 digest. The production entry requires the SHA-256 pin as well as the SHA-1 identity. | Reviewed fixture and pin semantics; keep both the compatibility check and SHA-256 requirement. |

Three existing focused tests passed. These include the no-secret-echo assertion and a wrong-SHA-256-pin case that must fail even with the correct SHA-1 identity. `REVIEW.json`, `source-manifest.json` and `replay.log` bind the exact result IDs, source bytes and replay.

This follow-up was kept separate from the already-submitted review package. The earlier package's 1,257-unreviewed count remains its historical snapshot; after these two item reviews, 1,255 of those prior high results remain unreviewed. No source, query, exclusion, severity threshold, alert state or remote branch was changed.
