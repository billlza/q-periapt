Wrote `/Users/bill/Desktop/Desktop/pqt_hybrid_suite/docs/ARCHITECTURE.md` (the repo already existed locally, so the doc is grounded in the actual code, not just the blueprint).

Key honesty/accuracy decisions reflected in the document:

- **Implemented vs scaffold labeling.** The real tree has only 4 compiling crates (`pqt-core` implemented; `pqt-kem`/`sig`/`policy` partial with toy primitives) and `pqt-ffi`/`pqt-wasm`/`pqt-tls-demo`/`pqt-cli` as empty `src`-less scaffolds. `pqt-backends` from the blueprint does not exist yet — marked PLANNED. `Cargo.lock` has zero external deps, so I stated X-Wing parity is asserted but unverified.

- **Real numbers, corrected.** CompatXWing absorbs exactly 134 B → 1 Keccak block (rate 136 B). ContextBound absorbs ≈2.5 KB for ML-KEM-768+X25519 → ≈19 blocks (not the blueprint's ~10; I computed it from the actual `u64`-LE prefixes and field sizes). ML-KEM-768 pk 1184 / ct 1088; X-Wing pk 1216 / ct 1120.

- **Removed unsubstantiated perf claims** per review: dropped the "8–10% encap/decap win" and demoted the "1,774 vs 12,586 cycles / 7×" figures to TBD-by-measurement, and flagged that the hash ratio is not the encap/decap ratio.

- **Incorporated all critical/high review findings** as a dedicated "Known gaps" section (§9): missing `Kem::C2PRI` guard, no `CompatXWing` length validation, no `implicit_reject`/`ct_select` (the `?` early-return oracle), policy floor non-functional, no signed policy, no KATs/backends, comment-only CT CI, empty formal artifacts, the u64-vs-u16/u32 prefix mismatch, `Secret: Clone` zeroization gap, and the `no_std` panic-freedom vs `catch_unwind` issue.

- **Reframed overstated wins** to verb-match evidence: cross-platform = reduced audit surface (not unique interop), P99 = correct measurement methodology (not "beats Cloudflare"), and led with agility/assumption-diversity as the one genuine structural win.

- **CT scope honesty + HQC carve-out:** stated that ~4 of 10 triples have no credible binary-CT gate, that CT is per-backend, and that HQC is excluded from the side-channel-resistant-first claim.

- **CI matrix divergence** documented honestly (4 build triples + placeholder cross-compiler vs the advertised 10-triple matrix; toolchain pinned 1.81/floating-stable vs blueprint 1.96).

ASCII module diagram included (§2) with implemented/partial/scaffold legend.