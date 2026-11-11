# Complete-source CodeQL checkout qualification

The candidate preserves the full analysis source tree while avoiding repeated materialization of historical evidence ZIPs in the five non-Rust CodeQL jobs. Its single GitHub-hosted qualification completed checkout in **15.861989596 seconds** and passed the full retained-file identity check.

## Source and execution identity

- Production candidate: `7c1c1b6f95747b9ccb877b803bd1ad7cee3cdd9d`.
- Candidate tree: `3c8aea118257a0919530c66bdf7b618c0d8dfc21`.
- Base: `d2f9035c341db488bf0aba7b440d6548660d62b7`.
- Diagnostic workflow commit: `beaf2773dd2f879dec1ae17724bf860583ed14bf`.
- Diagnostic tree: `d837c639d324ce4d2131ec8ceb4df0c53edf0329`.
- [Completed run 43066759983](https://github.com/billlza/q-periapt/actions/runs/43066759983), attempt 1; job `130683671253`, runner `ubuntu-24.04`.
- Artifact `13876775935`: 288,676 bytes, SHA-256 `5470a1db44ae6af62f3d64e0d190b3c9087a2ec3e094190845366c9876619048`.

The production candidate and the earlier local commit `5c1dd3134e07a2e7f1b7006b2d5c1291c53b5e73` have the same tree and base. Both changed paths match the original local qualification's source blob identities.

## Results

| Measurement or check | Observed result |
| --- | ---: |
| Complete tracked-file census | 7,929 |
| Retained files verified against HEAD Git blobs and exact modes | 7,387 |
| Retained file bytes | 239,527,127 |
| Precisely omitted historical evidence ZIPs | 542 |
| Omitted Git blob bytes | 4,787,753,249 |
| Retained Rust source paths | 1,241 |
| Authenticated archived Rust sources | 68 |
| Checkout measurement interval | 15.861989596 s |
| GitHub checkout step, timestamp resolution of one second | 16 s |
| Files under the Git object directory after checkout | 100,256,247 B |
| Workflow contract tests | 10 passed in 0.029 s |

The hosted verifier compares the complete index with HEAD, permits skip-worktree only for the exact 542 historical ZIP paths, checks that those paths are absent, and hashes every retained regular file using Git's blob representation. It verifies exact executable/file modes and a clean checkout. The archived-source validator separately authenticates the five source-pin manifests and all 68 frozen Rust source snapshots.

Independent artifact readback verifies the original ZIP's API size, SHA-256, six-member census and CRCs. It reconstructs the candidate Git tree from GitHub's full recursive blob inventory, compares every retained path/blob/mode/length and every omitted path/blob, and authenticates the source, workflow and completed run identities. The inventory also confirms that the candidate changes only the production CodeQL workflow and its existing contract test.

## Scope and source identity

Only the `analyze` matrix checkout changes: GitHub Actions, C/C++, Python, Java/Kotlin and Swift. The existing language build steps, query suites and analysis inputs remain intact. The pattern keeps all files except lower-case `.zip` files inside `research/sdk-alpha1/evidence/`; its directory re-inclusion preserves source files located inside directories whose names end in `.zip`.

All four Rust jobs retain full checkout. Their generic provenance guard continues to reject skip-worktree and assume-unchanged flags and to authenticate the complete tracked tree. No provenance exception or source-identity policy was added. Ordinary CI is unchanged, including tests that consume historical evidence ZIPs.

The local Git fixture also verifies source retention across directory boundaries, manifests and lockfiles, query capsules, archive snapshots, uppercase ZIP suffixes and similarly named directories. A filtered-clone fixture confirms that omitted ZIP blobs remain unfetched. The existing provenance rejection control still passes.

## Reading the performance evidence

This packet records one hosted checkout measurement on Ubuntu 24.04. The Git object-directory byte count includes object storage and related files; it is distinct from network transfer bytes and the size of materialized files. The 4,787,753,249 omitted bytes are Git blob content sizes. The packet uses these as storage and source-selection measurements, without converting the byte ratio into a wall-time speedup.

The optimization removes unnecessary historical ZIP materialization from five jobs while preserving their complete source inputs. Rust query execution has separate performance evidence and is outside this checkout measurement.

## Packet and reproduction

`local/` contains the original nine-file local qualification packet unchanged. Its manifest SHA-256 is `3bcbfb9cee79873f7b845ccd81d4a66bcac5d3df9941abcadbc79b3dcc7adf98`.

`hosted/` contains the original artifact ZIP, execution and source API receipts, job log, exact diagnostic workflow, the gzip-compressed full GitHub tree response, a reproducible readback script and its result. Gzip stores that response losslessly; the script reconstructs the Git tree from the decoded records.

Run from this packet directory:

```sh
python3 hosted/qualify_hosted.py
```

The script authenticates the local nine-file packet and the hosted result, then reproduces `hosted/READBACK.json`. The top-level `MANIFEST.json` records byte lengths, SHA-256 and Git blob identities for every sealed file except itself. This is an evidence-only addition; it does not install the diagnostic workflow or change any production source.
