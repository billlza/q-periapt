# Canonical CodeQL: hosted qualification and alert review

The Rust analysis for canonical head `87fee58926f8b849a142018efb6d7502cbad673f` passed its checkout, extraction-quality and upload gates on 11 November 2026. All 38 standard CodeQL queries completed. The same canonical source also passed the full hosted dependency audit, including sparse-index checksums and yanked-package checks.

## Source and run identity

| Item | Identity |
| --- | --- |
| Canonical head | `87fee58926f8b849a142018efb6d7502cbad673f` |
| Hosted PR merge checkout | `5e269d2fb399890b5d37944541031c9670b2e90d` |
| Tree shared by the head and checkout | `865d6aafb8e6a2adf8b28c5076cedd9cbc520863` |
| CodeQL run | [42995542891](https://github.com/billlza/q-periapt/actions/runs/42995542891) |
| Rust analysis job | `130438751368`, completed successfully |
| Aggregate CodeQL check | [130443254661](https://github.com/billlza/q-periapt/runs/130443254661) |

`checkout-identity.json` records the PR merge parents and tree. `run.json`, `jobs.json` and `checks.json` preserve the captured GitHub response data; `checks.json` contains the selected aggregate CodeQL check object.

## Hosted Rust qualification

All 174 tracked Rust files were extracted: 106 current-source files and 68 archival snippets authenticated by exact identity. The 68 semantic-context diagnostics and 615 unresolved macros belong to those pinned archives. The gate rejects unresolved-macro details outside that exact set, so the current-source unresolved-macro count is zero. The reported database totals include 6,155 source macro calls and 212 source format arguments.

The 38 standard queries comprise **18 security queries, 10 diagnostic queries, 8 summary queries and 2 telemetry queries**. `REVIEW.json` records every query-completion entry.

| Time on 11 November 2026, UTC | Hosted result |
| --- | --- |
| 09:37:38 | Checkout identity passed before analysis. |
| 09:42:38 | Query 38 of 38 completed; `SummaryStats.bqrs` was written. |
| 09:42:42 | Checkout identity passed after analysis. |
| 09:46:47 | `CODEQL_RUST_DATABASE_QUALITY_PASS` was recorded. |
| 09:46:48 | SARIF results were uploaded successfully. |

`rust-job-130438751368.log.gz` preserves the exact decoded hosted log. Its compressed and uncompressed byte identities are recorded in `REVIEW.json`.

## Full hosted dependency audit

Canonical audit job [130438613213](https://github.com/billlza/q-periapt/actions/runs/42995542913/job/130438613213) recorded `RUST_WORKSPACE_DEPENDENCY_AUDIT_PASS` at **10:03:55 UTC** and completed successfully at 10:03:56 UTC. It checked **227 workspace registry packages and 38 fuzz registry packages**, with `sparse_checksums=exact`, `yanked=0`, `warnings=denied` and `locks_stable=1`, against RustSec database commit `31cf5a8673e10d3a4d7d829ad5095f47ed419049`.

`audit-hosted.json` retains the original check object, exact pass line and log identities; `audit-job-130438613213.log.gz` preserves the decoded log. This result covers the canonical workspace and fuzz graphs. The `rustix 1.1.4` entry in the cargo-audit installation output belongs to that tool's own dependency graph; the audited project update is `rustix 1.1.6`. SDK hosted-gate completion remains a separate result.

## The 14 aggregate annotations

| Count | Reported source locations | Finding from the source review |
| --- | --- | --- |
| 8 critical | `bootstrap.rs`, lines 1969 and 1974, in the `entry`, `initial`, `reply` and `terminal` archives | Two public deterministic known-answer tests repeated in four byte-identical files. The containing module is `cfg(test)` and the function is marked `test`. |
| 1 critical | `entry/.../q-periapt-sdk/src/purpose.rs`, line 14 | A public HKDF domain-separation salt. IKM comes from `SharedSecret`, and `info` binds the protocol context. |
| 1 high | `ack/.../durable/messages/rekey.rs`, line 306 | A crash-effect output hook whose definition and both call sites are guarded by `cfg(all(test, unix))`. The directory is supplied by the test environment. |
| 4 high | `audit_matched_traces.py`, line 66 twice, then lines 67 and 71 | Explicit local CLI inputs. Manifest-driven reads use the fixed 126-member corpus inventory, canonical confined paths and regular-file identity checks. |

`annotations.json` preserves the captured locations, titles, severities, messages and source links. `REVIEW.json` maps each annotation to the inspected source and its SHA-256 identity. `annotations.public.html.gz` retains all 14 annotation elements from the public check page, with transient UI nonce attributes removed. The extraction and original-page identity are recorded in `publication-review.json`.

The public page exposed each warning's location and message; its related-location popups did not load. The review therefore followed the exact source definitions and entry points. It identified no unauthorized path-selection or secret-key disclosure counterexample in these reported flows. Alert dispositions and scan rules were left unchanged.

The HKDF assessment uses the actual `SharedSecret` input and the public role of the reported constant. [RFC 5869, sections 2.2 and 3.1](https://www.rfc-editor.org/rfc/rfc5869.html) defines salt as non-secret and HKDF with or without random salt. This finding is scoped to the reported constant and dataflow.

## Existing input-boundary controls

The exact canonical auditor, existing test file and public-manifest fixture were copied to an isolated directory. **All 10 existing tests passed in 0.018 seconds using Python 3.12.14.** The controls cover path escape, symlinks, replacement before opening, modification during reading, fixed manifest membership and binding reported digests to parsed bytes. `matched-path-controls.json` records the source hashes, interpreter and command; `matched-path-controls.log` retains the output. These are local controls, recorded separately from the hosted results.

The copied source files are omitted from this publication packet because they can be recovered at the exact commit paths recorded in the receipt.

## Snapshot status and publication scope

At the captured CodeQL snapshot, aggregate check `130443254661` reported failure: Swift job `130438751730` was queued and `/language:swift` had not yet been uploaded. The 14 annotations remained visible. The successful Rust qualification and canonical dependency audit are completed results; the captured aggregate state is retained as observed.

Publish only the files listed in `MANIFEST.json`. The packet contains receipts, exact compressed logs, captured mutable GitHub response data and the annotation excerpt. Large immutable commit diffs, temporary source copies and the full web page's signed socket channels are omitted. No source, archival evidence, rule, scan configuration or alert disposition was changed by this review.
