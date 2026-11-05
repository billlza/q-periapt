# Corrected-source CI wave: atomic update and readback

One normal atomic fast-forward completed at **2026-11-05 10:14:05 UTC** in
5.887 seconds, after the final older run and its coverage join became terminal.
No force, tag, release or registry publication operation was used.

| PR / branch | Previous head | New head |
| --- | --- | --- |
| [#117](https://github.com/billlza/q-periapt/pull/117), `feat/continuity-publication-verification` | `475cd23923e45819b01b6041c91c44540ec056ec` | `232ace17915407596d66f3a5fd7c7765251a38cc` |
| [#118](https://github.com/billlza/q-periapt/pull/118), `feat/accountable-prekey-directory` | `6084f3bfb09333f6b66291b38809ed512296a27b` | `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20` |

The GitHub connector verified both new heads and #118's new base `232ace17`
after Git returned success. Exact existing commit objects were transferred through
the authenticated Git HTTPS transport; connector reads supplied the before/after
ref and queue evidence. The actual command, stdout, stderr, timestamps and terminal
receipt are retained. The immutable `ff072bd6` source has the completed local
Rust/C, Swift and Kotlin qualification; its Android host JNI extension was still
running at push time. This wave is not final candidate or platform acceptance.

At the fresh 10:13:12 UTC gate, repository-wide `in_progress`, `queued`, `waiting`,
`pending` and `requested` run collections were all empty, and PR heads/bases
matched the expected chain. The gate was 47 seconds old when execution began.
The last historical run 41724563802 has 71 terminal jobs: 59 success, 11 failure
and one cancellation. Its final Android-labelled job **126266162501** failed in
the old C account-TLS phase-workload check, before qualifying JNI. Its upload log
reports artifact 13406565024, 32,121,924 bytes, SHA-256
`19c5938ae8866bfd3e406df5a8122a90535a217556568f8233f9b11ff2fb3247`;
that container was not downloaded. Coverage **127180430509** downloaded six
partition artifacts and rejected the compound completion/schema/claim predicate.
The merge-checkout coverage validator matches the earlier pinned push validator.
No hosted actual phase count or specific failed guard conjunct is reconstructed.
Both complete logs are retained alongside the earlier
[historical account-TLS evidence](../20261105-ci-historical-account-tls/README.md).

The update generated 16 run records. Four #118 PR runs were superseded before
runner execution. Each representative check annotation explicitly attributes
cancellation to a higher-priority waiting request in the same concurrency group;
the four source-pinned workflows have `cancel-in-progress: true`. All 76 jobs
in those four cancelled runs have no steps and no allocated runner. The task
issued no cancellation or manual rerun. Cancelled runs do not count as passes.

The **12 surviving runs**, still queued/running in the 10:20 UTC snapshot, are:

| Head | Run | Workflow / event |
| --- | ---: | --- |
| `232ace17` | 42008993544 | Main CI / push |
| `232ace17` | 42009005313 | Main CI / PR |
| `232ace17` | 42009005586 | Reference account / PR |
| `232ace17` | 42009005415 | Focused regressions / PR |
| `232ace17` | 42009005451 | Installed Windows lifecycle / PR |
| `ff072bd6` | 42008993679 | Main CI / push |
| `ff072bd6` | 42009001947 | Main CI / PR |
| `ff072bd6` | 42008993976 | Reference account / push |
| `ff072bd6` | 42009001650 | Reference account / PR |
| `ff072bd6` | 42008994078 | Independent interoperability / push |
| `ff072bd6` | 42009002052 | Focused regressions / PR |
| `ff072bd6` | 42009001884 | Directory lease contract / PR |

At that snapshot two runs were in progress, ten queued and the four superseded
runs cancelled. None of the 12 is declared successful here. Keep this wave intact;
after it finishes, verify the hosted SDK producer report/archive identities before
changing the explicit focused Android input pin and uploading later retained fixes.

## Dependency warning scope

Git's remote stderr reported three open Dependabot alerts. The connector has no
Dependabot/check-annotation endpoint, so existing authenticated GitHub CLI GETs
read the actual records without changing alerts, permissions or the default
branch. They all reference default-branch `Cargo.lock` rustls **0.23.43**.
The independently fetched default `main` commit
`7ed1f96a7ec33732f02a989dd5a4669cdcce39ad` confirms that version.

The advisories cover [Brotli allocation](https://github.com/rustls/rustls/security/advisories/GHSA-h2v8-394m-p7vv),
[unauthenticated key-exchange cache updates](https://github.com/rustls/rustls/security/advisories/GHSA-w44r-93j7-qv28)
and [secret-bearing Debug formatting](https://github.com/rustls/rustls/security/advisories/GHSA-c8m5-c952-6cm4).
Each identifies **0.23.46** as patched. Both pushed candidates, the previous
#118 head and current local evidence head already pin 0.23.46 in their root and
Continuity candidate lockfiles. Eight nonhistorical, nonvendored tracked lockfiles
were examined at each pin; those two are the only ones containing rustls.
Both installed Rust/C foundation lockfiles also contain 0.23.46. Thus these
three vulnerable version ranges do not call for another candidate dependency
upgrade. This limited readback does not close the full final dependency/security
audit or dismiss the default-branch alerts.

`CAPTURE.zip` contains the actual guarded push driver/receipts, fresh gate inputs,
post-push PR/runs, cancellation inventories/annotations, old final failure logs,
and alert/source-lock readback. All 63 members were reread: **290,870 bytes**,
SHA-256 `c1fb37c36a5cb8e843b6952014a40f24ffa4032f64241e149972c6594d1141a4`.
`FILES.json` binds individual members and `READBACK.json` records scope. Formal
proof, final ABI/platform qualification, external review and release remain open.
