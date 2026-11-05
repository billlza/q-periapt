# Current-head CI terminal results and remaining historical queue

At 2026-11-05 09:05:50 UTC, all 336 jobs in the twelve tracked current-head
runs are terminal: 298 successes, 35 failures, one cancellation and two skips.
The last PR #117 main run reports terminal failure, updated at 08:58:35 UTC.
The two current heads remain `475cd239` and `6084f3bf`; the latest explicit PR
readback is retained in the next-wave preparation. No corrected-source hosted
qualification is inferred from these old heads.

Four later foreign-labelled failures all stop in the old exact-142 C/OpenSSL
prerequisite, bringing the observed P0 checker count to 27. The logs do not
establish foreign-consumer execution or disclose a hosted numeric count.

| Job | Scope | Actual checkout | Reported artifact | Bytes | Upload SHA-256 |
| --- | --- | --- | ---: | ---: | --- |
| [126449258020](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126449258020) | continuity-installed-swift-release | `475cd239` | 13397229899 | 47,600,969 | `cae7b42be7e620562a72e83bd713153a1d975b4e0aecdf7eda41dee1a2fc8c77` |
| [126449258037](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/126449258037) | continuity-installed-swift-debug | `475cd239` | 13398705011 | 47,522,704 | `9e823de7db167e2e143da4342b32495ec04caed52b20805cd886a5ac1c4fbb50` |
| [126456506096](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126456506096) | continuity-installed-kotlin-debug | `9aa535b4` | 13398845282 | 47,522,575 | `13e3e4494529da59d8674e31690d2eae1970b512866c02767f00951f37899e51` |
| [126456506122](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/126456506122) | continuity-installed-swift-release | `9aa535b4` | 13401336342 | 47,592,703 | `8fd4f26ce19dabbc7affbc10e7d44a6c763d99ab756c3fd3eef2c2ce24ffb168` |

The push-side [coverage join 127122411070](https://github.com/billlza/q-periapt/actions/runs/41791511701/job/127122411070)
downloads all six named partition artifacts and fails the compound
completion/schema/claim predicate. The frozen iteration order identifies the
first checked input as Swift Debug; the particular failed conjunct is not
independently established from the console log. The merge-side
[coverage join 127146720219](https://github.com/billlza/q-periapt/actions/runs/41791519877/job/127146720219)
reports only five named artifacts, with Kotlin Release absent, and fails the
partition-directory-set guard. Both exact source-pinned validators are retained
and byte-identical. Neither join successfully uploads its coverage output.
Together with the earlier captures, all four current-head coverage joins have
failed; no incomplete partition is counted as passed.

The missing merge Kotlin Release job had been cancelled before runner execution.
A subsequent read-only GitHub CLI GET retrieves its check annotation after the
connector rejected the unsupported check-run endpoint. The annotation explicitly
reports a 24-hour limit while awaiting a runner. This resolves the previously
[unconfirmed cancellation cause](../20261105-ci-queued-cancellation-readback/README.md).
It is queue waiting, not 330 minutes of consumer execution; the original failed
connector responses and earlier classification remain preserved. This task
issued no cancellation or rerun.

Current-head terminality did **not** imply an empty related queue. Repository-wide
active-run discovery found three older runs on the same publication branch.
The 09:05 readback has the two native jobs of run 41726500731 terminal, while
these three older foreign jobs remain assigned to live runners:

| Run | Job | Scope | Observed start UTC |
| ---: | ---: | --- | --- |
| 41724505316 | 126268252580 | Android Release | 2026-11-05 08:00:23 |
| 41724563802 | 126266162426 | Swift Release | 2026-11-05 08:17:37 |
| 41724563802 | 126266162501 | Android Release | 2026-11-05 08:54:14 |

Their queue occupancy is tracked separately from current-source qualification.
The earlier same-head-only inventory was insufficient as a next-wave queue gate;
no remote push was made on that basis. New-wave readiness remains false until
the related running/queued work reaches a verified terminal state.

The concrete next source wave is prepared as one normal atomic fast-forward:
PR #117 to `232ace17915407596d66f3a5fd7c7765251a38cc`, and PR #118 to the clean
locally qualified `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`. A single Git
`push --dry-run --porcelain --atomic` succeeded with no ref update. Its retained
record is explicitly a copied tool-return observation, not an invented separate
raw subprocess capture. Local ancestry checks pass; the proposed objects include
217 blobs totaling 63,471,378 bytes, with the largest 31,663,407 bytes.
Git transport can preserve these existing commit identities, which the
connector's new-commit tool does not import verbatim. Remote status/identity
checks continue through the connector.

This source wave precedes the retained focused Android workflow correction.
After the new producer wave completes, verify its hosted SDK report/archive
identity and update the explicit Android pin before the later workflow wave.
Do not replace that sequence with a latest-artifact fallback or push the whole
local tip with the old input pin. Fresh queue and remote-ref checks are still
required immediately before an actual push. No force push is authorized.

The four reported foreign artifact containers were not downloaded locally.
`CAPTURE.zip` retains their full logs, both coverage logs/validators, current
snapshots, both historical queue snapshots, active-run discovery, the cancellation
annotation, dry-run observation and next-wave preparation. All 20 members
were reread: 415,998 bytes, SHA-256
`b990bd2e1a66645f390b69185b5b69d8fe45c249aed924418fdcbc9a708c87be`.
No push, rerun, cancellation, release or final qualification is claimed.

The [subsequent historical account-TLS readback](../20261105-ci-historical-account-tls/README.md)
records the older push Android and PR Swift terminal failures, the downloaded
Android-labelled native receipt, and the remaining PR Android job. These use
the older account admission checker, not the current-head exact-142 predicate;
the original snapshots and capsule above remain unchanged.
