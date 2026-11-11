# CodeQL optimization integration and hosted launch

PR [#168](https://github.com/billlza/q-periapt/pull/168) merged the validated
implementation into SDK head `faabcff16fc49e1a99388c68f0991a2bfd64d509`.
Its tree is `b5c6e256b9abb95a8163efae052c34ae6bd0f035`, identical to reviewed
candidate `4fb3b2db1d6647ec4fa85fb8bd744b1d97ef1215` and the explicit experiment
launch commit `0d7d856bc3cac866e5fe2879f4fb4cc2e61c9993`.

The retained [paired experiment](https://github.com/billlza/q-periapt/actions/runs/43009541277)
was created from a push to its dedicated launch ref. At 2026-11-11 11:16:46 UTC
it was pending and had no job objects yet. The new SDK revision had 74 queued
checks. Its workflow-run census contained one ordinary CI run, triggered by
the pull request; the former integration push duplicate was absent.

The successful local integration tests, actual bundle admission, independent
review and Windows fixture controls are in the adjacent
`20261111-codeql-optimization-integration` and
`20261111-summary-projection-admission` packets. The completed nonempty full
SummaryStats comparison is in `20261111-summary-projection-fixture`.
The production CodeQL workflow retains its original query path. The fixed
large-project experiment supplies the remaining completion and resource
measurement for adopting the projected plan in that path.

`READBACK.json.gz` preserves the complete API responses for the SDK and paper
checks, SDK workflow runs, experiment job census, protected-main ref, merge
commit and experiment launch commit. `STATE.json` binds its raw/compressed
bytes and summarizes the exact observation. Merge authorship belongs to the
configured public user; GitHub generated the merge commit's committer field.
All source and experiment commits use the configured public user identity.

The canonical paper head was unchanged, with 38 successful checks, one running,
two queued and its previously reviewed CodeQL aggregate finding. Main remained
`48d0fb9a5651b50494ec33d025dda52bd2ff5eae`; its 33 required contexts continue
to govern admission. The timestamped queue state is preserved as an observation,
separate from the completed execution evidence in the adjacent packets.
