# Stable specification lock across selected distribution builds

The existing release-manifest verifier at source
`b1cff2a045d23aecf75aef12122e5080a8419676` places each distribution metadata
document's file digest in the normative package-graph commitment. That document
also contains the build's source commit/tree and artifact references. Rebuilding
the same package graph therefore changes the lock even when every normative
document, interface, package identity and dependency edge remains unchanged.

`BEFORE.json` records the reproduced failure against the original implementation.
The complete synthetic release fixture passes initially, then fails with
`package graph differs from the specification lock` after selecting newly hashed
artifacts and matching source/distribution records under the unchanged lock.

The correction adds an explicitly selected specification-lock schema `2`.
It retains distribution identity, version, format, metadata path, dependencies
and interfaces in the graph commitment. The outer manifest continues to verify
the complete distribution metadata, selected source, artifacts, assessments and
their final reread. Cargo/npm definitions and Cargo workspaces retain their
complete size/digest pins. Schema `1` retains its original commitment. Unknown
schemas and an old digest under a schema-2 label are rejected.

`CONTROLS.json` is produced by the runnable control below. Schema `1` reproduces
the historical failure. Schema `2` verifies the distinct build while preserving
the exact normative lock bytes. These are synthetic identity fixtures, with no
binary production or platform-qualification claim.

```sh
sh artifact/python-run.sh research/sdk-alpha1/evidence/20261109-release-lock-rebuild/reproduce.py
sh artifact/python-run.sh -m unittest -v test_continuity_release_manifest
```

The focused suite retains the 31 original checks and adds seven tests covering
stable rebuilds, preserved schema-1 semantics, explicit schema selection,
normative package/dependency/interface/path changes, Cargo/npm/workspace pins,
unselected artifact changes, mismatched source/artifact bindings and mutation of
input rows. Each negative case must reject; the implementation never retries
another schema after a digest mismatch.

`HISTORICAL_GRAPH.json` independently recomputes the original graph digest of the
retained 16-package candidate capture from 7 November. Its schema-1 digest
remains exactly `a3985d5e0e56196368a3349c37a9589faf2526682b9cf37d8912bd9479eb07ad`.
This is a historical graph-commitment check; the original capture retains its
full input and qualification scope.

The final 0.2.0 admission uses schema `2` when it constructs its normative lock.
The freeze flags, historical receipts, artifact selections and publication state
remain unchanged by this correction. Formal native/Android/service distribution
and their selected artifacts remain the recorded packaging work.
