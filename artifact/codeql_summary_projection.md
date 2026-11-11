# Stage3 and Stage4 read-target projection

The `projection` mode gives the full Rust SummaryStats query an explicit,
source-bound compiled plan. Within each of the Stage3 and Stage4 forward
recursions, it carries the six columns consumed by the next forward state. The
original eleven-column read relation is reconstructed after each closure for its
complete downstream consumers, including reverse traversal and PathGraph. The source patch retains
the original join, both type checks, and both access-path branches.

The retained-database controller exposes three explicit modes:

| Selected mode | Full SummaryStats plan | Embedded library source | Evaluator join option |
| --- | --- | --- | --- |
| `none` (default) | Original official QLX | Original official source | `none` |
| `all` | Existing fixed join-order capsule | Original official source | `all` |
| `projection` | Fixed Stage3+Stage4 target-projection capsule | One declared vendor patch | `all` |

`projection` is an admission mode, not a new CodeQL command-line value. Its
compiler input key is `6a7530eb694360655ab8331a895c9fcd`. Both retained-database allocation arms use
the same capsule and patch. The comparison command must select `projection`
explicitly; reports from other modes cannot be substituted even though `all`
and `projection` have the same evaluator join option.

## Source and plan identity

[codeql_summary_projection.json](codeql_summary_projection.json) pins the
official Rust CLI 2.27.2 bundle, all 39 root-query identities, the original
compiled-query inventory, the projected inventory, and the complete capsule.
Its digest is independently fixed in the installer. The capsule contains the
full SummaryStats QLX and its 15 referenced stages. Its SHA-256 is
`5b17fb41cd3c59fea564ec4e9cb49ef586c0ad06ccc3f2445e46b7b5ca8430cb`.

These pins identify the Stage3+Stage4 product. The earlier Stage4-only capsule
has a different compiler key, source inventory and compiled-query inventory;
the current admission checks distinguish those products even though their
controller mode is named `projection`.

The vendor patch changes only
`codeql/dataflow@2.1.15/codeql/dataflow/internal/DataFlowImpl.qll`. The manifest
binds its upstream digest, exact patch digest and effective digest. The
compressed inventory enumerates all 1,175 files in the root query pack's
`.codeql/libraries` directory before and after that one change. The installer
applies the patch to this actual embedded dependency, where the published pack
resolves its library; an external overlay cannot stand in for the resolved
source. It also binds the pack's six local `.qll` support files, including
`Stats.qll` and `TaintReach.qll`, and its three package metadata files.

The full root query remains byte-identical to the official query, with SHA-256
`7278d53373afb4f8069122e287c9c036a959ba0d167c152d67cd0de885881d67`.
The other 38 QLX files also remain byte-identical to the bundle. The declared
vendor change is a transitive source change for the projected full summary.

## Installation and evaluation

The controller first authenticates the original bundle and query set, then
cross-checks their identities against the selected capsule's fixed manifest. The
projection installer then checks the fixed manifest, patch, complete dependency
inventory, root queries, compiled queries, support files and every capsule
member before it changes the pack. Patch application requires exact hunk
positions and source context, with no fuzzy application or subprocess.

It records the original vendor source, original full QLX, exact patch and source
inventories in the evidence directory. New stages and pending replacement files
are created exclusively. It replaces the vendor source, replaces the full QLX
last, and reopens the complete installed state before returning an admitted
identity. An installation error ends the run before the JVM probe or evaluator;
a partially installed pack must be discarded and restored from the bundle.

After the supervised evaluator stops, the controller rechecks both the full
query inventory and the projection's source/capsule closure. A secondary
integrity failure is retained alongside the original evaluator failure. A
successful result requires exactly the 39 admitted precompiled queries, zero
implicit compilation, all 39 fresh results, equality with the retained 38
results, and full semantic equality between allocation arms. Source and plan
admission do not change the result comparison or resource budget.

Select the mode in the existing controller:

```sh
sh artifact/python-run.sh artifact/codeql_summary_control.py run \
  --codeql "$CODEQL" --tool-archive "$CODEQL_ARCHIVE" \
  --output "$RUNNER_TEMP/summary-projection" \
  --profile heap-2048 --summary-plan-mode projection
```

For the paired result, use `compare --summary-plan-mode projection` with the
existing baseline and candidate report arguments. Installation uses fixed
compiled bytes; it performs no compilation or download of its own.

## Production analysis

The SDK workflow selects the reviewed projection explicitly for native, WASM
and macOS-origin Rust databases. Compilation and extraction retain their
existing platform tools and source-coverage checks. Linux native preparation
authenticates the fixed protoc 3.21.12 release by size and SHA-256, verifies its
version and compiles a schema with a standard protobuf import before exporting
the tool paths. WASM preparation compiles an object with the runner's existing
clang; profile preparation then records the selected compiler path and checks
its WASM target support.
These target-specific steps use the required tools directly without refreshing
the operating-system package index. Each Linux analysis worker
downloads the fixed 98,247,028-byte official Rust archive, verifies its digest,
and passes it to `codeql_rust_profile.py analyze --summary-plan-mode projection`.
The production command uses the existing 14,000-MB budget, 9,329 MB outside the
Java heap, four threads and the single five-hour supervisor.

`codeql_rust_plan.py` restores a private runtime from the authenticated archive
and installs the same reviewed projection. It binds all 2,282 runtime files
outside the separately admitted query pack, an empty private QL configuration,
the complete frozen suite and the database source root. Before publication, the
producer rechecks those identities and requires exactly 39 precompiled loads,
39 completed queries, zero implicit compilations and all 39 fresh result files.
The publisher independently validates the resulting plan and runtime receipts
alongside the existing source, compiler, target-coverage and SARIF checks.

The version-two plan receipt binds the complete per-query completion set to
the original `analyze.stderr`, including its byte count and digest. Publication
rereads that file and requires the exact 39 admitted query identities. Internal
evaluator logs retain their observed completion count and continue to supply
the independent start, precompiled-load, compilation and allocation evidence.
This accounts for the pinned CLI retaining all 39 completion messages on
stderr while its internal log can omit individual progress messages.

Production and diagnostic execution share the bounded evaluator-log reader.
The production command selects progress verbosity. A display-only sink prints
completion counts for distinct
admitted queries as stderr arrives; the original byte stream is retained.
Completion and publication still depend on the full result receipts.

CodeQL jobs queue by language or Rust target. A delayed platform job therefore
does not reserve every language's queue. The publication job still requires the
native, WASM and macOS results from its own workflow and source revision.

The one-off integration and nonempty-fixture workflows belong to their
diagnostic branches. Ongoing regression coverage uses the existing artifact
test discovery and target preflight checks.

## Why the source transformation preserves the fixed point

Write the original full read join as `R = H(X)`, where `X` contains the other
forward-recursive relations, and let `P` project a read tuple to its six target
columns. The only recursive consumer of `R` uses `P(R)`, so the original system
is `X = G(X, P(R)); R = H(X)`. The candidate uses
`X = G(X, T); T = P(H(X))` instead. For any assignment to `X`, the helper body
is precisely the existential projection of the original body: its five extra
existential witnesses are exactly the five discarded columns.

The map `(X, R) -> (X, P(R))` preserves the initial empty relations, commutes
with each immediate-consequence step, and preserves increasing unions. Thus
the two positive systems have the same least fixed point on their common
forward state. Computing the unchanged `H(X)` after convergence restores the
full read relation for subsequent consumers. Stage3 and Stage4 select this helper;
the other stages retain the original read path. Stage2 is unchanged, and the
Stage3 argument preserves the exported relations used as Stage4 inputs. The same
argument therefore applies to Stage4 with those preserved inputs.

The frozen candidate compiled successfully with the official CLI, and its
optimized RA places the six-column helper within each selected stage's forward
recursive layer and the complete eleven-column relation outside it. Both later
`readStepFwd` consumers retain the complete relation. These establish source
equivalence and the intended compiled structure. Runtime completion and resource
measurements are obtained from the explicitly selected evaluation and retained
in its report.

## Maintenance and verification

The fixed manifest and capsule isolate this optimization from the general
allocation controller. `codeql_summary_plan.py` shares only bounded capsule I/O,
header/closure checks and effective-member validation; the existing `all`
manifest, compiler key and capsule bytes are unchanged. The projection module
owns its source inventory and patch contract. It does not accept a caller-supplied
manifest or arbitrary vendor patch.

When updating the official CodeQL bundle, rebuild and review the projection as
a new set of pinned artifacts: exact upstream/preimage and patch, full dependency
inventories, unchanged root/other-query inventories, compiler input key, closed
capsule, and source/IR equivalence. A new manifest digest is an explicit review
boundary. Preserve the original consumers and rerun the complete result
comparison for the updated plan.

The focused regression suite runs without a CodeQL installation:

```sh
sh artifact/python-run.sh -m unittest -v \
  test_codeql_summary_control test_codeql_summary_plan \
  test_codeql_summary_projection test_codeql_process_resources \
  test_codeql_rust_plan test_codeql_rust_profile test_codeql_rust_publication \
  test_codeql_rust_transfer test_codeql_progress test_codeql_workflow_contract
```

It uses the real frozen capsule with small synthetic source fixtures for
filesystem and patch failures. The production source inventory is separately
checked against a freshly extracted, authenticated bundle. Controls cover altered
sources, absent or extra dependencies, symlinks and special files, changed patch
or capsule bytes, stage closure and compiler-key mismatches, partial writes,
post-evaluation mutation, mixed modes, and incomplete or unequal full results.
