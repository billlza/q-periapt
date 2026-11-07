# Continuity release-manifest identity contract, revision 1

`artifact/continuity_release_manifest.py` implements the package, export and
normative-file consistency part of the
[0.2.0 admission change](RELEASE_0_2_ADMISSION_PLAN.md). It reads actual files under
an explicitly selected root and checks their sizes and SHA-256 digests against an
independently selected manifest. It also checks the selected source commit/tree,
package definitions and dependency order, separate C interfaces, and the
specification lock.

A successful result means **identity consistency**. The verifier neither runs
the referenced qualification tools nor approves a release. Both its input and
output require `release_claim_eligible: false` and `publication_performed: false`,
including in `release` mode. Existing package, platform, security-review and
journaled-publication contracts retain their responsibilities. No new device,
paper theorem, benchmark or publication channel is selected here.

## Inputs and independent selection

All file references have exactly three fields:

| Field | Meaning |
| --- | --- |
| `path` | Canonical relative path under the selected root, with no traversal, absolute path or symlink components. |
| `bytes` | Actual positive integer file size. |
| `sha256` | SHA-256 of those exact bytes, as 64 lowercase hexadecimal characters. |

The caller supplies the expected manifest SHA-256, source commit, source tree and
stage independently. The verifier does not obtain these expected identities from
the manifest being checked. It does not infer them from a possibly dirty checkout
or claim that the whole checkout is clean. A captured inventory can refer to its
recorded committed source while unrelated authoring continues elsewhere.

Files are read with the shared `evidence_io` no-symlink, regular-file snapshot
helpers. Duplicate paths with contradictory pins, duplicate JSON keys, non-finite
JSON numbers, missing files and changed bytes are rejected. The complete referenced
inventory is checked again before a successful result is returned. Artifact hashing
streams bytes instead of loading an entire native archive into memory.

Bounds are 64 package rows, 32 artifacts and 32 assessment records per package,
1,024 distinct files and 4 GiB total input. Individual manifests/locks are at most
1 MiB, normative/definition documents 2 MiB, assessments 16 MiB and artifacts
256 MiB. These are verifier input bounds, not product resource budgets.

## Manifest schema

The main document has these exact fields:

- `schema_version: 1`, `kind: "qperiapt.continuity_release_manifest"`.
- `stage: "candidate"` or `"release"`; `product_version: "0.2.0"`.
- `source: {commit, tree}`, each an exact 40-character lowercase Git identity.
- `spec_lock`: one file reference to the specification inventory below.
- `packages`: ordered package rows, in dependency-before-consumer order.
- `interfaces`: the separate `sdk_c` and `continuity_c` entries below.
- `release_claim_eligible: false`, `publication_performed: false`.

Every package row has exactly `id`, `role`, `name`, `version`, `format`,
`metadata`, `workspace`, `dependencies`, `interfaces`, `artifacts`, and
`assessments`.

| Field | Contract |
| --- | --- |
| `id` | Unique stable row ID; dependency edges use this ID. |
| `role` | `sdk`, `engine`, `native`, `swift`, `kotlin`, `android`, `browser`, `service`, or `independent`. |
| `name`, `version` | Actual package identity, checked against the pinned definition. Versions are exact `major.minor.patch` strings. |
| `format` | `cargo`, `npm`, or `distribution`. SDK/engine roles require Cargo; native/Swift/Kotlin/Android require a distribution identity; browser permits its Cargo bridge and npm package; service permits Cargo or distribution. |
| `metadata` | File reference to the actual Cargo manifest, npm package definition, or distribution identity document. |
| `workspace` | Pinned Cargo workspace manifest when needed for inherited versions/dependencies; otherwise `null`. Non-Cargo rows require `null`. |
| `dependencies` | Unique preceding row IDs. Cargo normal, build and target-specific production dependencies are checked against this set; internal dependencies must use exact matching versions. Development dependencies are separate. |
| `interfaces` | Zero or more of `sdk_c`, `continuity_c`, with matching package versions. The native companion must name `continuity_c`. |
| `artifacts` | File references to actual archives/binaries. An empty candidate list records that no artifact is selected. |
| `assessments` | File references to original JSON assessment reports. Candidate records may retain unfinished outcomes. Release-mode records must say `completed: true` and have no `failure` field. Their full scope and provenance remain in the pinned reports. |

Package IDs and `(format, name)` identities are unique. Cargo and npm legitimately
use the same `q-periapt-sdk-wasm` name; Cargo dependencies resolve only against
Cargo rows. The verifier follows Cargo aliases by their real package name.
An SDK row cannot depend on the Continuity engine; the engine depends on SDK rows.
Cycles and missing graph edges are rejected.

A Cargo local dependency path must resolve to the selected dependency's actual
`Cargo.toml`, inside the input root and without a symlink route. A matching name
and version do not admit a different local directory. Inherited dependency paths
are resolved from the pinned workspace directory. The selected workspace must
match the package's explicit workspace setting or its nearest enclosing workspace;
implicit selections are checked again before completion. Member-level inherited
dependencies can add feature/optional/default-feature settings, but cannot replace
the inherited package, version or source. These identity rules follow Cargo's
[dependency inheritance](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#inheriting-a-dependency-from-a-workspace)
and [workspace selection](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-members-and-exclude-fields)
contracts. The original packaging qualifier still owns compiler-specific feature
resolution and installed dependency-resolution checks.

For npm, internal ordinary, optional and peer dependency edges must resolve to npm
rows with exact matching versions. Optional dependencies override same-named
ordinary entries. `npm:` aliases resolve by the target package name, and local
`file:` directory dependencies resolve to the selected `package.json`, including
directory aliases. The graph also retains the browser's same-name/version Cargo
bridge when that bridge is present. Extra or missing graph edges and a null or
targetless `./web` export are rejected.

For `distribution`, metadata has exactly `schema_version: 1`,
`kind: "qperiapt.continuity_distribution_identity"`, `name`, `version`, `source`,
`dependencies`, `interfaces`, and `artifacts`. It repeats the actual selected
distribution's identities; the source, dependency IDs, interface names and
artifact references must match its package row. This document is an identity
projection of distribution construction, not a replacement qualification report.
The verifier checks npm's existing `./web` export for browser packages.

Each interface entry has exactly `abi`, `package_version`, `contract`, and
`exports`. `exports` is the sorted unique symbol list from the pinned declaration
contract. `sdk_c` uses integer ABI `2` and the existing
`qperiapt.c_abi_contract` document. `continuity_c` uses `"qpc-owner/1"` and the
existing declaration snapshot. Their `q_periapt_` and `qpc_` symbol namespaces
remain separate. This does not rerun the existing header/layout/binary checks.

## Specification inventory and release mode

The lock has exactly:

- `schema_version: 1`, `kind: "qperiapt.continuity_spec_lock"`, `stage`,
  `product_version: "0.2.0"`, `frozen_product_contract`.
- `normative_files`: exactly the `protocol`, `wire`, `state`, `storage`, `metadata`,
  `budgets`, and `upgrade` roles, each containing one distinct file reference.
- `supporting_files`: additional distinct normative references, including the
  selected enrollment, bootstrap, directory, authority and witness contracts.
- `compiled_descriptor`: the separately retained compiled contract output, or
  `null` for a candidate inventory without that output.
- `package_graph_sha256`, `interfaces_sha256`.

`package_graph_sha256` is `canonical_digest` of package rows with only `artifacts`
and `assessments` omitted. `interfaces_sha256` is `canonical_digest` of the full
interface object. The implementation exposes `package_graph_digest(packages)` and
`canonical_digest(value)`, using the existing publication canonical-JSON function.
Callers should use these helpers rather than an independently formatted JSON dump.
Actual package-definition and interface file pins therefore participate in the
lock; individual build artifacts and assessment reports remain in the outer
manifest. The lock must not reference itself or the outer manifest.

Candidate mode retains false freeze flags, current unpublished package versions,
and an honestly incomplete distribution inventory. Its result reports which
release roles are absent. No absent artifact or compiled output is generated or
inferred. In particular, copying the budgets file to a new name is not evidence
that a program emitted it; an actual retained compiled output and its original
producer evidence must be selected when claiming that provenance.

Release mode additionally requires a frozen normative descriptor and Continuity
ABI identity at product version 0.2.0, an equal separately retained compiled
descriptor, all twelve existing SDK crates, the already agreed package surfaces,
the actual npm browser surface, and nonempty artifact/complete-assessment lists.
The independent testing implementation may keep its own version. Source and
artifact pins still require independent selection; a `completed` report field is
not treated as broad security or publication approval. The verifier's result
remains an identity-consistency result with release eligibility false.

The original `continuity_contract.validate` and C candidate reader are unchanged.
The new verifier checks the selected freeze state separately and reuses the
candidate descriptor grammar on an in-memory validation copy. It never rewrites
the candidate budget or declaration files. Moving from candidate to release
therefore requires the actual coordinated admission change, not relabeling this
manifest.

## Running the check

With the independently retained pins supplied by the caller:

```sh
sh artifact/python-run.sh artifact/continuity_release_manifest.py \
  --root "$inventory_root" --manifest "$manifest_relative_path" \
  --manifest-sha256 "$selected_manifest_sha256" \
  --source-commit "$selected_source_commit" --source-tree "$selected_source_tree" \
  --stage candidate
```

The command prints its verification result only after every required check and
final input reread succeeds. It performs no repository, registry or publication
mutation. The caller may retain the result with the exact manifest and original
assessment receipts. The release tooling still owns actual publication and its
unknown-outcome reconciliation.
