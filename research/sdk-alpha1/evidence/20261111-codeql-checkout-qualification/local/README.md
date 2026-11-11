# CodeQL checkout qualification

The candidate changes only the non-Rust `analyze` matrix checkout and its existing workflow contract test. Actions, C/C++, Python, Java/Kotlin and Swift retain every tracked object except historical `.zip` payload files below `research/sdk-alpha1/evidence/`. The complete query suites and build steps are unchanged.

## Source and exclusion scope

Base commit: `d2f9035c341db488bf0aba7b440d6548660d62b7`  
Base tree: `5c83921d4f04660d67a668a07944800681513bce`

The complete, non-truncated GitHub tree contains 7,929 regular/executable files totalling 5,027,276,416 bytes. Exactly 542 historical ZIP files account for 4,787,753,249 bytes. All 7,387 other files (239,523,167 bytes on the base tree), including all 1,241 Rust files, remain selected. These are tracked-object sizes, not measured network bytes or a hosted timing result.

The third sparse pattern re-includes directories. This preserves source files under a directory whose name itself ends with `.zip`, while still omitting ZIP files inside it. The regression also checks capsules, paper snapshots, manifests/locks, ordinary logs, uppercase extensions, ZIP digest sidecars and similarly named adjacent directories.

The Kotlin path executes Cargo's FFI build and Gradle tests; the Swift path executes Cargo's FFI build and native Swift tests. Inspection of those source/build files found no historical evidence ZIP consumer or generic provenance invocation. The CodeQL preparation dependency on the retained `consumer-Cargo.lock` remains selected.

## Why Rust keeps a full checkout

`codeql_rust_quality.require_clean_checkout` uses `git_provenance.inspect_worktree`. That shared gate independently compares HEAD, index and every tracked file's actual bytes, rejects skip-worktree/assume-unchanged flags, and remains unchanged. The Rust producer, macOS preparation/import and publication checkouts therefore retain their complete existing configuration. The new workflow test enforces this scope. No source-identity exception or new provenance policy is introduced.

## Fixed checkout implementation

The exact checkout action is `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`.

- [action inputs](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/action.yml): `filter`, multiline `sparse-checkout` and `sparse-checkout-cone-mode`.
- [input helper](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/src/input-helper.ts): filter and sparse patterns are parsed independently.
- [source provider](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/src/git-source-provider.ts): the filter is supplied to fetch, then the non-cone sparse setup runs before checkout.
- [Git command manager](https://github.com/actions/checkout/blob/3d3c42e5aac5ba805825da76410c181273ba90b1/src/git-command-manager.ts): non-cone setup enables sparse checkout and writes the supplied patterns.

The input description's phrase about overriding sparse checkout refers to choosing the fetch filter. The pinned implementation still applies the explicit sparse patterns.

## Executed checks

`qualify_checkout.py` uses actual Git operations in temporary repositories:

1. All 7,929 exact paths and modes are placed in an index using empty fixture blobs. Git's real sparse matching omits exactly the 542 declared ZIP files, retains all 7,387 other paths and their executable modes, and preserves the index tree.
2. A local upload-pack server with filtering enabled serves a separate fixture. A fresh `blob:none` partial clone checks out the exact commit/tree using these patterns. Retained bytes are equal, Git status is clean, and both omitted ZIP blobs remain absent from the object database. This verifies partial-clone mechanics without accessing or downloading the large remote repository.
3. All 10 existing workflow contract tests pass, including the new real Git path boundary control. The unchanged provenance control independently confirms that skip-worktree and assume-unchanged flags remain rejected by the general guard.
4. YAML parsing verifies the selected action inputs and all four unchanged Rust checkout configurations; `git diff --check` passes.

The parent will measure the real GitHub checkout separately. This local qualification makes no hosted wall-time claim.

