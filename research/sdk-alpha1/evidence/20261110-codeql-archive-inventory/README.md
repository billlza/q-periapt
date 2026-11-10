# CodeQL Rust archive inventory repair

The exact integration baseline `0e2ca2d79ab0000bed79130cec97b31181e936ea` reproduces the hosted macOS preparation failure: four of 159 Python tests reject 1241 tracked Rust files against the former 1173-file count. The added 68 paths are frozen bootstrap proof inputs, enumerated in `artifact/CODEQL_RUST_ARCHIVES.md` and their retained source-pin manifests.

The candidate passes all 170 tests in the same eight-module selection, including 11 new archive admission and macro-coverage tests. Every archived path must remain extracted. Each retained source is checked against its exact pinned byte length, SHA-256 and Git blob identity; same-count path substitutions, byte changes, pin rewrites, Cargo manifests and source symlinks are rejected. Raw macro entity and unresolved counts remain complete, with frozen snapshot entities reported separately. Current compiler and peer macro-coverage requirements stay in force.

`RESULT.json` binds the candidate source files, baseline and candidate test inventories, logs and all 68 archive identities. The candidate was tested from a separate normal checkout using CPython 3.14.7 because release provenance intentionally rejects Git worktree pointers. The retained baseline is the successful reproduction after supplying the required sparse workspace manifests.

These results validate the admission repair and its rejection controls. Current-head hosted compilation, extraction and full security-query completion remain separate CI results.
