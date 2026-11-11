# Retained Rust source files in the extractor file view

This packet records the cause and the narrowly scoped correction for the native
Rust extraction failure in [run 42982431606](https://github.com/billlza/q-periapt/actions/runs/42982431606).
The original source census contained 1,241 files. All 1,241 were extracted, while
the successful-extraction relation contained 1,173. The remaining 68 paths are
exactly the authenticated source snapshots under
`paper/continuity/artifacts/bootstrap/`: each has the same warning that the file
was not included in the files loaded from the manifest. No unexpected path,
extraction error, or unextracted element occurs in this retained result.

## Evidence and correction

`NATIVE_READBACK.json` is the original, unmodified readback receipt produced by
[run 43027793640](https://github.com/billlza/q-periapt/actions/runs/43027793640).
It binds the old artifact ZIP, the selected members, the full missing-path list,
metrics, command inputs, and bounded original diagnostic contexts. The old run
head was `1b47a1931cab2a944902316619cdcf479bd64ab0`; the extracted PR merge checkout
was `0d781a9ddb77bbb5cc9dce5ed1fc82e2a7eeb9f5`. These are distinct identities in
the receipt. `ROOT_CAUSE.json` records the derived equality between all 68
warning paths and the missing archive paths, including a canonical path-set
digest.

The correction in commit `92866a994a0c063689b2ffc250b3f062f6591236` sets
`CODEQL_EXTRACTOR_RUST_OPTION_EXTRA_INCLUDES` to a JSON array containing the
absolute, original archive directory before database creation. This makes the
already authenticated files available to the Rust analyzer's virtual file
system. The pinned CodeQL 2.27.2 extractor distinguishes a file absent from that
file view from a loaded file that is not a Cargo module. The latter retains its
non-module role and is extracted without semantics at informational severity.
The additional file root creates no Cargo package, manifest, or module.

The archive bytes and their original manifests remain intact. Complete tracked
source equality, warning and error gates, and the existing compiler-root and
profile contracts continue to apply. The implementation changes one extractor
environment value; it does not change query selection or publication rules.

## Fixed upstream sources

`UPSTREAM_SOURCES.json` binds the relevant original files at the CodeQL release
commit `a7057b836bf29767461026718b14d20790b9085f`, including the configuration
decoder, loader diagnostics, successful-extraction predicate, and dependency
lock. The `extra_includes` behavior is also traced through the versioned
rust-analyzer 0.0.352 package sources: local package roots feed the directory
loader, which reads the included files into the virtual file system after the
crate graph has been constructed. The listed crate archive checksums come from
the fixed upstream lock file; the versioned docs.rs references identify the
inspected published source. The manifest does not assign Git source-byte hashes
to those published crate source pages.

## Completed regression and next integration readback

`PROFILE_TESTS.json` and `profile-tests.log` preserve the actual 38-test profile
regression, which passed in 1.868 seconds. The added regression invokes a real
child process and verifies that it receives the exact archive-root JSON array,
including a root containing a comma and spaces, and that an unrelated inherited
include is replaced. The receipt binds the three changed files byte for byte.
The command was:

```sh
sh artifact/python-run.sh -m unittest -v test_codeql_rust_profile
```

This packet contains the retained failure diagnosis and the completed Python
regression. The subsequent normal SDK extraction will supply the actual
extractor readback for the corrected file view.

## Packet layout

`MANIFEST.json` records the bytes and SHA-256 of the six payload files. The
readback and test records preserve their original bytes; the root-cause and
upstream-source records are separate derivations. No retained source snapshot,
Cargo manifest, executable reproduction source, or full artifact ZIP is copied
into this packet.
