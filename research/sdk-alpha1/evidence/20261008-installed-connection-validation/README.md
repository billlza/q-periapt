# Installed-connection producer validation

The producer fix `b20cafd7` takes an explicit real Rust toolchain root. It no
longer strips the caller's private rustup home then relies on `cargo +1.98.1`.
The retained failing invocation shows that a real Cargo executable rejects that
proxy-only selector. The installed producer now verifies Cargo/rustc/sysroot,
uses explicit compiler paths, and binds the clippy tools before and after work.
The complete installed macOS baseline and native Linux connection are in the
adjacent connection checkpoint.

The clean standalone clone at `acac92b0` passed **2,659 artifact tests** with
warnings treated as errors and **no skips** in 554.036 seconds of test time.
Its complete runner took 556.005 seconds. Source identity remained unchanged.
The `artifact` Git subtree is identical at source-gate commit `f5115b2f`, whose
current/historical proof-input checks pass at **254/249**, with release eligibility
still false. Documentation-only successors retain their own source-gate checks.

Before the next authorized push, Rust CodeQL job `113316063560` for uploaded
head `33ca8c5c` completed analysis, source recheck, quality, upload and retention
successfully at 14:21:11 UTC. Artifact `11556178682` is retained, unexpired,
475,351,461 bytes, with API digest
`a51ec293b4d89efe8fdb1f018a5cfe1c6410b5af34eb50f8544fcb7855d83fd7`.
This checkpoint captures its API metadata; it does not claim to have downloaded
or disposed the new SARIF findings. That successful prior run does not qualify
later changes, and the complete 0.2.0 goal remains open.
