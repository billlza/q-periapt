# Scanner content-read budget

The scanner checked `metadata.len()` before an unbounded `read_to_string`.
A file growing after that check could exceed its stated 2 MiB content budget.
The content reader now consumes at most 2 MiB plus one detection byte and rejects
oversized input. It never treats truncation as a complete scan. Invalid UTF-8
still fails explicitly. No SDK protocol, cryptographic constant or ABI changes.

The parent is `b626bf923d045f0cf1a25c7d6c61159f87e76e0e`; the qualification
record pins the modified implementation separately. `red.patch.gz` only extracts
the existing reader and adds the regression. Applied to that parent, it
reproduces the exact executed source hash. The old reader fails the target
assertion with cargo exit 101. Growth is inserted deterministically between
metadata admission and the actual reader call, without timing hooks or mocks.

Both Rust 1.98.1 and minimum Rust 1.90.0 pass:

```sh
cargo test --offline --locked -p q-periapt-cli --all-features
cargo clippy --offline --locked -p q-periapt-cli --all-features --all-targets -- -D warnings
```

Each test run has 12 library, one binary and seven inventory tests. Direct calls
to both actual binaries separately check four JSON/exit cases: ordinary input
(0, complete); exactly 2 MiB of multibyte UTF-8 ending in a legacy finding
(2, complete); 2 MiB + 1 byte (1, incomplete); invalid UTF-8 (1, incomplete).
`PROCESSES.json` binds each binary, input and output. Raw streams and the red
patch use lossless gzip, preserving their original bytes. Formatting and diff
checks are required before the source commit.

This repair enforces a per-file content budget. It does not provide a total
scanner memory/time limit, an atomic snapshot of a changing tree, or protection
against concurrent hostile pathname replacement. The related CodeQL path
finding is not automatically dismissed by this separate resource-bound repair.
Hosted CI and complete 0.2.0 readiness remain separate gates.
