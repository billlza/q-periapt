# Installed Rust and independent Python lifecycle

The complete existing installed-Python registered-owner runner passes on Apple
Silicon at `6ce866b31088b3215bcc24bcfef84b4075ff5907`. Its Rust counterpart was
built outside the checkout from the actual installed SDK crate archives and a
freshly packaged Continuity candidate. Python was installed from its exact wheel
outside the checkout. The build and runtime reports identify the same native
binary, and both recheck their inputs after execution.

| Input or boundary | Observed identity/result |
| --- | --- |
| SDK producer | `6084f3bfb09333f6b66291b38809ed512296a27b`; report SHA-256 `d9cd990bf3dc6a731ec09b659fdc38f3f3cbc17b2f035b09e5e61094cbc11885` |
| Candidate/consumer source | `6ce866b31088b3215bcc24bcfef84b4075ff5907` |
| Installed native binary | `f7fe7507bdd539b4404709b45df207869b5d06ecfc1f62f979c866e01f8437a8` |
| Python wheel | `596bba62781296558a64d768a12ed618043b8cf3e14070cdf81c2ed423d3a094` |
| Resolver | Nine product crates, 118 external packages; original lockfile retained |
| Toolchain | Rust 1.98.1, exact matching Clippy frontend and driver; both consumers pass build and strict Clippy |
| Independent provider | cryptography 48.0.1 / OpenSSL 4.0.1; CPython 3.14 |
| Runtime | 25 top-level commands return zero with empty stderr; 22 explicitly invoke this installed native binary |

The runtime covers its existing one-time publication and directory readers,
registered local/witness owners, enrollment sessions and post-expiry extension,
intermediate-peer recovery, three/32-member account paths, pending outcomes,
archived-writer storage migration, roster refresh/revocation, local/witness policy
continuation, and policy/credential/roster composition including capacity. The
original per-scenario assertions and scope statements remain in the captured
reports. In particular, archived format-five to format-nine migration is not a
claim of complete Witness handoff, and explicit fixture-clock expiry is not a
wall-clock/device expiry result. SIGKILL evidence is not physical power loss.

The real directory CLI's same 15 Release public files from the
[P2 checkpoint](../20261104-directory-cli-crosscheck/README.md) also pass in this
installed runner. Its output-loss retry, cancelled history and canonical-conflict
checks retain their historical-only scope. The directory producer itself remains
source-built. This run adds actual installed Rust/Python interoperability; it
does not reclassify the separate CLI producer or every source-only independent
scenario as installed qualification.

## Reproduced toolchain-routing defect

The first independent-clone build at `0fa0e17d` built the native consumer but
failed Clippy with E0514: Rust 1.98.1 metadata was read by the Rust 1.99.1 driver.
The selected Cargo executable and leading PATH entry did not determine the
extension used: Cargo searches `CARGO_HOME/bin` before PATH for external commands,
as documented in the [Cargo reference](https://doc.rust-lang.org/cargo/reference/external-tools.html).
The admitted registry cache contained a rustup proxy using the other default.
Three retained real probes distinguish Cargo extension dispatch (Clippy 0.1.99)
from direct selected frontend/driver execution (both 0.1.98).

Commit `6ce866b3` invokes and checks the selected `cargo-clippy` and `clippy-driver`
directly and sets `CARGO` to the same selected Cargo. It retains tool hashes,
warnings-as-errors, exact version admission and end-of-run identity checks.
Nine focused package tests and all 58 independent artifact regressions pass;
the subsequent actual installed consumer/importer builds and Clippy checks pass.
No toolchain default, registry configuration or global installation was changed.

An earlier linked-worktree attempt was refused because the existing provenance
contract requires a real, non-symlink `.git` directory. Its failure is retained.
A clean independent local clone supplied that existing boundary; no provenance
check was weakened. The old failed build and linked-worktree refusal remain
failed attempts, separate from the successful build and runtime cohort.

## Commands and retained evidence

The actual builder used `artifact/continuity_independent_package.py --report`
with the pinned SDK report above, `--report-sha256` with its exact digest,
`--toolchain-root /Users/bhmq03@durham.ac.uk/.rustup/toolchains/1.98.1-aarch64-apple-darwin`,
the existing credential-free registry cache and a fresh
`target/independent-installed-current-02` output. Its exact compiler, packaging,
resolution, build and Clippy commands are in `build-passed/*.json`.

The completed runtime command, through `artifact/python-run.sh`, was:

```sh
QPERIAPT_PYTHON=/Users/bhmq03@durham.ac.uk/.local/bin/python3 \
sh artifact/python-run.sh artifact/continuity_independent_python_run.py \
  --wheel /Users/bhmq03@durham.ac.uk/Desktop/Q-periapt/target/directory-cli-crosscheck/wheel-final/qperiapt_continuity_reference-0.0.0-py3-none-any.whl \
  --provider-root /private/var/folders/_1/c5pzdh_j04q963k2csf4vlkh0000gn/T/qperiapt-directory-python-akg2_n1g/provider \
  --native target/independent-installed-current-02/counterpart \
  --directory-cli-public /Users/bhmq03@durham.ac.uk/Desktop/Q-periapt/target/directory-cli-crosscheck/public-release-02 \
  --output target/independent-installed-lifecycle-01
```

`CAPTURE.zip` retains 223 files: the original failed and successful build command
records, complete installed runtime report and top-level command outputs,
individual scenario reports, exact public directory inputs, public one-time and
lease vectors, SDK report, compiler probes and regression outputs. It also
retains the separate #117 parent-line READY checker regression. Private owner
stores, wrapping keys and signer files are excluded. `SHA256.json` pins every
member; every archived byte was read back. `CHECKS.json` records the joined
identities and checks against 26 builder and 239 runtime source inputs.

This closes the selected local installed-interoperability cohort. Cross-host
execution, other platforms, hosted execution of these commits, final candidate
qualification, product ABI admission and external review remain separate.
The builder's own `runtime_qualified: false` is preserved: runtime qualification
is supplied by the separately executed and hash-joined runtime report, not by
silently changing the build receipt. Neither receipt asserts release eligibility.
