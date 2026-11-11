# CodeQL optimization integration

This packet records the completed implementation and integration checks for
candidate [`4fb3b2db1d6647ec4fa85fb8bd744b1d97ef1215`](https://github.com/billlza/q-periapt/commit/4fb3b2db1d6647ec4fa85fb8bd744b1d97ef1215),
tree `b5c6e256b9abb95a8163efae052c34ae6bd0f035`, based on SDK
`4870db5eff0a611973a302f29e94c0992df66cfe`. The public commit uses the existing
project author's public Git identity. Its tree matches the locally integrated
source recorded in `SOURCE_IDENTITY.json`.

## Recorded results

| Check | Recorded result | Evidence |
| --- | --- | --- |
| Projection admission and mode contracts | 159 tests passed in 8.765 seconds; real official-bundle admission and final recheck passed. | [Separate admission packet](../20261111-summary-projection-admission/README.md) |
| Scheduling, profile, publication and transfer contracts | 80 tests passed in 1.614 seconds on the scheduling change. | `schedule/RECEIPT.json` and its retained test-output chunk |
| Combined CodeQL integration | 207 tests passed in 10.144 seconds at the recorded integration inputs. | `INTEGRATED_TESTS.json` and the original `integrated-tests.log` |
| Windows license fixture control | The original Windows CRLF mismatch was reproduced; the corrected fixture passed the existing test under native and CRLF-emulated writes. | `windows/RECEIPT.json`, before/after logs, and the original hosted job log |

The combined invocation checks overlapping component suites. Each count above
describes its recorded invocation.

## Source correspondence

The 207-test invocation used the working contents subsequently committed without
changes as `099349204e6366314fdc74985e95abafa559c6b0`, tree
`eaded9357e0a639ee796be44319b690e9842e45b`. Its command was:

```sh
# Working directory: artifact
python3 -m unittest -q \
  test_codeql_summary_archive_input test_codeql_summary_control \
  test_codeql_summary_plan test_codeql_summary_projection \
  test_codeql_process_resources test_codeql_rust_profile \
  test_codeql_workflow_contract
```

`SOURCE_IDENTITY.json` binds 54 corresponding inputs: the changed integration
files, repository-local imports of the selected tests, pinned query/capsule
inputs, Rust quality queries, and production workflow. Every listed input is
byte-identical in the published candidate tree.

Three files changed after that combined invocation: the Windows fixture received
its separately verified one-line correction, and `docs/SDK_0_2_RELEASE_READINESS.md`
and `docs/SDK_INTERNAL_REVIEW.md` received the engineering review documentation.
The implementation before those two documents is commit
`d86dc60cfa08ae3344ace7291c26ee7e1b5f800e`, tree
`8f0a3a2872babe196000a18ce03e579767fe517d`. This correspondence preserves the
actual test sequence while binding the checked implementation to its public
source.

## Scheduling and failure behavior

The candidate removes the duplicate integration-branch push subscription from
general CI while retaining all PR, main, tag and manual entry points. The entire
CI `jobs` section and production `codeql.yml` are byte-identical to the SDK base;
their hashes are recorded in `SOURCE_IDENTITY.json`.

The retained SummaryStats experiment is selected explicitly through
`diagnostic/codeql-summary-projection` or manual mode selection. The projection
capsule, exact source inventory, complete query/result requirements, failure
controls and independent review are retained once in the adjacent admission
packet. Current-source production analysis continues through its existing full
query and publication gates.

## Windows fixture diagnosis

[Hosted job 130442108833](https://github.com/billlza/q-periapt/actions/runs/42996553264/job/130442108833)
checked out SDK `4870db5eff0a611973a302f29e94c0992df66cfe`. Its test invocation
reported 187 tests, one failure and six skips. The failure was the synthetic
license fixture's text-mode newline translation: Windows wrote CRLF, while the
exact-byte assertion expected LF. The collector had preserved the input bytes
correctly.

Commit `a680dba994ad235a6cfea7cd65d7e12ab18c87a6` changed that fixture to explicit
UTF-8 byte writing. The targeted control first reproduced the same mismatch on
the original source, then passed the corrected case with both native writes
and Windows CRLF translation emulation. These are local targeted controls;
their receipt records the distinction from a native Windows rerun. Production
collection, inventory hashing and verification code remain unchanged.

## Packet contents

The `schedule/` and `windows/` subdirectories preserve their original receipts,
patches and logs. The Windows hosted log is stored as gzip of the original
connector-decoded UTF-8 text, retaining its CRLF and BOM. `MANIFEST.json` binds
every payload file in this directory by relative path, byte count and SHA-256.
The sibling admission packet retains its own original manifest and complete
receipts, without duplicating its contents here.

This packet covers implementation admission, integration contracts and the
Windows fixture correction. Database runtime measurements and hosted execution
results are recorded in their own source-bound evidence when available.
