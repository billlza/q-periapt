# CodeQL 2.27.2 command compatibility

This packet preserves the first hosted wrapper failure and the correction to
the command-specific `--qlconfig-file` arguments. The fixed CodeQL 2.27.2 CLI
accepts this pack-manager option for `database analyze` and `resolve queries`.
It rejects it for `version`, `resolve ram`, `test extract` and `bqrs decode`.
The repair removes the option only from those four commands and retains the
private configuration on the two query/pack-aware commands.

## Original hosted result

[Run 43027793640](https://github.com/billlza/q-periapt/actions/runs/43027793640),
job `130546797767`, used source
`cd84d3cb051651c0edc634705d086a0824837725`. Its nine workflow contract tests
passed in 0.003 seconds, and both historical artifact readbacks completed.
The source inputs, authenticated tool downloads and toolchain setup completed.
The fixture then stopped at `codeql test extract`: exit 2 after
0.266631261 seconds, with `Unknown option: --qlconfig-file` in `extract.stderr`.
Extraction had not started, and no query or query compilation ran in this
wrapper attempt.

`original-artifact.zip` is the unchanged uploaded artifact `13858241410`,
originally named `codeql-wrapper-fixture-43027793640-1`: 1,111,042 bytes,
SHA-256 `9ebece8ac152f57aca7590f1cc19cac982099a4fcb155086ea4eb2ba4d25c6bf`.
`ARTIFACT_API_READBACK.json` records the matching GitHub artifact identity.
`ARTIFACT_MEMBERS.json` records its member census.

The complete decoded job log is also unchanged and has Git blob identity
`e09273bf7abb6ea53e864e79b7a782c3a23b3de2`. The standalone `extract.*` and
`FIXTURE_FAILURE.json` files were byte-checked against the artifact's
`qperiapt-codeql-wrapper-fixture/evidence/` namespace. The same archive also
contains historical Rust extraction readback files; those are separate inputs,
not the result of this attempted fixture extraction.

## Command compatibility evidence

`CLI_SUPPORT_REVIEW.json` binds the official 98,247,028-byte Rust bundle and
its JAR hash. Its static check follows the command classes, superclasses,
Picocli mixins and argument groups to the actual option declaration. It also
records four executed parser controls that reject the unsupported option with
exit 2 before opening their intentionally absent inputs. These controls perform
no extraction or query evaluation.

`parser-controls.zip` is a newly assembled container of the 31 unchanged local
parser/help records. Their original names, byte sizes and SHA-256 values are
listed in `RUN_READBACK.json`. The earlier diagnostic combinations with `--help`
are retained: this CLI prints help before checking unknown options, so those
exit-zero outputs are inconclusive for option acceptance. The later rejection
controls omit `--help`.

The small static inspection script is retained. The runtime archive, JAR,
raw class bytes and bulk declaration dumps are excluded; their identities and
the relevant class/mixin closure remain in `CLI_SUPPORT_REVIEW.json`.

## Repair and completed local regression

| Patch | Local commit | Changes |
| --- | --- | --- |
| `production-cli.patch` | `bacd692a15d3a9d29cbb39324396f04311cea40d` | Remove unsupported arguments from version and RAM resolution; adjust the memory-helper API and its command controls. |
| `fixture-cli.patch` | `10729f12f62029901ec700266e0f5dd400c0011e` | Remove unsupported arguments from fixture extraction and result decoding; remove the unused extraction configuration and adapt the memory-helper call. |

The local producer/plan regression passed **58 tests in 2.401 seconds**.
`TARGETED_TESTS.json` and `targeted-python-tests.log` preserve the command,
timing, source hashes and original output. The wrapper passed its AST parse.
These results are distinct from the nine earlier hosted workflow contracts.

The authenticated runtime, controlled environment, private analysis
configuration, full 39-query selection, precompiled-query observation and
result/SARIF gates remain in place. The subsequent corrected wrapper execution
is recorded separately; it is not included in this packet.

## Integrity and assembly

`FIRST_WRAPPER_EVIDENCE_MANIFEST.json` is the unchanged source handoff manifest;
its ZIP filename refers to the original download name. `MANIFEST.json` binds
every file at its final packet path, including `original-artifact.zip` and the
new parser-record container. `RUN_READBACK.json` records the namespace mapping,
identity checks and scope. Assembly copied and hashed existing evidence only;
it did not rerun tests, launch CodeQL or start a workflow.
