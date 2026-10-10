# Actual v21 reader against the v22 publication registry

This macOS arm64 study runs the previously qualified, unmodified C executables
and libraries from `ce70bf83a6f131b6727b67e9c9a4b8266abe72ef`. Both Debug and
Release binaries match their retained hashes and export the original 119-entry
interface, with no publication entry point. The current C clients and an isolated
extension of the `f9ae04b9` registration harness create and exercise the state.
The old reader is not recompiled or replaced with a model of its parser.

Both profiles observed the same sequence:

1. The old executable successfully activates the original v21 installation.
2. The current owner prepares a publication, changing that journal's active image
   to `QPVLT022`. The old executable now refuses activation with `QPC_CORRUPT` (209).
3. The current client reopens and retries the original publication ID and plan,
   returning byte-identical artifact data.
4. After the current client retires the public artifact, the permanent ordinal
   registry still produces `QPVLT022`. The old executable again refuses with 209.
5. The current client preserves the next ordinal and completes the original
   registration, TLS, application-delivery and roster-refresh workload.

Each old-reader invocation is bracketed by complete key/value-transcript hashes
for the SDK policy, enrollment, installation and journal user tables, including
their exact table identities and entry counts. All four remain unchanged. The
wrapping and signing files and the directory namespace remain unchanged too.
In both v22 refusal cases, the archive database is never reached and its complete
file bytes also remain unchanged. These are actual state comparisons in addition
to the error code and successful current-client recovery.

## Why whole-file identity was the wrong initial test

The initial stronger hypothesis failed: the old reader changed the physical
bytes of the four redb databases it opened. Its successful v21 control also
opened the archive database and changed that file's bytes. This is observable
database activity, so the result must not be called physically read-only.

The pinned redb 4.3.0 implementation closes a `Database` by persisting allocator
state and a shutdown header (`src/db.rs:1957–2028`). The captured source excerpt,
hash and third-party licenses identify that implementation. The final probe
therefore separately records physical changes and compares every user-table
entry, key-file bytes and namespace. The original failing runs are retained;
they are not hidden behind the final passing result. An intermediate diagnostic
incorrectly labelled the admitted control's archive bytes as unchanged; final
Debug/Release `06` captures explicitly correct that field to `false` for the
control and require `true` for the v22 refusals.

`QUALIFICATION.json` records exact old/new executable and library hashes, build
commands, Clippy success, stage outcomes and full normal-workload readback.
`CAPTURES.zip` has 224 members, 208,345 bytes, SHA-256
`ed7da94afc0215d5c982b294422cfdb471800d2816a4f363b56f183e09a3ab3a`.
It includes the isolated harness, a 202-line patch against its recorded base,
drivers, diagnostics and public artifacts. Private database files, wrapping keys
and signer bytes are excluded. The host-only repeated-output filename is retained
under another public name before retry because the C fixture deliberately creates
its output file exclusively; the protocol operation identity never changes.

This closes the actual-old-binary check for these two v22 states and this pinned
prior build on macOS arm64. It provides no crash/power-loss, physical-erasure,
general future-schema, independent-implementation or release qualification.
Format refusal still performs database I/O. No product or protocol code was
changed for this study, and no database durability check was disabled.
