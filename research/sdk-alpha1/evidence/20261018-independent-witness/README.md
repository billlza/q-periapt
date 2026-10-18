# Independent required-witness recovery

The independent Python session now supports an explicit required-witness profile
against the actual Rust `AnchorStore` and a required-witness Rust journal. The
local and volatile constructors continue to reject that policy. Inactive creation
returns only a public genesis for separately approved control-plane enrollment;
ordinary signed requests cannot register or reset a subject. The new `QPREFW01`
image binds the original scope, witness, subject and writer fence. Its state remains
`QPREFS04`; it is not an implicit migration from a local-only store.

The main scenario passes bootstrap, bidirectional consumption and three alternating
PQ rekeys with 36 fresh-process operations, 244 native commands, three real SIGKILL
cuts and 47 direct negative controls. The process cuts occur after creation intent,
remote advancement and local image publication. The 222 loopback witness attempts
include no-dispatch, lost-reply and corrupt-reply faults. A separate valid-reply
test closes the client during its host transport callback and verifies that the
result is withheld. TCP controls reject oversized/truncated framing and a trickle
that exceeds the total deadline. Their elapsed times are timeout observations,
not performance benchmarks.

A lost witness reply preserves the exact original intent. Once the witness has
committed it, reopening can reconcile AlreadyAppliedExact even after authority
expiry; the reservation remains `Reserved`, and ordinary output is denied. With
the fixture's valid clock restored, the original send resumes and exact replay
returns the same ciphertext. Actual witness-store close/open retains its head.
An old client backup is rejected. An external writer fence applied after a local
send commits prevents output and subsequent reopening under the old fence.

All ten previous local lanes also pass on the same 55-source closure. Four public
readers complete without diagnostics, checking source/binary identity, worker
PIDs and cut markers, native command bytes, actual plaintext results and protocol
transcripts. The witness reader verifies 221 signed witness replies, 223 distinct
challenges including the direct close control, the original recovered genesis,
exact commands across retries and all 12 signed rekey flights. Private image
authentication and the direct close/rollback/timeout refusals remain runtime
assertions; the readers load no private images or keys.

Release build, strict all-target Clippy, rustfmt, workflow lint and 46 focused
source-contract tests pass. The real Git source snapshot contains 724 Rust files;
this is not a new CodeQL database analysis. The actual ARM64 Mach-O counterpart is
SHA-256 `c7c7d98d5b11e055601e411b3f13da7bc59268cbcd0c5647a9749953cc28f38d`.

`CAPTURE.zip` contains the eleven final public lanes, exact sources, actual binary,
four readers and outputs, build/lint/source checks and a verified member manifest:
11,345,004 bytes, 4,121 members, SHA-256
`1f01e73a2b0bcde4d6ffd5e27350d4f5ee31fefb9bf3306c72bac73fbadc3b64`.
The first build's wrong test-adapter argument, launcher import error and incorrect
`PendingSend` test expectation are retained as diagnostic history. The latter was
corrected to the existing `Reserved` contract; no runtime behavior was changed to
make that assertion pass. Original interrupted private directories remain local.

This closes the bounded witnessed bootstrap/traffic/rekey recovery path, not the
independent product lifecycle. The loopback bridge is test orchestration and
exposes public witness metadata. Whole-witness rollback, whole-service process
restart, separate-host deployment, authority renewal/revocation/migration,
installed-package admission, physical erasure, power-loss qualification and PCS
proof remain outside this checkpoint. Hosted qualification is pending.
