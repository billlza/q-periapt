# Paper CI qualification, 11 November 2026

This record accompanies the paper branch's Rust analysis and Android cleanup
repairs. The reviewed `paper/continuity` tree remains
`dae7ffda4ed5431a69b17167e1aad4268d64192a`. `paper-sync-identity.json` records
the existing paper/PDF/export verification and the metadata-only replacement
of the unpublished synchronization commit with the repository owner's public
author and committer identity.

## Rust analysis

The original failure was the Rust job
[129965837798](https://github.com/billlza/q-periapt/actions/runs/42855086715/job/129965837798)
at `11e113f27d7708474cd55713d4a22cc028f80944`. Its 38 security queries
completed. The quality gate then treated 68 immutable, partial paper source
archives as current Cargo sources. Those archives have no Cargo manifests and
the extractor records the specific missing-semantic-context diagnostic for
each of them. The 106 current Rust sources were successfully extracted.

The repair keeps all tracked Rust sources in the database and all security
queries enabled. Current source paths must all be successfully extracted and
their unresolved macro count must be zero. Archive qualification requires the
existing exact source paths, bytes, SHA-256 and Git blob pins, the five pinned
source manifests, and the absence of Cargo manifests above archived sources.
The only admitted archive diagnostic is the extractor's complete, exact
missing-semantic-context warning. File counts, macro counts and diagnostic
counts reconcile with the global query results. The original 26 metric
formulas, zero-defect checks, telemetry checks and positive current-source
sentinels remain enforced.

The local qualification used the official CodeQL 2.26.2 bundle and Rust 1.94.0
with `rust-src`. It extracted **all 68 original archive sources plus two Cargo
probe modules** and ran the three repository quality queries with
`--warnings=error`. `QUALIFICATION.json` records 70 extracted files, two
successful current files, 68 exact archive diagnostics, six current macro
calls, one current format argument, and zero extraction errors or
AST/CFG/SSA/dataflow defects. The original gate rejects this database; the
repaired gate accepts it. Eleven deliberately damaged evidence or source
controls are all rejected, including a missing current source, a current
unresolved macro, changed archive bytes and a newly introduced archive Cargo
manifest.

The three `qualified-*.json` files are decoded results from the actual CodeQL
database. Their `.log` companions and `qualification-extraction.log` preserve
execution output. `qualification-commands.json` records the commands, elapsed
times and return codes. The probe exercise qualifies the archive handling
against a real extractor; its source scope is the two probes plus 68 archives.
The full repository source scope continues to be checked by hosted CI.

## Exact fixture and replay

`FIXTURE.json` stores the original relative path, UTF-8 bytes, byte length and
SHA-256 of both probe modules and their two Cargo manifests. It also contains
the five original archive manifests and the 68 archive source identities. The
archived source bytes are read from their unchanged repository paths. The
probe modules are encoded as JSON data so that they do not add product source
paths to the repository's 174-file tracked Rust inventory.

The same JSON embeds `replay.py` and `qualify.py`, each with byte length and
SHA-256. From a normal checkout, extract the replay entry point to a location
outside the checkout:

```sh
python3 - <<'PY'
import hashlib, json, pathlib
fixture = pathlib.Path('research/sdk-alpha1/evidence/20261111-paper-ci/FIXTURE.json')
record = json.loads(fixture.read_text())['scripts']['replay.py']
data = record['utf8'].encode('utf-8')
assert len(data) == record['bytes']
assert hashlib.sha256(data).hexdigest() == record['sha256']
pathlib.Path('/tmp/qperiapt-paper-replay.py').write_bytes(data)
PY
python3 /tmp/qperiapt-paper-replay.py \
  --fixture research/sdk-alpha1/evidence/20261111-paper-ci/FIXTURE.json \
  --repository "$PWD" \
  --output /tmp/qperiapt-paper-qualification \
  --codeql /absolute/path/to/codeql/codeql \
  --rust-bin /absolute/path/to/1.94.0-x86_64-unknown-linux-gnu/bin
```

Use a new output directory on each run. The selected Rust toolchain must
include `rust-src`. The fixture records the verified official bundle URL,
size and SHA-256; the replay checks the CLI and compiler versions, every
materialized source digest, and the three query digests before execution.
It creates an isolated source root and database and writes logs, decoded
results, command receipts and `QUALIFICATION.json` to the output directory.
The setup can be verified without running CodeQL by replacing the final two
tool arguments with `--prepare-only`.

The committed fixture was materialized through this entry point. All 77
fixture files matched the original experiment byte for byte. Reapplying the
embedded qualifier to that materialized fixture and the retained real query
results reproduced the qualification result and all eleven rejection
controls. `qualification-portable-replay.log` preserves the portable
qualifier's result.

## Android cleanup

The original Android 16 KiB job was
[130209634251](https://github.com/billlza/q-periapt/actions/runs/42855086673/job/130209634251),
also at `11e113f27d7708474cd55713d4a22cc028f80944`.
`android-cleanup-timing-control.json` compares the original and repaired shell
cleanup using a deterministic clock and the actual cleanup function. In the
recorded interleaving, a four-second owned uninstall starts at second 44. The
original 45-second window truncates that request to one second and exits with
status 2. The repaired function completes at second 57 after reauthorizing
ownership and observing three consecutive absent states.

The new 120-second cleanup window reserves its final 20 seconds for absence
readback and caps each uninstall request at 60 seconds. The shared deadline,
identity and signer checks, two matching ownership observations before an
uninstall, bounded recovery, and structural/signal failure propagation remain
in force. Timing and device-result logs are included in failed-job artifacts.
The deterministic experiment measures this cleanup interleaving; execution on
the hosted emulator remains part of the Android CI job.

`android-cleanup-regression.log` contains the original 35 targeted Android
checks. `codeql-paper-tests.log` and `codeql-paper-input-tests.log` contain the
original 58 quality and 13 input-provenance checks. The combined-source
verification receipt and fresh logs record the tests rerun in a normal,
independent clone with a real `.git` directory; no provenance requirement was
changed to accommodate a worktree.
