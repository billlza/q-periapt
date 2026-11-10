# Archive input binding and cleanup ownership

## Reviewed source

The review covers `artifact/codeql_log_recovery.py` and
`artifact/deterministic_archive.py` at integration commit
`6a0ac0bbd7a5be77443e10b22c20a31f4b3be271`. Both implementation blobs match the
retained CodeQL scan commit `56f191f04a57806869b8a03078ee4d27ffe900ab`.
The selected scope contains 46 path-flow results and 121 complete thread flows.
Those flows identify review locations; they are not 46 distinct vulnerabilities.

The Python SARIF came from artifact `13654276807` of run `42554273879`.
Its downloaded ZIP has SHA-256
`826c53352c27bcc877b45a93c4b1561acf427c78a3ea5512e6827435da3d48b1`;
the contained SARIF has SHA-256
`cd5d6bf8a4f0b5a75e85b6ce99355c71117cd6f188d8a2e36d35dac39aae6abb`.
The complete selected results are retained in `selected-sarif-results.json.gz`.

## Confirmed defects and corrections

### Log bytes after archive validation

The previous recovery hashed a file and then read its ZIP index and members
through the same mutable descriptor. A real, equal-length ZIP rewrite after
hashing changed the recovered payload from `original` to `replaced`, while the
admitted archive digest still described the original ZIP. The counterexample
keeps the inode and length and restores the original mtime.

Recovery now uses `consume_regular_snapshot` to hash and copy the same bounded
chunks into a private `TemporaryFile`. ZIP indexing and member reads use that
copy. Subsequent changes or replacements of the original pathname cannot change
the validated bytes being parsed. The independent reproduction now recovers
`original` in both the stable and rewritten-source cases. Wrong or incomplete
captured inputs still fail, and the recovery failure receipt retains
`diagnostic_recovery_complete=false`.

This uses the existing cross-platform snapshot helper rather than treating
Windows creation time as POSIX ctime. The deployed recovery workflow currently
uses Ubuntu 24.04. Local verification was performed with CPython 3.12.14 on
Linux; this review does not claim a new Windows execution.

The copy uses chunks of at most one MiB. Additional temporary disk is capped at
the pinned archive size, 600,073,757 bytes, and the temporary object closes on
success or failure. Copying and recovery share the existing 600-second checked
budget. Archive pins, member census, line limits, total log limits and compressed
output limits are unchanged. The helper rejects observed input changes while
capturing; the copied bytes and pinned SHA-256 establish the parsing identity.

### Cleanup after unsuccessful exclusive creation

Three cleanup sites could remove a path that another call had created before
the current call's exclusive creation completed:

- log recovery's `.gz.partial` file;
- deterministic archive creation's temporary file;
- deterministic extraction's staging directory.

Each site now records ownership only after `open('xb')` or `mkdir` succeeds.
Failure cleanup runs for those owned paths. The tests insert actual competing
files or directories before the exclusive operation and retain the resulting
real `FileExistsError`. The competing data survives after the correction.
The existing owned-output cleanup, target-creation races and error reporting
remain covered. The archive module's existing caller-controlled parent-directory
premise continues to apply.

## Verification

From the selected `artifact` directory:

```sh
python -m unittest -v test_codeql_log_recovery test_deterministic_archive
```

The candidate passes 44 tests: 20 log-recovery tests and 24 archive tests.
The identical test files on the original implementations produce six failing
assertions across four test methods: one wrong recovered payload, one deleted
competing partial, and four deleted competing archive paths across tar.gz and
ZIP creation/extraction. The remaining controls retain their expected outcomes.

The standalone reproduction is run as:

```sh
python reproduce_log_binding.py /path/to/selected/artifact
```

`log-binding-before.json` and `log-binding-after.json` preserve the source
digests, exact fixture digests, actual inode/size/mtime observations and recovered
payloads. `source-manifest.json` binds all four changed implementation/test files
to their original Git blobs. Baseline implementation files remain unchanged;
the red-run test files contain the new regression controls.

No workflow, query suite, alert threshold, package format, protocol operation,
formal model, or release claim is modified by this increment. No remote alert
has been dismissed.
