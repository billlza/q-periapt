# Coordinated 0.2.0 normative freeze

The budgets, actual Rust descriptor emitter and `qpc-owner/1` declaration
metadata select the same frozen contract. Current native/Android/Windows/C
qualification callers explicitly use release-stage readers; historical candidate
defaults still reject frozen input. SDK ABI 2 and its 51 exports remain separate
from the 158 Continuity exports.

`capture_freeze.py` retains the selected 21-package schema-2 graph, normative
documents and the **actual stdout** of the compiled Rust `contract_report`
example. It does not obtain a compiled descriptor by copying the budgets file.
The program was built with Rust 1.98.1, the committed lockfile, all features and
`RUSTFLAGS=-D warnings`; compilation completed without diagnostics. The existing
contract verifier then executed the binary and compared every field in release
mode. Its default historical candidate mode separately refused the same actual
binary and retained an incomplete refusal receipt as expected.

The selected descriptor has 21 joint limits and 39 signature-purpose entries.
Comparing against the earlier assessed source confirms that only the freeze
flag changed in the descriptor and owner declaration document: no domain,
profile digest, purpose byte, limit or C declaration changed. `CAPTURE.json`
records the independently selected descriptor digest and the lock identity.

The capture took place in the authoring checkout. It explicitly makes no clean
final-commit claim. Final source CI must reproduce this descriptor and qualify
the selected packages, and the final release manifest must bind that source,
actual artifacts and completed assessment receipts. The stable lock contains
neither a speculative future source commit nor fabricated artifact records.

The initial 120-test Python run reported two errors: an installed Windows test
still selected the historical reader, and local ignored build products entered
the source census. The test caller was corrected. The source census was rerun
from a 3,024-file tracked-source mirror, preserving all original local files;
116 tests passed and four Linux C-compiler controls were correctly reported as
not executable on this Mac. The additional actual-lock consistency test and its
full 39-test manifest module then passed. After adding the normative files and
that test to the source mirror, the consolidated 121-test run passed 117 tests
and retained the same four Linux-only skips. `VALIDATION.json` binds the actual
logs and final mirror identity. The required Linux controls remain for hosted
qualification; skipped controls are not counted as passes.
