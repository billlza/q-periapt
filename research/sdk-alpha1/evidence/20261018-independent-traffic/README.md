# Independent epoch-zero traffic checkpoint

The Python/OpenSSL peer now derives the initial directional traffic and ACK keys
from its own confirmed root and exchanges real ChaCha20-Poly1305 frames with the
Rust candidate's actual `DeviceJournal`. No Rust root-export hook was introduced.
The complete original bootstrap controls remain, followed by a separate fresh
bootstrap for the durable Rust session.

The final run passes 41 native commands and 51 Python refusal controls. Each
direction carries three new messages of 0, 31 and 16384 plaintext bytes, with
associated data of 5, 19 and 1024 bytes. Reordered delivery exercises both peers'
skipped keys. Invalid tags and application AD do not consume the original keys.
Exact sends and retained native outboxes replay unchanged; consumed message IDs
cannot become new sends. Out-of-order consumption leaves prefix zero until gaps
are filled, then both directions authenticate prefix three. A valid old ACK is
idempotently ignored without regressing that prefix.

Five actual Rust journal close/reopen boundaries retain the reply, completed
bootstrap, skipped keys, outbox and accepted ACK state. Message operations run at
trusted time 170 after the signed advertisement and leaves expire at 160, while
credentials, rosters and policy remain valid until 200. The same context refuses
a new bootstrap at 170 and all traffic at authority expiry. This distinguishes
established-session admission from fresh prekey admission.

The Rust driver separates enrollment, bounded control I/O and journal operations.
Strict build, Clippy, format and workflow lint pass. Its 118 registry dependency
versions/checksums match the original candidate lock. All 46 source-inventory gate
tests pass against the actual 722 Rust sources. The new source count does not
claim a new CodeQL analyzer/query result.

Private journal/key fixtures remain outside the public experiment directory.
A negative run points the temporary directory inside that directory: creation
is refused before any private file is written, the process fails, and no success
result is produced. The empty refused directory and diagnostics are retained.
The CI runner explicitly places temporary files in its separate runner directory.
The capture includes only public test messages, controls, build records and the
native executable; it contains no wrapping key or private journal image.

`CHECKS.json` binds the 14 peer/counterpart source files, actual executable,
provider and capture bytes. Every saved native command input/output hash and
status was checked, including exact replay after reopening. The final provider
is cryptography 48.0.1 with hash-pinned OpenSSL 4.0.1 wheels. Earlier successful
runs and the deliberately failing artifact-boundary control remain in the capture.

**The independent side is still volatile.** This is root/traffic interoperability
against a real Rust storage boundary, not independent durable session admission.
The five reopens retain the original process and are not process-crash or
power-loss tests. Independent commit-before-release, rekey, recovery, witness,
renewal, revocation and full lifecycle remain required. The earlier hosted `b60`
bootstrap result does not qualify this new traffic increment.
