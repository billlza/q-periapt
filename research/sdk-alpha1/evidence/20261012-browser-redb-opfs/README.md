# Browser redb/OPFS storage experiment

An isolated WASM probe ran the existing redb 4.3.0 engine over real browser OPFS
synchronous access handles. It establishes a viable storage direction for
Continuity without introducing a second transaction engine. It does **not**
admit browser Continuity or change the supported SDK entry points.

Chrome 154.0.8037.99 on macOS arm64 ran the probe in dedicated Workers. The
backend enforces a 64 MiB extent, exact read/write lengths, exclusive file handles
and a cooperating lifetime Web Lock. An ordinary update atomically changes a
revision and image with redb Immediate durability and two-phase commit. Both
flushes were observed. No in-memory backend substitutes for persistence.

[RESULT.json](RESULT.json) records eleven cases:

| Boundary | Observed result |
| --- | --- |
| Second cooperating owner / direct second OPFS handle | Busy / `NoModificationAllowedError` |
| Normal commit, close and reopen | Exact new revision and image |
| Browser file → native redb update → browser reopen | Revisions 1 → 2, exact corresponding images |
| I/O exceptions before/after flush 1 | Error, owner closed, original pair recovered |
| I/O exceptions before/after flush 2 | Error, owner closed, new pair recovered |
| Worker termination before/after each of the two flushes | Original/new pairs respectively, never a mixed pair |
| One-phase negative control, termination after flush | Refused before mutation; file SHA-256 unchanged |

The I/O exceptions are explicitly injected around real flush calls; they are
not quota exhaustion or physical disk failures. Worker termination interrupts a
bounded test-only pause at the selected boundary. The controller verifies that
the operation has not returned, terminates it, waits for actual lease release,
and reopens the original file. Five observed lease releases took approximately
2.01–2.03 seconds; calling `terminate()` is not completion evidence.

An error at the second flush can leave a committed new image. That is an
unknown operation outcome requiring original-operation recovery, not permission
to allocate a replacement operation. This reproduces the reason Continuity's
existing pending intents and witness agreement must survive the browser port.

The native `refuse_unclean_foreign_redb` rule was extracted into a private,
platform-independent format module and compiled directly into the probe. The
native admission wrapper and its unsupported-platform refusal remain intact.
The existing 37 filesystem tests pass, including recovery-header, short-file,
read-error, locking and publication failures. The one-phase method exists only
in the isolated negative-control probe. No public storage escape hatch was added.

[CHECKS.json](CHECKS.json) pins every input and the 59-member [CAPTURE.zip](CAPTURE.zip)
(SHA-256 `644a03bb0e03d1436560838c2512b853622588a1c6e47f424472486a382816f9`).
The capture includes exact WASM and glue, pinned Cargo inputs, native and browser
files, source snapshots, assertions, raw logs and the verification script. It
also preserves the earlier probe compile/import and runner syntax failures;
those are not successful experiments. The compiled format snapshot precedes
rustfmt; the final source is included separately. All archive members were
reread. Final Web Lock inventory was empty, the named browser was closed, and
both owned servers were confirmed absent.

The relevant API contract is the [WHATWG File System Standard](https://fs.spec.whatwg.org/#api-filesystemsyncaccesshandle),
read on 2026-10-12: synchronous handles are restricted to secure dedicated
Workers, acquire exclusive access, and expose explicit `flush()`; `close()`
alone does not provide the flush guarantee. The experiment does not establish
power-loss behavior, storage eviction resistance or Safari/Firefox/mobile support.

Next integration must reuse the original journal and account transactions,
authenticated write intents, witness decisions and root fences. Installation
publication, wrapping-key ownership, browser transport, clocks, cancellation,
quota and whole-profile rollback remain separate obligations. The current probe
contains public test strings, no session protocol or security proof, and makes
no performance claim. Existing Android and iPad acceptance remain unchanged.
