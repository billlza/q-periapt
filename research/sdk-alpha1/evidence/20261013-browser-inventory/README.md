# Browser prekey inventory maintenance

The private browser owner now exposes `prekey_status` and `retire_prekey` through
the same device-service state machine as the native implementation. Generation
and inventory operations live together in small dedicated modules. No private
key, signer, raw storage handle or new traffic authority is exposed.

The installed npm archive was exercised in real Chrome against a fresh signed
witness cohort. Four cases completed 314 witness requests:

- An absent request becomes Available after generation, and reopening recovers
  the identical public key. Retirement is repeatable, survives reopening, and
  regeneration rejects with `KeyRetired` and a closed owner.
- After runtime closure, a held policy still permits inventory observation and
  retirement. A fresh generation rejects with `Closed` and closes the owner.
- Retiring publication history leaves all four inventory members Available.
  Retiring one member leaves the other three Available. Reusing the retired
  member rejects before reserving another publication. An independent native
  process verified the original public artifact's signature, context and all
  membership proofs using the same Rust protocol engine.
- Retiring an absent request rejects with `Absent`; reopening confirms that no
  record was fabricated.

The package's 10 existing browser scenarios, installed Node checks, strict
TypeScript checks, product/engine WASM Clippy and formatting also passed. Full
artifact-test discovery ran in a real Git checkout; the retained log records its
exact count and platform-conditioned skips. The earlier attempt from the main
worktree failed two source-inventory checks because their provenance contract
requires a real `.git` directory. The requirement was retained. An initial Clippy
failure from moving a shared import was fixed before packaging; both logs remain.

`CHECKS.json` pins the package, manifest, source overlay and `CAPTURE.zip`. The
capture includes the actual harness, public fixture inputs, native-verifier
source, request/response records and command receipts. Private authority and
wrapping-key directories are excluded. The source overlay is based on `ecabd332`;
the subsequent CI-isolation assertion repair does not alter these runtime bytes.

These cases exercise Absent, Available and Retired. Reserved, Consumed and
Abandoned have exhaustive enum mappings but were not produced by this browser
run. Logical retirement does not prove physical/backup erasure or remove public
advertisements from remote recipients. This is local Chrome/Node qualification,
not an independent protocol implementation, deployed HTTPS/browser matrix, PCS
proof or completed 0.2.0 release. Native installed-package qualification and
hosted CI/CodeQL remain separate.
