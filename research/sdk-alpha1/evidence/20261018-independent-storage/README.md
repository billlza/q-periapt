# Independent persisted session checkpoint

The Python/OpenSSL reference now owns an encrypted local journal and persists its
original bootstrap, epoch-zero traffic, outgoing reservations, ciphertext outboxes,
incoming plaintext and consumption acknowledgements. Its protocol and storage
state machines are independent of Rust and redb. The exact format, trust inputs,
failure contract and limits are in [STORAGE.md](../../../continuity-openssl-peer/STORAGE.md).
Identity signing private keys are never placed in session snapshots or restarted
workers. The retained reply KEM seed and traffic material are encrypted; this is
not an erasure or post-compromise recovery claim.

The final local Apple Silicon validation ran:

- `storage_checks.py`: 16 real SIGKILL workers, 37 checks, including exact-target
  recovery, original genesis, missing state, private files, competing leases,
  two-thread CAS, authenticated conflicting predecessors and reserved capacity.
- `durability_checks.py`: 27 fresh-process operations, six real SIGKILL cuts and
  nine commands against a live Rust journal; six malformed snapshot refusals.
  The exact original ciphertext, plaintext and ACK are recovered after lost
  results. Retired IDs cannot become new operations. Expired authority allows
  status inspection but denies protocol output.
- `run.py`: all original 41 native commands and 51 independent refusals remain.
- Explicit provider-origin negative control: a shadow module is rejected before
  its code executes. Python AST checks, workflow lint and whitespace checks pass.

Each command used `artifact/python-run.sh`, the explicitly selected Python 3.14,
the hash-pinned cryptography 48.0.1/OpenSSL 4.0.1 provider and the native counterpart
whose hash is in `CHECKS.json`. Successful output directories are `store-qualified`,
`session-qualified-02` and `volatile-qualified-02` in the capture. `review.py`
rechecks all 23 source hashes, public signatures/transcripts, command hashes,
worker outputs, exact replay and the retained red/green evidence. No private
wrapping key, configuration or journal image enters this capture. The private
fixtures and failed states remain at their original local paths.

The newly written prototype initially released cached final/initial bootstrap
output after advertisement expiry. The added expiry case failed before the fix;
the actual Rust contract already enforced this gate. The old prototype source,
failed output and diagnostic are retained. The repaired owner checks the full
bootstrap authority even for replay; established traffic retains its distinct
authority gate. A separate attempted run used a mistyped Python path and failed
before protocol execution; its stderr is preserved and not counted as a runtime
failure or pass.

This is one fixed-authority, local-only, pairwise bootstrap/epoch-zero session.
The independent workers restart; the Rust counterpart process remains alive.
SIGKILL does not qualify hardware power loss. Consistent backup rollback and
physical erasure are not provided. Rekey, required witnesses, renewal, revocation,
multiple-device lifecycle, installation/upgrade management, network carriers and
installed independent packages remain open. The earlier hosted volatile cohort
does not qualify these new persistence paths; hosted validation is being added to
the same Linux x86_64/Apple Silicon workflow. No Intel Mac lane is introduced.
