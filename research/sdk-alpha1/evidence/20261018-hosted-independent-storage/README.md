# Hosted Linux independent storage checkpoint

Job [117682453935](https://github.com/billlza/q-periapt/actions/runs/39129803021/job/117682453935)
at `0cff3934a8042816259944f2e4fd28236e61c49a` completed successfully after the
direct-worker correction. Its complete original 2,044,063-byte artifact is retained
in the capture, with SHA-256
`3bf55021759c63adca4e255c03a3c864c2642036fb92b560fa8d9d23b1c50f35`.

The local readback matches all 24 source hashes to that exact Git commit, verifies
the actual ELF64 x86_64 executable, and rechecks public authority, signatures,
bootstrap/session fields and command/result hashes. The original 41-command and
51-refusal volatile regression passes. The new storage lane passes 16 real kills
and 37 checks; persisted sessions pass six kills, 27 operations, nine native commands
and six codec refusals. The kill markers record the actual worker PIDs verified by
the harness before killing and waiting. Exact output recovery and expiry refusals
remain; no private key or journal image is included.

This is local-only persisted bootstrap/epoch-zero interoperability on hosted Linux.
The earlier failed launcher run remains failed and retained in the preceding
checkpoint. Hosted macOS, independent durable rekey, required witnesses, complete
identity/installation lifecycle, hardware power loss and release readiness remain
separate. Secret MAC/AEAD verification occurs in the actual runtime tests; the
public artifact reader does not rederive those keys.
