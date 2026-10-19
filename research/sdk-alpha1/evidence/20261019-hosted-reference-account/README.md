# Hosted optional reference-account checks

[Run 39190947340](https://github.com/billlza/q-periapt/actions/runs/39190947340)
completed successfully at `c891e32a874d76f14a8e8e6247517282dfefb77d` on
Linux x86_64 and Apple Silicon. Both terminal artifacts were downloaded after
completion, checked against their GitHub digests, and read without executing
artifact code.

Each host passed formatting, all eight named storage/authentication/HTTP tests,
strict all-target Clippy and a release build. Readback checked the exact Git
head and lockfile, all expected test names, no ignored/filtered tests, Rust
1.98.1 and the expected target architecture. It did not inspect live job logs.

The tests use an upstream software authenticator and simulated user verification.
The separate local real-user Passkey/restart receipt remains separate evidence.
No hosted executable was exported: `binary.sha256` is a producer observation,
not a locally inspected or installed binary. Device approval/issuance, deployed
HTTPS, installed application qualification and the complete lifecycle remain open.

`CAPTURE.zip` retains both complete upstream artifacts, terminal job/run metadata,
readback scripts/results and the exact 13 app/workflow source files. Its manifest
checks every other member. SDK dependency sources are identified by the exact
Git head rather than duplicated here. No private account database, browser
session, real account name or device secret is included. The optional app is
not an SDK account requirement.
