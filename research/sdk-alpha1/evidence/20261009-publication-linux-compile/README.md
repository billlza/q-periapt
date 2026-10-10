# Native Linux compiler check for publication client repair

The installed Rust/C GitHub job at `b1006eb3` failed under GCC 15 because
`publication_client.c` put an unguarded `decode` immediately after a one-line
`if` on the same source line. The `f9ae04b9` repair places that statement on its
own line, retaining the argument check and decode behavior.

This follow-up uses the retained native Linux aarch64 VZ VM, its original
Debian 12 container and **GCC 12.2.0**. Both exact Git snapshots were copied to
new guest directories, with every C/header file hashed. Compilation runs as
UID 1000 and the container has no host bind mounts. The complete `client.c`,
`recovery_client.c` and `opening_client.c` translation units were compiled to
objects under both `-O0 -g` and `-O2`, always with
`-std=c11 -Wall -Wextra -Werror -Wpedantic -pthread`.

Both old-client compilations fail specifically on `-Wmisleading-indentation`;
all six corrected-source object compilations pass. The four old recovery/opening
control compilations also pass. No warning suppression, compiler installation
or product-source edit was made. The VM/container were restored to their original
stopped state after the run; their disk and this run's objects remain retained.

`CAPTURES.zip` contains both source-input sets, all twelve commands/statuses,
compiler/kernel/container identities, diagnostics, successful object hashes and
shutdown verification. This supplements the previous macOS GCC 15 red/green and
actual C runtime evidence. It does **not** qualify GCC 15 on x86_64 Linux, link or
execute these new Linux objects, or replace the pending hosted installed-package
rerun. Current Rust CodeQL must finish and retain diagnostics before the next
same-ref push.
