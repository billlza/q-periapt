# Installed Apple/Swift maintenance-cohort qualification

The complete existing Apple packaging and Swift Debug/Release qualifiers passed
over the [completed installed C foundation](../20261104-continuity-c-maintenance/README.md).
The gate ran from 2026-11-05 00:05:04 to 02:20:16 UTC, taking 8,111.512 seconds
within its 18,000-second parent budget. Component limits remained 900 seconds
and 16 MiB per stream. The 152 top-level command receipts have zero exits;
intentional nested fault/refusal outcomes retain their scenario validators.

The clean qualification checkout is `ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`;
SDK producer `f560d803c43a24fff222daa5e5e5bd623bfdf874` has report SHA-256
`93fbef9dace1af6550a85095f6d2392285197a8fe589838f4d6f8447ba03c4f8`.
Source inputs, native-foundation binaries and reused build receipts were checked
unchanged before and after execution. At capture, current selected runtime
inputs matched; only the separately repaired CI public-export workflow differed.
This does not bind future packaging changes to this completed run.

The extracted binary package passes the macOS arm64 installed owner probe and
arm64 iOS device/simulator consumer builds. Its archive SHA-256 is
`65107175de27152a720dc3b9d29a0850640d13e7f4f971e3448194f9bcd20792`.
These iOS results are builds, not device or simulator execution. The package has
only three arm64 Rust targets: it does **not** satisfy the retained x86_64 iOS
simulator packaging requirement in [the release scope](../../../../docs/continuity/RELEASE_0_2_SCOPE.md).
That reproducible packaging gap requires its own corrected-package validation;
macOS remains Apple Silicon only.

Both Swift profiles execute the existing owner, enrollment, publication,
communication, recovery, account/root lifecycle, cancellation, cleanup and
fault/interruption scenarios. Their owner-test outputs and public publication
bytes were independently reread. The Rust 1.90 minimum-root regression also
passes with a same-source Debug C engine and Swift facade: four original and
alternative root-recovery routes, default worker stacks, cleanup and
bidirectional message recovery after rekey. This minimum-compiler result covers
that root regression, not every foreign scenario on Rust 1.90.

The evidence contains 36,554 original selected output files. Five volumes keep
each repository blob below the unchanged 100-MiB limit:

| Volume | Bytes | Members | SHA-256 |
| --- | ---: | ---: | --- |
| `PACKAGES.zip` | 36,325,977 | 4 | `992695141b6b0946a9e5cafd480cdbb3e38494c9c100ae7e9aabb5afd450d65c` |
| `DEBUG.zip` | 43,365,305 | 17,396 | `d88566e0415b55d1325511b37284157949b74f813c359b9be01a8f2a0a511eba` |
| `RELEASE.zip` | 43,437,846 | 17,396 | `84a4a72b0e382b8985b45d886092a5f5d3289df6aecaadeb81acb45bd7c5463c` |
| `MINIMUM.zip` | 30,457,855 | 1,675 | `aa0fcb7f6c62b30c88c30ed66cea2a5d7ab48cc30d1dd120b7c7e09ca445c0a9` |
| `CAPTURE.zip` | 6,201,823 | 104 | `8f508d61ce0e12a9e54ca374712ab53d7742c609ade1340d860e8b883bdcb12e` |

Every member was reread byte-for-byte; `FILES.json` records both member and
volume, and `READBACK.json` records public manifests, input checks and scope.
The first sealer's combined-volume size failure and original script/streams
remain in the capture. Splitting volumes changed no runtime result and caused
no runtime rerun. Private installations, stores and credentials are excluded.

This closes the named local Swift cohort and minimum-root regression. The full
Apple architecture matrix, Kotlin/Android, other platform/device qualification,
hosted CI, product ABI admission, external review and release remain separate.
No workflow, remote branch or release was changed.
