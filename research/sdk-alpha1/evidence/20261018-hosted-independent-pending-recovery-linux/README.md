# Hosted Linux exact pending-write recovery

GitHub Actions run `39168493073`, job `117796403320`, completed successfully at
`ace757f40d1af6eaad75397a6909624082e76e2b`. All seventeen independent reference
entrypoints pass on Linux x86_64. Nine local public readers verify the exact
85-file committed source closure, actual ELF executable, signatures, complete
pending-write views, original messages, renewal/rekey history and process cuts.
No live job logs were fetched.

Artifact `12150854785` contains 14,105 members and 44,979,946 bytes; SHA-256
`7f4997125ef4198528212c5262559bd6ee44f327273863d6166d03a986c52907`.
The executable SHA-256 is
`f38d21a47f708f8c3dc2c064453367501b3e0793f376530a15ef65c1746d4ced`.

The new pending-recovery lane confirms the five profiles from the
[local checkpoint](../20261018-independent-pending-recovery/README.md): unapplied,
already-applied, expired policy, Query cancellation and two recovery/renewal
cycles. Its exact 25,574-byte and 79,986-byte public views are independently
parsed; unknown delivery and Reserved work remain explicit. The readback verifies
fresh signed Query history, independent controller approval where required,
original ciphertext, current renewal and same-session rekey. It preserves the
refusal to reinterpret a renewal head as an ordinary Advance.

`CAPTURE.zip` is 40,566,922 bytes with 131 members, SHA-256
`b48e2a8dca30f0da96160de626f5bfd26b860823ddb29ac6241d90a6054c03e6`. It retains the original terminal artifact, exact
Git sources, job/artifact metadata, nine readers, their outputs and a verified
manifest. Private images and keys are excluded.

This closes the Linux hosted portion of the tested recovery increment. Apple
Silicon remains separately pending. Private image authentication and unchanged
sealed bytes remain runtime assertions; public readers do not reconstruct private
MACs. The privileged fixture controller is not deployed account authentication.
Installed/deployed independent lifecycle, minimum platforms, physical erasure,
power loss, resources/energy and full retained-state PCS/refinement remain outside
this receipt. It is not full 0.2.0 admission.
