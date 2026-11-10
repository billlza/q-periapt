# Installed Windows lifecycle: original hosted readback

[Run 42009005451](https://github.com/billlza/q-periapt/actions/runs/42009005451)
completed all eight jobs successfully. This record captures its original
artifacts and reproduces both public readers. It does not execute a new Windows
workload or qualify the later local candidate.

The run's PR head is `232ace17915407596d66f3a5fd7c7765251a38cc`. The actual
checked-out producer/consumer source is the PR merge commit
`93aa0582362bf91040e55f5ac3b8ee0e568d1e62`, with that head and base
`ed257e10c75af6798838ee6a95e0ccc6930cf388` as parents. The retained commit API
response, all eight job logs, producer input and all four native reports agree
on this distinction. The successful head status alone is not a source identity.

## Actual installed execution

The four native jobs cover Windows 2022 and Windows 2025, each under Debug and
Release, using Rust 1.98.1 for `x86_64-pc-windows-msvc`. Each consumes the same
external archive bundle and resolves nine SDK crates plus the unpublished
Continuity candidate from that bundle, outside the repository checkout.
The C clients use the produced DLL and matching header/import library.

Each profile retains the original three-case Rust owned-connection result,
ten-case C-owner integration result and four-case configuration-path result,
all with zero failures, ignored cases or filtered cases. The counts include
the existing test helpers; they are not counts of independent security claims.
The complete public readers additionally check seven C owner paths, four
account-root replacement routes and six first-registration carrier/trust cases,
including real-clock expiry and independent renewal. Forty-six successful
command receipts are present per profile.

The retained workloads cover original-operation recovery, cancellation,
unknown commits, revocation, device replacement/retirement, continued traffic
and the recorded Windows `TerminateProcess` cuts. They share the native engine
and host. They are neither independent protocol implementations nor power-loss
experiments. Later private-publication maintenance changes and the current
candidate's formal/product admission remain separate.

## Package and source identity

The byte-exact input digest is
`5ff8edfad88b181376bb52e987beddba674f1caada32c2c9ca223ac64e565792`.
Its SDK receipt digest is
`923788025b6ab6f91b561a56295a6418bb21be6e7899962330ae1f68a19085ef`.
The producer SDK workspace digest is
`75bbe6e71aadf3d3315c5708047684cbf55f782e6c1e1decf77a59e387d39f51`.

The local identity audit checks the 383-file SDK workspace against the actual
merge tree, 20 additional SDK source bindings, 126 facade source bindings,
720 candidate source/test files, all 1,182 installed bundle files, all twelve
SDK archives and the candidate archive. The nine selected SDK archive trees
and candidate tree match the installed bundle byte-for-byte. All four actual
Cargo metadata records resolve the expected ten product packages and preserve
171 external package identities/checksums. All eight downloaded ZIP hashes
also match GitHub's artifact digests, not only their advertised lengths.

The retained DLL archives contain the exact header, import library and x86_64
PE DLL. DLL SHA-256 values are:

| Native profile | DLL SHA-256 |
| --- | --- |
| Windows 2022 Debug | `98585b0ba7244d9ec4e55e46b0ca47e03009bfcc6c5419f4c14f6164ad3d9ec5` |
| Windows 2022 Release | `92115a2fca789eec3512f3070e4bdf09262a76ebf433e305b00eed10e1e50422` |
| Windows 2025 Debug | `f911204954c2d2b473ac27a8b4ee55cf0f208beeef03d4329b3a56f3a7825342` |
| Windows 2025 Release | `cd4cfa1c5ebaaf8ea45e6a2eb458e27ab403e7af66cef7c8782684668564c5d6` |

At local head `4cda512f0e2a8d5e986f49a28261bd37a74cb0bb`, 52 of the
checked workspace/candidate/facade inputs differ: 15 SDK workspace files,
14 candidate source/test files and 23 facade files. The current SDK workspace
digest is `c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d`.
The full changed-input list is retained. These original successes cannot be
transferred wholesale to that current source.

## Readback and retained files

At 18:16 UTC on 2026-11-05, the original public reader was executed separately
for each Windows version on the downloaded Debug/Release pair. Both returned
zero and reproduced the complete hosted `NETWORK_REVIEW.json` value exactly.
Each loaded 44 repository modules, all checked against the pinned merge source;
the static import closure of 104 modules is retained. The subsequent identity
audit also passed. These local commands read evidence; no Windows process was
executed locally and no hosted job was retried.

`INPUTS.zip` contains the original SDK/package-input artifacts, pinned readers,
producer workflow/scripts, inventories and capture/replay drivers. `RESULTS.zip`
contains the six original native/readback artifacts, API provenance, all job
logs, reproduced reports, module identities and identity-audit command streams.
The original archives contain 6,072 members in total. Both capture capsules
were fully reread, including every member's length and SHA-256.

| Capsule | Bytes | Members | SHA-256 |
| --- | ---: | ---: | --- |
| `INPUTS.zip` | 15,987,141 | 127 | `ca5a0f2d855a45289e708fa48cfe4a67ea2dc39aa19ad9b030772d2f15e81b90` |
| `RESULTS.zip` | 81,563,027 | 32 | `ee323b8252d11a0c1515ce557c9175b145bf498b64219b5c54d05ee43b7e6735` |

`FILES.json` binds each captured member. `CAPTURE.json` separately identifies all
eight original artifact IDs, sizes and hashes. No product source, support
contract, release flag or workflow timeout was changed for this readback.
