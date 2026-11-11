# Complete browser peer receipt evidence

The browser fixture now binds every peer Fetch attempt to the retained request
and response bytes for that phase. Only a fulfilled, complete response can
explain its own HTTP 200 / `ERR_ABORTED` observer event. The deliberate dropped
response still requires the original rejected Fetch, exact request body,
`ERR_EMPTY_RESPONSE`, closed owner, and unchanged retry after process restart.

Implementation: `4807d0d9a39fdbf842003562e4420f6c03e201c9`, integrated into the
main checkout as `7bc5a4333e2bafdca2ff1620dece446064060aec`. This changes the
fixture, transcript readers and regression tests; the SDK transport is unchanged.
New local-policy and required-witness reports use schemas 5 and 6 respectively.
Historical reports retain their original schemas and outcomes. Peer receipt
fields cannot be reinterpreted through a legacy schema.

## Executed evidence

All browser runs used the original hosted WASM archive built from
`ff072bd66b1f5d3bdbb80171ee39bad15cbc3c20`, actually installed outside the checkout.
Its SHA-256 is `4985b8e980c364aa9224446c5c0eab1ec9fc6e44f5d061f4ea5c668ee0443394`.
The Node consumer tests and TypeScript 7.0.2 strict NodeNext checks passed under
private Node 26.10.0 / npm 12.1.0. Playwright CLI remains pinned to 0.1.22.

| Case | Actual scope | Outcome |
| --- | --- | --- |
| 01 | Install original SDK; first native build | Installation passed; build failed because OpenSSL was not selected. Original logs and the driver commit transcription erratum are retained. |
| 02 | Existing isolated OpenSSL 3.5.9 selected | Native Release build passed; CLI update notice caused the strict startup gate to fail. The already-created test browser was explicitly closed; cleanup receipt retained. |
| 03 | Chrome 157, original response delivery | Five complete peer replies and one real loss; old witness-only validator rejected the newly collected peer receipts. |
| 04 | Chrome for Testing 156.0.8078.80, original delivery | Same client outcome; no extra normal-request abort observed in this finite run. Old validator rejected the new receipts. |
| 05 | Chrome 156, response written in two parts 20 ms apart | Four normal requests reported `ERR_ABORTED` despite fulfilled Fetch Promises and exact complete client/relay byte matches. Real dropped response remained rejected. Old validator still rejected. |
| 06 | Chrome 157, same split delivery | Complete client bytes, with only the deliberate loss reported. Old validator still rejected the new receipts. |
| 07 | Chrome 156, new schema 6 reader, split delivery | Full required-witness workflow passed in 79.06 seconds: forward exchange, deliberate loss, original retry after complete native and witness restart, reverse delivery and receiver recovery. |
| 08 | Chrome 157, same new reader and split delivery | Full required-witness workflow passed in 73.92 seconds. |
| 09 | Chrome 156, schema 5, local policy | Full forward/restart/reverse workflow passed in 27.49 seconds. |
| 10 | Explicit startup diagnostic refusal | Qualification correctly failed; the new cleanup path closed the owned browser. This is a passing cleanup control, not a passing qualification. |

Cases 07–09 each retain eight forward frames and four reverse frames. The
original and independently exported transcripts were accepted by the complete
existing readers. Seventy-one browser regression checks passed, including
missing, duplicate, truncated or mismatched completion evidence; request and
response observation bounds; original Promise/rejection preservation; exact
lost-request binding; retry phase separation; and schema downgrade rejection.

The split delivery is retained as a streaming regression workload. It does not
delay the client or change response bytes. This local comparison supports the
observer discrepancy described in the [upstream Chromium issue](https://github.com/microsoft/playwright/issues/42742).
It does not retroactively establish client receipt for the original Linux CI
failure, which had no peer completion telemetry. That failed artifact remains
unchanged and still requires a new Linux execution.

The startup cleanup correction addresses an observed fixture leak: a browser
could open before the stderr gate raised, while the old cleanup flag was still
false. Cleanup ownership is now recorded before the open attempt. The primary
failure and any cleanup errors remain visible.

## Artifact and limits

`CAPTURE.zip`: **16,153,080 bytes**, **2,335 members**, SHA-256
`8632db3934a4c4edec57fe403b3bbe6a6dddb5c05736eb0d982ae2e703d61102`.
`CAPTURE.json` contains the closed member inventory and per-file hashes.
`READBACK.json` summarizes the measured cases. The archive retains original
failed attempts, public transcripts, drivers, changed source, actual native
binaries, SDK archive, dependency preparation records and test logs. It omits
private issuer keys, browser profiles and application private storage.

Chrome for Testing came from Google's exact-version manifest and HTTPS archive;
all 673 extracted entries matched that archive. The archive has ad hoc linker
signatures and no Developer ID team identity. The initial Developer ID check
failed and is retained. No resigning, quarantine removal or OS policy change
was performed. Chrome 157's installed version was observed as 157.0.8103.39;
browser transcripts retain their actual reduced user-agent strings.

This is macOS arm64 fixture qualification of the original ff072 SDK cohort.
Main's existing Windows-test-only source delta changes its workspace digest to
`c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d`;
the qualified SDK remains bound to
`ef0a49c67ca697b8bb8c6c9df309e668cc5367e62692fe66d8c37c60fab52137`.
The integration receipt proves this browser correction itself changed neither
the C/JNI package source inputs nor the WASM package source inputs. It does not
qualify a new SDK package for the Windows-fixed root. Linux CI, full platform
acceptance, computational proof, external review and release remain open.
