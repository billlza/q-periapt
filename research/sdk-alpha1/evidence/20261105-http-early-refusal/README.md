# HTTP early refusal: actual TCP red/green

Commit `d4c20bd323e2e380fc5545a180da7d38375e6a4a` corrects the shared
qualification-only account HTTP client. Previously it wrote the complete body
before reading a response. A server rejecting a declared oversized body could
close while that upload was still being written. The fixture then failed on
the write instead of verifying the actual refusal.

The original macOS CI failure is retained: job `127182939597`, actual merge
source `b08a90d840e1a6f8763cc60b7dabb0a04b6f578b`, policy-approval oversized
request, connection reset during the write. A new real loopback TCP regression
exposed the same write-before-response problem in the old helper as
`Broken pipe (os error 32)`; it exited 101.

Nonempty request bodies now use `Expect: 100-continue`. The client sends the
body only after receiving Continue, or reads an early final response. This is
the response coordination defined by [RFC 9110 section 10.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1).
The fixture does not retry a request, ignore write/read failures, manufacture
413, or accept a truncated response. Unsupported informational responses and
missing final responses fail. Existing header/body bounds, socket timeouts,
no-store checks, authentication, origin checks and exact size-refusal assertions
remain in force. The actual server and SDK code are unchanged.

Verification on macOS arm64 with Rust 1.98.1 and the existing isolated OpenSSL
3.5.9 installation:

* Old helper plus the new early-refusal regression: one failure, exit 101.
* Corrected complete HTTP binary suite: 16/16 Debug and 16/16 Release passed.
* The original policy-approval lifecycle test passed in both profiles.
* New live TCP controls cover complete early 413 without body upload, exact
  body delivery after Continue, and incomplete or missing final responses.
* All-target Clippy with `-D warnings` and the manifest-wide format check passed.

The C/JNI package and WASM package source-input digests remained unchanged;
the checked impact receipt is included. This test helper change does not
qualify a new SDK package for the existing Windows source delta. No claim about
library runtime test counts is inferred from Clippy. Remote macOS and Linux
confirmation remains pending the next valid CI wave.

`CAPTURE.zip`: 61,868 bytes, 23 members, SHA-256
`b5adef325cae9ac761e11d13cf1f092019b70d5401cc00a13ec63f607d14b3db`.
It retains the original remote failure artifact/log, local red and green source,
actual commands and streams, source-impact receipt and current source. Every
member was CRC checked and byte-compared against `CAPTURE.json`.
